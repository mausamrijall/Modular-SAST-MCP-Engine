"""Second-stage assurance: proof verification and expected-usage noise reduction.

Executed inside the isolated Docker container by ``sandbox/worker.py``.  This
module layers a verification stage on top of the deterministic static
findings:

* ``verify_pocs`` - for each candidate finding it builds an isolated,
  in-process harness for Python targets: the enclosing function is loaded and
  called with a benign random marker while every dangerous sink (``open``,
  ``os.system``, ``subprocess``, ``eval``/``exec``, ``urllib``, ...) is
  replaced by a recording no-op.  A finding is ``verified`` only when the
  marker actually reaches an instrumented sink.  Static-truth findings
  (embedded credentials, supply-chain artifacts) are ``static-confirmed``
  because the finding *is* the artifact.  Other languages receive a
  ``static-only`` verdict because the current sandbox has no runtime for them.

* ``assess_behavior`` - re-derives the deterministic findings in-sandbox and
  classifies each one as ``expected`` (test/fixture/example/docs/lockfile
  content, template config, intentional crawl policy) or ``unexpected`` so the
  orchestrator can filter noise before counting valued findings.

Safety: the harness never sends a network request (the container runs with
``--network=none``), never mutates the target (read-only mount), and replaces
every dangerous sink with a no-op that only records its arguments.  No exploit
payload is used and no real operation is ever executed.
"""

from __future__ import annotations

import ast
import collections
import inspect
import io
import re
import secrets
import threading
from pathlib import Path
from typing import Any

from sandbox.analysis import _display_path, _read_text, iter_source_files

STATIC_TRUTH_CHECKS = {"01", "30", "supply-chain"}
STATIC_TRUTH_RULES = {
    "hardcoded-credential",
    "default-credentials",
    "unpinned-dependency",
    "install-script-network-execution",
    "package-script-download-execute",
}

_NOISE_SEGMENTS = (
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "fixtures",
    "fixture",
    "examples",
    "example",
    "samples",
    "sample",
    "docs",
    "doc",
    "documentation",
    "stubs",
    "mock",
    "mocks",
    ".github",
    ".gitlab",
    ".vscode",
    ".idea",
    "templates",
)
_NOISE_FILENAMES = {
    "robots.txt",
    "readme",
    "readme.md",
    "license",
    "changelog",
    "contributing",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "composer.lock",
    "go.sum",
    "gemfile.lock",
    "cargo.lock",
    "flake.lock",
    "pipfile.lock",
    "pubspec.lock",
    "deno.lock",
}
_NOISE_EXTENSIONS = (
    ".md",
    ".markdown",
    ".rst",
    ".txt",
    ".po",
    ".pot",
    ".min.js",
    ".map",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".woff",
    ".woff2",
    ".pdf",
)
_TEMPLATE_ENV_SEGMENTS = (".example", ".sample", ".template")


# ---------------------------------------------------------------------------
# Proof-of-concept verification
# ---------------------------------------------------------------------------


class _FakeCompleted:
    returncode = 0
    stdout = ""
    stderr = ""


class _FakePopen:
    returncode = 0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.stdout = None
        self.stderr = None

    def communicate(self, *args: Any, **kwargs: Any):
        return (b"", b"")

    def wait(self, *args: Any, **kwargs: Any) -> int:
        return 0

    def __enter__(self):
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


class _FakeResponse:
    status = 200

    def read(self, *args: Any, **kwargs: Any):
        return b""

    def __enter__(self):
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


def _make_sink_recorder(hits: list[dict[str, Any]], marker: str):
    """Build a sink recorder factory.  Every dangerous call whose arguments
    contain the benign marker is recorded; the real operation is replaced by
    ``fallback`` so nothing destructive ever runs."""

    def build(kind: str, fallback):
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            rendered = repr((args, kwargs))
            if marker in rendered:
                hits.append({"kind": kind, "args": rendered[:300]})
            return fallback(*args, **kwargs)

        return wrapper

    return build


def _import_instrumented(path: Path, hits: list[dict[str, Any]], marker: str):
    """Import ``path`` as a module while instrumenting dangerous sinks.

    The module top-level code runs inside the isolated worker process.  Sinks
    that are safe to replace before import (``open``, ``os.*``, ``subprocess``,
    ``urllib``) are patched first.  ``builtins.exec``/``builtins.eval`` are
    intentionally NOT patched here because importlib itself resolves ``exec``
    through ``__builtins__``; they are patched just-in-time around the target
    call (see ``_call_with_builtin_patch``) so later imports in the same
    process keep working.  Every sink is a recording no-op, so any
    marker-bearing call is observed without executing the dangerous operation.
    """
    import builtins
    import importlib.util
    import os
    import subprocess

    record = _make_sink_recorder(hits, marker)
    builtins.open = record("builtins.open", lambda *a, **k: io.StringIO(""))
    for attr in ("system", "popen", "execl", "execv", "spawnl", "spawnv"):
        if hasattr(os, attr):
            setattr(os, attr, record(f"os.{attr}", lambda *a, **k: 0))
    for name in ("run", "call", "check_call", "check_output"):
        if hasattr(subprocess, name):
            setattr(subprocess, name, record(f"subprocess.{name}", lambda *a, **k: _FakeCompleted()))
    if hasattr(subprocess, "Popen"):
        subprocess.Popen = record("subprocess.Popen", _FakePopen)
    try:
        import urllib.request

        urllib.request.urlopen = record("urllib.request.urlopen", lambda *a, **k: _FakeResponse())
    except Exception:
        pass

    unique_name = f"sast_verify_{abs(hash(path)) & 0xFFFFFFFF:x}"
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:
        raise ImportError("could not build an import spec")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _enclosing_function(tree: ast.AST, line_no: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", None) or node.lineno
            if start <= line_no <= end and (best is None or start >= best.lineno):
                best = node
    return best


def _resolve_function(module: Any, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> Any:
    obj = getattr(module, func_node.name, None)
    if callable(obj):
        return obj
    for value in vars(module).values():
        if callable(value) and getattr(value, "__name__", None) == func_node.name:
            return value
    return None


def _build_call_kwargs(func_obj: Any, marker: str, finding: dict[str, Any]) -> dict[str, Any]:
    try:
        signature = inspect.signature(func_obj)
    except (ValueError, TypeError):
        return {}
    evidence = finding.get("evidence") or {}
    taint_path = finding.get("taint_path") or []
    source_vars = [step.get("variable") for step in taint_path if step.get("operation") == "source"]
    parameter_hint = evidence.get("parameter")

    target_param: str | None = None
    for candidate in [*source_vars, parameter_hint]:
        if candidate and candidate in signature.parameters:
            target_param = candidate
            break
    if target_param is None:
        for param in signature.parameters.values():
            if param.name in ("self", "cls"):
                continue
            if re.search(r"(?i)(id|name|input|param|query|key|route|req|arg|data|file|path|url|value|token|code)", param.name):
                target_param = param.name
                break
    if target_param is None:
        positional = [
            p.name
            for p in signature.parameters.values()
            if p.name not in ("self", "cls") and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        if positional:
            target_param = positional[0]

    kwargs: dict[str, Any] = {}
    for param in signature.parameters.values():
        if param.name in ("self", "cls"):
            continue
        if param.name == target_param:
            kwargs[param.name] = marker
        elif param.default is not inspect.Parameter.empty:
            continue
        elif param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD):
            kwargs[param.name] = ""
    return kwargs


def _call_with_timeout(func_obj: Any, kwargs: dict[str, Any], timeout: float = 4.0) -> dict[str, Any]:
    box: dict[str, Any] = {}

    def _run() -> None:
        try:
            box["result"] = func_obj(**kwargs)
        except Exception as exc:  # noqa: BLE001 - recorded for the verdict
            box["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return {"timeout": True}
    return box


def _call_with_builtin_patch(
    func_obj: Any,
    kwargs: dict[str, Any],
    hits: list[dict[str, Any]],
    marker: str,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """Invoke ``func_obj`` with ``exec``/``eval`` instrumented as no-ops.

    The patch is scoped to the call and restored afterwards so subsequent
    module imports in the same worker process are unaffected.
    """
    import builtins

    record = _make_sink_recorder(hits, marker)
    saved_exec, saved_eval = builtins.exec, builtins.eval
    builtins.exec = record("exec", lambda *a, **k: None)
    builtins.eval = record("eval", lambda *a, **k: None)
    try:
        return _call_with_timeout(func_obj, kwargs, timeout)
    finally:
        builtins.exec, builtins.eval = saved_exec, saved_eval


def _dynamic_python(
    root: Path,
    rel: str,
    line_no: int,
    finding: dict[str, Any],
) -> tuple[str, dict[str, Any], list[str]]:
    marker = f"SASTCHK_{secrets.token_hex(4)}"
    log: list[str] = []
    path = root / rel
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as exc:
        return "unsupported", {"reason": f"parse failed: {type(exc).__name__}"}, log

    func_node = _enclosing_function(tree, line_no)
    if func_node is None:
        return (
            "static-confirmed",
            {"reason": "module-level constant (no callable harness); artifact confirmed at reported line"},
            log,
        )

    hits: list[dict[str, Any]] = []
    try:
        module = _import_instrumented(path, hits, marker)
    except Exception as exc:  # noqa: BLE001 - recorded for the verdict
        log.append(f"import failed: {type(exc).__name__}: {exc}")
        return "unsupported", {"reason": f"module import failed: {type(exc).__name__}: {str(exc)[:200]}"}, log

    func_obj = _resolve_function(module, func_node)
    if func_obj is None:
        return "unsupported", {"reason": "enclosing function not resolvable as a module attribute"}, log

    kwargs = _build_call_kwargs(func_obj, marker, finding)
    log.append(f"calling {func_node.name}({kwargs})")
    outcome = _call_with_builtin_patch(func_obj, kwargs, hits, marker)
    if outcome.get("timeout"):
        log.append("call timed out; no sink observed")
        return "not-reproduced", {"marker": marker, "sink_hits": hits, "log": log}, log
    if "error" in outcome:
        log.append(f"call raised {type(outcome['error']).__name__}: {outcome['error']}")
        return "not-reproduced", {"marker": marker, "sink_hits": hits, "log": log}, log
    if hits:
        return "verified", {"marker": marker, "sink_hits": hits, "log": log}, log
    return "not-reproduced", {"marker": marker, "sink_hits": [], "log": log}, log


def _verify_one(root: Path, finding: dict[str, Any]) -> dict[str, Any]:
    rel = str(finding.get("file", ""))
    line_no = int(finding.get("line", 1) or 1)
    check_id = str(finding.get("check_id", ""))
    result: dict[str, Any] = {
        "id": finding.get("id"),
        "check_id": check_id,
        "file": rel,
        "line": line_no,
        "poc_payload": finding.get("poc_payload"),
    }
    path = root / rel
    if not path.is_file():
        result.update({"verdict": "unsupported", "evidence": {"reason": "file not found"}})
        return result

    suffix = path.suffix.lower()
    if suffix == ".py":
        verdict, evidence, log = _dynamic_python(root, rel, line_no, finding)
        result.update({"verdict": verdict, "evidence": evidence, "log": log})
        return result

    if check_id in STATIC_TRUTH_CHECKS or finding.get("rule") in STATIC_TRUTH_RULES:
        result.update(
            {
                "verdict": "static-confirmed",
                "evidence": {"reason": "static-truth finding; the evidence artifact is present at the reported location"},
            }
        )
        return result

    result.update(
        {
            "verdict": "static-only",
            "evidence": {
                "reason": f"no runtime harness for '{suffix or 'unknown'}' in the sandbox; exercise the proof blueprint in an isolated fixture"
            },
        }
    )
    return result


def verify_pocs(target: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Verify candidate findings inside the isolated sandbox."""
    root = Path(target).resolve()
    results = [_verify_one(root, finding) for finding in findings]
    counts = collections.Counter(result.get("verdict", "unsupported") for result in results)
    return {
        "verification_agent": "Proof-of-Concept Verifier",
        "verification_type": "poc",
        "status": "completed",
        "target": str(root),
        "assessed_findings": len(results),
        "verified_count": counts.get("verified", 0),
        "static_confirmed_count": counts.get("static-confirmed", 0),
        "not_reproduced_count": counts.get("not-reproduced", 0),
        "static_only_count": counts.get("static-only", 0),
        "unsupported_count": counts.get("unsupported", 0),
        "results": results,
    }


# ---------------------------------------------------------------------------
# Expected-usage / noise reduction
# ---------------------------------------------------------------------------


def _collect_findings(target: str) -> list[dict[str, Any]]:
    """Deterministically reproduce the findings the orchestrator collects.

    Finding IDs are stable hashes of ``check:file:line:snippet``, so the
    annotations produced here merge cleanly onto the orchestrator's findings.
    """
    from sandbox.analysis import audit_agent, audit_supply_chain
    from sandbox.research import audit_business_logic, audit_logic_flaws, audit_taint

    findings: list[dict[str, Any]] = []
    for agent in ("secrets", "injection", "infra"):
        findings.extend(audit_agent(target, agent).get("findings", []))
    findings.extend(audit_supply_chain(target).get("findings", []))
    findings.extend(audit_taint(target).get("findings", []))
    findings.extend(audit_logic_flaws(target).get("findings", []))
    findings.extend(audit_business_logic(target).get("findings", []))
    return findings


def _assess_finding(root: Path, finding: dict[str, Any]) -> dict[str, Any]:
    rel = str(finding.get("file", ""))
    check_id = str(finding.get("check_id", ""))
    parts = Path(rel).parts
    lower = rel.lower()
    base = Path(rel).name.lower()
    reasons: list[str] = []

    if any(part.lower() in _NOISE_SEGMENTS for part in parts):
        reasons.append(f"path is inside a test/fixture/example/docs segment: {rel}")
    if base in _NOISE_FILENAMES:
        reasons.append(f"filename is a documentation, template, or lockfile artifact: {base}")
    if lower.endswith(_NOISE_EXTENSIONS):
        reasons.append(f"non-source documentation or generated asset: {rel}")

    if base.startswith(".env") and check_id in {"01", "30"}:
        if any(segment in base for segment in _TEMPLATE_ENV_SEGMENTS) or "example" in base:
            reasons.append("secret-shaped value appears in an env template where placeholders are expected")
    if base == "robots.txt":
        reasons.append("robots.txt directives are intentional crawl policy")

    if reasons:
        return {
            "behavior": "expected",
            "file": rel,
            "line": finding.get("line"),
            "rationale": "; ".join(reasons),
        }
    return {
        "behavior": "unexpected",
        "file": rel,
        "line": finding.get("line"),
        "rationale": "no expected-usage signal found",
    }


def assess_behavior(target: str) -> dict[str, Any]:
    """Classify each finding as expected or unexpected usage to reduce noise."""
    root = Path(target).resolve()
    findings = _collect_findings(target)
    annotations: dict[str, dict[str, Any]] = {
        finding["id"]: _assess_finding(root, finding) for finding in findings
    }
    expected_count = sum(1 for annotation in annotations.values() if annotation["behavior"] == "expected")
    return {
        "behavior_agent": "Behavior & Expected-Usage Evaluator",
        "behavior_type": "expected-usage",
        "status": "completed",
        "target": str(root),
        "assessed_findings": len(annotations),
        "expected_count": expected_count,
        "unexpected_count": len(annotations) - expected_count,
        "annotations": annotations,
    }
