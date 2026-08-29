"""Higher-assurance research analyses executed inside the sandbox.

This module implements the advanced research capabilities of the engine:

* ``trace_dataflow`` / ``audit_taint`` - a cross-file taint engine that
  follows user-controlled sources into dangerous sinks, records the exact
  ``taint_path`` (files, lines, and variable transformations) and verifies
  whether a sanitizer neutralizes the flow.
* ``audit_logic_flaws`` - a business-logic and authorization engine focused
  on checks 05 (Missing Authz), 06 (Cross-User Access), and 33 (IDOR/BOLA).
* ``generate_poc`` / ``generate_safe_pocs`` - non-executing proof blueprints
  (curl blocks and raw HTTP specs) that never send a request or run code.

All analysis is deterministic and local.  It is imported by the worker inside
the isolated container, never by the MCP server processes.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from sandbox.analysis import _display_path, _read_text, iter_source_files
from sandbox.slicer import build_call_tree, get_code_slice

MAX_TAINT_DEPTH = 2

TAINT_SOURCES = (
    (r"(?i)\b(?:req(?:uest)?|request|ctx)\.(?:params|query|body|cookies|headers|args|form|json|path)\b", "HTTP request data"),
    (r"(?i)\brequest\.(?:query_params|get_json|json)\b", "HTTP request data"),
    (r"(?i)\b\$_?(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", "PHP superglobal"),
    (r"(?i)\b(?:os\.)?environ\b", "process environment"),
    (r"(?i)\b(?:sys\.)?argv\b", "process arguments"),
    (r"(?i)\b(?:input|URLSearchParams|FormData)\b", "user input API"),
    (r"(?i)\b(?:request|ctx|context)\.(?:state|session|user)\b", "session-derived input"),
)

TAINT_SINKS = (
    (r"(?i)\b(?:db|knex|pool|client|conn|connection|sequelize|mongoose)\.(?:query|execute|executemany|raw|findById|findOne|find|where)\s*\(", "database query"),
    (r"(?i)\b(?:cursor|stmt|statement|pdo)\.(?:execute|executemany)\s*\(", "database query"),
    (r"(?i)\b\w+\.(?:execute|executemany)\s*\(", "database query"),
    (r"(?i)\b(?:execute|executemany|raw)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)", "database query"),
    (r"(?i)\b(?:eval|exec|compile)\s*\(", "dynamic code execution"),
    (r"(?i)\b(?:system|popen|shell_exec|passthru|proc_open)\s*\(", "process execution"),
    (r"(?i)\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b", "HTML sink"),
    (r"(?i)\b(?:fetch|axios\.(?:get|post|put|delete)|requests\.(?:get|post)|urllib\.request|curl_init|file_get_contents)\s*\(", "server-side network request"),
    (r"(?i)\b(?:open|readFile|writeFile|sendFile|unlink|file_put_contents|include|require|import_module)\s*\(", "filesystem or include operation"),
)

TAINT_SANITIZERS = (
    (r"(?i)(?:escape|htmlspecialchars|htmlentities|strip_tags|encodeURIComponent|encodeURI|json\.dumps|json\.stringify|parameterized)\s*\(", "contextual escaping"),
    (r"(?i)(?:int|intval|float|bool|strval|parseInt|parseFloat|Number)\s*\(", "numeric cast"),
    (r"(?i)(?:prepare|bindParam|bindValue|bind)\s*\(", "parameterized statement"),
    (r"(?i)(?:validate|isInt|isEmail|check|whitelist|sanitize|clean)\s*\(", "input validation"),
    (r"(?i)(?:hashlib|bcrypt|hash|md5|sha1|sha256|crypt)\s*\(", "cryptographic hash"),
    (r"(?:%s|:[a-zA-Z_][a-zA-Z0-9_]*|\?['\"])", "parameter binding"),
)


@dataclass
class TaintValue:
    """A tainted value with its propagation history."""

    steps: list[dict[str, Any]] = field(default_factory=list)
    source_kind: str = ""
    source_file: str = ""
    source_line: int = 0
    sanitized: bool = False
    sanitizer: str | None = None

    def step(self, file_name: str, line_number: int, variable: str, operation: str, sanitizer: str | None = None) -> "TaintValue":
        return TaintValue(
            steps=self.steps + [{"file": file_name, "line": line_number, "variable": variable, "operation": operation}],
            source_kind=self.source_kind,
            source_file=self.source_file,
            source_line=self.source_line,
            sanitized=self.sanitized or sanitizer is not None,
            sanitizer=self.sanitizer or sanitizer,
        )


def _research_id(prefix: str, file_name: str, line: int, text: str) -> str:
    digest = hashlib.sha256(f"{prefix}:{file_name}:{line}:{text}".encode()).hexdigest()[:16]
    return f"RESEARCH-{prefix}-{digest}"


def _research_finding(
    *,
    prefix: str,
    category: str,
    file_name: str,
    line: int,
    snippet: str,
    severity: str,
    confidence: str,
    rule: str,
    description: str,
    remediation: str,
    evidence: dict[str, Any],
    taint_path: list[dict[str, Any]] | None = None,
    poc_payload: str | None = None,
) -> dict[str, Any]:
    return {
        "id": _research_id(prefix, file_name, line, snippet),
        "check_id": f"research-{prefix.lower()}",
        "category": category,
        "agent": f"research_{prefix.lower()}",
        "sub_agent": f"research_{prefix.lower()}.{rule}",
        "severity": severity,
        "confidence": confidence,
        "file": file_name,
        "line": line,
        "snippet": snippet[:500],
        "rule": rule,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
        "taint_path": taint_path or [],
        "poc_payload": poc_payload,
    }


# ---------------------------------------------------------------------------
# Small structural helpers shared by the engines
# ---------------------------------------------------------------------------


def _find_paren_end(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


def _split_args(args_text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    quote: str | None = None
    for char in args_text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
        elif char in {"(", "[", "{"}:
            depth += 1
            current.append(char)
        elif char in {")", "]", "}"}:
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def _iter_assignments(line: str) -> Iterator[tuple[str, str]]:
    pattern = re.compile(r"(?:\b(?:let|const|var)\s+)?\$?([A-Za-z_][\w$]*)\s*=\s*(.+)$")
    for match in pattern.finditer(line):
        rhs = match.group(2).rstrip(";").strip()
        if rhs.startswith(("=", ">", "<", "!")):
            continue
        yield match.group(1), rhs


def _iter_calls(line: str, language: str) -> Iterator[tuple[str, str]]:
    if language == "php":
        pattern = re.compile(r"\$?[A-Za-z_][\w$]*(?:\s*(?:->|::)\s*\$?[A-Za-z_][\w$]*)*\s*\(")
    elif language in {"javascript", "typescript"}:
        pattern = re.compile(r"[A-Za-z_$][\w$]*(?:\s*(?:\.|\?\.)\s*[A-Za-z_$][\w$]*)*\s*\(")
    else:
        pattern = re.compile(r"[A-Za-z_][\w$]*(?:\s*\.\s*[A-Za-z_][\w$]*)*\s*\(")
    for match in pattern.finditer(line):
        name = re.sub(r"\s*(?:->|::|\.|\?\.)\s*", ".", match.group(0)).strip().rstrip("(")
        open_index = match.end() - 1
        close_index = _find_paren_end(line, open_index)
        yield name, line[open_index + 1 : close_index]


def _segment(name: str) -> str:
    return name.rstrip("$").split(".")[-1]


def _sanitizer_label(expr: str) -> str | None:
    for pattern, label in TAINT_SANITIZERS:
        if re.search(pattern, expr):
            return label
    return None


def _source_match(expr: str) -> tuple[str, str] | None:
    for pattern, label in TAINT_SOURCES:
        match = re.search(pattern, expr)
        if match:
            return label, match.group(0)
    return None


def _is_sink_call(name: str) -> bool:
    for pattern, _label in TAINT_SINKS:
        if re.search(pattern, name + "()"):
            return True
    return False


# ---------------------------------------------------------------------------
# Cross-file taint engine
# ---------------------------------------------------------------------------


class _TaintEngine:
    """Deterministic, bounded cross-file taint tracker.

    The engine is deliberately pragmatic: it tracks variable-level taint
    within a function, propagates tainted arguments into callees (up to
    ``MAX_TAINT_DEPTH`` levels) across file boundaries, and records every
    transformation in a ``taint_path``.  Sanitizer calls neutralize the
    taint and are recorded as ``sanitize`` steps so a downstream review can
    verify the defense.
    """

    def __init__(self, target_root: str, maps: dict[str, dict[str, Any]]) -> None:
        self.target_root = Path(target_root)
        self.maps = maps
        self.flows: list[dict[str, Any]] = []
        self._lines_cache: dict[str, list[str]] = {}
        self._active: set[tuple[str, str]] = set()

    def _lines(self, rel: str) -> list[str]:
        if rel not in self._lines_cache:
            path = self.target_root / rel
            self._lines_cache[rel] = _read_text(path).splitlines() if path.exists() else []
        return self._lines_cache[rel]

    def _module_record(self, rel: str, tree: dict[str, Any]) -> dict[str, Any]:
        lines = self._lines(rel)
        min_start = min((record["start"] for record in tree["functions"].values()), default=len(lines) + 1)
        return {
            "name": "<module>",
            "qualname": "<module>",
            "kind": "module",
            "start": 1,
            "end": max(1, min_start - 1),
            "params": [],
        }

    def run(self, source_file: str | None = None, sink_function: str | None = None) -> list[dict[str, Any]]:
        sink_filter = self._sink_filter(sink_function)
        files = [source_file] if source_file else sorted(self.maps)
        for rel in files:
            tree = self.maps.get(rel)
            if tree is None:
                continue
            self._analyze_function(rel, self._module_record(rel, tree), tree, {}, 0, sink_filter)
            for record in tree["functions"].values():
                self._analyze_function(rel, record, tree, {}, 0, sink_filter)
        return self.flows

    def _find_any_record(self, name: str) -> dict[str, Any] | None:
        for rel, tree in self.maps.items():
            for qualname in tree["by_segment"].get(_segment(name), []):
                return tree["functions"][qualname]
            if name in tree["functions"]:
                return tree["functions"][name]
        return None

    def _sink_filter(self, sink_function: str | None):
        """Return a predicate accepting a sink when it matches the requested
        function or any callee within ``MAX_TAINT_DEPTH`` of it."""
        if sink_function is None:
            return lambda name, tree: True
        sink_segment = _segment(sink_function)

        def allow(name: str, tree: dict[str, Any]) -> bool:
            if name in {sink_function, sink_segment}:
                return True
            seen: set[str] = set()
            frontier: set[str] = {sink_segment}
            for _ in range(MAX_TAINT_DEPTH):
                next_frontier: set[str] = set()
                for function_name in frontier:
                    record = self._find_any_record(function_name)
                    if record is None:
                        continue
                    for called in record.get("calls", []):
                        segment = _segment(called)
                        if segment == _segment(name):
                            return True
                        if segment not in seen:
                            seen.add(segment)
                            next_frontier.add(segment)
                frontier = next_frontier
            return False

        return allow

    def _resolve_callee(self, name: str, tree: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        segment = _segment(name)
        candidates: list[tuple[str, dict[str, Any]]] = []
        for qualname in tree["by_segment"].get(segment, []):
            candidates.append((self._current_rel, tree["functions"][qualname]))
        if name in tree["functions"]:
            candidate = (self._current_rel, tree["functions"][name])
            if candidate not in candidates:
                candidates.append(candidate)
        if candidates:
            return candidates[:2]
        for rel, other in self.maps.items():
            for qualname in other["by_segment"].get(segment, []):
                candidate = (rel, other["functions"][qualname])
                if candidate not in candidates:
                    candidates.append(candidate)
                if len(candidates) >= 2:
                    return candidates
        return candidates

    def _analyze_function(
        self,
        rel: str,
        record: dict[str, Any],
        tree: dict[str, Any],
        pre_taints: dict[str, TaintValue],
        depth: int,
        sink_filter,
    ) -> None:
        if record["end"] < record["start"]:
            return
        self._current_rel = rel
        language = tree.get("language")
        lines = self._lines(rel)
        vars_taint: dict[str, TaintValue] = dict(pre_taints)

        for line_no in range(record["start"], record["end"] + 1):
            if line_no > len(lines):
                break
            line = lines[line_no - 1]

            for sink_pattern, sink_label in TAINT_SINKS:
                match = re.search(sink_pattern, line)
                if match is None:
                    continue
                args = self._sink_args(line, match.start())
                for taint in self._sink_taints(args, vars_taint, rel, line_no):
                    if sink_filter and not sink_filter(record["name"], tree):
                        continue
                    steps = taint.steps + [
                        {"file": rel, "line": line_no, "variable": _segment(record["name"]) or "(sink)", "operation": "sink"}
                    ]
                    arg_sanitizer = _sanitizer_label(args)
                    flow = {
                        "file": rel,
                        "source": {
                            "file": taint.source_file,
                            "line": taint.source_line,
                            "kind": taint.source_kind,
                        },
                        "sink": {
                            "file": rel,
                            "line": line_no,
                            "kind": sink_label,
                            "function": record["name"],
                        },
                        "sanitized": taint.sanitized or arg_sanitizer is not None,
                        "sanitizer": taint.sanitizer or arg_sanitizer,
                        "taint_path": steps,
                        "confidence": "high" if not taint.sanitized and arg_sanitizer is None else "medium",
                    }
                    self.flows.append(flow)
                break

            for var, rhs in _iter_assignments(line):
                taint = self._expr_taint(rhs, vars_taint, rel, line_no)
                if taint is None:
                    vars_taint.pop(var, None)
                else:
                    vars_taint[var] = taint.step(rel, line_no, var, "propagate")

            if depth >= MAX_TAINT_DEPTH:
                continue
            for call_name, args_text in _iter_calls(line, language or "python"):
                if _is_sink_call(call_name) or _sanitizer_label(call_name + "("):
                    continue
                tainted_args = self._tainted_args(args_text, vars_taint, rel, line_no)
                if not any(tainted_args):
                    continue
                for callee_file, callee in self._resolve_callee(call_name, tree):
                    key = (callee_file, callee["qualname"])
                    if key in self._active:
                        continue
                    pre: dict[str, TaintValue] = {}
                    for index, taint in enumerate(tainted_args):
                        if taint is not None and index < len(callee.get("params", [])):
                            param = callee["params"][index]
                            pre[param] = taint.step(rel, line_no, param, "propagate")
                    self._active.add(key)
                    self._analyze_function(callee_file, callee, self.maps[callee_file], pre, depth + 1, sink_filter)
                    self._active.discard(key)

    def _sink_args(self, line: str, start: int) -> str:
        open_index = line.find("(", start)
        if open_index == -1:
            return line[start:]
        return line[open_index + 1 : _find_paren_end(line, open_index)]

    def _expr_taint(self, expr: str, vars_taint: dict[str, TaintValue], rel: str, line_no: int) -> TaintValue | None:
        source = _source_match(expr)
        if source:
            label, matched = source
            return TaintValue(
                steps=[{"file": rel, "line": line_no, "variable": matched, "operation": "source"}],
                source_kind=label,
                source_file=rel,
                source_line=line_no,
            )
        for var, taint in vars_taint.items():
            if re.search(rf"\b{re.escape(var)}\b", expr):
                sanitizer = _sanitizer_label(expr)
                return taint.step(rel, line_no, var, "sanitize", sanitizer) if sanitizer else taint.step(rel, line_no, var, "propagate")
        return None

    def _tainted_args(self, args_text: str, vars_taint: dict[str, TaintValue], rel: str, line_no: int) -> list[TaintValue | None]:
        result: list[TaintValue | None] = []
        for arg in _split_args(args_text):
            if not arg or arg in {"this", "self"}:
                result.append(None)
                continue
            direct = _source_match(arg)
            if direct:
                label, matched = direct
                result.append(
                    TaintValue(
                        steps=[{"file": rel, "line": line_no, "variable": matched, "operation": "source"}],
                        source_kind=label,
                        source_file=rel,
                        source_line=line_no,
                    )
                )
                continue
            matched = False
            for var, taint in vars_taint.items():
                if re.search(rf"\b{re.escape(var)}\b", arg):
                    result.append(taint)
                    matched = True
                    break
            if not matched:
                result.append(None)
        return result

    def _sink_taints(self, args: str, vars_taint: dict[str, TaintValue], rel: str, line_no: int) -> list[TaintValue]:
        result: list[TaintValue] = []
        direct = _source_match(args)
        if direct:
            label, matched = direct
            result.append(
                TaintValue(
                    steps=[{"file": rel, "line": line_no, "variable": matched, "operation": "source"}],
                    source_kind=label,
                    source_file=rel,
                    source_line=line_no,
                )
            )
        for var, taint in vars_taint.items():
            if re.search(rf"\b{re.escape(var)}\b", args):
                result.append(taint)
        return result


def _build_maps(target: str) -> dict[str, dict[str, Any]]:
    root = Path(target).resolve()
    maps: dict[str, dict[str, Any]] = {}
    for path in iter_source_files(target):
        relative_name = _display_path(path, root)
        tree = build_call_tree(path)
        if tree["language"]:
            maps[relative_name] = tree
    return maps


def _resolve_source_file(target: str, source_file: str) -> str:
    if Path(source_file).is_absolute():
        try:
            return str(Path(source_file).resolve().relative_to(Path(target).resolve()))
        except ValueError:
            return Path(source_file).name
    return source_file


def trace_dataflow(target: str, source_file: str, sink_function: str) -> dict[str, Any]:
    """Trace tainted data from ``source_file`` into ``sink_function``.

    Cross-file call resolution is bounded to ``MAX_TAINT_DEPTH`` callee
    levels.  Every returned flow contains a ``taint_path`` array of exact
    file/line/variable transformations plus a ``sanitized`` verdict.
    """
    root = Path(target).resolve()
    resolved = _resolve_source_file(target, source_file)
    maps = _build_maps(target)
    engine = _TaintEngine(root, maps)
    flows = engine.run(source_file=resolved, sink_function=sink_function)
    return {
        "research_agent": "Cross-File Taint Analyzer",
        "research_type": "trace",
        "status": "completed",
        "target": str(root),
        "source_file": resolved,
        "sink_function": sink_function,
        "flows": flows,
        "taint_paths": [flow["taint_path"] for flow in flows if not flow["sanitized"]],
        "flow_count": len(flows),
    }


def audit_taint(target: str) -> dict[str, Any]:
    """Run the cross-file taint engine over the complete target."""
    root = Path(target).resolve()
    maps = _build_maps(target)
    engine = _TaintEngine(root, maps)
    flows = engine.run()
    findings: list[dict[str, Any]] = []
    for flow in flows:
        if flow["sanitized"]:
            continue
        findings.append(
            _research_finding(
                prefix="TAINT",
                category="Semantic Taint Flow",
                file_name=flow["sink"]["file"],
                line=flow["sink"]["line"],
                snippet=_read_text(root / flow["sink"]["file"]).splitlines()[flow["sink"]["line"] - 1].strip()
                if flow["sink"]["line"] <= len(_read_text(root / flow["sink"]["file"]).splitlines())
                else "",
                severity="high",
                confidence=flow["confidence"],
                rule="source-to-sink-flow",
                description=(
                    f"Untrusted data from {flow['source']['kind']} reaches a "
                    f"{flow['sink']['kind']} sink without a recognized sanitizer."
                ),
                remediation="Validate and constrain the value at the trust boundary, then use a context-safe API at the sink.",
                evidence=flow,
                taint_path=flow["taint_path"],
            )
        )
    return {
        "research_agent": "Cross-File Taint Analyzer",
        "research_type": "taint",
        "status": "completed",
        "target": str(root),
        "flows": flows,
        "findings": findings,
        "flow_count": len(flows),
        "sanitized_flow_count": sum(1 for flow in flows if flow["sanitized"]),
    }


# ---------------------------------------------------------------------------
# Business logic and authorization engine (checks 05, 06, 33)
# ---------------------------------------------------------------------------

_AUTH_MIDDLEWARE = re.compile(
    r"(?i)(auth|authenticate|requireauth|isauthenticated|verifytoken|authorize|protect|jwt|session|login|guard|policy)"
)
_OWNERSHIP_SIGNAL = re.compile(
    r"(?i)(owner_?id|user_?id|\.id|_id|account_?id|tenant_?id)\s*[!=]={0,2}\s*(req(?:uest)?\.|request\.|session\.|auth|current_user|currentUser|ctx|context|userId|user_id)"
    r"|(Auth::user|request\.user|req\.user|current_user)\s*(->|\.|\[)[a-zA-Z_]*\s*[!=]={0,2}\s*(row|user|obj|doc|record|item|order|account|result)(\.|->|\[)"
)
_AUTH_BY_NAME = re.compile(r"(?i)\b(auth|authenticate|requireauth|isauthenticated|verifytoken|authorize|protect|ensureloggedin|jwt|session)\w*\b")
_ROUTE_PARAM = re.compile(r"(?:\:([A-Za-z_]\w*)|{([A-Za-z_]\w*)})")
_DB_QUERY_IN_HANDLER = re.compile(
    r"(?i)\b(?:query|execute|executemany|findById|findOne|find|where|first|get|all|select)\s*\("
    r"|::\s*(?:query|find|first|all|where)\s*\("
)


def _framework_for(line: str) -> str | None:
    if re.search(r"(?i)\bRoute::", line):
        return "laravel"
    if line.lstrip().startswith("@"):
        return "fastapi"
    if re.search(r"(?i)\b(?:app|router)\.", line):
        return "express"
    return None


def _extract_routes(file_name: str, lines: list[str]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        match = re.search(r"(?i)\b(?:app|router)\.(get|post|put|patch|delete|all)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", line)
        framework = "express"
        if match is None:
            match = re.search(r"(?i)@(?:app|router)\.(get|post|put|patch|delete|all)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", line)
            framework = "fastapi"
        if match is None:
            match = re.search(r"(?i)\bRoute::(get|post|put|patch|delete|any)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", line)
            framework = "laravel"
        if match is None:
            continue
        method = match.group(1).upper()
        path = match.group(2)
        params = [group for group in _ROUTE_PARAM.findall(path) for group in group if group]
        routes.append(
            {
                "file": file_name,
                "line": line_no,
                "method": method,
                "path": path,
                "params": params,
                "framework": framework,
                "text": line.strip(),
            }
        )
    return routes


def _handler_window(file_name: str, route: dict[str, Any], lines: list[str]) -> tuple[int, int]:
    """Return the inclusive line range of the route handler."""
    start_line = route["line"]
    if route["framework"] == "fastapi":
        for line_no in range(start_line + 1, min(len(lines) + 1, start_line + 40)):
            match = re.search(r"(?i)\b(?:async\s+)?def\s+\w+\s*\(", lines[line_no - 1])
            if match:
                body_start = line_no + 1
                for body_line in range(body_start, min(len(lines) + 1, body_start + 60)):
                    if lines[body_line - 1].strip() and not lines[body_line - 1].startswith((" ", "\t")):
                        return body_start, body_line - 1
                return body_start, min(len(lines), body_start + 60)
    if route["framework"] == "laravel":
        controller_match = re.search(r"(?i)\b([A-Za-z_]\w*)(?:Controller)?@(\w+)|\[[^\]]*::class\s*,\s*['\"](\w+)['\"]\]", route["text"])
        method_name = controller_match.group(2) or controller_match.group(3) if controller_match else None
        if method_name:
            for line_no in range(1, len(lines) + 1):
                if re.search(rf"(?i)\bfunction\s+{re.escape(method_name)}\s*\(", lines[line_no - 1]):
                    return line_no, min(len(lines), line_no + 60)
        return start_line, min(len(lines), start_line + 60)
    full_text = "\n".join(lines)
    offset = sum(len(line) + 1 for line in lines[: start_line - 1])
    remainder = full_text[offset:]
    arrow = remainder.find("=>")
    if arrow != -1:
        brace = remainder.find("{", arrow)
        if brace != -1:
            end = _find_paren_end_in_text(remainder, brace)
            return start_line, start_line + remainder[:end].count("\n")
    function_match = re.search(r"\bfunction\s*\([^)]*\)\s*\{", remainder)
    if function_match:
        brace = remainder.find("{", function_match.start())
        if brace != -1:
            end = _find_paren_end_in_text(remainder, brace)
            return start_line, start_line + remainder[:end].count("\n")
    return start_line, min(len(lines), start_line + 40)


def _find_paren_end_in_text(text: str, open_index: int) -> int:
    depth = 0
    quote: str | None = None
    for index in range(open_index, len(text)):
        char = text[index]
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


def _has_auth_signal(file_name: str, route: dict[str, Any], lines: list[str], window: tuple[int, int]) -> dict[str, Any]:
    start, end = window
    window_lines = lines[start - 1 : end]
    window_text = "\n".join(window_lines)
    signals: list[str] = []

    if route["framework"] == "express":
        if re.search(r"(?i)\b(?:app|router)\.use\s*\([^)]*(auth|jwt|session|token)", "\n".join(lines)):
            signals.append("global auth middleware")
        if _AUTH_BY_NAME.search(window_text):
            signals.append("auth middleware in route chain")
        if re.search(r"(?i)(req|request)\.(user|auth|session)", window_text):
            signals.append("request principal accessed")
    elif route["framework"] == "fastapi":
        if re.search(r"(?i)Depends\s*\(\s*(\w+)", window_text) and _AUTH_MIDDLEWARE.search(window_text):
            signals.append("auth dependency")
        if re.search(r"(?i)(current_user|currentUser|get_current|require_auth|verify_token)", window_text):
            signals.append("auth dependency or principal")
    elif route["framework"] == "laravel":
        if re.search(r"(?i)->middleware\s*\([^)]*(auth)", window_text):
            signals.append("route middleware('auth')")
        if re.search(r"(?i)\$this->middleware\s*\([^)]*(auth)", "\n".join(lines)):
            signals.append("controller middleware('auth')")
        if re.search(r"(?i)(Auth::user|auth\(\)->user)", window_text):
            signals.append("authenticated principal")
    return {"protected": bool(signals), "signals": signals}


_ROUTE_REGISTRATION = re.compile(
    r"(?i)\b(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\("
    r"|@(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\("
    r"|\bRoute::(?:get|post|put|patch|delete|any)\s*\("
)


def _find_param_query(file_name: str, route: dict[str, Any], lines: list[str], window: tuple[int, int]) -> list[dict[str, Any]]:
    start, end = window
    hits: list[dict[str, Any]] = []
    for line_no in range(start, end + 1):
        line = lines[line_no - 1]
        if _ROUTE_REGISTRATION.search(line):
            continue
        if not _DB_QUERY_IN_HANDLER.search(line):
            continue
        for param in route["params"]:
            if re.search(rf"\b{re.escape(param)}\b", line) or re.search(rf"\b\${re.escape(param)}\b", line):
                hits.append(
                    {
                        "line": line_no,
                        "param": param,
                        "snippet": line.strip(),
                        "taint_path": [
                            {"file": file_name, "line": route["line"], "variable": param, "operation": "source"},
                            {"file": file_name, "line": line_no, "variable": param, "operation": "propagate"},
                            {"file": file_name, "line": line_no, "variable": param, "operation": "sink"},
                        ],
                    }
                )
    return hits


def audit_logic_flaws(target: str) -> dict[str, Any]:
    """Focus the authorization engine on checks 05, 06, and 33."""
    root = Path(target).resolve()
    findings: list[dict[str, Any]] = []

    for path in iter_source_files(target):
        file_name = _display_path(path, root)
        lines = _read_text(path).splitlines()
        for route in _extract_routes(file_name, lines):
            window = _handler_window(file_name, route, lines)
            auth = _has_auth_signal(file_name, route, lines, window)
            param_hits = _find_param_query(file_name, route, lines, window)
            if not param_hits:
                continue
            for hit in param_hits:
                ownership = _OWNERSHIP_SIGNAL.search("\n".join(lines[window[0] - 1 : window[1]]))
                if not auth["protected"]:
                    findings.append(
                        _research_finding(
                            prefix="LOGIC",
                            category="Business Logic & Authorization",
                            file_name=file_name,
                            line=hit["line"],
                            snippet=hit["snippet"],
                            severity="high",
                            confidence="medium",
                            rule="missing-authorization",
                            description=(
                                f"{route['method']} {route['path']} executes a database query on route parameter "
                                f"'{hit['param']}' but no authorization guard is present in its handler chain."
                            ),
                            remediation="Require an explicit server-side authentication and authorization decision before the object access.",
                            evidence={
                                "check": "05",
                                "check_name": "Missing Authz",
                                "route": route["path"],
                                "method": route["method"],
                                "framework": route["framework"],
                                "parameter": hit["param"],
                                "query_line": hit["line"],
                                "auth_signals": auth["signals"],
                            },
                            taint_path=hit["taint_path"],
                        )
                    )
                elif ownership is None:
                    findings.append(
                        _research_finding(
                            prefix="LOGIC",
                            category="Business Logic & Authorization",
                            file_name=file_name,
                            line=hit["line"],
                            snippet=hit["snippet"],
                            severity="high",
                            confidence="medium",
                            rule="idor-bola",
                            description=(
                                f"{route['method']} {route['path']} looks up a resource by route parameter "
                                f"'{hit['param']}' without comparing resource ownership against the session principal."
                            ),
                            remediation="Bind the object access to the authenticated principal and tenant; return 404 for non-owned resources.",
                            evidence={
                                "check": "33",
                                "check_name": "IDOR / BOLA",
                                "related_checks": ["06"],
                                "route": route["path"],
                                "method": route["method"],
                                "framework": route["framework"],
                                "parameter": hit["param"],
                                "query_line": hit["line"],
                                "auth_signals": auth["signals"],
                            },
                            taint_path=hit["taint_path"],
                        )
                    )

    return {
        "research_agent": "Business Logic & Authorization Engine",
        "research_type": "logic_flaws",
        "status": "completed",
        "target": str(root),
        "findings": findings,
        "finding_count": len(findings),
        "checked_routes": sum(len(_extract_routes(_display_path(path, root), _read_text(path).splitlines())) for path in iter_source_files(target)),
    }


def audit_business_logic(target: str) -> dict[str, Any]:
    """Inspect sensitive routes and mutation paths for business-control gaps."""
    root = Path(target).resolve()
    findings: list[dict[str, Any]] = []
    route_pattern = re.compile(
        r"(?i)(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"'`]([^\"'`]+)"
    )
    sensitive_route = re.compile(
        r"(?i)(admin|manage|billing|payment|refund|role|permission|delete|export|invite|reset)"
    )
    auth_marker = re.compile(
        r"(?i)(authorize|authorization|authenticated|current_user|currentUser|permission|requireAuth|session)"
    )
    mutable_trust = re.compile(
        r"(?i)(req(?:uest)?\.(?:body|query|params)|request\.(?:json|form|args)).{0,80}"
        r"(amount|price|discount|role|permission|status|owner|user_id|tenant)"
    )

    for path in iter_source_files(target):
        file_name = _display_path(path, root)
        lines = _read_text(path).splitlines()
        for line_number, line in enumerate(lines, start=1):
            route_match = route_pattern.search(line)
            if route_match and sensitive_route.search(route_match.group(2)):
                window_start = max(0, line_number - 1)
                window_end = min(len(lines), line_number + 14)
                window = "\n".join(lines[window_start:window_end])
                if not auth_marker.search(window):
                    findings.append(
                        _research_finding(
                            prefix="LOGIC",
                            category="Context-Aware Business Logic",
                            file_name=file_name,
                            line=line_number,
                            snippet=line.strip(),
                            severity="high",
                            confidence="medium",
                            rule="sensitive-route-without-authorization-signal",
                            description="A sensitive route has no recognizable authorization control in its local handler context.",
                            remediation="Require an explicit server-side policy decision for the operation and bind it to the authenticated principal and tenant.",
                            evidence={
                                "route_method": route_match.group(1).upper(),
                                "route": route_match.group(2),
                                "context_lines": [window_start + 1, window_end],
                                "missing_signal": "authorization guard",
                            },
                        )
                    )

            if mutable_trust.search(line):
                findings.append(
                    _research_finding(
                        prefix="LOGIC",
                        category="Context-Aware Business Logic",
                        file_name=file_name,
                        line=line_number,
                        snippet=line.strip(),
                        severity="high",
                        confidence="medium",
                        rule="client-controlled-business-value",
                        description="A business-critical value appears to be accepted from a request without evidence of server-side recomputation.",
                        remediation="Derive prices, roles, ownership, status transitions, and tenant identity from trusted server state.",
                        evidence={"trust_boundary": "request input", "matched_fields": True},
                    )
                )

    return {
        "research_agent": "Context-Aware Business Logic Evaluator",
        "research_type": "business_logic",
        "status": "completed",
        "target": str(root),
        "findings": findings,
        "finding_count": len(findings),
    }


# ---------------------------------------------------------------------------
# Safe, non-executing proof-of-concept generation
# ---------------------------------------------------------------------------


def _poc_payload(check_id: str, details: dict[str, Any]) -> str:
    method = str(details.get("method") or details.get("http_method") or "GET").upper()
    path = str(
        details.get("endpoint")
        or details.get("route")
        or details.get("path")
        or "/REPLACE_WITH_LOCAL_TEST_PATH"
    )
    parameter = details.get("parameter") or (details.get("params") or ["field"])[0]
    has_query_param = bool(details.get("parameter")) or bool(details.get("params"))
    has_body = check_id.lower() in {"05", "06", "33"} and not has_query_param

    payload_field = "TEST_MARKER_123"
    substituted = path.replace(f":{parameter}", payload_field).replace(f"{{{parameter}}}", payload_field)
    path_param_substituted = substituted != path

    if has_query_param:
        query_suffix = "" if path_param_substituted else f"?{parameter}={payload_field}"
        curl = f"curl -i -X {method} 'http://127.0.0.1:8000{substituted}{query_suffix}'"
        http_body = ""
    else:
        curl = (
            f"curl -i -X {method} 'http://127.0.0.1:8000{substituted}' \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -d '{{\"{parameter}\":\"{payload_field}\"}}'"
        )
        query_suffix = ""
        http_body = f'\n\n{{"{parameter}":"{payload_field}"}}'

    http_spec = (
        f"{method} {substituted}{query_suffix} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:8000\r\n"
        f"Content-Type: application/json\r\n"
        f"Connection: close"
        f"{http_body}"
    )

    return (
        f"# Non-executing proof blueprint for {check_id}\n"
        f"# Target: {details.get('file', 'unknown')}:{details.get('line', 0)}\n"
        f"# 1. curl reproduction block (do NOT run against production):\n"
        f"{curl}\n\n"
        f"# 2. Raw HTTP request spec:\n"
        f"{http_spec}\n\n"
        f"# 3. Expected signal: the benign marker {payload_field} should be rejected, "
        f"encoded, parameterized, or denied by an authorization policy.\n"
        f"# Safety: this blueprint is never executed by the engine."
    )


def generate_poc(check_id: str, vulnerability_details: dict[str, Any]) -> dict[str, Any]:
    """Generate a non-executing PoC blueprint for a single finding."""
    if not check_id:
        raise ValueError("check_id is required")
    payload = _poc_payload(check_id, vulnerability_details)
    return {
        "check_id": check_id,
        "poc_payload": payload,
        "mode": "non-executing",
        "safety": {
            "executed": False,
            "network_requests": False,
            "payloads_generated": False,
            "target_mutated": False,
        },
        "preconditions": [
            "Use an isolated local fixture or disposable test environment.",
            "Use synthetic accounts and marker values only.",
            "Do not send the request to production or a third-party service.",
        ],
        "request_template": {
            "method": vulnerability_details.get("method") or "GET",
            "path": vulnerability_details.get("endpoint") or vulnerability_details.get("route") or "/REPLACE_WITH_LOCAL_TEST_PATH",
            "headers": {"Content-Type": "application/json"},
            "body": {"field": "TEST_MARKER_123"},
        },
    }


def generate_safe_pocs(target: str) -> dict[str, Any]:
    """Create inert, local proof blueprints from taint and logic evidence."""
    root = Path(target).resolve()
    taint_report = audit_taint(target)
    logic_report = audit_logic_flaws(target)
    proofs: list[dict[str, Any]] = []

    for finding in [*taint_report["findings"], *logic_report["findings"]]:
        evidence = finding.get("evidence") or {}
        details: dict[str, Any] = {
            "file": finding["file"],
            "line": finding["line"],
            "method": evidence.get("method"),
            "endpoint": evidence.get("route") or evidence.get("path"),
            "parameter": evidence.get("parameter"),
            "params": finding.get("taint_path") or [],
        }
        poc = _poc_payload(finding["check_id"], details)
        proof_id = _research_id("POC", finding["file"], finding["line"], finding["id"])
        proofs.append(
            {
                "id": proof_id,
                "source_finding_id": finding["id"],
                "check_id": finding["check_id"],
                "title": f"Local verification plan for {finding['category']}",
                "target": {"file": finding["file"], "line": finding["line"]},
                "mode": "non-executing",
                "poc_payload": poc,
                "preconditions": [
                    "Use an isolated local fixture or disposable test environment.",
                    "Use synthetic accounts and marker values only.",
                    "Do not send the request to production or a third-party service.",
                ],
                "steps": [
                    "Create a minimal fixture that reaches the reported code path.",
                    "Provide the benign marker value TEST_MARKER_123 at the reported trust boundary.",
                    "Observe whether the marker reaches the reported sink or changes protected state.",
                    "Record the result and remove the fixture after verification.",
                ],
                "request_template": {
                    "method": evidence.get("method") or "REPLACE_WITH_METHOD",
                    "path": evidence.get("route") or "REPLACE_WITH_LOCAL_TEST_PATH",
                    "headers": {"Content-Type": "application/json"},
                    "body": {"field": "TEST_MARKER_123"},
                },
                "expected_signal": "The marker should be rejected, encoded, parameterized, or denied by an authorization policy.",
                "safety_note": "This is a proof blueprint only. It contains no exploit payload and is never executed by the engine.",
            }
        )

    return {
        "research_agent": "Automated Exploit Proof-of-Concept Generator",
        "research_type": "safe_poc",
        "status": "completed",
        "target": str(root),
        "proofs": proofs,
        "source_findings": len(taint_report["findings"]) + len(logic_report["findings"]),
        "findings": [],
        "safety": {
            "executed": False,
            "network_requests": False,
            "payloads_generated": False,
            "target_mutated": False,
        },
    }
