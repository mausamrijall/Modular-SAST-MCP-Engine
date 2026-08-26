"""Deterministic source analysis that is executed by sandbox/worker.py.

This module contains the filesystem traversal, regex checks, and Python AST
checks.  It is deliberately imported by the worker inside the isolated
container, never by the MCP server processes.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
}
DEPENDENCY_FILES = {"package.json", "composer.json", "requirements.txt"}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 3000


def _config_path() -> Path:
    return Path(__file__).resolve().parents[1] / "config" / "checks_map.json"


def load_checks() -> dict[str, dict[str, Any]]:
    with _config_path().open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return {str(item["id"]): item for item in payload["checks"]}


def iter_source_files(target: str) -> Iterable[Path]:
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    if root.is_symlink():
        raise ValueError("Symlink targets are not allowed")

    if root.is_file():
        yield root
        return

    count = 0
    for path in sorted(root.rglob("*")):
        if count >= MAX_FILES:
            break
        if path.is_symlink() or not path.is_file():
            continue
        if any(part in SKIP_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        count += 1
        yield path


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _display_path(path: Path, target: Path) -> str:
    if target.is_file():
        return path.name
    try:
        return str(path.relative_to(target))
    except ValueError:
        return str(path)


def _redact_snippet(line: str) -> str:
    # Keep useful context while preventing an audit report from becoming a
    # second secret store.
    redacted = re.sub(
        r"(?i)(secret|token|password|passwd|api[_-]?key|authorization)"
        r"(\s*[:=]\s*)([\"']?)([^\"'\s,;]+)",
        r"\1\2\3[REDACTED]",
        line,
    )
    redacted = re.sub(r"(?i)\b(ghp_|github_pat_|sk_live_|AKIA[0-9A-Z]{12,})[A-Za-z0-9_-]+", "[REDACTED]", redacted)
    return redacted.strip()[:500]


def _finding(
    *,
    check: dict[str, Any],
    agent: str,
    file_name: str,
    line_number: int,
    line: str,
    rule_name: str | None = None,
) -> dict[str, Any]:
    rule = check["default_rule"]
    fingerprint_source = f"{check['id']}:{file_name}:{line_number}:{line}"
    fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:16]
    return {
        "id": f"SAST-{check['id']}-{fingerprint}",
        "check_id": check["id"],
        "category": check["name"],
        "agent": agent,
        "sub_agent": f"{agent}.{check['id']}",
        "severity": rule.get("severity", "medium"),
        "confidence": rule.get("confidence", "medium"),
        "file": file_name,
        "line": line_number,
        "snippet": _redact_snippet(line),
        "rule": rule_name or rule.get("rule_id", "configured-rule"),
        "description": rule.get("description", check.get("description", "")),
        "remediation": rule.get("remediation", "Review this code path and apply the least-privilege secure alternative."),
    }


def _line_matches(check: dict[str, Any], line: str) -> list[str]:
    rule = check["default_rule"]
    patterns = rule.get("patterns", [])
    matches: list[str] = []
    for pattern in patterns:
        try:
            if re.search(pattern, line, flags=re.IGNORECASE):
                matches.append(pattern)
        except re.error:
            # A malformed optional rule must not crash the complete audit.
            continue
    excluded = rule.get("exclude_patterns", [])
    if matches and any(re.search(pattern, line, flags=re.IGNORECASE) for pattern in excluded):
        return []
    return matches


def _filename_matches(check: dict[str, Any], relative_name: str) -> bool:
    filenames = check["default_rule"].get("filenames", [])
    base_name = Path(relative_name).name.lower()
    return any(
        base_name == str(candidate).lower()
        or relative_name.lower().endswith(str(candidate).lower())
        for candidate in filenames
    )


class _PythonAstVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.events: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> Any:
        function_name = ""
        if isinstance(node.func, ast.Name):
            function_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr

        if function_name in {"eval", "exec", "compile"}:
            self.events.append((node.lineno, f"dynamic execution via {function_name}"))
        if function_name in {"system", "popen"}:
            self.events.append((node.lineno, f"shell execution via {function_name}"))
        if function_name == "loads" and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                self.events.append((node.lineno, "unsafe pickle deserialization"))
        self.generic_visit(node)


def _ast_events(check: dict[str, Any], text: str) -> dict[int, str]:
    if check["default_rule"].get("kind") != "ast_or_regex":
        return {}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    visitor = _PythonAstVisitor()
    visitor.visit(tree)
    wanted = check["default_rule"].get("ast_events", [])
    return {line: message for line, message in visitor.events if message in wanted or not wanted}


def dependency_inventory(target: str) -> list[str]:
    root = Path(target).resolve()
    files = iter_source_files(target)
    result: list[str] = []
    for path in files:
        if path.name in DEPENDENCY_FILES:
            result.append(_display_path(path, root))
    return sorted(set(result))


def audit_agent(target: str, agent: str, check_ids: list[str] | None = None) -> dict[str, Any]:
    all_checks = load_checks()
    selected = check_ids or [
        check_id for check_id, check in all_checks.items() if check.get("agent") == agent
    ]
    checks = [all_checks[check_id] for check_id in selected if check_id in all_checks]
    root = Path(target).resolve()
    files = list(iter_source_files(target))
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()

    for path in files:
        relative_name = _display_path(path, root)
        text = _read_text(path)
        lines = text.splitlines()
        ast_cache: dict[str, dict[int, str]] = {}
        for check in checks:
            rule = check["default_rule"]
            if rule.get("kind") == "filename" and _filename_matches(check, relative_name):
                key = (check["id"], relative_name, 1)
                if key not in seen:
                    findings.append(
                        _finding(
                            check=check,
                            agent=agent,
                            file_name=relative_name,
                            line_number=1,
                            line=relative_name,
                            rule_name=rule.get("rule_id"),
                        )
                    )
                    seen.add(key)
                continue

            if rule.get("kind") == "ast_or_regex" and path.suffix == ".py":
                ast_cache[check["id"]] = _ast_events(check, text)

            for line_number, line in enumerate(lines, start=1):
                matches = _line_matches(check, line)
                ast_message = ast_cache.get(check["id"], {}).get(line_number)
                if not matches and not ast_message:
                    continue
                key = (check["id"], relative_name, line_number)
                if key in seen:
                    continue
                findings.append(
                    _finding(
                        check=check,
                        agent=agent,
                        file_name=relative_name,
                        line_number=line_number,
                        line=line,
                        rule_name=ast_message or matches[0],
                    )
                )
                seen.add(key)

    check_reports = {
        check["id"]: {
            "name": check["name"],
            "sub_agent": f"{agent}.{check['id']}",
            "finding_count": sum(item["check_id"] == check["id"] for item in findings),
            "status": "completed",
        }
        for check in checks
    }
    return {
        "agent": agent,
        "status": "completed",
        "target": str(root),
        "findings": findings,
        "dependency_files": dependency_inventory(target),
        "sub_agents": check_reports,
    }


def _supply_finding(
    *,
    target_file: str,
    line_number: int,
    line: str,
    severity: str,
    rule: str,
    description: str,
    remediation: str,
) -> dict[str, Any]:
    fingerprint = hashlib.sha256(f"{target_file}:{line_number}:{line}:{rule}".encode()).hexdigest()[:16]
    return {
        "id": f"SAST-SC-{fingerprint}",
        "check_id": "supply-chain",
        "category": "Supply Chain",
        "agent": "supply_chain",
        "sub_agent": "supply_chain.dependency-audit",
        "severity": severity,
        "confidence": "medium",
        "file": target_file,
        "line": line_number,
        "snippet": _redact_snippet(line),
        "rule": rule,
        "description": description,
        "remediation": remediation,
    }


def audit_supply_chain(target: str, requested_by: list[str] | None = None) -> dict[str, Any]:
    root = Path(target).resolve()
    findings: list[dict[str, Any]] = []
    dependency_files = dependency_inventory(target)

    for path in list(iter_source_files(target)):
        if path.name not in DEPENDENCY_FILES:
            continue
        relative_name = _display_path(path, root)
        lines = _read_text(path).splitlines()
        for line_number, line in enumerate(lines, start=1):
            if re.search(r'(?i)"?\*"?\s*[:=]', line) or re.search(r"(?i)(latest|master|main)\b", line):
                findings.append(
                    _supply_finding(
                        target_file=relative_name,
                        line_number=line_number,
                        line=line,
                        severity="medium",
                        rule="unpinned-dependency",
                        description="Dependency versions appear unpinned or follow a moving tag.",
                        remediation="Pin dependencies to reviewed versions and use lockfiles with integrity checks.",
                    )
                )
            if re.search(r"(?i)(preinstall|postinstall|install).*(curl|wget|bash|sh)", line):
                findings.append(
                    _supply_finding(
                        target_file=relative_name,
                        line_number=line_number,
                        line=line,
                        severity="high",
                        rule="install-script-network-execution",
                        description="A dependency installation hook executes a network or shell command.",
                        remediation="Remove the hook where possible, pin the source, and review it in an isolated build.",
                    )
                )

        if path.name == "package.json":
            try:
                package_data = json.loads(_read_text(path))
                scripts = package_data.get("scripts", {})
                for script_name, script in scripts.items():
                    if re.search(r"(?i)(curl|wget).*(\||&&).*(sh|bash)", str(script)):
                        findings.append(
                            _supply_finding(
                                target_file=relative_name,
                                line_number=1,
                                line=f"{script_name}: {script}",
                                severity="high",
                                rule="package-script-download-execute",
                                description="A package script downloads and executes a shell payload.",
                                remediation="Replace download-and-execute behavior with a verified package or checked-in build step.",
                            )
                        )
            except (json.JSONDecodeError, OSError):
                pass

    return {
        "worker": "Unified Supply Chain Worker",
        "status": "completed",
        "target": str(root),
        "requested_by": sorted(set(requested_by or [])),
        "dependency_files": dependency_files,
        "findings": findings,
    }
