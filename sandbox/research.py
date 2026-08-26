"""Higher-assurance research analyses executed inside the sandbox.

These analyses are intentionally deterministic and local.  The PoC generator
produces non-executing proof blueprints; it never sends requests, runs a
payload, or mutates the target.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from sandbox.analysis import _display_path, _read_text, iter_source_files


TAINT_SOURCES = (
    (r"(?i)\breq(?:uest)?\.(?:body|query|params|cookies|headers)\b", "HTTP request data"),
    (r"(?i)\b(?:os\.)?environ(?:\.get)?\b", "process environment"),
    (r"(?i)\b(?:sys\.)?argv\b", "process arguments"),
    (r"(?i)\b(?:input|URLSearchParams|FormData)\b", "user input API"),
)
TAINT_SINKS = (
    (r"(?i)\b(?:execute|executemany|query|raw)\s*\(", "database query"),
    (r"(?i)\b(?:eval|exec|compile)\s*\(", "dynamic code execution"),
    (r"(?i)\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b", "HTML sink"),
    (r"(?i)\b(?:fetch|axios|requests\.(?:get|post)|urllib\.request)\s*\(", "server-side network request"),
    (r"(?i)\b(?:open|readFile|writeFile|sendFile|unlink)\s*\(", "filesystem operation"),
    (r"(?i)\b(?:exec|system|popen|subprocess\.)\b", "process execution"),
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
    }


def audit_taint(target: str) -> dict[str, Any]:
    """Trace simple source-to-sink data flows without executing target code."""
    root = Path(target).resolve()
    flows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for path in iter_source_files(target):
        file_name = _display_path(path, root)
        lines = _read_text(path).splitlines()
        tainted_variables: dict[str, tuple[int, str]] = {}
        for line_number, line in enumerate(lines, start=1):
            assignment = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", line)
            source_hits = [
                label for pattern, label in TAINT_SOURCES if re.search(pattern, line)
            ]
            if assignment and source_hits:
                tainted_variables[assignment.group(1)] = (line_number, source_hits[0])

            sink_hits = [
                label for pattern, label in TAINT_SINKS if re.search(pattern, line)
            ]
            if not sink_hits:
                continue

            matching_sources: list[tuple[int, str, str]] = []
            for pattern, label in TAINT_SOURCES:
                if re.search(pattern, line):
                    matching_sources.append((line_number, label, "direct source-to-sink"))
            for variable, (source_line, source_label) in tainted_variables.items():
                if re.search(rf"\b{re.escape(variable)}\b", line) and source_line <= line_number:
                    matching_sources.append((source_line, source_label, f"tainted variable: {variable}"))

            for source_line, source_label, path_kind in matching_sources:
                sink_label = sink_hits[0]
                flow = {
                    "file": file_name,
                    "source": {"line": source_line, "kind": source_label},
                    "sink": {"line": line_number, "kind": sink_label},
                    "path": path_kind,
                    "confidence": "medium" if path_kind.startswith("tainted") else "high",
                }
                flows.append(flow)
                findings.append(
                    _research_finding(
                        prefix="TAINT",
                        category="Semantic Taint Flow",
                        file_name=file_name,
                        line=line_number,
                        snippet=line.strip(),
                        severity="high",
                        confidence=flow["confidence"],
                        rule="source-to-sink-flow",
                        description=f"Untrusted data may flow from {source_label} into a {sink_label} sink.",
                        remediation="Validate and constrain the value at the trust boundary, then use a context-safe API at the sink.",
                        evidence=flow,
                    )
                )

    return {
        "research_agent": "Semantic Flow & Taint Engine",
        "research_type": "taint",
        "status": "completed",
        "target": str(root),
        "flows": flows,
        "findings": findings,
        "flow_count": len(flows),
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
                    evidence = {
                        "route_method": route_match.group(1).upper(),
                        "route": route_match.group(2),
                        "context_lines": [window_start + 1, window_end],
                        "missing_signal": "authorization guard",
                    }
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
                            evidence=evidence,
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


def generate_safe_pocs(target: str) -> dict[str, Any]:
    """Create inert, local proof blueprints from taint and logic evidence."""
    root = Path(target).resolve()
    taint_report = audit_taint(target)
    logic_report = audit_business_logic(target)
    proofs: list[dict[str, Any]] = []

    for finding in [*taint_report["findings"], *logic_report["findings"]]:
        proof_id = _research_id("POC", finding["file"], finding["line"], finding["id"])
        proofs.append(
            {
                "id": proof_id,
                "source_finding_id": finding["id"],
                "title": f"Local verification plan for {finding['category']}",
                "target": {"file": finding["file"], "line": finding["line"]},
                "mode": "non-executing",
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
                    "method": "REPLACE_WITH_METHOD",
                    "path": "REPLACE_WITH_LOCAL_TEST_PATH",
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
