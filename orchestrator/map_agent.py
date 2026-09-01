"""Main Orchestrator Agent for the modular SAST MCP engine."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.llm import LLMConfig
from orchestrator import web_research


class McpClientError(RuntimeError):
    """Raised when an MCP child process returns an error."""


class StdioMcpClient:
    """Minimal MCP/JSON-RPC client used for local stdio worker processes."""

    def __init__(self, module: str) -> None:
        self.module = module
        self.process: subprocess.Popen[str] | None = None
        self.request_id = 0

    def __enter__(self) -> "StdioMcpClient":
        self.process = subprocess.Popen(
            [sys.executable, "-m", self.module],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.request("initialize", {"clientInfo": {"name": "Main Orchestrator Agent", "version": "1.0.0"}})
        self.notify("notifications/initialized")
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self.process is None:
            return
        if self.process.stdin:
            self.process.stdin.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self.process is None or self.process.stdin is None:
            raise McpClientError("MCP client is not started")
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}}) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise McpClientError("MCP client is not started")
        self.request_id += 1
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params or {}}) + "\n"
        )
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise McpClientError(f"{self.module} stopped without a response: {stderr[-500:]}")
        response = json.loads(line)
        if "error" in response:
            raise McpClientError(response["error"].get("message", "Unknown MCP error"))
        return response["result"]

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.request(
            "tools/call",
            {"name": tool_name, "arguments": arguments},
        )
        structured = response.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        text = response.get("content", [{}])[0].get("text", "{}")
        return json.loads(text)


AGENTS = {
    "secrets": ("mcp_servers.secrets_agent", "audit_secrets", "Secrets & Identity Agent"),
    "injection": ("mcp_servers.injection_agent", "audit_injection", "Input & Injection Agent"),
    "infra": ("mcp_servers.infra_agent", "audit_infra", "Infra & Client Agent"),
}

RESEARCH_AGENTS = {
    "taint": ("mcp_servers.taint_analyzer", "audit_taint", "Cross-File Taint Analyzer"),
    "business_logic": (
        "mcp_servers.logic_flaw_agent",
        "audit_logic_flaws",
        "Business Logic & Authorization Engine",
    ),
    "safe_poc": (
        "mcp_servers.poc_generator",
        "generate_safe_poc",
        "Automated Exploit Proof-of-Concept Generator",
    ),
}

VERIFICATION_AGENTS = {
    "verify_poc": ("mcp_servers.poc_verifier", "verify_pocs", "Proof-of-Concept Verifier"),
    "behavior": (
        "mcp_servers.behavior_checker",
        "assess_behavior",
        "Behavior & Expected-Usage Evaluator",
    ),
}

SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAX_VERIFY_FINDINGS = 100
VALUED_VERDICTS = {"verified", "static-confirmed"}


def _run_domain(agent: str, target_path: str) -> dict[str, Any]:
    module, tool_name, display_name = AGENTS[agent]
    try:
        with StdioMcpClient(module) as client:
            client.request("tools/list")
            result = client.call_tool(tool_name, {"target_path": target_path})
        result["display_name"] = display_name
        return result
    except Exception as exc:
        return {
            "agent": agent,
            "display_name": display_name,
            "status": "failed",
            "error": str(exc),
            "findings": [],
            "dependency_files": [],
            "sub_agents": {},
        }


def _run_supply_chain(target_path: str, requested_by: list[str]) -> dict[str, Any]:
    try:
        with StdioMcpClient("mcp_servers.supply_chain_agent") as client:
            client.request("tools/list")
            return client.call_tool(
                "audit_supply_chain",
                {"target_path": target_path, "requested_by": requested_by},
            )
    except Exception as exc:
        return {
            "worker": "Unified Supply Chain Worker",
            "status": "failed",
            "error": str(exc),
            "findings": [],
            "dependency_files": [],
            "requested_by": requested_by,
        }


def _load_agent_for_check(check_id: str) -> str | None:
    """Return the domain-agent key owning ``check_id`` per the check map."""
    checks_path = Path(__file__).resolve().parents[1] / "config" / "checks_map.json"
    checks = json.loads(checks_path.read_text(encoding="utf-8")).get("checks", [])
    for check in checks:
        if check.get("id") == check_id:
            return check.get("agent")
    return None


def _run_clarification(
    module: str,
    tool_name: str,
    display_name: str,
    check_id: str,
    question: str,
) -> dict[str, Any]:
    """Ask one sub-agent a methodology question through its ``clarify`` tool."""
    try:
        with StdioMcpClient(module) as client:
            client.request("tools/list")
            return client.call_tool(
                "clarify",
                {"check_id": check_id, "question": question},
            )
    except Exception as exc:
        return {
            "agent": display_name,
            "check_id": check_id,
            "question": question,
            "status": "failed",
            "error": str(exc),
        }


def _build_llm(llm_overrides: dict[str, str] | None) -> LLMConfig | None:
    """Build an LLMConfig from explicit overrides plus environment fallback.

    Returns ``None`` (instead of raising) when no API key is configured so the
    report can record ``llm-not-configured`` instead of failing the audit.
    """
    if not llm_overrides:
        llm_overrides = {}
    try:
        return LLMConfig.from_settings(
            api_key=llm_overrides.get("api_key", ""),
            provider=llm_overrides.get("provider", ""),
            base_url=llm_overrides.get("base_url", ""),
            model=llm_overrides.get("model", ""),
        )
    except ValueError:
        return None


def _run_web_research(
    urls: list[str],
    methodology_topic: str | None,
    llm_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run the main agent's outbound research and methodology synthesis."""
    topic = methodology_topic or "SAST methodology enrichment"
    llm = _build_llm(llm_overrides)
    synthesis_status = "disabled" if llm is None else "enabled"
    research = web_research.research_web(topic, urls, llm=llm)
    research["synthesis_status"] = synthesis_status
    return research


def _findings_digest(all_findings: list[dict[str, Any]], max_items: int = 40) -> str:
    """Compact, redacted digest of the top findings for the LLM summary."""
    prioritized = sorted(
        all_findings,
        key=lambda finding: SEVERITY_PRIORITY.get(str(finding.get("severity", "medium")), 5),
    )
    lines: list[str] = []
    for finding in prioritized[:max_items]:
        snippet = str(finding.get("snippet", ""))[:100]
        lines.append(
            f"- [{finding.get('severity')}] check {finding.get('check_id')} "
            f"{finding.get('file')}:{finding.get('line')} "
            f"{finding.get('rule', '')} :: {snippet}"
        )
    if len(all_findings) > max_items:
        lines.append(f"- ... and {len(all_findings) - max_items} more findings")
    return "\n".join(lines)


def _run_llm_summary(
    llm: LLMConfig | None,
    all_findings: list[dict[str, Any]],
    severity_counts: dict[str, int],
    valued_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Ask the configured LLM for an executive summary and remediation plan.

    This is the standalone "self-working" mode: when the user supplies a
    provider, endpoint, API key, and model, the engine produces an AI-written
    audit summary instead of only structured JSON.
    """
    if llm is None:
        return {
            "status": "llm-not-configured",
            "message": "No API key provided. Pass --llm-api-key (with --llm-provider/--llm-endpoint/--llm-model) or set USER_LLM_API_KEY.",
            "severity_counts": severity_counts,
        }
    digest = _findings_digest(all_findings)
    valued_digest = _findings_digest(valued_findings, max_items=20) if valued_findings else "n/a"
    messages = [
        {
            "role": "system",
            "content": (
                "You are a defensive application-security reviewer. Produce a concise "
                "executive audit summary with a prioritized remediation plan. Focus on "
                "real risk, group noisy duplicates, and never suggest attacking systems, "
                "bypassing controls, or scanning without authorization."
            ),
        },
        {
            "role": "user",
            "content": (
                "Security findings from a static audit.\n"
                f"Severity totals: {severity_counts}\n"
                f"Valued findings (verified/static-confirmed after noise filtering): {len(valued_findings)}\n\n"
                f"Top findings:\n{digest}\n\n"
                f"Valued findings:\n{valued_digest}\n\n"
                "Write an executive summary (a few paragraphs), the top 5 risks with "
                "file:line references, and a prioritized remediation plan."
            ),
        },
    ]
    try:
        summary = llm.complete(messages, timeout=90.0)
    except Exception as exc:  # noqa: BLE001 - report the failure, do not crash the audit
        return {
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
            "connection": llm.redacted(),
            "severity_counts": severity_counts,
        }
    return {
        "status": "completed",
        "connection": llm.redacted(),
        "summary": summary,
        "severity_counts": severity_counts,
        "valued_findings_count": len(valued_findings),
    }


def _run_research(research_type: str, target_path: str) -> dict[str, Any]:
    module, tool_name, display_name = RESEARCH_AGENTS[research_type]
    try:
        with StdioMcpClient(module) as client:
            client.request("tools/list")
            result = client.call_tool(tool_name, {"target_path": target_path})
        result["display_name"] = display_name
        result["orchestrator_research_type"] = research_type
        return result
    except Exception as exc:
        return {
            "research_type": research_type,
            "display_name": display_name,
            "status": "failed",
            "error": str(exc),
            "findings": [],
        }


def _run_behavior(target_path: str) -> dict[str, Any]:
    module, tool_name, display_name = VERIFICATION_AGENTS["behavior"]
    try:
        with StdioMcpClient(module) as client:
            client.request("tools/list")
            result = client.call_tool(tool_name, {"target_path": target_path})
        result["display_name"] = display_name
        return result
    except Exception as exc:
        return {
            "verification_type": "behavior",
            "display_name": display_name,
            "status": "failed",
            "error": str(exc),
            "annotations": {},
        }


def _run_verify(target_path: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    module, tool_name, display_name = VERIFICATION_AGENTS["verify_poc"]
    candidates = sorted(
        findings,
        key=lambda finding: SEVERITY_PRIORITY.get(str(finding.get("severity", "medium")), 5),
    )[:MAX_VERIFY_FINDINGS]
    try:
        with StdioMcpClient(module) as client:
            client.request("tools/list")
            result = client.call_tool(tool_name, {"findings": candidates, "target_path": target_path})
        result["display_name"] = display_name
        result["assessed_findings"] = len(candidates)
        if len(findings) > len(candidates):
            result["truncated"] = True
            result["truncated_from"] = len(findings)
        return result
    except Exception as exc:
        return {
            "verification_type": "verify_poc",
            "display_name": display_name,
            "status": "failed",
            "error": str(exc),
            "results": [],
        }


def _merge_verification(all_findings: list[dict[str, Any]], verification_reports: dict[str, Any]) -> None:
    """Attach behavior annotations and verification verdicts onto findings."""
    behavior = verification_reports.get("behavior") or {}
    behavior_by_id = behavior.get("annotations") or {}
    verify = verification_reports.get("verify_poc") or {}
    verify_by_id = {result.get("id"): result for result in verify.get("results") or []}
    for finding in all_findings:
        finding_id = finding.get("id")
        annotation = behavior_by_id.get(finding_id)
        if annotation:
            finding["behavior"] = annotation.get("behavior", "unexpected")
            finding["behavior_rationale"] = annotation.get("rationale", "")
        else:
            finding["behavior"] = "unexpected"
            finding["behavior_rationale"] = ""
        result = verify_by_id.get(finding_id)
        if result:
            verdict = result.get("verdict")
            finding["poc_verified"] = verdict == "verified"
            finding["verification_verdict"] = verdict
            finding["verification_evidence"] = result.get("evidence")
        else:
            finding["poc_verified"] = None
            finding["verification_verdict"] = None


def _compute_valued(all_findings: list[dict[str, Any]], policy: str) -> list[dict[str, Any]]:
    valued: list[dict[str, Any]] = []
    for finding in all_findings:
        if finding.get("behavior") == "expected":
            continue
        verdict = finding.get("verification_verdict")
        if policy == "lenient":
            if verdict in {"verified", "static-confirmed", "static-only"}:
                valued.append(finding)
        else:
            if verdict in VALUED_VERDICTS:
                valued.append(finding)
    return valued


def build_audit_report(
    target_path: str,
    diff_path: str | None = None,
    research_enabled: set[str] | None = None,
    web_urls: list[str] | None = None,
    methodology_topic: str | None = None,
    clarify_check_ids: list[str] | None = None,
    clarify_question: str = "",
    verification_enabled: set[str] | None = None,
    verification_policy: str = "strict",
    llm_overrides: dict[str, str] | None = None,
    with_llm_summary: bool = False,
) -> dict[str, Any]:
    target = str(Path(target_path).expanduser().resolve())
    analysis_target = str(Path(diff_path).expanduser().resolve()) if diff_path else target
    if diff_path and not Path(analysis_target).is_file():
        raise FileNotFoundError(f"Diff does not exist or is not a file: {diff_path}")
    if research_enabled is None:
        research_agents = set(RESEARCH_AGENTS)
    else:
        research_agents = set(research_enabled) & set(RESEARCH_AGENTS)
        # PoC blueprints are derived from taint and logic-flaw evidence, so
        # requesting them pulls in their evidence producers.
        if "safe_poc" in research_agents:
            research_agents.update({"taint", "business_logic"})
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="research-layer") as executor:
        futures = {
            executor.submit(_run_domain, agent, analysis_target): ("domain", agent)
            for agent in AGENTS
        }
        futures.update(
            {
                executor.submit(_run_research, research_type, analysis_target): (
                    "research",
                    research_type,
                )
                for research_type in sorted(research_agents)
            }
        )
        domain_reports: dict[str, dict[str, Any]] = {}
        research_reports: dict[str, dict[str, Any]] = {}
        for future in as_completed(futures):
            report_kind, report_name = futures[future]
            if report_kind == "domain":
                domain_reports[report_name] = future.result()
            else:
                research_reports[report_name] = future.result()

    requested_by = sorted(
        agent
        for agent, report in domain_reports.items()
        if report.get("dependency_files")
    )
    supply_chain = _run_supply_chain(analysis_target, requested_by)

    all_findings: list[dict[str, Any]] = []
    for report in domain_reports.values():
        all_findings.extend(report.get("findings", []))
    all_findings.extend(supply_chain.get("findings", []))
    for report in research_reports.values():
        all_findings.extend(report.get("findings", []))

    # Extended finding schema: guarantee every finding carries the optional
    # taint_path and poc_payload fields, and attach the safe-PoC blueprints
    # to the research findings they were generated for.
    poc_by_finding: dict[str, str] = {}
    safe_poc = research_reports.get("safe_poc") or {}
    for proof in safe_poc.get("proofs", []):
        source_id = proof.get("source_finding_id")
        if source_id and proof.get("poc_payload"):
            poc_by_finding[source_id] = proof["poc_payload"]
    for finding in all_findings:
        finding["taint_path"] = finding.get("taint_path") or []
        finding["poc_payload"] = finding.get("poc_payload")
        payload = poc_by_finding.get(finding.get("id"))
        if payload:
            finding["poc_payload"] = payload

    # Verification layer: expected-usage noise filtering and PoC execution.
    # It runs after the parallel phases because it consumes the findings they
    # produced.  The behavior checker re-derives findings deterministically
    # in-sandbox and the verifier executes the generated proofs with no-op
    # sinks; together they gate which findings are "valued".
    verification_reports: dict[str, dict[str, Any]] = {}
    valued_findings: list[dict[str, Any]] = []
    if verification_enabled:
        if "behavior" in verification_enabled:
            verification_reports["behavior"] = _run_behavior(analysis_target)
        if "verify_poc" in verification_enabled:
            verification_reports["verify_poc"] = _run_verify(analysis_target, all_findings)
        _merge_verification(all_findings, verification_reports)
        valued_findings = _compute_valued(all_findings, verification_policy)

    severity_counts: dict[str, int] = {}
    for finding in all_findings:
        severity = str(finding.get("severity", "unknown"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    methodology_research: dict[str, Any] | None = None
    if web_urls:
        methodology_research = _run_web_research(web_urls, methodology_topic, llm_overrides)

    llm_summary: dict[str, Any] | None = None
    if with_llm_summary:
        llm_summary = _run_llm_summary(
            _build_llm(llm_overrides),
            all_findings,
            severity_counts,
            valued_findings,
        )

    clarifications: list[dict[str, Any]] = []
    for check_id in clarify_check_ids or []:
        agent_key = _load_agent_for_check(check_id)
        if agent_key and agent_key in AGENTS:
            module, tool_name, display_name = AGENTS[agent_key]
        else:
            module, tool_name, display_name = RESEARCH_AGENTS["business_logic"]
            display_name = f"{display_name} (fallback for unknown check)"
        clarifications.append(
            _run_clarification(module, tool_name, display_name, check_id, clarify_question)
        )

    return {
        "schema_version": "1.0",
        "audit_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "orchestrator": {
            "name": "Main Orchestrator Agent",
            "role": "Map / Router Agent",
            "routing": {
                "target": target,
                "analysis_target": analysis_target,
                "diff": str(Path(diff_path).resolve()) if diff_path else None,
                "delegated_in_parallel": {
                    "domain_agents": list(AGENTS),
                    "research_agents": list(RESEARCH_AGENTS),
                },
                "hierarchy": {
                    "main": "Main Orchestrator Agent",
                    "domain_agents": {
                        agent: {
                            "name": AGENTS[agent][2],
                            "sub_agents": sorted(report.get("sub_agents", {}).keys()),
                        }
                        for agent, report in domain_reports.items()
                    },
                    "shared_worker": "Unified Supply Chain Worker",
                    "research_layer": {
                        "name": "Orchestrator Research Layer",
                        "agents": {
                            research_type: RESEARCH_AGENTS[research_type][2]
                            for research_type in RESEARCH_AGENTS
                        },
                    },
                    "verification_layer": {
                        "name": "Orchestrator Verification Layer",
                        "agents": {
                            verification_type: VERIFICATION_AGENTS[verification_type][2]
                            for verification_type in VERIFICATION_AGENTS
                        },
                    },
                },
            },
        },
        "summary": {
            "status": "completed"
            if all(report.get("status") == "completed" for report in domain_reports.values())
            and supply_chain.get("status") == "completed"
            and all(report.get("status") == "completed" for report in research_reports.values())
            and all(report.get("status") == "completed" for report in verification_reports.values())
            else "completed_with_errors",
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "failed_agents": [
                report.get("display_name", report.get("agent", "unknown"))
                for report in domain_reports.values()
                if report.get("status") != "completed"
            ]
            + (
                ["Unified Supply Chain Worker"]
                if supply_chain.get("status") != "completed"
                else []
            )
            + [
                report.get("display_name", report.get("research_type", "research"))
                for report in research_reports.values()
                if report.get("status") != "completed"
            ]
            + [
                report.get("display_name", report.get("verification_type", "verification"))
                for report in verification_reports.values()
                if report.get("status") != "completed"
            ],
            "verification_layer": _verification_summary(
                verification_reports,
                all_findings,
                valued_findings,
                verification_policy,
                bool(verification_enabled),
            ),
        },
        "agents": domain_reports,
        "supply_chain": supply_chain,
        "research_layer": {
            "name": "Orchestrator Research Layer",
            "status": "completed"
            if all(report.get("status") == "completed" for report in research_reports.values())
            else "completed_with_errors",
            "agents": research_reports,
            "hierarchy": {
                "parent": "Orchestrator Research Layer",
                "children": {
                    research_type: {
                        "name": RESEARCH_AGENTS[research_type][2],
                        "tool": RESEARCH_AGENTS[research_type][1],
                    }
                    for research_type in RESEARCH_AGENTS
                },
            },
        },
        "methodology_research": methodology_research,
        "clarifications": clarifications,
        "llm_summary": llm_summary,
        "verification_layer": _verification_layer_report(
            verification_reports,
            all_findings,
            valued_findings,
            verification_policy,
            bool(verification_enabled),
        ),
        "valued_findings": valued_findings,
        "findings": all_findings,
    }


def _verification_summary(
    verification_reports: dict[str, dict[str, Any]],
    all_findings: list[dict[str, Any]],
    valued_findings: list[dict[str, Any]],
    policy: str,
    enabled: bool,
) -> dict[str, Any]:
    if not enabled:
        return {"enabled": False, "status": "skipped"}
    behavior = verification_reports.get("behavior") or {}
    verify = verification_reports.get("verify_poc") or {}
    return {
        "enabled": True,
        "status": "completed"
        if all(report.get("status") == "completed" for report in verification_reports.values())
        else "completed_with_errors",
        "verification_policy": policy,
        "behavior": {
            "status": behavior.get("status", "skipped"),
            "expected_count": behavior.get("expected_count", 0),
            "unexpected_count": behavior.get("unexpected_count", 0),
        },
        "poc_verification": {
            "status": verify.get("status", "skipped"),
            "assessed_findings": verify.get("assessed_findings", 0),
            "verified_count": verify.get("verified_count", 0),
            "static_confirmed_count": verify.get("static_confirmed_count", 0),
            "not_reproduced_count": verify.get("not_reproduced_count", 0),
            "static_only_count": verify.get("static_only_count", 0),
            "unsupported_count": verify.get("unsupported_count", 0),
            "truncated": verify.get("truncated", False),
        },
        "valued_findings_count": len(valued_findings),
        "noise_filtered_count": sum(
            1 for finding in all_findings if finding.get("behavior") == "expected"
        ),
    }


def _verification_layer_report(
    verification_reports: dict[str, dict[str, Any]],
    all_findings: list[dict[str, Any]],
    valued_findings: list[dict[str, Any]],
    policy: str,
    enabled: bool,
) -> dict[str, Any]:
    if not enabled:
        return {
            "name": "Orchestrator Verification Layer",
            "status": "skipped",
            "agents": {},
            "hierarchy": {
                "parent": "Main Orchestrator Agent",
                "children": {
                    verification_type: {"name": VERIFICATION_AGENTS[verification_type][2]}
                    for verification_type in VERIFICATION_AGENTS
                },
            },
        }
    return {
        "name": "Orchestrator Verification Layer",
        "status": "completed"
        if all(report.get("status") == "completed" for report in verification_reports.values())
        else "completed_with_errors",
        "verification_policy": policy,
        "agents": verification_reports,
        "hierarchy": {
            "parent": "Main Orchestrator Agent",
            "children": {
                verification_type: {
                    "name": VERIFICATION_AGENTS[verification_type][2],
                    "tool": VERIFICATION_AGENTS[verification_type][1],
                }
                for verification_type in VERIFICATION_AGENTS
            },
        },
        "valued_findings_count": len(valued_findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Map a source repository or diff to parallel SAST MCP domain agents."
    )
    parser.add_argument("target_path", help="Repository directory or a diff/source file")
    parser.add_argument("--diff", dest="diff_path", help="Optional diff file associated with the target")
    parser.add_argument("--output", "-o", help="Write the consolidated JSON report to this path")
    parser.add_argument(
        "--with-taint",
        action="store_true",
        help="Enable the cross-file taint analyzer research agent",
    )
    parser.add_argument(
        "--with-poc",
        action="store_true",
        help="Enable safe proof-of-concept generation (also runs taint and logic-flaw evidence)",
    )
    parser.add_argument(
        "--with-behavior",
        action="store_true",
        help="Run the Behavior & Expected-Usage Evaluator to reduce noise by annotating expected usage",
    )
    parser.add_argument(
        "--with-verify",
        action="store_true",
        help="Run generated proofs in the isolated harness; only verified findings count as valued (implies --with-poc)",
    )
    parser.add_argument(
        "--verification-policy",
        choices=("strict", "lenient"),
        default="strict",
        help="strict: only verified/static-confirmed findings are valued; lenient: static-only also counts",
    )
    parser.add_argument(
        "--with-llm-summary",
        action="store_true",
        help="Generate an AI-written executive summary and remediation plan from the findings",
    )
    parser.add_argument(
        "--llm-provider",
        help="LLM provider display name (default: USER_LLM_PROVIDER or openai-compatible)",
    )
    parser.add_argument(
        "--llm-endpoint",
        help="OpenAI-compatible chat completions base URL (default: USER_LLM_BASE_URL)",
    )
    parser.add_argument(
        "--llm-api-key",
        help="Your own LLM API key (default: USER_LLM_API_KEY); never bundled with the project",
    )
    parser.add_argument(
        "--llm-model",
        help="Model identifier (default: USER_LLM_MODEL or gpt-4o-mini)",
    )
    parser.add_argument(
        "--research-url",
        action="append",
        default=[],
        metavar="URL",
        help="Public URL for the main agent to fetch for methodology research (repeatable)",
    )
    parser.add_argument(
        "--methodology-topic",
        help="Topic label attached to the main agent's web research",
    )
    parser.add_argument(
        "--clarify",
        action="append",
        default=[],
        metavar="CHECK_ID",
        help="Ask the owning sub-agent a clarifying methodology question (repeatable)",
    )
    parser.add_argument(
        "--clarify-question",
        default="Explain the detection methodology and expected evidence for this check.",
        help="Question text used for the --clarify requests",
    )
    args = parser.parse_args()

    research_enabled: set[str] | None = None
    if args.with_taint or args.with_poc or args.with_verify:
        research_enabled = set()
        if args.with_taint:
            research_enabled.add("taint")
        if args.with_poc or args.with_verify:
            research_enabled.add("safe_poc")

    verification_enabled: set[str] | None = None
    if args.with_verify or args.with_behavior:
        verification_enabled = set()
        if args.with_behavior:
            verification_enabled.add("behavior")
        if args.with_verify:
            verification_enabled.add("verify_poc")

    llm_overrides: dict[str, str] = {}
    if args.llm_provider:
        llm_overrides["provider"] = args.llm_provider
    if args.llm_endpoint:
        llm_overrides["base_url"] = args.llm_endpoint
    if args.llm_api_key:
        llm_overrides["api_key"] = args.llm_api_key
    if args.llm_model:
        llm_overrides["model"] = args.llm_model

    report = build_audit_report(
        args.target_path,
        args.diff_path,
        research_enabled,
        web_urls=args.research_url or None,
        methodology_topic=args.methodology_topic,
        clarify_check_ids=args.clarify or None,
        clarify_question=args.clarify_question,
        verification_enabled=verification_enabled,
        verification_policy=args.verification_policy,
        llm_overrides=llm_overrides or None,
        with_llm_summary=args.with_llm_summary,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote audit report to {output_path}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
