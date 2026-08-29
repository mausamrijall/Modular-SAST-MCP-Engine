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


def _run_web_research(
    urls: list[str],
    methodology_topic: str | None,
) -> dict[str, Any]:
    """Run the main agent's outbound research and methodology synthesis."""
    topic = methodology_topic or "SAST methodology enrichment"
    llm: LLMConfig | None = None
    synthesis_status = "disabled"
    try:
        llm = LLMConfig.from_env()
        synthesis_status = "enabled"
    except ValueError:
        synthesis_status = "llm-not-configured"
    research = web_research.research_web(topic, urls, llm=llm)
    research["synthesis_status"] = synthesis_status
    return research


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


def build_audit_report(
    target_path: str,
    diff_path: str | None = None,
    research_enabled: set[str] | None = None,
    web_urls: list[str] | None = None,
    methodology_topic: str | None = None,
    clarify_check_ids: list[str] | None = None,
    clarify_question: str = "",
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

    severity_counts: dict[str, int] = {}
    for finding in all_findings:
        severity = str(finding.get("severity", "unknown"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    methodology_research: dict[str, Any] | None = None
    if web_urls:
        methodology_research = _run_web_research(web_urls, methodology_topic)

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
                },
            },
        },
        "summary": {
            "status": "completed"
            if all(report.get("status") == "completed" for report in domain_reports.values())
            and supply_chain.get("status") == "completed"
            and all(report.get("status") == "completed" for report in research_reports.values())
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
            ],
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
        "findings": all_findings,
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
    if args.with_taint or args.with_poc:
        research_enabled = set()
        if args.with_taint:
            research_enabled.add("taint")
        if args.with_poc:
            research_enabled.add("safe_poc")

    report = build_audit_report(
        args.target_path,
        args.diff_path,
        research_enabled,
        web_urls=args.research_url or None,
        methodology_topic=args.methodology_topic,
        clarify_check_ids=args.clarify or None,
        clarify_question=args.clarify_question,
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
