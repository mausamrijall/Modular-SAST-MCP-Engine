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
    "taint": ("mcp_servers.taint_agent", "audit_taint", "Semantic Flow & Taint Engine"),
    "business_logic": (
        "mcp_servers.business_logic_agent",
        "audit_business_logic",
        "Context-Aware Business Logic Evaluator",
    ),
    "safe_poc": (
        "mcp_servers.poc_agent",
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


def build_audit_report(target_path: str, diff_path: str | None = None) -> dict[str, Any]:
    target = str(Path(target_path).expanduser().resolve())
    analysis_target = str(Path(diff_path).expanduser().resolve()) if diff_path else target
    if diff_path and not Path(analysis_target).is_file():
        raise FileNotFoundError(f"Diff does not exist or is not a file: {diff_path}")
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
                for research_type in RESEARCH_AGENTS
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

    severity_counts: dict[str, int] = {}
    for finding in all_findings:
        severity = str(finding.get("severity", "unknown"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

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
        "findings": all_findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Map a source repository or diff to parallel SAST MCP domain agents."
    )
    parser.add_argument("target_path", help="Repository directory or a diff/source file")
    parser.add_argument("--diff", dest="diff_path", help="Optional diff file associated with the target")
    parser.add_argument("--output", "-o", help="Write the consolidated JSON report to this path")
    args = parser.parse_args()

    report = build_audit_report(args.target_path, args.diff_path)
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
