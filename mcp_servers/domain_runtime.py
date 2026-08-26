"""Runtime shared by Agent A, Agent B, and Agent C parent servers."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from mcp_servers.sub_agent_client import StdioMcpClient


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "checks_map.json"
SUB_AGENT_MODULE = "mcp_servers.check_agent"


def _checks_for_agent(agent: str) -> list[dict[str, Any]]:
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    return [check for check in config["checks"] if check.get("agent") == agent]


def _run_child(agent: str, check: dict[str, Any], target_path: str) -> dict[str, Any]:
    check_id = str(check["id"])
    child_name = f"{agent}.{check_id}"
    try:
        with StdioMcpClient(
            SUB_AGENT_MODULE,
            ["--parent-agent", agent, "--check-id", check_id],
        ) as client:
            available = client.request("tools/list")
            tool_names = {tool["name"] for tool in available.get("tools", [])}
            if "audit_check" not in tool_names:
                raise RuntimeError("Child MCP server did not expose audit_check")
            report = client.call_tool("audit_check", {"target_path": target_path})
        return {
            "id": check_id,
            "name": check["name"],
            "sub_agent": child_name,
            "status": report.get("status", "completed"),
            "tool": "audit_check",
            "server": SUB_AGENT_MODULE,
            "report": report,
        }
    except Exception as exc:
        return {
            "id": check_id,
            "name": check["name"],
            "sub_agent": child_name,
            "status": "failed",
            "tool": "audit_check",
            "server": SUB_AGENT_MODULE,
            "error": str(exc),
            "report": {
                "agent": agent,
                "check_id": check_id,
                "status": "failed",
                "findings": [],
                "dependency_files": [],
            },
        }


def audit_domain(target_path: str, agent: str, display_name: str) -> dict[str, Any]:
    """Fan out to real MCP children and return the parent domain report."""
    checks = _checks_for_agent(agent)
    child_reports: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(
        max_workers=min(8, max(1, len(checks))),
        thread_name_prefix=f"{agent}-sub-agent",
    ) as executor:
        futures = {
            executor.submit(_run_child, agent, check, target_path): str(check["id"])
            for check in checks
        }
        for future in as_completed(futures):
            child_report = future.result()
            child_reports[child_report["id"]] = child_report

    findings: list[dict[str, Any]] = []
    dependency_files: set[str] = set()
    for child_report in child_reports.values():
        report = child_report.get("report", {})
        findings.extend(report.get("findings", []))
        dependency_files.update(report.get("dependency_files", []))

    child_failures = [
        child_report["sub_agent"]
        for child_report in child_reports.values()
        if child_report.get("status") != "completed"
    ]
    return {
        "agent": agent,
        "display_name": display_name,
        "status": "completed" if not child_failures else "completed_with_errors",
        "target": target_path,
        "findings": findings,
        "dependency_files": sorted(dependency_files),
        "sub_agents": child_reports,
        "failed_sub_agents": child_failures,
    }
