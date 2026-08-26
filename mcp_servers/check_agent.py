"""Generic executable MCP sub-agent for one configured SAST check.

The domain parent starts this module as a child process with a fixed agent and
check ID.  The child exposes one callable MCP tool and sends all analysis to
the Docker sandbox.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcp_servers.common import serve_mcp
from sandbox.runner import run_sandboxed


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "checks_map.json"


def _check_name(agent: str, check_id: str) -> str:
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    for check in config["checks"]:
        if str(check["id"]) == check_id:
            if check.get("agent") != agent:
                raise ValueError(f"Check {check_id} is not routed to parent agent {agent}")
            return str(check["name"])
    raise ValueError(f"Unknown check ID: {check_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one SAST check as an MCP child agent")
    parser.add_argument("--parent-agent", choices=("secrets", "injection", "infra"), required=True)
    parser.add_argument("--check-id", required=True)
    args = parser.parse_args()
    check_name = _check_name(args.parent_agent, args.check_id)

    def audit_check(target_path: str) -> dict:
        report = run_sandboxed(
            target_path,
            operation="audit",
            agent=args.parent_agent,
            check_ids=[args.check_id],
        )
        report.update(
            {
                "check_id": args.check_id,
                "check_name": check_name,
                "sub_agent": f"{args.parent_agent}.{args.check_id}",
                "executable_tool": "audit_check",
            }
        )
        return report

    schema = json.dumps(
        {
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
            },
            "required": ["target_path"],
            "additionalProperties": False,
        }
    )
    serve_mcp(
        server_name=f"{args.parent_agent}.{args.check_id} Sub-Agent",
        server_version="1.0.0",
        tools={
            "audit_check": (
                f"Executable read-only MCP sub-agent for check {args.check_id}: {check_name}.",
                schema,
                audit_check,
            )
        },
    )


if __name__ == "__main__":
    main()
