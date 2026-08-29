"""Safe Proof-of-Concept Generator MCP server.

``generate_poc`` builds non-destructive HTTP reproduction blocks (curl and
raw HTTP specs) for a single finding using the benign marker
``TEST_MARKER_123``.  Nothing is ever executed, sent, or mutated: the output
is a reproducible test blueprint for an isolated local fixture.
"""

from __future__ import annotations

import json
import os

from mcp_servers.common import build_research_clarifier, required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def _poc_schema() -> str:
    return json.dumps(
        {
            "type": "object",
            "properties": {
                "check_id": {
                    "type": "string",
                    "description": "Finding check ID, for example 05, 06, or 33",
                },
                "vulnerability_details": {
                    "type": "object",
                    "description": "Finding details such as file, line, method, route, and parameter",
                },
                "target_path": {
                    "type": "string",
                    "description": "Optional repository path; defaults to SAST_TARGET_PATH",
                },
            },
            "required": ["check_id", "vulnerability_details"],
            "additionalProperties": False,
        }
    )


def generate_poc(check_id: str, vulnerability_details: dict, target_path: str | None = None) -> dict:
    """Generate a non-executing PoC blueprint for one finding.

    Runs in the sandbox so the same isolation guarantees apply; the returned
    ``poc_payload`` is a curl/HTTP reproduction block that is never executed.
    """
    target = target_path or os.environ.get("SAST_TARGET_PATH")
    if not target:
        raise ValueError("target_path is required or SAST_TARGET_PATH must be set")
    return run_sandboxed(
        target,
        operation="poc",
        check_id=check_id,
        vulnerability_details=vulnerability_details,
    )


def generate_safe_poc(target_path: str) -> dict:
    """Generate inert local proof blueprints from all research evidence."""
    return run_sandboxed(target_path, operation="research", research_kind="safe-poc")


def main() -> None:
    serve_mcp(
        server_name="Automated Exploit Proof-of-Concept Generator",
        server_version="1.0.0",
        tools={
            "generate_poc": (
                "Generate a non-executing curl/HTTP proof blueprint for a single finding.",
                _poc_schema(),
                generate_poc,
            ),
            "generate_safe_poc": (
                "Generate non-executing, local-only proof blueprints from research evidence.",
                required_target_schema(),
                generate_safe_poc,
            ),
        },
        clarify_handler=build_research_clarifier("safe_poc"),
    )


if __name__ == "__main__":
    main()
