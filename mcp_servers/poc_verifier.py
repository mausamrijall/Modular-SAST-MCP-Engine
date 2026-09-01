"""Proof-of-Concept Verifier MCP server.

``verify_pocs`` runs the generated proof blueprints through a behavioral
verification harness inside the isolated sandbox.  Each candidate finding's
enclosing function is loaded and called with a benign random marker while
dangerous sinks are instrumented as recording no-ops.  A finding is reported
``verified`` only when the marker actually reaches an instrumented sink;
static-truth findings (embedded credentials, supply-chain artifacts) are
``static-confirmed`` because the finding is the artifact itself.

The harness runs in the Docker container with ``--network=none``, a read-only
target mount, and no-op sinks, so no request is ever sent and no real
operation is executed.
"""

from __future__ import annotations

import json
import os

from mcp_servers.common import build_research_clarifier, serve_mcp
from sandbox.runner import run_sandboxed


def _verify_schema() -> str:
    return json.dumps(
        {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Candidate findings that carry proof blueprints (id, check_id, file, line, poc_payload, evidence, taint_path)",
                },
                "target_path": {
                    "type": "string",
                    "description": "Optional repository path; defaults to SAST_TARGET_PATH",
                },
            },
            "required": ["findings"],
            "additionalProperties": False,
        }
    )


def verify_pocs(findings: list, target_path: str | None = None) -> dict:
    """Run proof blueprints through the isolated behavioral harness.

    Returns a per-finding verdict: ``verified``, ``static-confirmed``,
    ``not-reproduced``, ``static-only``, or ``unsupported``.  Only verified and
    static-confirmed findings are counted as valued by the orchestrator.
    """
    target = target_path or os.environ.get("SAST_TARGET_PATH")
    if not target:
        raise ValueError("target_path is required or SAST_TARGET_PATH must be set")
    return run_sandboxed(
        target,
        operation="verify-poc",
        findings=findings,
    )


def main() -> None:
    serve_mcp(
        server_name="Proof-of-Concept Verifier",
        server_version="1.0.0",
        tools={
            "verify_pocs": (
                "Execute proof blueprints in the isolated harness and report which findings are verified.",
                _verify_schema(),
                verify_pocs,
            ),
        },
        clarify_handler=build_research_clarifier("verify_poc"),
    )


if __name__ == "__main__":
    main()
