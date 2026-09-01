"""Behavior & Expected-Usage Evaluator MCP server.

``assess_behavior`` re-derives the deterministic findings in-sandbox and
classifies each one as ``expected`` (test/fixture/example/docs/lockfile
content, template config, intentional crawl policy) or ``unexpected``.  The
orchestrator uses these annotations to filter noise before counting valued
findings.
"""

from __future__ import annotations

import os

from mcp_servers.common import build_research_clarifier, required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def assess_behavior(target_path: str | None = None) -> dict:
    """Classify findings as expected or unexpected usage to reduce noise."""
    target = target_path or os.environ.get("SAST_TARGET_PATH")
    if not target:
        raise ValueError("target_path is required or SAST_TARGET_PATH must be set")
    return run_sandboxed(target, operation="behavior")


def main() -> None:
    serve_mcp(
        server_name="Behavior & Expected-Usage Evaluator",
        server_version="1.0.0",
        tools={
            "assess_behavior": (
                "Re-derive findings in-sandbox and annotate each as expected or unexpected usage.",
                required_target_schema(),
                assess_behavior,
            ),
        },
        clarify_handler=build_research_clarifier("behavior"),
    )


if __name__ == "__main__":
    main()
