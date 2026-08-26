"""Context-Aware Business Logic Evaluator MCP server."""

from __future__ import annotations

from mcp_servers.common import required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def audit_business_logic(target_path: str) -> dict:
    """Inspect sensitive routes and business-critical trust boundaries."""
    return run_sandboxed(
        target_path,
        operation="research",
        research_kind="business-logic",
    )


def main() -> None:
    serve_mcp(
        server_name="Context-Aware Business Logic Evaluator",
        server_version="1.0.0",
        tools={
            "audit_business_logic": (
                "Read-only context-aware business-logic analysis in the sandbox.",
                required_target_schema(),
                audit_business_logic,
            )
        },
    )


if __name__ == "__main__":
    main()
