"""Semantic Flow & Taint Engine MCP server."""

from __future__ import annotations

from mcp_servers.common import required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def audit_taint(target_path: str) -> dict:
    """Trace local source-to-sink flows without executing target code."""
    return run_sandboxed(target_path, operation="research", research_kind="taint")


def main() -> None:
    serve_mcp(
        server_name="Semantic Flow & Taint Engine",
        server_version="1.0.0",
        tools={
            "audit_taint": (
                "Read-only semantic source-to-sink taint analysis in the sandbox.",
                required_target_schema(),
                audit_taint,
            )
        },
    )


if __name__ == "__main__":
    main()
