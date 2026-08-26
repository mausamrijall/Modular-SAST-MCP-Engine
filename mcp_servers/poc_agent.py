"""Safe Automated Exploit Proof-of-Concept Generator MCP server."""

from __future__ import annotations

from mcp_servers.common import required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def generate_poc(target_path: str) -> dict:
    """Generate inert local verification blueprints; never execute them."""
    return run_sandboxed(
        target_path,
        operation="research",
        research_kind="safe-poc",
    )


def main() -> None:
    serve_mcp(
        server_name="Automated Exploit Proof-of-Concept Generator",
        server_version="1.0.0",
        tools={
            "generate_safe_poc": (
                "Generate non-executing, local-only proof blueprints from research evidence.",
                required_target_schema(),
                generate_poc,
            )
        },
    )


if __name__ == "__main__":
    main()
