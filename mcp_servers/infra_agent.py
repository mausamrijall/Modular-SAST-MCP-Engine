"""Agent C: Infra & Client MCP server."""

from __future__ import annotations

from mcp_servers.common import required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def audit_infra(target_path: str) -> dict:
    """Audit deployment, client configuration, exposure, and operational controls."""
    return run_sandboxed(target_path, operation="audit", agent="infra")


def main() -> None:
    serve_mcp(
        server_name="Infra & Client Agent",
        server_version="1.0.0",
        tools={
            "audit_infra": (
                "Read-only Agent C audit for checks 8-10, 12, 15, and 27-29, 32, and 35-36.",
                required_target_schema(),
                audit_infra,
            )
        },
    )


if __name__ == "__main__":
    main()
