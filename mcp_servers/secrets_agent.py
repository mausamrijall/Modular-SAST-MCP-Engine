"""Agent A: Secrets & Identity MCP server."""

from __future__ import annotations

from mcp_servers.common import required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def audit_secrets(target_path: str) -> dict:
    """Audit secrets, identity, authorization, sessions, and credential hygiene."""
    return run_sandboxed(target_path, operation="audit", agent="secrets")


def main() -> None:
    serve_mcp(
        server_name="Secrets & Identity Agent",
        server_version="1.0.0",
        tools={
            "audit_secrets": (
                "Read-only Agent A audit for checks 1-7, 11, 13-14, 24-26, and 30.",
                required_target_schema(),
                audit_secrets,
            )
        },
    )


if __name__ == "__main__":
    main()
