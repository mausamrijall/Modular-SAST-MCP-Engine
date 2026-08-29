"""Agent A: Secrets & Identity MCP server."""

from __future__ import annotations

from mcp_servers.common import build_check_clarifier, required_target_schema, serve_mcp
from mcp_servers.domain_runtime import audit_domain


def audit_secrets(target_path: str) -> dict:
    """Audit secrets, identity, authorization, sessions, and credential hygiene."""
    return audit_domain(target_path, "secrets", "Agent A: Secrets & Identity Agent")


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
        clarify_handler=build_check_clarifier("secrets"),
    )


if __name__ == "__main__":
    main()
