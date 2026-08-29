"""Agent B: Input & Injection MCP server."""

from __future__ import annotations

from mcp_servers.common import build_check_clarifier, required_target_schema, serve_mcp
from mcp_servers.domain_runtime import audit_domain


def audit_injection(target_path: str) -> dict:
    """Audit input validation, injection, webhooks, and object access controls."""
    return audit_domain(target_path, "injection", "Agent B: Input & Injection Agent")


def main() -> None:
    serve_mcp(
        server_name="Input & Injection Agent",
        server_version="1.0.0",
        tools={
            "audit_injection": (
                "Read-only Agent B audit for checks 16-23, 31, 33, and 34.",
                required_target_schema(),
                audit_injection,
            )
        },
        clarify_handler=build_check_clarifier("injection"),
    )


if __name__ == "__main__":
    main()
