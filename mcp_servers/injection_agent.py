"""Agent B: Input & Injection MCP server."""

from __future__ import annotations

from mcp_servers.common import required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def audit_injection(target_path: str) -> dict:
    """Audit input validation, injection, webhooks, and object access controls."""
    return run_sandboxed(target_path, operation="audit", agent="injection")


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
    )


if __name__ == "__main__":
    main()
