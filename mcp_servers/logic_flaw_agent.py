"""Business Logic & Authorization Engine MCP server.

Focused on checks 05 (Missing Authz), 06 (Cross-User Access), and
33 (IDOR/BOLA).  It parses Express, FastAPI, and Laravel route definitions,
cross-references them against their middleware stacks, and flags endpoints
that execute database queries on route parameters without an ownership
comparison against the session principal.
"""

from __future__ import annotations

from mcp_servers.common import build_research_clarifier, required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def audit_logic_flaws(target_path: str) -> dict:
    """Audit authorization gaps for checks 05, 06, and 33."""
    return run_sandboxed(
        target_path,
        operation="research",
        research_kind="logic-flaw",
    )


def main() -> None:
    serve_mcp(
        server_name="Business Logic & Authorization Engine",
        server_version="1.0.0",
        tools={
            "audit_logic_flaws": (
                "Read-only route/middleware/ownership analysis for checks 05, 06, and 33 in the sandbox.",
                required_target_schema(),
                audit_logic_flaws,
            )
        },
        clarify_handler=build_research_clarifier("business_logic"),
    )


if __name__ == "__main__":
    main()
