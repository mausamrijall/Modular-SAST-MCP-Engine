"""Unified Supply Chain Worker MCP server."""

from __future__ import annotations

import json

from mcp_servers.common import serve_mcp
from sandbox.runner import run_sandboxed


def audit_supply_chain(target_path: str, requested_by: list[str] | None = None) -> dict:
    """Audit dependency manifests in the isolated runner."""
    return run_sandboxed(
        target_path,
        operation="supply-chain",
        requested_by=requested_by or [],
    )


def main() -> None:
    schema = json.dumps(
        {
            "type": "object",
            "properties": {
                "target_path": {"type": "string"},
                "requested_by": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["target_path"],
        }
    )
    serve_mcp(
        server_name="Unified Supply Chain Worker",
        server_version="1.0.0",
        tools={
            "audit_supply_chain": (
                "Read-only dependency manifest and install-hook audit requested by domain agents.",
                schema,
                audit_supply_chain,
            )
        },
    )


if __name__ == "__main__":
    main()
