"""Cross-File Taint Analyzer MCP server.

Exposed to child agents as a dedicated research tool.  ``trace_dataflow``
resolves the requested sink across file boundaries in the sandbox and returns
exact ``taint_path`` sequences plus a sanitizer verdict.
"""

from __future__ import annotations

import json
import os

from mcp_servers.common import build_research_clarifier, required_target_schema, serve_mcp
from sandbox.runner import run_sandboxed


def _trace_schema() -> str:
    return json.dumps(
        {
            "type": "object",
            "properties": {
                "source_file": {
                    "type": "string",
                    "description": "Source file, relative to the analysis target",
                },
                "sink_function": {
                    "type": "string",
                    "description": "Name of the function expected to consume the tainted data",
                },
                "target_path": {
                    "type": "string",
                    "description": "Optional repository path; defaults to SAST_TARGET_PATH",
                },
            },
            "required": ["source_file", "sink_function"],
            "additionalProperties": False,
        }
    )


def trace_dataflow(source_file: str, sink_function: str, target_path: str | None = None) -> dict:
    """Trace tainted data from ``source_file`` into ``sink_function``.

    The trace runs entirely inside the Docker sandbox and returns the
    ``taint_path`` (files, lines, and variable transformations) for every
    flow, together with whether a sanitizer neutralizes it.
    """
    target = target_path or os.environ.get("SAST_TARGET_PATH")
    if not target:
        raise ValueError("target_path is required or SAST_TARGET_PATH must be set")
    return run_sandboxed(
        target,
        operation="trace",
        source_file=source_file,
        sink_function=sink_function,
    )


def audit_taint(target_path: str) -> dict:
    """Run the cross-file taint engine over the complete target."""
    return run_sandboxed(target_path, operation="research", research_kind="taint")


def main() -> None:
    serve_mcp(
        server_name="Cross-File Taint Analyzer",
        server_version="1.0.0",
        tools={
            "trace_dataflow": (
                "Trace user-controlled data from a source file into a sink function, returning taint paths and sanitizer verdicts.",
                _trace_schema(),
                trace_dataflow,
            ),
            "audit_taint": (
                "Read-only cross-file source-to-sink taint analysis over the whole target.",
                required_target_schema(),
                audit_taint,
            ),
        },
        clarify_handler=build_research_clarifier("taint"),
    )


if __name__ == "__main__":
    main()
