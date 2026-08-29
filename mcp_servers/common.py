"""Shared JSON-RPC and server helpers for the SAST MCP workers.

The project intentionally uses the MCP wire conventions without requiring an
MCP SDK.  Each server speaks newline-delimited JSON-RPC 2.0 over stdin/stdout,
which makes the workers easy to run from the orchestrator or from any MCP
compatible process supervisor.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any


JsonObject = dict[str, Any]
ToolHandler = Callable[..., JsonObject]

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _jsonrpc_error(request_id: Any, code: int, message: str) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        },
        separators=(",", ":"),
    )


def _jsonrpc_result(request_id: Any, result: Any) -> str:
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "result": result},
        separators=(",", ":"),
    )


def serve_mcp(
    *,
    server_name: str,
    server_version: str,
    tools: dict[str, tuple[str, str, ToolHandler]],
    clarify_handler: ToolHandler | None = None,
) -> None:
    """Serve a small, stdio JSON-RPC MCP surface.

    tools maps a tool name to (description, input_schema, handler).  The
    handler is called with keyword arguments from tools/call.arguments.

    When ``clarify_handler`` is provided, a built-in ``clarify`` tool is
    registered.  It lets the main agent ask the sub-agent a methodology
    question for a check or research kind.
    """
    all_tools = dict(tools)
    if clarify_handler is not None:
        all_tools["clarify"] = (
            "Answer the main agent's clarifying question about the methodology "
            "behind a check or research kind.",
            json.dumps(
                {
                    "type": "object",
                    "properties": {
                        "check_id": {
                            "type": "string",
                            "description": "Optional check or research kind identifier",
                        },
                        "question": {
                            "type": "string",
                            "description": "Free-form clarifying question from the main agent",
                        },
                    },
                    "additionalProperties": False,
                }
            ),
            clarify_handler,
        )

    for raw_line in sys.stdin:
        if not raw_line.strip():
            continue
        request_id: Any = None
        try:
            request = json.loads(raw_line)
            request_id = request.get("id")
            method = request.get("method")
            params = request.get("params") or {}

            if method == "initialize":
                result = {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": server_name,
                        "version": server_version,
                    },
                }
            elif method == "notifications/initialized":
                # JSON-RPC notifications have no response.  Continue reading.
                continue
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {
                    "tools": [
                        {
                            "name": tool_name,
                            "description": description,
                            "inputSchema": json.loads(input_schema),
                        }
                        for tool_name, (description, input_schema, _handler) in all_tools.items()
                    ]
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                if tool_name not in all_tools:
                    raise ValueError(f"Unknown tool: {tool_name}")
                arguments = params.get("arguments") or {}
                _description, _schema, handler = all_tools[tool_name]
                result = handler(**arguments)
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, sort_keys=True),
                        }
                    ],
                    "structuredContent": result,
                    "isError": False,
                }
            else:
                raise ValueError(f"Unsupported method: {method}")

            sys.stdout.write(_jsonrpc_result(request_id, result) + "\n")
            sys.stdout.flush()
        except json.JSONDecodeError as exc:
            sys.stdout.write(_jsonrpc_error(request_id, -32700, f"Invalid JSON: {exc}") + "\n")
            sys.stdout.flush()
        except (TypeError, ValueError, OSError) as exc:
            sys.stdout.write(_jsonrpc_error(request_id, -32602, str(exc)) + "\n")
            sys.stdout.flush()
        except Exception as exc:  # pragma: no cover - defensive process boundary
            sys.stdout.write(_jsonrpc_error(request_id, -32603, f"Worker failure: {exc}") + "\n")
            sys.stdout.flush()


def required_target_schema() -> str:
    return json.dumps(
        {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Absolute or workspace-relative source path",
                }
            },
            "required": ["target_path"],
            "additionalProperties": False,
        }
    )


def _load_checks_map() -> list[JsonObject]:
    checks_path = PROJECT_ROOT / "config" / "checks_map.json"
    return json.loads(checks_path.read_text(encoding="utf-8")).get("checks", [])


def build_check_clarifier(agent: str) -> ToolHandler:
    """Build a ``clarify`` handler that answers methodology questions for the
    checks routed to one domain agent."""
    checks = [c for c in _load_checks_map() if c.get("agent") == agent]

    def _clarify(check_id: str = "", question: str = "") -> JsonObject:
        matched = [c for c in checks if c.get("id") == check_id]
        if matched:
            check = matched[0]
            rule = check.get("default_rule", {}) if isinstance(check.get("default_rule"), dict) else {}
            methodology = {
                "check_id": check.get("id"),
                "name": check.get("name"),
                "description": check.get("description"),
                "patterns": rule.get("patterns", []),
                "severity": rule.get("severity"),
                "confidence": rule.get("confidence"),
                "remediation": rule.get("remediation"),
            }
        else:
            methodology = {
                "check_id": check_id,
                "note": "No matching check routed to this agent",
                "available_check_ids": sorted({c.get("id") for c in checks}),
            }
        return {"agent": agent, "check_id": check_id, "question": question, "methodology": methodology}

    return _clarify


RESEARCH_METHODOLOGY: dict[str, JsonObject] = {
    "taint": {
        "name": "Cross-File Taint Analyzer",
        "description": "Bounded variable-level dataflow from user-controlled sources to sinks.",
        "sources": ["HTTP request data, route parameters, body payloads"],
        "sinks": ["SQL/query builders, command executors, filesystem writes"],
        "sanitizers": ["int()/type coercion, parameterized queries, prepared statements"],
        "depth_bounds": "MAX_TAINT_DEPTH=2, per-function cycle guard",
    },
    "business_logic": {
        "name": "Business Logic & Authorization Engine",
        "description": "Route/middleware/ownership analysis for checks 05, 06, and 33.",
        "flaws": ["missing-authorization", "idor-bola", "business-logic-rule"],
        "frameworks": ["Express", "FastAPI", "Laravel"],
    },
    "safe_poc": {
        "name": "Automated Exploit Proof-of-Concept Generator",
        "description": "Non-executing curl/HTTP proof blueprints from research evidence.",
        "marker": "TEST_MARKER_123",
        "safety": "never executes, never sends network requests, never mutates target",
    },
}


def build_research_clarifier(research_type: str) -> ToolHandler:
    """Build a ``clarify`` handler that explains one research-kind methodology."""
    methodology = RESEARCH_METHODOLOGY.get(research_type, {"name": research_type})

    def _clarify(check_id: str = "", question: str = "") -> JsonObject:
        return {
            "research_type": research_type,
            "check_id": check_id,
            "question": question,
            "methodology": methodology,
        }

    return _clarify
