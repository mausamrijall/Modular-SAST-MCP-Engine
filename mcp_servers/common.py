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
from typing import Any


JsonObject = dict[str, Any]
ToolHandler = Callable[..., JsonObject]


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
) -> None:
    """Serve a small, stdio JSON-RPC MCP surface.

    tools maps a tool name to (description, input_schema, handler).  The
    handler is called with keyword arguments from tools/call.arguments.
    """

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
                        for tool_name, (description, input_schema, _handler) in tools.items()
                    ]
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                if tool_name not in tools:
                    raise ValueError(f"Unknown tool: {tool_name}")
                arguments = params.get("arguments") or {}
                _description, _schema, handler = tools[tool_name]
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
