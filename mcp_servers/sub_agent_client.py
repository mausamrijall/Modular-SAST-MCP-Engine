"""Small stdio MCP client used by domain parents to call child agents."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any


class SubAgentError(RuntimeError):
    """Raised when a child MCP process cannot complete a request."""


class StdioMcpClient:
    """MCP JSON-RPC client for one locally spawned child server."""

    def __init__(self, module: str, arguments: list[str] | None = None) -> None:
        self.module = module
        self.arguments = arguments or []
        self.process: subprocess.Popen[str] | None = None
        self.request_id = 0

    def __enter__(self) -> "StdioMcpClient":
        self.process = subprocess.Popen(
            [sys.executable, "-m", self.module, *self.arguments],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.request("initialize", {"clientInfo": {"name": "Domain Parent Agent", "version": "1.0.0"}})
        self.notify("notifications/initialized")
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self.process is None:
            return
        if self.process.stdin:
            self.process.stdin.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        if self.process is None or self.process.stdin is None:
            raise SubAgentError("Child MCP process is not started")
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}}) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise SubAgentError("Child MCP process is not started")
        self.request_id += 1
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params or {}}) + "\n"
        )
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise SubAgentError(f"{self.module} stopped without responding: {stderr[-500:]}")
        response = json.loads(line)
        if "error" in response:
            raise SubAgentError(response["error"].get("message", "Unknown child MCP error"))
        return response["result"]

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.request("tools/call", {"name": tool_name, "arguments": arguments})
        structured = response.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        content = response.get("content", [{}])
        text = content[0].get("text", "{}") if content else "{}"
        return json.loads(text)
