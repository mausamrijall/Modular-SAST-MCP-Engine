"""Main Orchestrator MCP Server.

Exposes the complete audit pipeline as a single MCP tool so any MCP host
(Claude Code, Cursor, generic clients) can run a full audit with one
``tools/call``.  All options of ``orchestrator.map_agent`` are available as
tool arguments, including the standalone LLM self-working settings: pass your
own provider, endpoint, API key, and model to get an AI-written executive
summary in addition to the structured report.

The audit itself runs the same parallel domain/research/verification agents and
the same Docker sandbox as the CLI.  This server only orchestrates; it performs
no analysis on the host.
"""

from __future__ import annotations

import json

from mcp_servers.common import serve_mcp
from orchestrator.map_agent import build_audit_report


def _run_audit_schema() -> str:
    return json.dumps(
        {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Repository directory or a diff/source file to audit",
                },
                "diff_path": {
                    "type": "string",
                    "description": "Optional diff file associated with the target",
                },
                "with_taint": {"type": "boolean", "description": "Enable the cross-file taint analyzer"},
                "with_poc": {"type": "boolean", "description": "Generate safe proof-of-concept blueprints"},
                "with_behavior": {"type": "boolean", "description": "Run the Behavior & Expected-Usage Evaluator to reduce noise"},
                "with_verify": {
                    "type": "boolean",
                    "description": "Run proofs in the isolated harness; only verified findings count as valued",
                },
                "verification_policy": {
                    "type": "string",
                    "enum": ["strict", "lenient"],
                    "description": "strict: verified/static-confirmed only; lenient: also counts static-only",
                },
                "research_urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Public URLs for main-agent methodology research",
                },
                "methodology_topic": {"type": "string", "description": "Topic label for web research"},
                "clarify": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Check IDs to ask clarifying methodology questions about",
                },
                "clarify_question": {"type": "string", "description": "Question text for clarify requests"},
                "with_llm_summary": {
                    "type": "boolean",
                    "description": "Generate an AI-written executive summary from the findings",
                },
                "llm_provider": {"type": "string", "description": "LLM provider display name"},
                "llm_endpoint": {"type": "string", "description": "OpenAI-compatible chat completions base URL"},
                "llm_api_key": {"type": "string", "description": "Your own LLM API key"},
                "llm_model": {"type": "string", "description": "LLM model identifier"},
            },
            "required": ["target_path"],
            "additionalProperties": False,
        }
    )


def run_audit(**arguments) -> dict:
    """Run a complete SAST audit through the orchestrator pipeline."""
    target_path = arguments.get("target_path")
    if not target_path:
        raise ValueError("target_path is required")

    research_enabled: set[str] | None = None
    if arguments.get("with_taint") or arguments.get("with_poc") or arguments.get("with_verify"):
        research_enabled = set()
        if arguments.get("with_taint"):
            research_enabled.add("taint")
        if arguments.get("with_poc") or arguments.get("with_verify"):
            research_enabled.add("safe_poc")

    verification_enabled: set[str] | None = None
    if arguments.get("with_verify") or arguments.get("with_behavior"):
        verification_enabled = set()
        if arguments.get("with_behavior"):
            verification_enabled.add("behavior")
        if arguments.get("with_verify"):
            verification_enabled.add("verify_poc")

    llm_overrides: dict[str, str] = {}
    if arguments.get("llm_provider"):
        llm_overrides["provider"] = arguments["llm_provider"]
    if arguments.get("llm_endpoint"):
        llm_overrides["base_url"] = arguments["llm_endpoint"]
    if arguments.get("llm_api_key"):
        llm_overrides["api_key"] = arguments["llm_api_key"]
    if arguments.get("llm_model"):
        llm_overrides["model"] = arguments["llm_model"]

    return build_audit_report(
        target_path,
        arguments.get("diff_path"),
        research_enabled,
        web_urls=arguments.get("research_urls") or None,
        methodology_topic=arguments.get("methodology_topic"),
        clarify_check_ids=arguments.get("clarify") or None,
        clarify_question=arguments.get("clarify_question", "Explain the detection methodology and expected evidence for this check."),
        verification_enabled=verification_enabled,
        verification_policy=arguments.get("verification_policy", "strict"),
        llm_overrides=llm_overrides or None,
        with_llm_summary=bool(arguments.get("with_llm_summary")),
    )


def main() -> None:
    serve_mcp(
        server_name="Main Orchestrator Audit Server",
        server_version="1.0.0",
        tools={
            "run_audit": (
                "Run a complete SAST audit (domain agents, optional research and verification layers, optional LLM summary) and return the JSON report.",
                _run_audit_schema(),
                run_audit,
            ),
        },
    )


if __name__ == "__main__":
    main()
