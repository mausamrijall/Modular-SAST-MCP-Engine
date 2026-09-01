"""Outbound research capability for the main orchestrator agent.

Only the orchestrator uses this module.  Sandbox workers keep ``--network=none``
so source analysis never touches the network.  The main agent may fetch public
documentation and, when the user configures an LLM key, ask for a synthesized
methodology draft.

All requests are bounded: explicit timeout, maximum response size, and an
http/https scheme allowlist.  No credentials are ever attached to these
requests, and redirects are followed only within the same scheme.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from config.llm import LLMConfig

HTTP_TIMEOUT = 15
MAX_BYTES = 256 * 1024
USER_AGENT = "sast-main-agent/1.0"


class WebResearchError(RuntimeError):
    """Raised when an outbound research request cannot complete safely."""


def fetch_url(url: str, timeout: int = HTTP_TIMEOUT, max_bytes: int = MAX_BYTES) -> dict[str, Any]:
    """Fetch a single public URL and return its text with metadata.

    The response is capped at ``max_bytes``; larger bodies are truncated and
    flagged.  Only ``http`` and ``https`` URLs are accepted.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise WebResearchError(f"Unsupported URL scheme: {scheme!r}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            content_type = response.headers.get("Content-Type", "")
            body = response.read(max_bytes + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        raise WebResearchError(f"Fetch failed for {url}: {exc}") from exc
    truncated = len(body) > max_bytes
    text = body[:max_bytes].decode("utf-8", errors="replace")
    return {
        "url": url,
        "status": status,
        "content_type": content_type,
        "truncated": truncated,
        "text": text,
    }


def _synthesize_llm(llm: LLMConfig, topic: str, evidence: list[dict[str, Any]]) -> str:
    """Ask the configured LLM to draft methodology from fetched evidence."""
    snippets = "\n\n".join(
        f"URL: {entry['url']}\n{entry['text'][:2000]}" for entry in evidence[:5]
    )
    messages = [
        {
            "role": "system",
            "content": (
                "You refine defensive static-analysis methodology. Propose concrete, "
                "reproducible check patterns with example code, remediation steps, and "
                "confidence guidance. Never recommend attacking systems or scanning "
                "without authorization."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Topic: {topic}\n\nReference material:\n{snippets}\n\n"
                "Draft a methodology section for this topic, including patterns to add "
                "to the SAST check map and any caveats."
            ),
        },
    ]
    return llm.complete(messages)


def research_web(
    topic: str,
    urls: list[str],
    llm: LLMConfig | None = None,
) -> dict[str, Any]:
    """Fetch reference URLs and optionally synthesize a methodology draft.

    Per-URL failures are collected in ``errors`` so one unreachable site does
    not fail the whole research step.  ``synthesis`` is only produced when an
    ``LLMConfig`` is provided.
    """
    evidence: list[dict[str, Any]] = []
    errors: list[str] = []
    for url in urls:
        try:
            evidence.append(fetch_url(url))
        except WebResearchError as exc:
            errors.append(str(exc))

    synthesis: str | None = None
    synthesis_error: str | None = None
    if llm is not None and evidence:
        try:
            synthesis = _synthesize_llm(llm, topic, evidence)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully on network/model errors
            synthesis_error = f"{type(exc).__name__}: {exc}"

    return {
        "topic": topic,
        "urls": list(urls),
        "evidence": evidence,
        "errors": errors,
        "synthesis": synthesis,
        "synthesis_error": synthesis_error,
    }
