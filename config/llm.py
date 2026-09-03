"""Optional OpenAI-compatible LLM connection configuration.

The engine never hardcodes credentials. Values are read at runtime from the
following user-facing environment variables:

- USER_LLM_PROVIDER  (default: "openai-compatible")
- USER_LLM_BASE_URL  (default: "https://api.openai.com/v1")
- USER_LLM_API_KEY   (required; no default)
- USER_LLM_MODEL     (default: "gpt-4o-mini")

Copy `.env.example` into `.env` and fill in the placeholders, then export the
values (or load them with your process supervisor). The module reads real
environment variables only; it never falls back to a hardcoded key.

The same settings can be supplied explicitly (for example as CLI flags or MCP
tool arguments) through :meth:`LLMConfig.from_settings`; explicitly provided
values take precedence over environment variables. This is what lets the
engine run standalone (self-working) when the user passes their own provider,
endpoint, API key, and model.
"""

from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LLMConfig:
    """Connection settings for an OpenAI-compatible chat completions API."""

    provider: str = "openai-compatible"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_settings(
        cls,
        api_key: str = "",
        provider: str = "",
        base_url: str = "",
        model: str = "",
        env: dict[str, str] | None = None,
    ) -> "LLMConfig":
        """Build a config from explicit settings with environment fallback.

        Explicitly provided values win; empty strings fall back to the
        ``USER_LLM_*`` environment variables.  Pass an explicit mapping in
        tests; otherwise ``os.environ`` is used.  Raises ``ValueError`` when
        no API key is configured anywhere.
        """
        source = env if env is not None else os.environ
        resolved = cls(
            provider=(provider or source.get("USER_LLM_PROVIDER", "openai-compatible")).strip(),
            base_url=(base_url or source.get("USER_LLM_BASE_URL", "https://api.openai.com/v1")).strip().rstrip("/"),
            api_key=(api_key or source.get("USER_LLM_API_KEY", "")).strip(),
            model=(model or source.get("USER_LLM_MODEL", "gpt-4o-mini")).strip(),
        )
        if not resolved.api_key:
            raise ValueError(
                "An LLM API key is required. Provide it via USER_LLM_API_KEY, "
                ".env, or an explicit --llm-api-key / MCP argument. No key is "
                "bundled with this project."
            )
        return resolved

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "LLMConfig":
        """Build a config from environment variables only."""
        return cls.from_settings(env=env)

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    @property
    def chat_url(self) -> str:
        """URL of the OpenAI-compatible chat completions endpoint."""
        return f"{self.base_url}/chat/completions"

    def headers(self) -> dict[str, str]:
        """HTTP headers carrying the bearer token."""
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def to_chat_payload(self, messages: list[dict[str, str]], temperature: float = 0.2) -> dict[str, object]:
        """Body for a chat completions request."""
        return {"model": self.model, "messages": messages, "temperature": temperature}

    def complete(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
        timeout: float = 60.0,
    ) -> str:
        """Send a chat completions request and return the assistant reply.

        Uses only the Python standard library.  Raises on transport or
        response errors so callers can decide whether to degrade gracefully.
        """
        payload = json.dumps(self.to_chat_payload(messages, temperature)).encode("utf-8")
        request = urllib.request.Request(
            self.chat_url,
            data=payload,
            headers=self.headers(),
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
        return str(result["choices"][0]["message"]["content"])

    def redacted(self) -> dict[str, str]:
        """Non-secret summary safe for logging and reports."""
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "api_key": "***" if self.api_key else "",
        }
