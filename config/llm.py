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
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class LLMConfig:
    """Connection settings for an OpenAI-compatible chat completions API."""

    provider: str = "openai-compatible"
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "LLMConfig":
        """Build a config from environment variables.

        Pass an explicit mapping in tests; otherwise ``os.environ`` is used.
        Raises ``ValueError`` when the API key is not configured.
        """
        source = env if env is not None else os.environ
        api_key = source.get("USER_LLM_API_KEY", "").strip()
        if not api_key:
            raise ValueError(
                "USER_LLM_API_KEY is not set. Provide your own key via "
                ".env or environment variables; no key is bundled with this project."
            )
        return cls(
            provider=source.get("USER_LLM_PROVIDER", "openai-compatible").strip(),
            base_url=source.get("USER_LLM_BASE_URL", "https://api.openai.com/v1").strip().rstrip("/"),
            api_key=api_key,
            model=source.get("USER_LLM_MODEL", "gpt-4o-mini").strip(),
        )

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

    def redacted(self) -> dict[str, str]:
        """Non-secret summary safe for logging and reports."""
        return {
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "api_key": "***" if self.api_key else "",
        }
