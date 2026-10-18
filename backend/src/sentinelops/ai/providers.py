"""LLM provider interface (spec 8.2).

* ``none`` (default) - no model; SentinelOps uses the deterministic template.
* ``mock`` - deterministic canned answers for tests and CI (spec 8.6).
* ``ollama`` - local model via an Ollama-compatible ``/api/chat`` endpoint.
* ``openai`` - any OpenAI-compatible ``/chat/completions`` endpoint (cloud,
  opt-in only).
* ``anthropic`` - Claude via the official ``anthropic`` SDK (cloud, opt-in
  only), with server-side refusal fallbacks enabled.

Providers only turn a prompt into text. They have no tools, cannot trigger
actions and never see anything but the evidence package (spec 8.1).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import anthropic
import httpx

from sentinelops.ai.prompts import Prompt

DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"
DEFAULT_TIMEOUT = 120.0


class ProviderError(RuntimeError):
    pass


class LLMProvider(Protocol):
    name: str
    model: str
    cloud: bool

    def complete(self, prompt: Prompt) -> str: ...

    def parameters(self) -> dict[str, Any]: ...


@dataclass
class MockProvider:
    """Returns a fixed answer or the result of ``responder(prompt)``."""

    responder: Callable[[Prompt], str] | str
    name: str = "mock"
    model: str = "mock-1"
    cloud: bool = False
    calls: list[Prompt] = field(default_factory=list)

    def complete(self, prompt: Prompt) -> str:
        self.calls.append(prompt)
        return self.responder(prompt) if callable(self.responder) else self.responder

    def parameters(self) -> dict[str, Any]:
        return {}


@dataclass
class OllamaProvider:
    base_url: str
    model: str
    name: str = "ollama"
    cloud: bool = False
    timeout: float = DEFAULT_TIMEOUT
    transport: httpx.BaseTransport | None = None

    def parameters(self) -> dict[str, Any]:
        return {"temperature": 0, "format": "json"}

    def complete(self, prompt: Prompt) -> str:
        body = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": prompt.instructions},
                {"role": "user", "content": f"BEGIN DATA\n{prompt.data}\nEND DATA"},
            ],
        }
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            try:
                response = client.post(f"{self.base_url.rstrip('/')}/api/chat", json=body)
                response.raise_for_status()
                content = response.json()["message"]["content"]
            except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
                raise ProviderError(f"ollama request failed: {exc}") from exc
        if not isinstance(content, str):
            raise ProviderError("ollama returned no text")
        return content


@dataclass
class OpenAICompatibleProvider:
    base_url: str
    model: str
    api_key: str
    name: str = "openai"
    cloud: bool = True
    timeout: float = DEFAULT_TIMEOUT
    transport: httpx.BaseTransport | None = None

    def parameters(self) -> dict[str, Any]:
        return {"temperature": 0, "response_format": "json_object"}

    def complete(self, prompt: Prompt) -> str:
        body = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": prompt.instructions},
                {"role": "user", "content": f"BEGIN DATA\n{prompt.data}\nEND DATA"},
            ],
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            try:
                response = client.post(f"{self.base_url.rstrip('/')}/chat/completions", json=body, headers=headers)
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
            except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
                raise ProviderError(f"OpenAI-compatible request failed: {exc}") from exc
        if not isinstance(content, str):
            raise ProviderError("no text in response")
        return content


@dataclass
class AnthropicProvider:
    """Claude via the official SDK.

    Current Claude models do not accept sampling parameters (temperature);
    determinism of reports comes from storing the validated output (spec 8.5),
    not from the model. Refusal fallbacks are enabled server-side.
    """

    api_key: str | None
    model: str = DEFAULT_ANTHROPIC_MODEL
    name: str = "anthropic"
    cloud: bool = True
    timeout: float = DEFAULT_TIMEOUT
    max_tokens: int = 16000
    effort: str = "medium"
    client: Any = None

    def parameters(self) -> dict[str, Any]:
        return {"max_tokens": self.max_tokens, "effort": self.effort, "fallbacks": "default"}

    def _client(self) -> Any:
        if self.client is None:
            self.client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout)
        return self.client

    def complete(self, prompt: Prompt) -> str:
        try:
            response = self._client().beta.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=prompt.instructions,
                messages=[{"role": "user", "content": f"BEGIN DATA\n{prompt.data}\nEND DATA"}],
                output_config={"effort": self.effort},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.APIConnectionError as exc:
            raise ProviderError(f"Anthropic connection failed: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"Anthropic API error {exc.status_code}") from exc
        if response.stop_reason == "refusal":
            raise ProviderError("model declined the request (refusal)")
        text = "".join(block.text for block in response.content if getattr(block, "type", None) == "text")
        if not text:
            raise ProviderError("no text in response")
        return text


@dataclass(frozen=True)
class ProviderConfig:
    provider: str = "none"
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    cloud_opt_in: bool = False


def build_provider(cfg: ProviderConfig) -> LLMProvider | None:
    """Create the configured provider; cloud providers require an explicit opt-in."""
    kind = cfg.provider.lower()
    if kind == "none":
        return None
    if kind == "ollama":
        return OllamaProvider(cfg.base_url or "http://localhost:11434", cfg.model or "llama3.1")
    if kind in ("openai", "anthropic") and not cfg.cloud_opt_in:
        raise ProviderError(
            f"cloud provider {kind!r} requires SENTINELOPS_LLM_CLOUD_OPT_IN=true (data leaves the installation)"
        )
    if kind == "openai":
        if not cfg.base_url or not cfg.api_key or not cfg.model:
            raise ProviderError("openai provider needs base URL, model and API key")
        return OpenAICompatibleProvider(cfg.base_url, cfg.model, cfg.api_key)
    if kind == "anthropic":
        return AnthropicProvider(cfg.api_key, cfg.model or DEFAULT_ANTHROPIC_MODEL)
    raise ProviderError(f"unknown LLM provider {cfg.provider!r}")
