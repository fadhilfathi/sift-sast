"""The model-agnostic LLM provider interface (CONTRIBUTING.md rule 5).

Every provider call in this project goes through this module. Callers name a
model slug and hand over messages; this module owns everything
gateway-specific: the base URL, auth headers, the provider-routing pin, and
parsing the response envelope. Nothing outside this file names the gateway,
so swapping gateways later means editing here, not across the codebase.

Routing pin: the gateway may serve one slug from several upstream providers
and silently move traffic between them. An unpinned switch would read as a
metric jump (D13 contamination watch) when it was only a routing change, so
every request carries an explicit upstream allowlist with fallbacks off.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field

from sift.eval.cost import PRICING, ModelId

#: Environment wiring. The key value is never printed, logged, or stamped
#: into any report — only sent as an Authorization header.
API_KEY_ENV = "SIFT_API_KEY"
BASE_URL_ENV = "SIFT_BASE_URL"

#: Default gateway endpoint. Lives here, inside the adapter, and nowhere else.
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

#: Upstream providers this project allows, in priority order. A single entry
#: keeps routing deterministic; fallbacks are off (see ProviderConfig).
DEFAULT_PROVIDER_ORDER: tuple[str, ...] = ("anthropic",)


class ProviderConfigError(RuntimeError):
    """The adapter is misconfigured — no network call was attempted."""


class ProviderError(RuntimeError):
    """The gateway answered with an error, or no usable answer at all."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        self.status = status
        super().__init__(message)


@dataclass(frozen=True)
class ProviderConfig:
    """Everything a call needs, with no gateway knowledge required of callers.

    `model` is an OpenRouter-style `vendor/model` slug; `provider_order` pins
    which upstream providers may serve it. The tier split lives in
    `sift.eval.cost.ModelId`, not here — this config cannot tell cheap from
    safety-critical, it just dials what it is told.
    """

    model: str
    temperature: float = 0.0
    provider_order: tuple[str, ...] = DEFAULT_PROVIDER_ORDER
    allow_fallbacks: bool = False
    base_url: str = field(default="")
    api_key: str = field(default="", repr=False)
    timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        base_url = self.base_url or os.environ.get(BASE_URL_ENV, DEFAULT_BASE_URL)
        api_key = self.api_key or os.environ.get(API_KEY_ENV, "")
        if not api_key:
            raise ProviderConfigError(
                f"no API key: set {API_KEY_ENV} (and optionally {BASE_URL_ENV})"
            )
        if not base_url.startswith("https://"):
            raise ProviderConfigError("base URL must be https — no file:// or custom schemes")
        # Frozen dataclass: route env/default resolution through object.__setattr__.
        object.__setattr__(self, "base_url", base_url.rstrip("/"))
        object.__setattr__(self, "api_key", api_key)

    @classmethod
    def for_role(cls, model: ModelId, *, temperature: float = 0.0) -> ProviderConfig:
        """Tier-aware constructor. Analysts pass HAIKU, the Adjudicator passes
        OPUS — the downgrade ban is enforced by which slug the caller picks,
        and this helper keeps the two tiers spelled the same way everywhere."""
        return cls(model=model.value, temperature=temperature)


class ChatMessage(BaseModel):
    """One OpenAI-compatible chat message. Content is the caller's prompt text."""

    model_config = ConfigDict(frozen=True)

    role: str
    content: str


class ProviderResponse(BaseModel):
    """A validated chat-completions answer. Every LLM output is a validated
    schema — the transport envelope is no exception."""

    model_config = ConfigDict(frozen=True)

    content: str
    model: str
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    cost_usd: float = Field(ge=0.0)


def _request_body(config: ProviderConfig, messages: list[ChatMessage]) -> dict[str, object]:
    return {
        "model": config.model,
        "messages": [m.model_dump() for m in messages],
        "temperature": config.temperature,
        # Pinned routing: serve only from these upstream providers, in order,
        # with no silent fallback. A routing change must be a config change
        # (stamped in EvalConfig.upstream_provider), never an invisible one.
        "provider": {
            "order": list(config.provider_order),
            "allow_fallbacks": config.allow_fallbacks,
        },
    }


def _parse_response_body(body: bytes, model: ModelId | None) -> ProviderResponse:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderError(f"gateway returned a non-JSON body ({len(body)} bytes)") from exc
    try:
        choice = payload["choices"][0]
        content = choice["message"]["content"]
        usage = payload.get("usage", {})
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError("gateway response has no choices[0].message.content") from exc
    if not isinstance(content, str):
        raise ProviderError("gateway response content is not text")
    prompt_tokens = int(usage.get("prompt_tokens", 0))
    completion_tokens = int(usage.get("completion_tokens", 0))
    cost_usd = 0.0
    if model is not None and model in PRICING:
        pricing = PRICING[model]
        cost_usd = (
            prompt_tokens * pricing.input_per_mtok + completion_tokens * pricing.output_per_mtok
        ) / 1_000_000
    return ProviderResponse(
        content=content,
        model=str(payload.get("model", "")),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost_usd=cost_usd,
    )


def complete(
    config: ProviderConfig, messages: list[ChatMessage], *, model: ModelId | None = None
) -> ProviderResponse:
    """One chat-completions call against the configured gateway.

    `model` is only the cost-table key for bookkeeping — the slug actually
    sent is always `config.model`, so a wrong key can misprice but never
    re-route a call.
    """
    body = json.dumps(_request_body(config, messages)).encode("utf-8")
    # S310: scheme is constrained to https:// in ProviderConfig.__post_init__,
    # so urlopen cannot be redirected at file:// or custom schemes here.
    request = urllib.request.Request(  # noqa: S310
        f"{config.base_url}/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:  # noqa: S310
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise ProviderError(
            f"gateway error: HTTP {exc.code} ({len(exc.read())} bytes of detail withheld)",
            status=exc.code,
        ) from exc
    except OSError as exc:
        raise ProviderError(f"gateway unreachable: {type(exc).__name__}") from exc
    return _parse_response_body(raw, model)
