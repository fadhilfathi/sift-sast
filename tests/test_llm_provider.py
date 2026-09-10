"""The provider adapter. No network: urlopen is stubbed, so these tests prove
request shape, auth handling, and response validation without spending."""

from __future__ import annotations

import email.message
import io
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

import pytest

from sift.eval.cost import ModelId
from sift.llm.provider import (
    API_KEY_ENV,
    BASE_URL_ENV,
    ChatMessage,
    ProviderConfig,
    ProviderConfigError,
    ProviderError,
    complete,
)


def _fake_open(
    body: bytes, seen: list[urllib.request.Request]
) -> Callable[[urllib.request.Request], io.BytesIO]:
    class FakeResponse(io.BytesIO):
        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def _urlopen(request: urllib.request.Request, **kwargs: object) -> FakeResponse:
        seen.append(request)
        return FakeResponse(body)

    return _urlopen


def _sent_json(request: urllib.request.Request) -> dict[str, object]:
    assert isinstance(request.data, bytes)
    loaded: dict[str, object] = json.loads(request.data.decode())
    return loaded


def _ok_body(**overrides: object) -> bytes:
    payload = {
        "model": "anthropic/claude-haiku-4-5",
        "choices": [{"message": {"role": "assistant", "content": '{"verdict": "OK"}'}}],
        "usage": {"prompt_tokens": 1000, "completion_tokens": 50},
    }
    return json.dumps(payload | overrides).encode()


def _config(**overrides: object) -> ProviderConfig:
    base: dict[str, object] = {"model": ModelId.HAIKU.value, "api_key": "test-key"}
    return ProviderConfig(**(base | overrides))  # type: ignore[arg-type]


def test_request_pins_model_provider_order_and_temperature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[urllib.request.Request] = []
    opener = _fake_open(_ok_body(), seen)
    monkeypatch.setattr(urllib.request, "urlopen", opener)
    config = _config(temperature=0.0)
    complete(config, [ChatMessage(role="user", content="hi")], model=ModelId.HAIKU)

    assert len(seen) == 1
    sent = _sent_json(seen[0])
    assert sent["model"] == "anthropic/claude-haiku-4-5"
    assert sent["temperature"] == 0.0
    # Pinned routing, no silent fallback — the D13 requirement.
    assert sent["provider"] == {"order": ["anthropic"], "allow_fallbacks": False}


def test_plain_message_content_is_a_string(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_open(_ok_body(), seen))
    complete(_config(), [ChatMessage(role="user", content="hi")])
    sent = _sent_json(seen[0])
    messages = sent["messages"]
    assert isinstance(messages, list)
    assert messages[0] == {"role": "user", "content": "hi"}


def test_cacheable_message_becomes_a_cache_control_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """P5's shared context prefix - see sift.agents.shared_context - is sent
    with `cacheable=True` so the gateway marks it as a cache breakpoint."""
    seen: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_open(_ok_body(), seen))
    complete(_config(), [ChatMessage(role="user", content="shared context", cacheable=True)])
    sent = _sent_json(seen[0])
    messages = sent["messages"]
    assert isinstance(messages, list)
    assert messages[0] == {
        "role": "user",
        "content": [
            {"type": "text", "text": "shared context", "cache_control": {"type": "ephemeral"}}
        ],
    }


def test_only_the_cacheable_message_gets_a_content_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mixed request - shared prefix cached, role-specific instructions not
    - must not accidentally cache the varying part too."""
    seen: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", _fake_open(_ok_body(), seen))
    complete(
        _config(),
        [
            ChatMessage(role="user", content="shared", cacheable=True),
            ChatMessage(role="user", content="instructions"),
        ],
    )
    messages = _sent_json(seen[0])["messages"]
    assert isinstance(messages, list)
    assert isinstance(messages[0]["content"], list)
    assert messages[1] == {"role": "user", "content": "instructions"}


def test_auth_header_carries_the_key_and_body_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[urllib.request.Request] = []
    opener = _fake_open(_ok_body(), seen)
    monkeypatch.setattr(urllib.request, "urlopen", opener)
    complete(_config(), [ChatMessage(role="user", content="hi")])

    request = seen[0]
    assert request.get_header("Authorization") == "Bearer test-key"
    assert "test-key" not in json.dumps(_sent_json(request))


def test_usage_and_cost_come_back_on_the_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", _fake_open(_ok_body(), []))
    response = complete(_config(), [ChatMessage(role="user", content="hi")], model=ModelId.HAIKU)
    assert response.content == '{"verdict": "OK"}'
    assert response.prompt_tokens == 1000
    assert response.completion_tokens == 50
    # 1000 * $1.00 + 50 * $5.00 per M.
    assert response.cost_usd == pytest.approx(0.00125)


def test_unknown_model_costs_zero_but_still_parses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong cost-table key must misprice, never re-route: the slug sent is
    always config.model, and the call still succeeds."""
    seen: list[urllib.request.Request] = []
    opener = _fake_open(_ok_body(), seen)
    monkeypatch.setattr(urllib.request, "urlopen", opener)
    response = complete(
        _config(model="vendor/something-else"), [ChatMessage(role="user", content="hi")]
    )
    assert _sent_json(seen[0])["model"] == "vendor/something-else"
    assert response.cost_usd == 0.0


def test_http_error_maps_to_provider_error_with_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _failing(request: urllib.request.Request, **kwargs: object) -> object:
        raise urllib.error.HTTPError(
            str(request.full_url),
            429,
            "rate limited",
            email.message.Message(),
            io.BytesIO(b"slow down"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _failing)
    with pytest.raises(ProviderError) as exc_info:
        complete(_config(), [ChatMessage(role="user", content="hi")])
    assert exc_info.value.status == 429


def test_non_json_body_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", _fake_open(b"<html>not json", []))
    with pytest.raises(ProviderError, match="non-JSON"):
        complete(_config(), [ChatMessage(role="user", content="hi")])


def test_empty_choices_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", _fake_open(_ok_body(choices=[]), []))
    with pytest.raises(ProviderError, match="no choices"):
        complete(_config(), [ChatMessage(role="user", content="hi")])


def test_missing_key_is_a_config_error_before_any_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    with pytest.raises(ProviderConfigError, match=API_KEY_ENV):
        ProviderConfig(model=ModelId.HAIKU.value)


def test_non_https_base_url_is_rejected() -> None:
    with pytest.raises(ProviderConfigError, match="https"):
        ProviderConfig(model=ModelId.HAIKU.value, api_key="x", base_url="http://insecure.example")


def test_env_wiring_for_base_url_and_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV, "env-key")
    monkeypatch.setenv(BASE_URL_ENV, "https://gateway.example/v1")
    config = ProviderConfig(model=ModelId.OPUS.value)
    assert config.base_url == "https://gateway.example/v1"


def test_for_role_keeps_the_tier_split(monkeypatch: pytest.MonkeyPatch) -> None:
    """Analysts get the cheap slug, the Adjudicator the strongest — the tier
    split is spelled once, here, not per call site."""
    monkeypatch.setenv(API_KEY_ENV, "env-key")
    assert ProviderConfig.for_role(ModelId.HAIKU).model == ModelId.HAIKU.value
    adjudicator = ProviderConfig.for_role(ModelId.OPUS)
    assert adjudicator.model == ModelId.OPUS.value
    assert adjudicator.model != ModelId.HAIKU.value


def test_gateway_name_appears_only_inside_the_adapter() -> None:
    """Model-agnosticism enforced repo-wide: only the adapter itself (and this
    test, which asserts the isolation) may name the gateway. A mention in
    docs/, evals/, or any other module would mean the swap leaked."""
    root = Path(__file__).resolve().parents[1]
    allowed = {
        Path("src/sift/llm/provider.py"),
        Path("tests/test_llm_provider.py"),
    }
    excluded_dirs = {
        ".git",
        ".venv",
        "venv",
        ".ruff_cache",
        ".mypy_cache",
        ".pytest_cache",
        ".hypothesis",
        "__pycache__",
        "dist",
        "htmlcov",
    }
    offenders = []
    for path in root.rglob("*.py"):
        if any(part in excluded_dirs for part in path.relative_to(root).parts):
            continue
        rel = path.relative_to(root)
        if rel in allowed:
            continue
        if "openrouter" in path.read_text(encoding="utf-8").lower():
            offenders.append(str(rel))
    assert offenders == []


def test_config_stamps_models_provider_temperature_and_hashes() -> None:
    from sift.eval.config import EvalConfig
    from sift.llm.provider import DEFAULT_PROVIDER_ORDER

    config = EvalConfig(
        temperature=0.0,
        dataset_path="evals/dataset/dataset.jsonl",
        budget_usd=5.00,
        prompt_hashes={"baseline.txt": "abc"},
    )
    assert config.adjudicator_model is ModelId.OPUS
    assert config.analyst_model is ModelId.HAIKU
    assert config.upstream_provider == "anthropic"
    # Tied source of truth: the stamp must equal the adapter's actual pin, so
    # editing the provider order without updating the stamp fails loudly here
    # instead of lying in every report (D13).
    assert config.upstream_provider == DEFAULT_PROVIDER_ORDER[0]
    assert config.temperature == 0.0
    assert config.prompt_hashes == {"baseline.txt": "abc"}
