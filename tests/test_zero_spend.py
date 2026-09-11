"""Zero live model calls anywhere in this suite, enforced by test - not
trusted by convention. See tests/conftest.py's autouse fixture, which every
other test in this suite runs under without knowing it.
"""

from __future__ import annotations

import pytest

from sift.eval.cost import ModelId
from sift.llm.provider import ChatMessage, ProviderConfig, complete
from tests.conftest import LiveNetworkCallError


def test_a_real_provider_call_with_no_local_override_is_blocked() -> None:
    """The one test in this suite that deliberately does NOT monkeypatch
    urlopen itself - proving the autouse fixture in conftest.py is what is
    actually stopping the call, not every test happening to patch it."""
    config = ProviderConfig(model=ModelId.HAIKU.value, api_key="test-key")
    with pytest.raises(LiveNetworkCallError):
        complete(config, [ChatMessage(role="user", content="hi")])
