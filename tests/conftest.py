"""Suite-wide fixtures.

Zero live model calls anywhere in this suite - see docs/ARCHITECTURE.md's
P5 zero-spend decision. Enforced here rather than trusted by convention: the
only network primitive `sift.llm.provider.complete` uses is
`urllib.request.urlopen`, patched to raise by default for every test. A test
that genuinely needs a fake response (e.g. tests/test_llm_provider.py)
overrides it locally with its own `monkeypatch.setattr`, which wins for the
duration of that one test and is undone automatically afterward - this
fixture never has to know about those tests, and they never have to know
about this fixture.
"""

from __future__ import annotations

import urllib.request
from collections.abc import Iterator

import pytest


class LiveNetworkCallError(RuntimeError):
    """A test tried to reach the network. This suite spends nothing, ever."""


@pytest.fixture(autouse=True)
def _block_live_network_calls(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def _refuse(*_args: object, **_kwargs: object) -> None:
        raise LiveNetworkCallError(
            "urllib.request.urlopen called with no local override - "
            "this suite must never make a live network call"
        )

    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    yield
