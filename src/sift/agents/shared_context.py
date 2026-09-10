"""The prompt-cached shared context block (P5).

Byte-identical across Reachability, Exploitability, Adversary, and the
Adjudicator for one finding, sent as its own leading message so the gateway's
prompt cache can serve all four calls from one cache write instead of paying
full input-token cost four times over.
"""

from __future__ import annotations

from sift.agents.context_render import common_bundle_fields
from sift.models.context import ContextBundle


def render_shared_context_prompt(template: str, bundle: ContextBundle) -> str:
    """Fill every `{placeholder}` in the shared context template."""
    return template.format(**common_bundle_fields(bundle))
