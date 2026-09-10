"""The Adversary's prompt assembly (P5).

The Adversary argues the finding IS a true positive and attacks every
mitigation and reachability gap it can find. It never outputs
`position: FALSE_POSITIVE` — see `prompts/adversary.txt`.
"""

from __future__ import annotations

from sift.agents.context_render import common_bundle_fields
from sift.models.context import ContextBundle


def render_adversary_prompt(template: str, bundle: ContextBundle) -> str:
    """Fill every `{placeholder}` in the adversary template from the bundle."""
    return template.format(**common_bundle_fields(bundle))
