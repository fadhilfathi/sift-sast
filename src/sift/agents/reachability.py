"""The Reachability Analyst's prompt assembly (P5)."""

from __future__ import annotations

from sift.agents.context_render import common_bundle_fields
from sift.models.context import ContextBundle


def render_reachability_prompt(template: str, bundle: ContextBundle) -> str:
    """Fill every `{placeholder}` in the reachability template from the bundle."""
    return template.format(**common_bundle_fields(bundle))
