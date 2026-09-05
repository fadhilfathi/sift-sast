"""Config stamping — CONTRIBUTING.md: "a metric without its configuration is
meaningless and must not reach the README."

Every eval report embeds an `EvalConfig`. A number with no `EvalConfig`
attached is not a number this project publishes.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from sift.eval.cost import ModelId


def hash_prompt_dir(prompt_dir: Path) -> dict[str, str]:
    """SHA-256 of every prompt file under `prompt_dir`, by filename.

    Returns an empty dict if the directory does not exist — true today, since
    P4 step 3 builds the harness before P4 step 5 writes the naive baseline's
    prompt. `EvalConfig.prompt_hashes` being empty is itself meaningful: it
    means no prompt existed yet when the report was generated, and a report
    claiming a real score with an empty hash set is a contradiction worth
    catching, not a warning to suppress.
    """
    if not prompt_dir.is_dir():
        return {}
    hashes = {}
    for path in sorted(prompt_dir.glob("*.txt")):
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def git_sha(path: Path) -> str | None:
    """The commit SHA `path` was last modified at, or None outside a repo /
    on an uncommitted file. Used to stamp which corpus version a run used."""
    try:
        # Fixed args, run against our own repo path — not attacker-influenced.
        result = subprocess.run(  # noqa: S603
            ["git", "log", "-1", "--format=%H", "--", str(path)],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            cwd=path.parent if path.is_file() else path,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    sha = result.stdout.strip()
    return sha or None


class EvalConfig(BaseModel):
    """Everything that must be recorded before a metric is reportable."""

    model_config = ConfigDict(frozen=True)

    analyst_model: ModelId = Field(
        default=ModelId.HAIKU,
        description="Reachability, Exploitability, Adversary. P5 only; unused by the P4 baseline.",
    )
    adjudicator_model: ModelId = Field(
        default=ModelId.OPUS,
        description="Never downgraded to save money — the safety-critical stage.",
    )
    baseline_model: ModelId = Field(
        default=ModelId.OPUS,
        description="What the P4 single-prompt baseline itself calls.",
    )
    temperature: float = Field(ge=0.0, le=1.0)
    upstream_provider: str = Field(
        default="anthropic",
        description="Pinned upstream serving every request (gateway routing pin). "
        "A metric move at an unchanged value is reasoning; at a changed value, suspect routing.",
    )
    prompt_hashes: dict[str, str] = Field(default_factory=dict)
    dataset_path: str
    corpus_sha: str | None = Field(
        default=None, description="git SHA the dataset file was last committed at."
    )
    budget_usd: float
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def is_reportable(self) -> bool:
        """A config with no prompt hash cannot back a real adjudication score.

        Not enforced as a hard raise here — a `--dry-run` estimate legitimately
        has no prompt yet, and callers that print a real accuracy number are
        the ones responsible for checking this before they do.
        """
        return bool(self.prompt_hashes)
