"""Config stamping. CONTRIBUTING.md: "a metric without its configuration is
meaningless and must not reach the README" — this is the config."""

from __future__ import annotations

from pathlib import Path

from sift.eval.config import EvalConfig, git_sha, hash_prompt_dir
from sift.eval.cost import ModelId


def make_config(**overrides: object) -> EvalConfig:
    base: dict[str, object] = {
        "temperature": 0.0,
        "dataset_path": "evals/dataset/dataset.jsonl",
        "budget_usd": 5.00,
    }
    return EvalConfig.model_validate(base | overrides)


def test_adjudicator_defaults_to_opus_never_haiku() -> None:
    """The Adjudicator is never downgraded to save money, per CONTRIBUTING.md -
    the default itself must not be able to pick the cheap model."""
    assert make_config().adjudicator_model is ModelId.OPUS


def test_analyst_model_defaults_to_haiku() -> None:
    assert make_config().analyst_model is ModelId.HAIKU


def test_is_reportable_false_with_no_prompts() -> None:
    assert make_config().is_reportable() is False


def test_is_reportable_true_once_a_prompt_is_hashed() -> None:
    assert make_config(prompt_hashes={"baseline.txt": "abc123"}).is_reportable() is True


def test_config_is_frozen() -> None:
    import pytest
    from pydantic import ValidationError

    config = make_config()
    with pytest.raises(ValidationError):
        config.temperature = 0.5  # type: ignore[misc]


def test_hash_prompt_dir_empty_when_directory_missing(tmp_path: Path) -> None:
    assert hash_prompt_dir(tmp_path / "nope") == {}


def test_hash_prompt_dir_hashes_every_txt_file(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "b.txt").write_text("world", encoding="utf-8")
    (tmp_path / "ignored.md").write_text("not a prompt", encoding="utf-8")
    hashes = hash_prompt_dir(tmp_path)
    assert set(hashes) == {"a.txt", "b.txt"}


def test_hash_prompt_dir_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    assert hash_prompt_dir(tmp_path) == hash_prompt_dir(tmp_path)


def test_hash_prompt_dir_changes_when_content_changes(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    before = hash_prompt_dir(tmp_path)
    (tmp_path / "a.txt").write_text("goodbye", encoding="utf-8")
    after = hash_prompt_dir(tmp_path)
    assert before != after


def test_git_sha_none_outside_a_repo(tmp_path: Path) -> None:
    assert git_sha(tmp_path / "nonexistent.file") is None


def test_git_sha_returns_a_real_sha_for_a_tracked_file() -> None:
    """Exercised against this very repo, on a file guaranteed to be tracked
    and committed - README.md exists from P0 onward."""
    sha = git_sha(Path("README.md"))
    assert sha is not None
    assert len(sha) == 40
    assert all(c in "0123456789abcdef" for c in sha)
