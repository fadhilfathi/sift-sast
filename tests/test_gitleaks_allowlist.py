"""Regression test for .gitleaks.toml.

The allowlist's correctness currently rests on having read it carefully, and
that erodes across commits. This proves it mechanically instead: runs the
real gitleaks binary — same version `security.yml` pins — against a
throwaway git repo. A secret in an allowlisted path must be suppressed; the
identical secret anywhere else must still fire. If a future edit widens the
allowlist by even one character too many, this fails.

Skipped, not failed, when the binary cannot be fetched (no network) so an
offline `pytest` run stays green; CI always has network and always runs it
for real.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"

#: Keep in sync with the pinned digest in .github/workflows/security.yml.
#: The workflow pins by sha256 digest, not this tag; this is best-effort
#: traceability, not an automatic check that the two agree.
GITLEAKS_VERSION = "8.24.3"

#: A secret shape the default ruleset actually recognizes (aws-access-token),
#: distinct from anything already committed elsewhere in the repo.
FAKE_SECRET = "AKIAABCDEFGHIJKLMNOP"


def _asset_name() -> str | None:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "x64" if machine in ("x86_64", "amd64") else None
    if arch is None:
        return None
    if system == "windows":
        return f"gitleaks_{GITLEAKS_VERSION}_windows_{arch}.zip"
    if system == "linux":
        return f"gitleaks_{GITLEAKS_VERSION}_linux_{arch}.tar.gz"
    return None


@pytest.fixture(scope="session")
def gitleaks_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The real gitleaks executable, downloaded once and cached for the session."""
    asset = _asset_name()
    if asset is None:
        pytest.skip(f"no gitleaks release asset for {platform.system()}/{platform.machine()}")

    cache_dir = tmp_path_factory.mktemp("gitleaks-bin")
    archive = cache_dir / asset
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/{asset}"

    try:
        import urllib.request

        urllib.request.urlretrieve(url, archive)
    except OSError:
        pytest.skip("could not download gitleaks (offline?)")

    if asset.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(cache_dir)
        binary = cache_dir / "gitleaks.exe"
    else:
        shutil.unpack_archive(archive, cache_dir)
        binary = cache_dir / "gitleaks"
        binary.chmod(0o755)

    if not binary.is_file():
        pytest.skip("gitleaks binary not found after extraction")
    return binary


def _run_gitleaks(binary: Path, repo: Path) -> list[dict[str, object]]:
    report = repo / "report.json"
    subprocess.run(
        [
            str(binary),
            "detect",
            "--source",
            str(repo),
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--exit-code",
            "0",  # never fail the subprocess; we assert on the report
            "--no-banner",
            "--redact",
        ],
        check=True,
        capture_output=True,
        cwd=repo,
    )
    if not report.is_file() or report.stat().st_size == 0:
        return []
    parsed = json.loads(report.read_text(encoding="utf-8"))
    if not isinstance(parsed, list):
        raise TypeError(f"expected a JSON array from gitleaks, got {type(parsed).__name__}")
    return parsed


def _make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copy(GITLEAKS_CONFIG, repo / ".gitleaks.toml")
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t.com", "commit", "-q", "-m", "init"],
        cwd=repo,
        check=True,
    )
    return repo


def test_allowlisted_file_suppresses_the_secret(gitleaks_binary: Path, tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, {"tests/test_redact.py": f'AWS_KEY = "{FAKE_SECRET}"\n'})
    leaks = _run_gitleaks(gitleaks_binary, repo)
    assert leaks == [], f"allowlisted path still flagged: {leaks}"


def test_the_second_allowlisted_path_also_suppresses_it(
    gitleaks_binary: Path, tmp_path: Path
) -> None:
    repo = _make_repo(
        tmp_path, {"tests/fixtures/python_project/src/app.py": f'AWS_KEY = "{FAKE_SECRET}"\n'}
    )
    leaks = _run_gitleaks(gitleaks_binary, repo)
    assert leaks == []


def test_the_identical_secret_elsewhere_still_fires(gitleaks_binary: Path, tmp_path: Path) -> None:
    """The regression this test exists to catch: an allowlist widened too far.

    Same secret, same content, one path outside the allowlist. If this ever
    stops firing, the allowlist has silently grown to cover it.
    """
    repo = _make_repo(tmp_path, {"src/oops.py": f'AWS_KEY = "{FAKE_SECRET}"\n'})
    leaks = _run_gitleaks(gitleaks_binary, repo)
    assert len(leaks) == 1
    assert leaks[0]["File"] == "src/oops.py"


def test_allowlist_is_scoped_not_a_free_pass_for_the_whole_directory(
    gitleaks_binary: Path, tmp_path: Path
) -> None:
    """A secret in a sibling file under the same allowlisted directory must
    still fire - the allowlist matches exact file paths, not tests/ wholesale."""
    repo = _make_repo(
        tmp_path,
        {
            "tests/test_redact.py": f'AWS_KEY = "{FAKE_SECRET}"\n',
            "tests/test_other_thing.py": f'AWS_KEY = "{FAKE_SECRET}"\n',
        },
    )
    leaks = _run_gitleaks(gitleaks_binary, repo)
    assert len(leaks) == 1
    assert leaks[0]["File"] == "tests/test_other_thing.py"


def test_both_secrets_present_at_once_only_the_unallowlisted_one_fires(
    gitleaks_binary: Path, tmp_path: Path
) -> None:
    repo = _make_repo(
        tmp_path,
        {
            "tests/test_redact.py": f'AWS_KEY = "{FAKE_SECRET}"\n',
            "src/oops.py": f'AWS_KEY = "{FAKE_SECRET}"\n',
        },
    )
    leaks = _run_gitleaks(gitleaks_binary, repo)
    assert [leak["File"] for leak in leaks] == ["src/oops.py"]
