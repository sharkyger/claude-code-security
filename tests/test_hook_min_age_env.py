"""Tests for the SAFE_INSTALL_MIN_AGE env-var pass-through in the hook.

The hook (`hooks/dependency-security-gate.sh`) intercepts package-install
commands and calls `dependency_security_check.py`. Users running through
the Claude Code hook can't add `--min-age` flags themselves, so the hook
reads SAFE_INSTALL_MIN_AGE from the environment and passes it through.

These tests stub the scanner with a shell script that records the args it
was called with, then assert the right flag (or none) appears.
"""

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path

HOOK_SOURCE = Path(__file__).resolve().parent.parent / "hooks" / "dependency-security-gate.sh"


def _setup_fake_layout(tmpdir: Path) -> Path:
    """Copy the real hook into a temp dir alongside a fake scanner stub.

    Returns the path to the hook copy. The fake scanner records its argv
    to argv.txt and exits 0 so the hook treats the call as clean.
    """
    hooks_dir = tmpdir / "hooks"
    hooks_dir.mkdir()
    hook_copy = hooks_dir / "dependency-security-gate.sh"
    shutil.copy(HOOK_SOURCE, hook_copy)
    hook_copy.chmod(0o755)

    # Fake scanner: record argv, emit a no-vuln result, exit 0.
    fake_scanner = tmpdir / "dependency_security_check.py"
    fake_scanner.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import sys, os
            with open(os.environ["ARGV_LOG"], "a") as f:
                f.write(" ".join(sys.argv[1:]) + "\\n")
            print('{"vulnerabilities": []}')
            sys.exit(0)
            """
        )
    )
    fake_scanner.chmod(0o755)
    return hook_copy


def _run_hook(hook_path: Path, argv_log: Path, env_overrides: dict, command: str) -> subprocess.CompletedProcess:
    payload = json.dumps({"tool_input": {"command": command}})
    env = {**os.environ, "ARGV_LOG": str(argv_log), **env_overrides}
    return subprocess.run(
        ["bash", str(hook_path)],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def test_env_var_unset_omits_min_age_flag():
    """When SAFE_INSTALL_MIN_AGE is unset, hook must NOT pass --min-age.

    The scanner has its own default (3 days). Passing nothing lets the
    scanner own the default, so future changes there don't drift from
    the hook.
    """
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        hook = _setup_fake_layout(td_path)
        argv_log = td_path / "argv.txt"
        argv_log.touch()

        env = {k: v for k, v in os.environ.items() if k != "SAFE_INSTALL_MIN_AGE"}
        result = subprocess.run(
            ["bash", str(hook)],
            input=json.dumps({"tool_input": {"command": "pip install requests"}}),
            capture_output=True,
            text=True,
            env={**env, "ARGV_LOG": str(argv_log)},
            timeout=10,
        )

        assert result.returncode == 0, f"hook should allow clean install, got stderr: {result.stderr}"
        recorded = argv_log.read_text()
        assert "--min-age" not in recorded, f"unset env should not pass --min-age, but got: {recorded!r}"


def test_env_var_zero_passes_min_age_zero():
    """SAFE_INSTALL_MIN_AGE=0 must pass --min-age 0 (disables freshness hold)."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        hook = _setup_fake_layout(td_path)
        argv_log = td_path / "argv.txt"
        argv_log.touch()

        result = _run_hook(hook, argv_log, {"SAFE_INSTALL_MIN_AGE": "0"}, "pip install requests")
        assert result.returncode == 0
        recorded = argv_log.read_text()
        assert "--min-age 0" in recorded, f"expected '--min-age 0' in args, got: {recorded!r}"


def test_env_var_seven_passes_min_age_seven():
    """SAFE_INSTALL_MIN_AGE=7 must pass --min-age 7 (stricter hold)."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        hook = _setup_fake_layout(td_path)
        argv_log = td_path / "argv.txt"
        argv_log.touch()

        result = _run_hook(hook, argv_log, {"SAFE_INSTALL_MIN_AGE": "7"}, "pip install requests")
        assert result.returncode == 0
        recorded = argv_log.read_text()
        assert "--min-age 7" in recorded, f"expected '--min-age 7' in args, got: {recorded!r}"


def test_env_var_empty_string_behaves_like_unset():
    """Empty SAFE_INSTALL_MIN_AGE must NOT pass --min-age "" to the scanner.

    Regression guard: an earlier draft used ${VAR+x} which is set even for
    empty values, causing every install to fail-closed with a confusing
    argparse error. The fix uses ${VAR:-} which treats empty as unset, so
    the scanner's own default applies.
    """
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        hook = _setup_fake_layout(td_path)
        argv_log = td_path / "argv.txt"
        argv_log.touch()

        result = _run_hook(hook, argv_log, {"SAFE_INSTALL_MIN_AGE": ""}, "pip install requests")
        assert result.returncode == 0, f"empty env var should not block, got: {result.stderr}"
        recorded = argv_log.read_text()
        assert "--min-age" not in recorded, (
            f"empty env var must behave like unset (no --min-age passed), got: {recorded!r}"
        )


def test_env_var_works_with_pinned_version():
    """Pinned-version path (line 107 in the hook) must also receive the flag."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        hook = _setup_fake_layout(td_path)
        argv_log = td_path / "argv.txt"
        argv_log.touch()

        result = _run_hook(hook, argv_log, {"SAFE_INSTALL_MIN_AGE": "0"}, "pip install requests==2.31.0")
        assert result.returncode == 0
        recorded = argv_log.read_text()
        assert "2.31.0" in recorded, f"expected pinned version in args, got: {recorded!r}"
        assert "--min-age 0" in recorded, f"expected --min-age 0 with pinned version, got: {recorded!r}"
