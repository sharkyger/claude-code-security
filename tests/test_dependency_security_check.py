"""Offline tests for dependency_security_check.py.

All HTTP and subprocess calls are mocked; pytest runs without network access.
A representative subset of the canonical agency-system test suite, focused on
the transitive-deps + min-age surface that v1.1 introduces.
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import dependency_security_check as dsc


def _fake_pip_report(top_pkg, top_ver, transitive):
    return json.dumps(
        {
            "version": "1",
            "install": [
                {"metadata": {"name": top_pkg, "version": top_ver}, "is_direct": True},
                *[{"metadata": {"name": n, "version": v}, "is_direct": False} for n, v in transitive],
            ],
        }
    )


def _mock_urlopen_with_response(payload):
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return cm


# ─── resolve_pip_deps ────────────────────────────────────────────────────────


def test_resolve_pip_deps_parses_top_level_first():
    fake = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=_fake_pip_report("requests", "2.31.0", [("urllib3", "2.0.0"), ("certifi", "2024.2.2")]),
        stderr="",
    )
    with patch.object(subprocess, "run", return_value=fake):
        deps = dsc.resolve_pip_deps("requests", "2.31.0")
    assert deps[0] == ("requests", "2.31.0"), "top-level must be first"
    assert ("urllib3", "2.0.0") in deps
    assert ("certifi", "2024.2.2") in deps
    assert len(deps) == 3


def test_resolve_pip_deps_raises_on_nonzero_exit():
    fake = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="ERROR: package not found")
    with (
        patch.object(subprocess, "run", return_value=fake),
        pytest.raises(RuntimeError, match="pip dry-run failed"),
    ):
        dsc.resolve_pip_deps("nonexistent-pkg-xyz")


# ─── query_osv_batch ─────────────────────────────────────────────────────────


def test_query_osv_batch_returns_only_vulnerable():
    packages = [("requests", "2.18.0"), ("certifi", "2024.2.2")]
    batch_response = {
        "results": [
            {"vulns": [{"id": "GHSA-fake-1"}]},
            {"vulns": []},
        ]
    }
    detail_response = {
        "vulns": [
            {
                "id": "GHSA-fake-1",
                "aliases": ["CVE-2018-99999"],
                "summary": "Fake CVE for testing",
                "database_specific": {"severity": "HIGH"},
            }
        ]
    }

    call_count = {"n": 0}

    def fake_urlopen(req, timeout=15):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_urlopen_with_response(batch_response)
        return _mock_urlopen_with_response(detail_response)

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        result = dsc.query_osv_batch(packages, "pip")

    assert ("requests", "2.18.0") in result
    assert ("certifi", "2024.2.2") not in result
    assert len(result[("requests", "2.18.0")]) == 1


def test_query_osv_batch_raises_on_network_error():
    import urllib.error

    with (
        patch.object(dsc, "_urlopen", side_effect=urllib.error.URLError("connection refused")),
        pytest.raises(RuntimeError, match="OSV batch query failed"),
    ):
        dsc.query_osv_batch([("foo", "1.0")], "pip")


# ─── _check_with_deps ────────────────────────────────────────────────────────


def test_check_with_deps_clean_path():
    fake_resolver = lambda name, version: [("foo", "1.0.0"), ("bar", "2.0.0")]  # noqa: E731

    with (
        patch.object(dsc, "resolve_pip_deps", side_effect=fake_resolver),
        patch.object(dsc, "query_osv", return_value=[]),
        patch.object(dsc, "query_github", return_value=[]),
        patch.object(dsc, "query_nvd", return_value=[]),
        patch.object(dsc, "query_osv_batch", return_value={}),
    ):
        status, output = dsc._check_with_deps("pip", "foo", "1.0.0")

    assert status == "clean"
    assert output["include_deps"] is True
    assert output["transitive_count"] == 1
    assert output["vulnerabilities"] == []


def test_check_with_deps_transitive_vulnerable():
    fake_resolver = lambda name, version: [("foo", "1.0.0"), ("bar", "2.0.0")]  # noqa: E731
    fake_transitive_findings = {
        ("bar", "2.0.0"): [
            {
                "source": "OSV.dev",
                "id": "CVE-2024-FAKE-2",
                "severity": "CRITICAL",
                "score": 9.8,
                "summary": "fake transitive vuln",
            }
        ]
    }

    with (
        patch.object(dsc, "resolve_pip_deps", side_effect=fake_resolver),
        patch.object(dsc, "query_osv", return_value=[]),
        patch.object(dsc, "query_github", return_value=[]),
        patch.object(dsc, "query_nvd", return_value=[]),
        patch.object(dsc, "query_osv_batch", return_value=fake_transitive_findings),
    ):
        status, output = dsc._check_with_deps("pip", "foo", "1.0.0")

    assert status == "vulnerable"
    assert any(v["package"] == "bar" and v["id"] == "CVE-2024-FAKE-2" for v in output["vulnerabilities"])


# ─── check_min_age ───────────────────────────────────────────────────────────


def test_check_min_age_fresh_package_blocks():
    with patch.object(dsc, "get_release_age_days", return_value=1):
        result = dsc.check_min_age("evil-typo", "0.0.1", "pip", min_age_days=3)
    assert result is not None
    assert result["package"] == "evil-typo"
    assert result["age_days"] == 1
    assert result["min_age_days"] == 3


def test_check_min_age_old_package_passes():
    with patch.object(dsc, "get_release_age_days", return_value=30):
        assert dsc.check_min_age("requests", "2.31.0", "pip", min_age_days=3) is None


def test_check_min_age_zero_disables():
    with patch.object(dsc, "get_release_age_days", return_value=0):
        assert dsc.check_min_age("foo", "1.0", "pip", min_age_days=0) is None


# ─── STRICT_FAIL_CLOSED end-to-end ───────────────────────────────────────────


def test_strict_fail_closed_blocks_when_set_and_errors_present(monkeypatch, tmp_path, capsys):
    """STRICT_FAIL_CLOSED=1 + DB errors → exit 2."""
    monkeypatch.setenv("STRICT_FAIL_CLOSED", "1")
    monkeypatch.setattr(
        "sys.argv",
        ["dsc", "pip", "requests", "2.31.0", "--no-deps", "--min-age", "0"],
    )

    err_finding = [
        {
            "source": "OSV.dev",
            "id": "ERROR",
            "severity": "UNKNOWN",
            "score": 0,
            "summary": "timeout",
        }
    ]
    with (
        patch.object(dsc, "query_osv", return_value=err_finding),
        patch.object(dsc, "query_github", return_value=[]),
        patch.object(dsc, "query_nvd", return_value=[]),
        pytest.raises(SystemExit) as exc_info,
    ):
        dsc.main()

    assert exc_info.value.code == 2, "STRICT_FAIL_CLOSED + errors must exit 2"
    captured = capsys.readouterr()
    assert "STRICT_FAIL_CLOSED" in captured.err


def test_strict_fail_closed_allows_when_unset_and_errors_present(monkeypatch):
    """Default: errors present but no vulns → exit 0 (best-effort allow)."""
    monkeypatch.delenv("STRICT_FAIL_CLOSED", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["dsc", "pip", "requests", "2.31.0", "--no-deps", "--min-age", "0"],
    )

    err_finding = [
        {
            "source": "OSV.dev",
            "id": "ERROR",
            "severity": "UNKNOWN",
            "score": 0,
            "summary": "timeout",
        }
    ]
    with (
        patch.object(dsc, "query_osv", return_value=err_finding),
        patch.object(dsc, "query_github", return_value=[]),
        patch.object(dsc, "query_nvd", return_value=[]),
        pytest.raises(SystemExit) as exc_info,
    ):
        dsc.main()

    assert exc_info.value.code == 0, "default posture: errors don't block a clean result"


def test_strict_fail_closed_allows_when_set_but_no_errors(monkeypatch):
    """STRICT_FAIL_CLOSED=1 + no errors + clean → still exit 0."""
    monkeypatch.setenv("STRICT_FAIL_CLOSED", "1")
    monkeypatch.setattr(
        "sys.argv",
        ["dsc", "pip", "requests", "2.31.0", "--no-deps", "--min-age", "0"],
    )

    with (
        patch.object(dsc, "query_osv", return_value=[]),
        patch.object(dsc, "query_github", return_value=[]),
        patch.object(dsc, "query_nvd", return_value=[]),
        pytest.raises(SystemExit) as exc_info,
    ):
        dsc.main()

    assert exc_info.value.code == 0, "no errors + clean → allow regardless of STRICT_FAIL_CLOSED"
