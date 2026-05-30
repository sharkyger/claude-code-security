"""Offline tests for npm_pmg_gate.py.

PATH lookup and subprocess invocation are monkey-patched; no real
`pmg` binary is required and no network calls are made.
"""

import shutil
import subprocess

import pytest

import npm_pmg_gate as gate


def test_is_pmg_available_returns_false_when_missing(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert gate.is_pmg_available() is False


def test_is_pmg_available_returns_true_when_present(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/pmg")
    assert gate.is_pmg_available() is True


def test_run_npm_via_pmg_raises_when_pmg_missing(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="PMG.*required"):
        gate.run_npm_via_pmg(["install", "express"])


def test_run_npm_via_pmg_invokes_pmg_subprocess(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/pmg")
    captured = {}

    class _CompletedProcess:
        returncode = 0

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _CompletedProcess()

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc = gate.run_npm_via_pmg(["install", "express"])
    assert rc == 0
    assert captured["args"] == ["pmg", "npm", "install", "express"]
    # check=False — we surface pmg's exit code rather than raising on non-zero.
    assert captured["kwargs"].get("check") is False
