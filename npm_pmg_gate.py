"""npm install gating via PMG (Package Manager Guard, safedep/pmg).

Integration model A (declared external dependency + runtime PATH check,
fail-closed). PMG is not vendored. At runtime this module probes for
the `pmg` binary on PATH; if present, npm operations are forwarded as
`pmg npm <args>`; if absent, callers get a RuntimeError with the
install hint instead of a silent passthrough to bare `npm`.

PMG itself runs the pre-install CVE + malware + configurable cooldown
check. License: Apache 2.0. Free tier requires no API key. See README
section "External dependency: PMG for npm gating" for the rationale and
docs/PRD.md "Scope" for fit with the broader cve-gate.

Phase 2 (separate PR): a PreToolUse Bash hook that auto-routes the
Claude Code agent's npm commands through this module. Without that
hook, this module only fires when explicitly invoked.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Sequence

PMG_INSTALL_HINT = (
    "PMG (Package Manager Guard) is required for npm gating.\n"
    "Install with: npm i -g @safedep/pmg\n"
    "Docs: https://github.com/safedep/pmg"
)


def is_pmg_available() -> bool:
    """Return True iff `pmg` resolves on PATH."""
    return shutil.which("pmg") is not None


def run_npm_via_pmg(npm_args: Sequence[str]) -> int:
    """Forward `npm <args>` through `pmg npm <args>`.

    Raises RuntimeError with PMG_INSTALL_HINT if `pmg` is not on PATH —
    callers MUST NOT fall back to bare npm. Returns the pmg subprocess
    exit code on success.
    """
    if not is_pmg_available():
        raise RuntimeError(PMG_INSTALL_HINT)
    return subprocess.run(
        ["pmg", "npm", *npm_args], check=False
    ).returncode
