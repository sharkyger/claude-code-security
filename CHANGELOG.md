# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-stable convention `v0.x.y` until v1.0.0.

## [Unreleased]

### Added

- npm install gating via PMG ([safedep/pmg](https://github.com/safedep/pmg), Apache 2.0).
  Documented as a declared external dependency; `npm_pmg_gate.run_npm_via_pmg(...)`
  routes `npm <args>` through `pmg npm <args>` with a runtime `PATH` check that
  fails closed when `pmg` is not installed. See README section "External dependency:
  PMG for npm gating" for install instructions. Phase 2 (separate): a Claude Code
  `PreToolUse` hook that auto-routes the agent's npm operations through this gate.
- Initial `docs/PRD.md` skeleton documenting mission, scope, non-goals, quality bar,
  retirement criteria, and architecture.

### Changed

- README: tightened the "3 databases" claim — Homebrew is NVD + GHSA only
  (OSV.dev doesn't index Homebrew formulae), and per-transitive GHSA is
  intentionally skipped to stay under rate limits.
- PRD: new "Known design limits" section covering the NVD fallback budget,
  the per-transitive GHSA scope, the stdlib-only `parse_version`
  pre-release behaviour, and Homebrew's OSV gap. Surfaced by the 2026-05-30
  first-run code-review baseline.
- `.gitignore`: ignore `*.local.md` so local-only working notes and security
  handoffs never reach git. Also ignore `.codereview/` (CodeRabbit + Vibe
  artifacts, agent-verification reports) per the fleet code-review
  folder convention.

### Fixed

- `hooks/dependency-security-gate.sh`: when a pip install spec is a range
  (`foo>=3.0,<4.0`), drop the version string before calling the scanner.
  The previous behaviour left the comma in the version, which the scanner
  parsed as `3.0.0` and silently lost the upper bound.
- `hooks/block-dangerous-bash.sh`: the secret-var pattern now matches both
  `$API_KEY` and `${API_KEY}` curly forms.
- `install.sh`: install `gitleaks-pre-write.sh` and `pii-redaction-gate.sh`
  alongside the other hooks. `settings-template.json` already referenced
  them; users following the install script ended up with two missing hooks.
