# Product Requirements Document — claude-code-cve-gate

> Last updated: 2026-05-29 — SKELETON draft (pending Sharky's review of TODOs)
> Third-party tool. Not affiliated with Anthropic.

## Mission

Pre-install CVE gate for Claude Code. Intercepts every `pip install`, `npm install`, `composer install`, `cargo`, `go get`, `gem install`, and `brew install` that Claude Code suggests; queries 3 vulnerability databases (NIST NVD + OSV.dev + GitHub Advisory) for the target version (including the transitive tree); blocks the install if known unpatched vulnerabilities are found. The gate fires **before** any install script executes.

## Why it exists / problem

Claude Code can install packages on the user's behalf, but it does not check whether those packages have known security issues. Most of the time that's fine; sometimes it isn't — a routine `pip install` can pull in a zero-hour typosquat or a known-vulnerable transitive dep. Native vulnerability gating at the install moment closes that gap deterministically. Post-install tools (`pip-audit`, `safety`, `composer audit`) run *after* download and potential script execution — by then a zero-hour attack has won.

## Scope (in)

- **PreToolUse Bash hook** intercepting `pip|npm|composer|cargo|go|gem|brew install` commands (7 ecosystems).
- **Full transitive tree resolution** via the package manager's own dry-run mode for pip / npm / composer / gem; `--no-deps` to scope down.
- **Multi-source vulnerability query:**
  - [NIST NVD](https://nvd.nist.gov/) — US government CVE database (keyword + CPE-version filtered).
  - [OSV.dev](https://osv.dev/) — Google's batch-queried advisory aggregator.
  - [GitHub Security Advisories](https://github.com/advisories) — ecosystem-tagged advisories, version-range filtered.
- **3-day freshness hold** (pip + npm) — typosquat / zero-hour publish defense. Overridable via `SAFE_INSTALL_MIN_AGE` env var.
- **Fail-closed mode** via `STRICT_FAIL_CLOSED=1`; default = best-effort allow when at least one DB returns clean.
- **Zero runtime deps** (Python stdlib only); no API keys required.
- **Shared `SAFE_INSTALL_MIN_AGE`** with `mistral-code-cve-gate` so one config covers both AI tools.
- **Empty env var = unset** — `SAFE_INSTALL_MIN_AGE=` is treated as default (3 days), not as 0. Closes the half-finished-export footgun.
- **npm gating via PMG** ([safedep/pmg](https://github.com/safedep/pmg), Apache 2.0) — declared external dependency. `npm_pmg_gate.run_npm_via_pmg(...)` routes `npm <args>` through `pmg npm <args>`, adding pre-install malware detection + configurable cooldown on top of the bundled CVE scanner. Fails closed when `pmg` is not on `PATH`. Phase 2 (separate PR) adds a `PreToolUse` Bash hook that auto-routes the agent's `npm install` / `npm ci` / `npx` / `pnpm install` through this module — until that hook lands, the gate only fires when explicitly invoked.

## Known design limits

These are intentional trade-offs surfaced by the 2026-05-30 first-run code-review baseline (see `.codereview/agent-verification-2026-05-30.local.md`).

- **NVD fallback budget** — `TRANSITIVE_NVD_BUDGET = 3` (scanner line 61). Transitive packages OSV reported clean get a sanity-check against NVD, but only the first 3 — beyond that we'd hit NVD's anonymous rate limit (5 req / 30s) and stall the gate. OSV-batch is the primary source for transitives; NVD is a fallback, not the spine.
- **GHSA not queried per-transitive** — top-level packages get OSV + GHSA + NVD; transitives get OSV-batch + bounded NVD only. GHSA has no batch endpoint and stricter rate limits; per-transitive querying would explode latency.
- **`parse_version` is stdlib-only** — pre-release suffixes (`-alpha`, `-rc1`, `+build`) currently round to the release tuple. Fix is gated on a coordinated fleet PR (scanner is shared lineage with composer-cve-gate / pip-cve-gate / mistral-code-cve-gate).
- **Homebrew is NVD + GHSA only** — OSV.dev does not index Homebrew formulae (`ECOSYSTEM_MAP["osv"]["brew"] = None`).

## Non-goals (out)

- **No post-install audit / SBOM / SARIF.** Pre-install gating only; `composer audit` / `pip-audit` / `safety` handle post-install.
- **No auto-remediation / auto-bumping.** Block + report; the user (or the AI) decides.
- **No IDE / CI integration as a primary surface.** The Claude Code hook IS the integration. CI gating belongs in standalone CLI tools (`pip-cve-gate`, `composer-cve-gate`).
- **No telemetry.** No phone-home.
- **No CVE-aware freshness-hold auto-bypass.** That logic lives in `homebrew-safe-upgrade`'s `brew safe-upgrade`, not in the scanner this hook calls. Set `SAFE_INSTALL_MIN_AGE=0` for a one-shot if needed.
- **No Mistral / Codestral hook surface.** That's `mistral-code-cve-gate`'s job. Same scanner, different host hook.

## Quality bar

- **3-layer code review** on every PR ([[fleet-code-review-standard]]).
- **Signed releases.**
- **No public security issues** ([[feedback_security_repos_no_public_issues]]).
- **Python static-analysis floor:** Bandit + Mypy moderate strict (pattern from `composer-cve-gate` #24). <TODO: confirm landed here — currently not.>
- **Shared scanner sync:** `dependency_security_check.py` is fleet-shared lineage with the cve-gate trilogy — stay in sync with the canonical version in `composer-cve-gate`. Pending sync items are tracked internally.

## Retirement / self-archive criteria

Retired when **both**:
1. Claude Code ships native, default-on pre-install vulnerability gating across all 7 ecosystems with equivalent multi-source query + freshness hold; AND
2. That native gate operates **pre-script-execution** (not post-install audit).

If only one ships, this repo keeps the uncovered half. If a generalized "AI-tool install gate" emerges that targets both Claude and Mistral, evaluate consolidating with `mistral-code-cve-gate`.

## Architecture

PreToolUse Bash hook that pattern-matches install commands and invokes a Python scanner (`dependency_security_check.py`) for vulnerability/freshness checking. Exit code maps to gate decision: clean → pass; vulnerable → block. Python is stdlib-only.

## References

- **Sibling:** [`mistral-code-cve-gate`](https://github.com/sharkyger/mistral-code-cve-gate) — same gate, Mistral hook surface.
- **CLI counterparts:** [`composer-cve-gate`](https://github.com/sharkyger/composer-cve-gate), [`pip-cve-gate`](https://github.com/sharkyger/pip-cve-gate), [`homebrew-safe-upgrade`](https://github.com/sharkyger/homebrew-safe-upgrade).
- **Fleet context:** `project_safe_install_fleet_design` memory (round-1 brainstorm 2026-05-23); `docs/roadmaps/safe-install-fleet.md` in agency-system.
- **Rename history:** `project_security_repos_rename` memory (claude-code-security → claude-code-cve-gate, 2026-05-17).

## Status

Current state: **no tags yet** → tag as **v0.1.0** (pre-stable) on the next release per [[feedback_oss_versioning_rule]]. Promotion to v1.0.0 gated on the quality floor (static-analysis + scanner sync + `.coderabbit.yaml`).

## Change log for this document

| Date | Author | Change |
|---|---|---|
| 2026-05-29 | claude (skeleton) | Initial draft from README + memory + convention template. |
