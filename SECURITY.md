# Security Policy

## Supported Versions

Only the latest released version is supported.

## Reporting a Vulnerability

**Do not open a public issue for security reports.**

Use GitHub's private vulnerability reporting:
https://github.com/sharkyger/claude-code-security/security/advisories/new

You can expect an acknowledgement within 7 days.

## Scope

In scope:

- Bugs in `dependency_security_check.py` that cause known-vulnerable versions to be classified as clean.
- Bugs in any hook script (`hooks/*.sh`) that allow blocked content (secrets, dangerous commands, vulnerable installs) to slip through.
- Bugs that cause hooks to leak the very content they're meant to block (e.g. printing a detected secret to logs).
- Weaknesses in the install or update process.

Out of scope:

- Known false positives from upstream vulnerability databases or pattern detectors — open a regular issue with the false-positive template.
- Vulnerabilities in Claude Code itself (report to Anthropic).
- Vulnerabilities in the packages being scanned (this tool reports them, it does not fix them).
