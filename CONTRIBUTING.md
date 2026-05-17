# Contributing

Thanks for considering a contribution to claude-code-cve-gate. This is a solo-maintained tool, so a few notes up front to set expectations:

- I review PRs and issues when I have time, usually within a few days.
- Small, focused changes get merged faster than sprawling ones.
- If you're planning something bigger than a bug fix, open an issue first so we can align before you write code.

## Reporting issues

Three flavors:

- **Bug** — something doesn't work the way it should
- **Feature request** — something you'd like the tool to do
- **Hook blocked something legitimate** — a hook fired on input that shouldn't have been blocked (the most common kind for this tool — pick this if a security gate misfires)

Pick the right template at <https://github.com/sharkyger/claude-code-cve-gate/issues/new/choose>.

**Security issues**: do not open a public issue. See [SECURITY.md](SECURITY.md) for the private disclosure flow.

## Dev setup

```bash
git clone https://github.com/sharkyger/claude-code-cve-gate.git
cd claude-code-cve-gate
```

The hooks are bash. The vulnerability checker is Python (no requirements file; `certifi` is used when available for SSL on macOS, otherwise the system CA bundle).

Lint the hook scripts:

```bash
brew install shellcheck
# or `brew safe-install shellcheck` if you have homebrew-safe-upgrade
shellcheck hooks/*.sh install.sh
```

The `gitleaks-pre-write.sh` hook depends on gitleaks:

```bash
brew install gitleaks
# or `brew safe-install gitleaks` if you have homebrew-safe-upgrade
```

Run the standalone vulnerability checker against a known package to verify the Python side:

```bash
python3 dependency_security_check.py pip requests 2.31.0
```

End-to-end verification: install via `bash install.sh` into a test profile, then trigger a hook by running a command Claude Code would intercept (e.g. asking it to `pip install <package>`).

## Branching

- Branch from `main`
- Use prefixes: `feature/`, `fix/`, `docs/`, `chore/`
- One logical change per branch — don't mix unrelated work

## Pull requests

Good PRs:

- Solve one problem (or a tightly scoped set of related ones)
- Include the test command(s) you used to verify the change in the PR description
- Pass shellcheck on any modified hook scripts
- Have a description that says **what** changed and **why** — not just what

Less good PRs:

- Mix unrelated changes
- Add new dependencies — this tool intentionally uses Python stdlib only and bash + jq + (gitleaks for one hook)
- Skip manual verification "because it's a small change"

## Adding new hooks

If you want to add a new hook:

1. Place the script in `hooks/` with a clear name describing what it gates
2. Document the trigger event (PreToolUse, PostToolUse, etc.) in a comment at the top of the file
3. Add the hook registration to `settings-template.json`
4. Update the hooks table in the README
5. Verify shellcheck passes

## Maintainer

Maintained by [@sharkyger](https://github.com/sharkyger). Thanks for contributing.
