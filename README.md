# Claude Code Security

**Supply chain security for Anthropic Claude Code.** Every pip install, npm install, and brew install your AI coding assistant runs gets checked against 3 vulnerability databases before execution.

> Your AI assistant installs packages on your machine. Nobody is checking what is in them. Until now.

## What This Does

When Claude Code tries to install a package, this system:

1. **Intercepts** the install command (pip, npm, composer, cargo, go, gem, brew)
2. **Queries 3 databases** for known vulnerabilities:
   - [NIST NVD](https://nvd.nist.gov/) - US government vulnerability database
   - [OSV.dev](https://osv.dev/) - Google open source vulnerability database
   - [GitHub Advisory Database](https://github.com/advisories) - GitHub security advisories
3. **Blocks** the install if vulnerabilities are found
4. **Allows** it through if clean

No API keys required. All three databases are free and public. Zero dependencies (Python stdlib only).

## How This Compares

Every other security tool for AI coding assistants scans what is already installed. This one blocks the bad package before it ever reaches your machine.

| Tool | What it does | Gap |
|------|-------------|-----|
| mcp-scan (Stytch) | Audits installed MCP server configs | Post-install audit only |
| AgentSeal | Scans MCP configs for prompt injection | Config audit, not install blocking |
| AgentAuditKit | 77-rule scanner with SARIF output | CI/CD integration, not real-time |
| Endor Labs | Dependency vetting for AI code | Enterprise SaaS, not open source |

**Our approach:** Real-time interception at the moment the AI agent suggests `pip install` / `npm install`. Three databases checked, decision made, install blocked or allowed — before anything touches your system.

## Quick Start

### Clone and install

```bash
git clone https://github.com/sharkyger/claude-code-security.git
cd claude-code-security
bash install.sh
```

Or manually:

```bash
cp dependency_security_check.py ~/.claude/
mkdir -p ~/.claude/hooks ~/.claude/agents
cp hooks/*.sh ~/.claude/hooks/
cp agents/*.md ~/.claude/agents/
```

Then merge the hooks from `settings-template.json` into your `~/.claude/settings.json`.

## What is Included

| File | What it does |
|------|-------------|
| `dependency_security_check.py` | 3-database vulnerability scanner (standalone, zero deps) |
| `hooks/dependency-security-gate.sh` | Blocks installs until CVE-clean |
| `hooks/block-dangerous-bash.sh` | Blocks rm -rf, eval injection, env dumping |
| `hooks/block-dangerous-git.sh` | Blocks force push, hook skipping, destructive operations |
| `hooks/secret-leak-detector.sh` | Detects API keys, AWS creds, JWTs, passwords in written files |
| `hooks/protect-sensitive-files.sh` | Blocks reading .env, credentials/, SSH keys |
| `hooks/gitleaks-pre-write.sh` | Scans content with gitleaks before Write — blocks secrets before they reach disk |
| `hooks/pii-redaction-gate.sh` | Blocks PII (emails, credit cards, IBAN) in prompts before the model sees them |
| `agents/security-red-team.md` | Offensive security agent — OWASP, supply chain, prompt injection testing |
| `agents/security-blue-team.md` | Defensive security agent — validates hooks, posture, compliance |
| `settings-template.json` | Ready-to-use Claude Code settings with all hooks wired up |
| `install.sh` | One-command installer |

## Test It

```bash
# Should return clean
python3 ~/.claude/dependency_security_check.py npm express 4.21.0

# Should return vulnerable (old version with known CVEs)
python3 ~/.claude/dependency_security_check.py npm express 4.17.1

# Works with any ecosystem
python3 ~/.claude/dependency_security_check.py pip requests 2.31.0
python3 ~/.claude/dependency_security_check.py brew openssl 3.2.0
```

## How the Scanner Works

The scanner queries all 3 databases and cross-references results:

- **OSV.dev** - native version filtering (most accurate for pip/npm)
- **GitHub Advisory** - checks vulnerable_version_range and first_patched_version
- **NIST NVD** - keyword search with CPE version matching, word-boundary filtering to avoid false positives

Version-aware: if you pass a version, only CVEs affecting that specific version are reported.

Output: JSON on stdout (machine parsing), human-readable on stderr.

## Why This Matters

AI coding assistants install packages on your behalf every day. Each install is a supply chain decision:

- **LiteLLM v1.82.8** was compromised with a credential stealer (March 2026)
- **axios npm** was hijacked in a DPRK-linked attack (March 2026)
- **Slopsquatting** — 20% of LLM-recommended packages don't exist, creating hijack opportunities ([USENIX 2025](https://arxiv.org/abs/2504.08538))
- **OWASP LLM03:2025** — Supply Chain is now a formal vulnerability category

Your AI assistant does not check for any of this. This project does.

## Red Team / Blue Team Agents

This repo includes two security agent definitions you can use with Claude Code's Agent tool:

**Red Team** (`agents/security-red-team.md`) — Offensive. Probes your code for:
- OWASP Top 10 vulnerabilities
- Supply chain risks (unpinned deps, typosquatting)
- Secrets in code and git history (via gitleaks)
- Prompt injection in Claude configs
- Insecure file permissions

**Blue Team** (`agents/security-blue-team.md`) — Defensive. Validates that:
- All security hooks are installed and wired
- Gitignore covers sensitive files
- Credential files have proper permissions (600)
- Dependencies are free of known CVEs
- Claude Code settings aren't overly permissive

Copy them to `.claude/agents/` and invoke via the Agent tool for on-demand security assessments.

## Prerequisites

- **gitleaks** (required for `gitleaks-pre-write.sh`): `brew install gitleaks`
- **jq** (required for all hooks): usually pre-installed on macOS

## Related

- [homebrew-safe-upgrade](https://github.com/sharkyger/homebrew-safe-upgrade) - Same scanner integrated into Homebrew upgrades
- [mistral-code-security](https://github.com/sharkyger/mistral-code-security) - Same protection for Mistral AI coding tools

## License

MIT
