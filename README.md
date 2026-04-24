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
mkdir -p ~/.claude/hooks
cp hooks/*.sh ~/.claude/hooks/
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

- **LiteLLM v1.82.8** was compromised with a credential stealer
- **xz-utils** had a backdoor that nearly made it into every Linux distro
- **event-stream** was hijacked to steal Bitcoin wallets

Your AI assistant does not check for any of this. This project does.

## Related

- [homebrew-safe-upgrade](https://github.com/sharkyger/homebrew-safe-upgrade) - Same scanner integrated into Homebrew upgrades
- [mistral-code-security](https://github.com/sharkyger/mistral-code-security) - Same protection for Mistral AI coding tools

## License

MIT
