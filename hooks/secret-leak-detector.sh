#!/usr/bin/env bash
# Claude Code Hook: Scan written/edited files for leaked secrets.
# Detects API keys, AWS credentials, private keys, JWTs, passwords,
# Slack/Discord/GitHub/Google tokens.
# Exit 0 always (PostToolUse — warns but does not block).
#
# Install: Add to ~/.claude/settings.json under hooks.PostToolUse (matcher: "Edit|Write")

set -euo pipefail

INPUT="$(cat)"
TOOL="$(echo "$INPUT" | jq -r '.tool_name // empty')"

# Get the file path from tool response or input
FILE_PATH="$(echo "$INPUT" | jq -r '.tool_response.filePath // .tool_input.file_path // empty')"

if [[ -z "$FILE_PATH" || ! -f "$FILE_PATH" ]]; then
  exit 0
fi

# Skip binary files and known safe extensions
if echo "$FILE_PATH" | grep -qE '\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip|tar|gz|lock)$'; then
  exit 0
fi

# Patterns that indicate leaked secrets
FINDINGS=""

# API keys (generic patterns)
if grep -qE '(api[_-]?key|apikey)\s*[:=]\s*["\x27]?[A-Za-z0-9_\-]{20,}' "$FILE_PATH" 2>/dev/null; then
  # Skip if it's a placeholder/example
  if ! grep -qE '(api[_-]?key|apikey)\s*[:=]\s*["\x27]?(your[_-]|example|placeholder|changeme|xxx|TODO|\$\{)' "$FILE_PATH" 2>/dev/null; then
    FINDINGS="${FINDINGS}Possible API key found. "
  fi
fi

# AWS access keys
if grep -qE 'AKIA[0-9A-Z]{16}' "$FILE_PATH" 2>/dev/null; then
  FINDINGS="${FINDINGS}AWS Access Key ID detected. "
fi

# AWS secret keys
if grep -qE '["\x27][A-Za-z0-9/+=]{40}["\x27]' "$FILE_PATH" 2>/dev/null; then
  if grep -qiE '(aws|secret|access)' "$FILE_PATH" 2>/dev/null; then
    FINDINGS="${FINDINGS}Possible AWS Secret Key detected. "
  fi
fi

# Private keys (PEM)
if grep -qE 'BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY' "$FILE_PATH" 2>/dev/null; then
  FINDINGS="${FINDINGS}Private key (PEM) embedded in file. "
fi

# JWT tokens
if grep -qE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.' "$FILE_PATH" 2>/dev/null; then
  FINDINGS="${FINDINGS}JWT token detected. "
fi

# Generic passwords in config
if grep -qiE '(password|passwd|pwd)\s*[:=]\s*["\x27][^"\x27]{8,}' "$FILE_PATH" 2>/dev/null; then
  if ! grep -qiE '(password|passwd|pwd)\s*[:=]\s*["\x27]?(your[_-]|example|placeholder|changeme|xxx|TODO|\$\{|process\.env|os\.environ|getenv)' "$FILE_PATH" 2>/dev/null; then
    FINDINGS="${FINDINGS}Hardcoded password detected. "
  fi
fi

# Slack/Discord tokens
if grep -qE 'xox[baprs]-[0-9a-zA-Z\-]{10,}' "$FILE_PATH" 2>/dev/null; then
  FINDINGS="${FINDINGS}Slack token detected. "
fi

# GitHub tokens
if grep -qE '(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}' "$FILE_PATH" 2>/dev/null; then
  FINDINGS="${FINDINGS}GitHub token detected. "
fi

# Google API keys
if grep -qE 'AIza[0-9A-Za-z\-_]{35}' "$FILE_PATH" 2>/dev/null; then
  FINDINGS="${FINDINGS}Google API key detected. "
fi

if [[ -n "$FINDINGS" ]]; then
  jq -n \
    --arg msg "SECRET LEAK WARNING in $FILE_PATH: ${FINDINGS}Remove secrets and use environment variables or .env instead." \
    '{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":$msg}}'
fi
