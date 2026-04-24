#!/usr/bin/env bash
# PreToolUse hook on Write — catches secrets BEFORE they reach the filesystem.
# Uses gitleaks to scan content about to be written. Blocks if secrets found.
# Defense-in-depth: secret-leak-detector.sh (PostToolUse) remains as backup.
#
# Note: gitleaks --pipe mode doesn't support filename context, so we write to a
# temp file and scan it with --no-git --source. This gives gitleaks the file
# extension context it needs for accurate rule matching.

set -euo pipefail

INPUT="$(cat)"

FILE_PATH="$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')"
CONTENT="$(echo "$INPUT" | jq -r '.tool_input.content // empty')"

# Nothing to scan
if [[ -z "$CONTENT" ]]; then
  exit 0
fi

# Skip binary/non-text files
if echo "$FILE_PATH" | grep -qE '\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip|tar|gz|lock|whl)$'; then
  exit 0
fi

# Check if gitleaks is installed
if ! command -v gitleaks &>/dev/null; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"WARNING: gitleaks not installed. Secret pre-scan skipped. Run: brew safe-install gitleaks"}}'
  exit 0
fi

# Write content to temp file (preserving original filename for gitleaks rule matching)
TMPDIR_SCAN="$(mktemp -d)"
BASENAME="$(basename "$FILE_PATH")"
TMPFILE="${TMPDIR_SCAN}/${BASENAME}"
echo "$CONTENT" > "$TMPFILE"

# Scan the temp file — capture exit code without triggering set -e
if gitleaks detect --no-git --source "$TMPDIR_SCAN" --no-banner >/dev/null 2>&1; then
  GITLEAKS_CLEAN=true
else
  GITLEAKS_CLEAN=false
fi

# Clean up
rm -rf "$TMPDIR_SCAN"

if [[ "$GITLEAKS_CLEAN" == "false" ]]; then
  echo "BLOCKED: gitleaks detected secrets in content about to be written to $FILE_PATH" >&2
  echo "Remove secrets and use environment variables instead." >&2
  exit 2
fi

exit 0
