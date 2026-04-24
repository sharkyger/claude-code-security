#!/bin/bash
# Claude Code Hook: Block reading/editing sensitive files.
# Protects .env, credentials/, .mcp.json, SSH keys, macOS Keychain.
# Exit 2 = block, exit 0 = allow
#
# Install: Add to ~/.claude/settings.json under hooks.PreToolUse (matcher: "Read|Edit|Write")

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

BASENAME=$(basename "$FILE_PATH")

# Block .env files
if [ "$BASENAME" = ".env" ] || [[ "$BASENAME" == .env.* ]]; then
  echo "BLOCKED: Cannot read/edit .env files — secrets must stay out of Claude's context." >&2
  exit 2
fi

# Block credentials directories
if [[ "$FILE_PATH" == *"/credentials/"* ]] || [[ "$FILE_PATH" == *"/credentials" ]]; then
  echo "BLOCKED: Cannot access credentials/ directory — contains secrets." >&2
  exit 2
fi

# Block .mcp.json (contains API tokens)
if [ "$BASENAME" = ".mcp.json" ]; then
  echo "BLOCKED: Cannot read/edit .mcp.json — contains API tokens." >&2
  exit 2
fi

# Block SSH keys
if [[ "$FILE_PATH" == *"/.ssh/"* ]]; then
  echo "BLOCKED: Cannot access .ssh/ directory — contains private keys." >&2
  exit 2
fi

# Block macOS Keychain files
if [[ "$FILE_PATH" == *"/Keychains/"* ]] || [[ "$BASENAME" == *.keychain-db ]]; then
  echo "BLOCKED: Cannot access Keychain files." >&2
  exit 2
fi

exit 0
