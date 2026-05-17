#!/bin/bash
# Claude Code Hook: Block package installs until vulnerability check passes.
# Queries NIST NVD, OSV.dev, and GitHub Advisory DB.
# Exit 2 = block, exit 0 = allow
#
# Install: Add to ~/.claude/settings.json under hooks.PreToolUse (matcher: "Bash")

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Extract primary command (ignore heredocs, PR bodies, commit messages)
PRIMARY_CMD=$(echo "$COMMAND" | head -1 | sed -E "s/--body ['\"].*//; s/--message ['\"].*//; s/-m ['\"].*//; s/<<.*//; s/\\\$\(cat <<.*//")

# Strip shell redirects
PRIMARY_CMD=$(echo "$PRIMARY_CMD" | sed -E 's/[0-9]*>[>&]*[^ ]*//g')

ECOSYSTEM=""
PACKAGES=""

# pip install
if echo "$PRIMARY_CMD" | grep -qE '(pip3?|python3? -m pip) install '; then
  ECOSYSTEM="pip"
  PIP_SEGMENT=$(echo "$PRIMARY_CMD" | grep -oE '(pip3?|python3? -m pip) install [^;&|]+' | head -1)
  PACKAGES=$(echo "$PIP_SEGMENT" | sed -E 's/.*(pip3?|pip) install //' | \
    tr ' ' '\n' | grep -vE '^-|^$|\.txt$|\.cfg$|^\.' | \
    sed -E 's/[>=<!\[].*//' | grep -vE '^$|^[0-9]+$' | tr '\n' ' ')
  [ -z "$(echo "$PACKAGES" | tr -d ' ')" ] && ECOSYSTEM=""
fi

# npm install / yarn add / pnpm add
if echo "$PRIMARY_CMD" | grep -qE '(npm (install|i)|yarn add|pnpm (add|install)) '; then
  ECOSYSTEM="npm"
  NPM_SEGMENT=$(echo "$PRIMARY_CMD" | grep -oE '(npm (install|i)|yarn add|pnpm (add|install)) [^;&|]+' | head -1)
  PACKAGES=$(echo "$NPM_SEGMENT" | sed -E 's/.*(install|add|i) //' | \
    tr ' ' '\n' | grep -vE '^-|^$' | sed -E 's/@[^@]*$//' | grep -vE '^$' | tr '\n' ' ')
  [ -z "$(echo "$PACKAGES" | tr -d ' ')" ] && ECOSYSTEM=""
fi

# composer require
if echo "$PRIMARY_CMD" | grep -qE 'composer require '; then
  ECOSYSTEM="composer"
  COMP_SEGMENT=$(echo "$PRIMARY_CMD" | grep -oE 'composer require [^;&|]+' | head -1)
  PACKAGES=$(echo "$COMP_SEGMENT" | sed -E 's/.*require //' | \
    tr ' ' '\n' | grep -vE '^-|^$' | sed -E 's/:.*$//' | grep -vE '^$' | tr '\n' ' ')
fi

# cargo install / cargo add
if echo "$PRIMARY_CMD" | grep -qE 'cargo (install|add) '; then
  ECOSYSTEM="cargo"
  CARGO_SEGMENT=$(echo "$PRIMARY_CMD" | grep -oE 'cargo (install|add) [^;&|]+' | head -1)
  PACKAGES=$(echo "$CARGO_SEGMENT" | sed -E 's/.*cargo (install|add) //' | \
    tr ' ' '\n' | grep -vE '^-|^$' | tr '\n' ' ')
fi

# go install / go get
if echo "$PRIMARY_CMD" | grep -qE 'go (install|get) '; then
  ECOSYSTEM="go"
  GO_SEGMENT=$(echo "$PRIMARY_CMD" | grep -oE 'go (install|get) [^;&|]+' | head -1)
  PACKAGES=$(echo "$GO_SEGMENT" | sed -E 's/.*go (install|get) //' | \
    tr ' ' '\n' | grep -vE '^-|^$' | sed -E 's/@.*$//' | grep -vE '^$' | tr '\n' ' ')
fi

# gem install
if echo "$PRIMARY_CMD" | grep -qE 'gem install '; then
  ECOSYSTEM="gem"
  GEM_SEGMENT=$(echo "$PRIMARY_CMD" | grep -oE 'gem install [^;&|]+' | head -1)
  PACKAGES=$(echo "$GEM_SEGMENT" | sed -E 's/.*gem install //' | \
    tr ' ' '\n' | grep -vE '^-|^$' | tr '\n' ' ')
fi

# brew install
if echo "$PRIMARY_CMD" | grep -qE 'brew install '; then
  ECOSYSTEM="brew"
  BREW_SEGMENT=$(echo "$PRIMARY_CMD" | grep -oE 'brew install [^;&|]+' | head -1)
  PACKAGES=$(echo "$BREW_SEGMENT" | sed -E 's/.*brew install //' | \
    tr ' ' '\n' | grep -vE '^-|^$' | tr '\n' ' ')
fi

# No install command detected — allow through
if [ -z "$ECOSYSTEM" ] || [ -z "$(echo "$PACKAGES" | tr -d ' ')" ]; then
  exit 0
fi

# Find the scanner script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/../dependency_security_check.py"
if [ ! -f "$SCRIPT" ]; then
  SCRIPT="$HOME/.claude/dependency_security_check.py"
fi
if [ ! -f "$SCRIPT" ]; then
  echo "BLOCKED: dependency_security_check.py not found. Install it first." >&2
  echo "See: https://github.com/sharkyger/claude-code-security" >&2
  exit 2
fi

# Override the scanner's default --min-age (3 days) when the user sets
# SAFE_INSTALL_MIN_AGE. Unset = scanner default, "0" = disable freshness hold,
# "7" = stricter hold. See README "Bypass / Override" section.
MIN_AGE_ARGS=()
if [ -n "${SAFE_INSTALL_MIN_AGE+x}" ]; then
  MIN_AGE_ARGS=(--min-age "$SAFE_INSTALL_MIN_AGE")
fi

BLOCKED=0
for PKG in $PACKAGES; do
  [ -z "$PKG" ] && continue

  PKG_VERSION=""
  if [ "$ECOSYSTEM" = "pip" ]; then
    PKG_WITH_VER=$(echo "$PIP_SEGMENT" | grep -oE "${PKG}[>=<!=]+[0-9][^ ]*" | head -1)
    [ -n "$PKG_WITH_VER" ] && PKG_VERSION=$(echo "$PKG_WITH_VER" | sed -E 's/^[^>=<!=]+[>=<!=]+//')
  fi

  if [ -n "$PKG_VERSION" ]; then
    RESULT=$(python3 "$SCRIPT" "$ECOSYSTEM" "$PKG" "$PKG_VERSION" "${MIN_AGE_ARGS[@]}" 2>&1)
  else
    RESULT=$(python3 "$SCRIPT" "$ECOSYSTEM" "$PKG" "${MIN_AGE_ARGS[@]}" 2>&1)
  fi
  EXIT_CODE=$?

  echo "$RESULT" >&2

  if [ $EXIT_CODE -eq 1 ]; then
    BLOCKED=1
  elif [ $EXIT_CODE -eq 2 ]; then
    echo "BLOCKED: Security check failed for $PKG — refusing to install without verification." >&2
    BLOCKED=1
  fi
done

if [ $BLOCKED -eq 1 ]; then
  echo "" >&2
  echo "BLOCKED: One or more packages have known vulnerabilities." >&2
  echo "Review the findings above before proceeding." >&2
  exit 2
fi

exit 0
