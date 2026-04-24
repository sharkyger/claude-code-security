#!/bin/bash
# Claude Code Hook: Block dangerous git operations.
# Prevents force push, reset --hard, --no-verify, clean -f, branch -D.
# Exit 2 = block, exit 0 = allow
#
# Install: Add to ~/.claude/settings.json under hooks.PreToolUse (matcher: "Bash")

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Block force push
if echo "$COMMAND" | grep -qE 'git\s+push\s+.*(-f|--force)'; then
  echo "BLOCKED: Force push is not allowed. Use --force-with-lease if absolutely necessary." >&2
  exit 2
fi

# Block git reset --hard
if echo "$COMMAND" | grep -qE 'git\s+reset\s+--hard'; then
  echo "BLOCKED: git reset --hard is destructive. Use git stash or create a backup branch first." >&2
  exit 2
fi

# Block --no-verify on commit/push
if echo "$COMMAND" | grep -qE 'git\s+(commit|push|merge)\s+.*--no-verify'; then
  echo "BLOCKED: --no-verify skips safety hooks. Fix the underlying issue instead." >&2
  exit 2
fi

# Block git clean -f (deletes untracked files)
if echo "$COMMAND" | grep -qE 'git\s+clean\s+.*-f'; then
  echo "BLOCKED: git clean -f deletes untracked files permanently. Review with git clean -n first." >&2
  exit 2
fi

# Block branch -D (force delete)
if echo "$COMMAND" | grep -qE 'git\s+branch\s+.*-D'; then
  echo "BLOCKED: git branch -D force-deletes without merge check. Use -d instead." >&2
  exit 2
fi

exit 0
