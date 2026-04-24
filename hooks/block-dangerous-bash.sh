#!/bin/bash
# Claude Code Hook: Block dangerous bash commands.
# Prevents rm -rf on broad paths, eval injection, env dumping,
# SSH key reads, curl|sh pipes, and SQL destructive operations.
# Exit 2 = block, exit 0 = allow
#
# Install: Add to ~/.claude/settings.json under hooks.PreToolUse (matcher: "Bash")

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Block rm -rf on broad/root paths
if echo "$COMMAND" | grep -qE 'rm\s+-rf\s+(/|~|\$HOME|\.\.|/Users)'; then
  echo "BLOCKED: rm -rf on broad paths is too dangerous." >&2
  exit 2
fi

# Block eval/exec with variables (injection risk)
if echo "$COMMAND" | grep -qE 'eval\s+\$|exec\s+\$'; then
  echo "BLOCKED: eval/exec with variables is a security risk." >&2
  exit 2
fi

# Block reading .env via bash
if echo "$COMMAND" | grep -qE '(cat|head|tail|less|more|bat)\s+.*\.env(\s|$)'; then
  echo "BLOCKED: Cannot read .env files — secrets must stay out of Claude's context." >&2
  exit 2
fi

# Block printing secret env vars
if echo "$COMMAND" | grep -qE '(echo|printf|printenv)\s+.*\$(API_KEY|SECRET_KEY|PASSWORD|PRIVATE_KEY|AWS_SECRET|ANTHROPIC_API_KEY|MISTRAL_API_KEY)'; then
  echo "BLOCKED: Cannot print secret environment variables." >&2
  exit 2
fi

# Block env/printenv dumping all vars
if echo "$COMMAND" | grep -qE '^\s*(env|printenv)\s*$'; then
  echo "BLOCKED: Dumping all environment variables could expose secrets." >&2
  exit 2
fi

# Block SSH key reads via bash
if echo "$COMMAND" | grep -qE '(cat|head|tail|less|more)\s+.*\.ssh/(id_|authorized|known)'; then
  echo "BLOCKED: Cannot read SSH key files." >&2
  exit 2
fi

# Block chmod 777
if echo "$COMMAND" | grep -qE 'chmod\s+(-R\s+)?777\s'; then
  echo "BLOCKED: chmod 777 — use specific permissions instead." >&2
  exit 2
fi

# Block dd writing to raw devices
if echo "$COMMAND" | grep -qE 'dd\s+.*of=/dev/'; then
  echo "BLOCKED: dd to raw device — extremely dangerous." >&2
  exit 2
fi

# Block mkfs (format filesystem)
if echo "$COMMAND" | grep -qE '(^|\s|&&|\|;)mkfs'; then
  echo "BLOCKED: mkfs — formats a filesystem." >&2
  exit 2
fi

# Block curl/wget piped to shell
if echo "$COMMAND" | grep -qE '(curl|wget)\s+.*\|\s*(bash|sh|zsh)'; then
  echo "BLOCKED: Piping remote content to shell — download and inspect first." >&2
  exit 2
fi

# Block SQL DROP/TRUNCATE
if echo "$COMMAND" | grep -qiE '(DROP\s+(DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE)'; then
  echo "BLOCKED: SQL destructive operation (DROP/TRUNCATE)." >&2
  exit 2
fi

exit 0
