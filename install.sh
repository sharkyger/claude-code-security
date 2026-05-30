#!/bin/bash
# Claude Code CVE Gate — Installer
# Downloads security hooks and vulnerability scanner into ~/.claude/

set -euo pipefail

INSTALL_DIR="$HOME/.claude"
HOOKS_DIR="$INSTALL_DIR/hooks"
REPO_URL="https://raw.githubusercontent.com/sharkyger/claude-code-cve-gate/main"

echo ""
echo "  Claude Code CVE Gate — Installing safety hooks"
echo "  ================================================"
echo ""

# Create directories
mkdir -p "$HOOKS_DIR"

# Download scanner
echo "  [1/8] Downloading vulnerability scanner..."
curl -fsSL "$REPO_URL/dependency_security_check.py" -o "$INSTALL_DIR/dependency_security_check.py"

# Download hooks
echo "  [2/8] Installing dependency security gate..."
curl -fsSL "$REPO_URL/hooks/dependency-security-gate.sh" -o "$HOOKS_DIR/dependency-security-gate.sh"
chmod +x "$HOOKS_DIR/dependency-security-gate.sh"

echo "  [3/8] Installing dangerous command blocker..."
curl -fsSL "$REPO_URL/hooks/block-dangerous-bash.sh" -o "$HOOKS_DIR/block-dangerous-bash.sh"
chmod +x "$HOOKS_DIR/block-dangerous-bash.sh"

echo "  [4/8] Installing dangerous git blocker..."
curl -fsSL "$REPO_URL/hooks/block-dangerous-git.sh" -o "$HOOKS_DIR/block-dangerous-git.sh"
chmod +x "$HOOKS_DIR/block-dangerous-git.sh"

echo "  [5/8] Installing secret leak detector..."
curl -fsSL "$REPO_URL/hooks/secret-leak-detector.sh" -o "$HOOKS_DIR/secret-leak-detector.sh"
chmod +x "$HOOKS_DIR/secret-leak-detector.sh"

echo "  [6/8] Installing sensitive file protector..."
curl -fsSL "$REPO_URL/hooks/protect-sensitive-files.sh" -o "$HOOKS_DIR/protect-sensitive-files.sh"
chmod +x "$HOOKS_DIR/protect-sensitive-files.sh"

echo "  [7/8] Installing gitleaks pre-write hook..."
curl -fsSL "$REPO_URL/hooks/gitleaks-pre-write.sh" -o "$HOOKS_DIR/gitleaks-pre-write.sh"
chmod +x "$HOOKS_DIR/gitleaks-pre-write.sh"

echo "  [8/8] Installing PII redaction gate..."
curl -fsSL "$REPO_URL/hooks/pii-redaction-gate.sh" -o "$HOOKS_DIR/pii-redaction-gate.sh"
chmod +x "$HOOKS_DIR/pii-redaction-gate.sh"

echo ""
echo "  Files installed to: $INSTALL_DIR"
echo ""
echo "  NEXT STEP: Add hooks to your Claude Code settings."
echo "  Copy the hooks section from settings-template.json into:"
echo "    $INSTALL_DIR/settings.json"
echo ""
echo "  Or merge manually if you already have settings."
echo ""
echo "  Test it works:"
echo "    python3 ~/.claude/dependency_security_check.py npm express 4.17.1"
echo ""
echo "  Done. Your AI coding assistant is now safer."
echo ""
