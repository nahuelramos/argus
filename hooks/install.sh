#!/usr/bin/env bash
# Argus — install PreToolUse and PostToolUse hooks into Claude Code settings
set -euo pipefail

SCOPE="${1:---user}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFLIGHT="$SCRIPT_DIR/preflight.py"
POSTCHECK="$SCRIPT_DIR/postcheck.py"

case "$SCOPE" in
  --user)    SETTINGS="$HOME/.claude/settings.json" ;;
  --project) SETTINGS="$(pwd)/.claude/settings.json" ;;
  *)
    echo "Usage: $0 [--user|--project]"
    echo "  --user     Install globally for this user (recommended)"
    echo "  --project  Install for current project only"
    exit 1
    ;;
esac

# ── Dependency checks ─────────────────────────────────────────────────────────
python3 --version >/dev/null 2>&1 || { echo "ERROR: python3 not found in PATH"; exit 1; }
jq --version      >/dev/null 2>&1 || { echo "ERROR: jq not found in PATH — install with: brew install jq / apt install jq"; exit 1; }

# ── Validate hook scripts exist ───────────────────────────────────────────────
[[ -f "$PREFLIGHT" ]] || { echo "ERROR: $PREFLIGHT not found"; exit 1; }
[[ -f "$POSTCHECK" ]] || { echo "ERROR: $POSTCHECK not found"; exit 1; }

chmod +x "$PREFLIGHT" "$POSTCHECK"

# ── Create settings file if absent ───────────────────────────────────────────
mkdir -p "$(dirname "$SETTINGS")"
[[ -f "$SETTINGS" ]] || echo '{}' > "$SETTINGS"

# ── Backup ────────────────────────────────────────────────────────────────────
BACKUP="$SETTINGS.argus-backup-$(date +%Y%m%d%H%M%S)"
cp "$SETTINGS" "$BACKUP"
echo "Backup saved: $BACKUP"

# ── Inject hooks (idempotent: skip if already present) ───────────────────────
PRE_CMD="python3 $PREFLIGHT"
POST_CMD="python3 $POSTCHECK"

jq --arg pre "$PRE_CMD" --arg post "$POST_CMD" '
  def add_hook(section; cmd):
    (.hooks[section] // []) as $existing |
    if ($existing | map(.hooks[]?.command) | any(. == cmd)) then
      .hooks[section] = $existing
    else
      .hooks[section] = $existing + [{"matcher": "", "hooks": [{"type": "command", "command": cmd}]}]
    end;
  . | add_hook("PreToolUse"; $pre) | add_hook("PostToolUse"; $post)
' "$SETTINGS" > "$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS"

# ── Create Argus home dirs ────────────────────────────────────────────────────
mkdir -p "$HOME/.argus/logs"

# ── Install the scanner skill ─────────────────────────────────────────────────
SKILL_SRC="$SCRIPT_DIR/../SKILL.md"
if [[ -f "$SKILL_SRC" ]]; then
  if [[ "$SCOPE" == "--user" ]]; then
    SKILL_DIR="$HOME/.claude/skills/argus-scanner"
  else
    SKILL_DIR="$(pwd)/.claude/skills/argus-scanner"
  fi
  mkdir -p "$SKILL_DIR"
  cp "$SKILL_SRC" "$SKILL_DIR/SKILL.md"
  echo "Skill installed: $SKILL_DIR/SKILL.md"
fi

# ── Verify ───────────────────────────────────────────────────────────────────
echo ""
echo "✓  Argus installed ($SCOPE)"
echo "   PreToolUse  hook  → $PREFLIGHT"
echo "   PostToolUse hook  → $POSTCHECK"
echo "   Scanner skill     → $SKILL_DIR/SKILL.md"
echo "   Audit log         → $HOME/.argus/logs/audit.jsonl"
echo ""
echo "Run tests:"
echo "   python3 -m pytest $SCRIPT_DIR/../tests/ -v"
echo ""
echo "Usage:"
echo "   Runtime protection is automatic."
echo "   For a full threat intel scan, tell Claude: 'scan my MCPs'"
