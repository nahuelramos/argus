#!/usr/bin/env bash
# Argus — remove hooks from Claude Code settings
set -euo pipefail

SCOPE="${1:---user}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFLIGHT="$SCRIPT_DIR/preflight.py"
POSTCHECK="$SCRIPT_DIR/postcheck.py"
STOPREPORT="$SCRIPT_DIR/session-report.py"

case "$SCOPE" in
  --user)    SETTINGS="$HOME/.claude/settings.json" ;;
  --project) SETTINGS="$(pwd)/.claude/settings.json" ;;
  *)         echo "Usage: $0 [--user|--project]" && exit 1 ;;
esac

[[ -f "$SETTINGS" ]] || { echo "Settings not found: $SETTINGS"; exit 1; }

BACKUP="$SETTINGS.argus-backup-$(date +%Y%m%d%H%M%S)"
cp "$SETTINGS" "$BACKUP"
echo "Backup saved: $BACKUP"

PRE_CMD="python3 $PREFLIGHT"
POST_CMD="python3 $POSTCHECK"

STOP_CMD="python3 $STOPREPORT"

jq --arg pre "$PRE_CMD" --arg post "$POST_CMD" --arg stop "$STOP_CMD" '
  def rm_hook(section; cmd):
    if .hooks[section] then
      .hooks[section] = [.hooks[section][] | select(.hooks[]?.command != cmd)]
    else . end;
  . | rm_hook("PreToolUse"; $pre)
    | rm_hook("PostToolUse"; $post)
    | rm_hook("Stop"; $stop)
' "$SETTINGS" > "$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS"

# ── Remove skill ──────────────────────────────────────────────────────────────
if [[ "$SCOPE" == "--user" ]]; then
  SKILL_DIR="$HOME/.claude/skills/argus-scanner"
else
  SKILL_DIR="$(pwd)/.claude/skills/argus-scanner"
fi
[[ -d "$SKILL_DIR" ]] && rm -rf "$SKILL_DIR" && echo "Skill removed: $SKILL_DIR"

echo "✓ Argus uninstalled ($SCOPE)"
