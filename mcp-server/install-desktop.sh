#!/usr/bin/env bash
# Argus — install MCP server into Claude Desktop config
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_PY="$SCRIPT_DIR/server.py"
PYTHON="$(which python3)"

# Detect Claude Desktop config path per OS
if [[ "$OSTYPE" == "darwin"* ]]; then
  CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || -n "${APPDATA:-}" ]]; then
  CONFIG="$(cygpath "$APPDATA" 2>/dev/null || echo "$APPDATA")/Claude/claude_desktop_config.json"
else
  # Linux — Claude Desktop uses XDG
  CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/Claude/claude_desktop_config.json"
fi

echo "Config path: $CONFIG"

python3 --version >/dev/null 2>&1 || { echo "ERROR: python3 required"; exit 1; }
jq --version      >/dev/null 2>&1 || { echo "ERROR: jq required"; exit 1; }
[[ -f "$SERVER_PY" ]] || { echo "ERROR: $SERVER_PY not found"; exit 1; }

# Install mcp Python package if missing
python3 -c "import mcp" 2>/dev/null || pip3 install mcp --quiet

chmod +x "$SERVER_PY"
mkdir -p "$(dirname "$CONFIG")"
[[ -f "$CONFIG" ]] || echo '{}' > "$CONFIG"

# Backup
cp "$CONFIG" "$CONFIG.argus-backup-$(date +%Y%m%d%H%M%S)"

# Inject into mcpServers (idempotent)
jq --arg py "$PYTHON" --arg srv "$SERVER_PY" '
  .mcpServers["argus-security"] = {
    "command": $py,
    "args": [$srv]
  }
' "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"

echo ""
echo "✓  Argus MCP server installed in Claude Desktop"
echo "   Config → $CONFIG"
echo "   Server → $SERVER_PY"
echo ""
echo "Restart Claude Desktop to activate."
echo ""
echo "Claude will now have these tools available:"
echo "   argus_check         — check any action before executing"
echo "   argus_scan_package  — scan npm/pip package before installing"
echo "   argus_scan_file     — static analysis on a local file"
echo "   argus_audit_log     — view recent security events"
