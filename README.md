# Argus

Security system for Claude — blocks credential theft, reverse shells, data
exfiltration, and prompt injection across Claude Code, Claude Desktop, and Claude Web.

---

## Platform support

| Platform | Protection level | Mechanism |
|---|---|---|
| **Claude Code CLI** | ✅ Enforced — tool calls are physically blocked | Hooks (`hooks/`) |
| **Claude Desktop** | ⚡ Best-effort — Claude has security tools available | MCP server (`mcp-server/`) |
| **Claude Web** | 📋 Policy-based — Claude follows security instructions | System prompt (`WEB_INSTRUCTIONS.md`) |

Claude Code CLI is the only platform with true enforcement. Hooks intercept every
tool call before it executes — Claude cannot bypass them. Desktop and Web work
through Claude voluntarily following security tools and instructions.

---

## How it works (Claude Code CLI)

Argus registers three local Python scripts as hooks in `~/.claude/settings.json`.
Claude Code calls them automatically — no action needed per session.

```
You ask Claude something
        │
        ▼
  Claude decides to run a tool (Bash, Read, Write…)
        │
        ▼
┌─────────────────────────────────┐
│  preflight.py  (PreToolUse)     │  ← runs BEFORE the tool
│  Checks against IOC database    │
│  Returns: allow / block / warn  │
└─────────────────────────────────┘
        │
   ┌────┴─────┐
   │          │
 BLOCK      ALLOW ──────────────────────────────────────────────┐
   │                                                            │
   │                                                     Tool executes
   │                                                            │
   │                                            ┌──────────────▼──────────────┐
   │                                            │  postcheck.py (PostToolUse) │
   │                                            │  Scans tool OUTPUT for      │
   │                                            │  secrets and sensitive data  │
   │                                            └─────────────────────────────┘
   │
   └── Claude sees the block reason and stops
        (explains to you what was blocked and why)
        │
        ▼
┌─────────────────────────────────┐
│  session-report.py  (Stop)      │  ← runs after EVERY Claude response
│  If any events occurred:        │
│  prints a security summary      │
└─────────────────────────────────┘
```

**Runtime:** 100% local, ~30-80ms per tool call, zero LLM cost for the hooks.
The scanner skill (on-demand only) makes outbound web requests to threat intel APIs.

---

## Components

```
┌──────────────────────────────────────────────────────────────┐
│  COMPONENT 1 — Runtime Hooks  (always on, Claude Code CLI)   │
│  preflight.py + postcheck.py + session-report.py             │
│  Blocks dangerous calls in real time. ~50ms. Zero LLM.       │
├──────────────────────────────────────────────────────────────┤
│  COMPONENT 2 — Scanner Skill  (on demand, all platforms)     │
│  SKILL.md + scripts/local-scan.py                            │
│  Deep scan against 8 threat intel sources when you ask.      │
│  Uses Claude + web search. Run before installing anything.   │
├──────────────────────────────────────────────────────────────┤
│  COMPONENT 3 — MCP Server  (Claude Desktop)                  │
│  mcp-server/server.py                                        │
│  4 security tools Claude can call before risky actions.      │
├──────────────────────────────────────────────────────────────┤
│  COMPONENT 4 — Web Instructions  (Claude Web)                │
│  WEB_INSTRUCTIONS.md                                         │
│  Security policy to paste into Project Instructions.         │
└──────────────────────────────────────────────────────────────┘
```

---

## Project structure

```
argus/
├── hooks/                       ← Claude Code CLI
│   ├── preflight.py             ← PreToolUse: blocks BEFORE execution
│   ├── postcheck.py             ← PostToolUse: DLP scan on outputs
│   ├── session-report.py        ← Stop: security summary after each response
│   ├── install.sh               ← Registers all hooks + installs skill
│   └── uninstall.sh
├── mcp-server/                  ← Claude Desktop
│   ├── server.py                ← MCP server with 4 security tools
│   └── install-desktop.sh       ← Installs into claude_desktop_config.json
├── scripts/
│   └── local-scan.py            ← Static file analyzer (shared by all)
├── data/
│   ├── iocs.json                ← Indicators of Compromise database
│   └── allowlist.json           ← Custom exceptions template
├── tests/
│   └── test_hooks.py            ← 120 regression tests
├── SKILL.md                     ← Scanner skill (Claude Code + Desktop)
├── WEB_INSTRUCTIONS.md          ← Claude Web: paste into Project Instructions
├── argus-report.py              ← CLI audit log viewer
└── README.md
```

---

## Installation — Claude Code CLI

- [macOS](#macos)
- [Linux](#linux)
- [Windows](#windows)

### macOS

**1. Install requirements**

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/homebrew/install/HEAD/install.sh)"

brew install python3 jq git
```

**2. Clone and install**

```bash
git clone https://github.com/nahuelramos/argus.git ~/argus
cd ~/argus
bash hooks/install.sh --user
```

**3. Verify**

```bash
cat ~/.claude/settings.json | python3 -m json.tool | grep -A5 PreToolUse
```

**4. Run tests**

```bash
cd ~/argus && python3 -m pytest tests/ -v
# Expected: 120 passed
```

---

### Linux

**1. Install requirements**

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y python3 python3-pip jq git

# Fedora / RHEL
sudo dnf install -y python3 python3-pip jq git

# Arch
sudo pacman -S python python-pip jq git
```

**2. Clone and install**

```bash
git clone https://github.com/nahuelramos/argus.git ~/argus
cd ~/argus
bash hooks/install.sh --user
```

**3. Verify**

```bash
cat ~/.claude/settings.json | python3 -m json.tool | grep -A5 PreToolUse
```

**4. Run tests**

```bash
cd ~/argus && python3 -m pytest tests/ -v
# Expected: 120 passed
```

---

### Windows

Windows requires **Git Bash** (included with [Git for Windows](https://git-scm.com/download/win))
or **WSL2** (recommended).

#### Option A — WSL2 (recommended)

```powershell
# In PowerShell
wsl --install
```

Then inside WSL2, follow the [Linux instructions](#linux) above.
After installing, update `%APPDATA%\Claude\settings.json` to use WSL paths:

```json
{
  "hooks": {
    "PreToolUse": [{"matcher": "", "hooks": [{"type": "command",
      "command": "wsl python3 /home/YOUR_WSL_USER/argus/hooks/preflight.py"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [{"type": "command",
      "command": "wsl python3 /home/YOUR_WSL_USER/argus/hooks/postcheck.py"}]}],
    "Stop": [{"matcher": "", "hooks": [{"type": "command",
      "command": "wsl python3 /home/YOUR_WSL_USER/argus/hooks/session-report.py"}]}]
  }
}
```

#### Option B — Git Bash (no WSL)

**Requirements:**
- [Git for Windows](https://git-scm.com/download/win) — includes Git Bash
- [Python 3](https://www.python.org/downloads/windows/) — check "Add to PATH"
- [jq for Windows](https://jqlang.org/download/) — rename to `jq.exe`, place in `C:\Windows\System32\`

```bash
# In Git Bash
git clone https://github.com/nahuelramos/argus.git ~/argus
cd ~/argus
bash hooks/install.sh --user
# Settings written to %APPDATA%\Claude\settings.json automatically
```

---

### What gets registered in settings.json

```json
{
  "hooks": {
    "PreToolUse": [{"matcher": "", "hooks": [
      {"type": "command", "command": "python3 /your-path/argus/hooks/preflight.py"}
    ]}],
    "PostToolUse": [{"matcher": "", "hooks": [
      {"type": "command", "command": "python3 /your-path/argus/hooks/postcheck.py"}
    ]}],
    "Stop": [{"matcher": "", "hooks": [
      {"type": "command", "command": "python3 /your-path/argus/hooks/session-report.py"}
    ]}]
  }
}
```

### Install for a single project only

```bash
cd /path/to/your/project
bash ~/argus/hooks/install.sh --project
```

### Uninstall

```bash
bash ~/argus/hooks/uninstall.sh --user
# or: bash ~/argus/hooks/uninstall.sh --project
```

---

## Installation — Claude Desktop

Claude Desktop supports MCPs but not hooks. Argus provides an MCP server that
gives Claude 4 security tools to call before risky actions.

**Requirements:** Python 3.8+, `pip install mcp`, jq

```bash
# macOS
bash ~/argus/mcp-server/install-desktop.sh
# Config: ~/Library/Application Support/Claude/claude_desktop_config.json

# Linux
bash ~/argus/mcp-server/install-desktop.sh
# Config: ~/.config/Claude/claude_desktop_config.json

# Windows (Git Bash)
bash ~/argus/mcp-server/install-desktop.sh
# Config: %APPDATA%\Claude\claude_desktop_config.json
```

Restart Claude Desktop after installing. Claude will have these tools:

| Tool | When Claude should call it |
|---|---|
| `argus_check` | Before any shell command, file access, or network request |
| `argus_scan_package` | Before `npm install` or `pip install` — queries GHSA + OSV + registry |
| `argus_scan_file` | Static IOC analysis on any local file |
| `argus_audit_log` | View recent security events |

> **Limitation:** Claude calls these tools voluntarily. There is no hook mechanism
> in Desktop to force interception the way CLI hooks work.

---

## Installation — Claude Web

Claude Web cannot run local code. Paste the security policy into Project Instructions:

1. Open `WEB_INSTRUCTIONS.md` from this repo
2. Copy the full content
3. Go to **claude.ai → Projects → Your Project → Edit Instructions**
4. Paste it in

> **Limitation:** Text-based policy only — no code enforcement. Claude follows
> the instructions as context, not as a system-level constraint.

---

## What it detects and blocks

### Credential file access
```
~/.ssh/id_rsa, ~/.aws/credentials, ~/.kube/config, ~/.docker/config.json
~/.vault-token, ~/.config/gcloud/, ~/.azure/, ~/.terraform.d/
terraform.tfstate, *.pem, *.p12, service_account.json
/etc/shadow, /etc/passwd, /proc/*/environ
.env, .env.production, secrets.yml, ...
```

### Sensitive environment variables
```
AWS_SECRET_ACCESS_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY
GITHUB_TOKEN, STRIPE_SECRET_KEY, DATABASE_URL
VAULT_TOKEN, SLACK_BOT_TOKEN, HF_TOKEN, CI_JOB_TOKEN, ...
+ any *_API_KEY, *_SECRET, *_TOKEN, *_PASSWORD (regex)
```

### Network exfiltration
```
Confirmed malicious: giftshop.club (Postmark MCP backdoor, Sept 2025)
Paste/upload: pastebin.com, transfer.sh, rentry.co, ghostbin.com
Webhooks/tunnels: webhook.site, pipedream.net, ngrok.io, bore.pub
Discord/Slack webhooks, direct IP URLs, suspicious TLDs (.tk .xyz .zip ...)
```

### Dangerous commands
```
curl/wget piped to bash/sh (remote code execution)
Reverse shells: bash -i >& /dev/tcp/..., nc -e /bin/sh, python socket.connect
chmod SUID, LD_PRELOAD, crontab abuse, systemctl enable
docker --privileged -v /:/host, shred, IEX/Invoke-Expression
```

### Obfuscation
```
base64 decode piped to bash, hex shellcode \x2f\x62..., $IFS tricks
python3 -c '__import__...', perl/ruby eval
```

### Prompt injection
```
"Ignore all previous instructions", "Act as root", "bypass safety"
Zero-width characters U+200B–U+200F (CVE-2025-54794)
RTL override U+202E used to hide text
```

### Supply chain attacks
```
Shai-Hulud npm campaign files: telemetry.js, setup_bun.js (2025)
Postinstall hooks with curl/wget
CI token theft via process.env.GITHUB_TOKEN in npm scripts
```

### Claude Code flag abuse
```
--dangerously-skip-permissions  (used by S1ngularity npm malware)
--yolo, --trust-all-tools
```

### DLP — sensitive data in tool outputs
18 secret formats detected in tool responses:
```
RSA/EC/OPENSSH private keys
AWS access key ID (AKIA...)
GitHub PAT: github_pat_... and ghp_...
Anthropic key: sk-ant-api03-...
OpenAI key: sk-proj-...
Stripe: sk_live_..., sk_test_...
Slack: xoxb-...
SendGrid: SG....
Twilio SIDs, HuggingFace: hf_...
Google Cloud service account JSON
Azure storage connection strings
JWT tokens, /etc/shadow hashes, credit card numbers
High-entropy strings (Shannon entropy ≥ 4.5)
```

---

## Security reports

### 1. Inline block message (in chat)

When Claude tries something blocked, it sees a detailed explanation and
communicates it to you:

```
🚫 ARGUS — Action blocked [HIGH]

Tool:     Bash
Command:  cat ~/.aws/credentials
Matched:  ~/.aws/credentials
Reason:   AWS credentials — leaking these gives full cloud account access

False positive? Add to ~/.argus/allowlist.json:
  {"paths": ["~/.aws/credentials"]}
```

### 2. Session report (after each response)

If any security events occurred during Claude's last response, a summary
prints automatically in the terminal:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡  ARGUS SECURITY REPORT — this response turn
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🚫 BLOCKED (1)
     🟠 [HIGH] Bash → ~/.aws/credentials

  Full log: ~/.argus/logs/audit.jsonl
  View:     python3 ~/argus/argus-report.py --blocks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 3. Audit log viewer

```bash
python3 ~/argus/argus-report.py            # last 50 entries
python3 ~/argus/argus-report.py --blocks   # blocked events only
python3 ~/argus/argus-report.py --today    # today only
python3 ~/argus/argus-report.py --stats    # statistics summary
python3 ~/argus/argus-report.py --all      # full history
```

---

## Allowlist — exceptions

**Global** — all sessions:
```bash
cat > ~/.argus/allowlist.json << 'EOF'
{
  "paths": ["/tmp/", "/home/youruser/project/.env.local"],
  "domains": ["api.your-company.com"],
  "commands": []
}
EOF
```

**Per project** — only in that directory:
```bash
mkdir -p .security
cat > .security/argus-allowlist.json << 'EOF'
{
  "paths": [".env.test"],
  "domains": ["staging.api.your-company.com"],
  "commands": []
}
EOF
```

Confirmed malicious domains (`giftshop.club`, etc.) cannot be allowlisted.

---

## Updating the IOC database

Edit `data/iocs.json` to add custom patterns without touching code:

```json
{
  "sensitive_paths": {
    "patterns": ["~/.your-app/secrets/"]
  },
  "allowlist": {
    "domains": ["api.your-company.com"]
  }
}
```

---

## Scanner skill — threat intelligence on demand

Tell Claude in plain English:

```
"scan my MCPs"
"is @modelcontextprotocol/server-filesystem safe to install?"
"audit all installed skills"
```

Claude checks each MCP/skill against 8 sources:

| Source | API |
|---|---|
| GitHub Advisory DB (GHSA) | `api.github.com/advisories?ecosystem=npm&package=X` |
| Google OSV Database | `POST api.osv.dev/v1/query` |
| NIST NVD (CVE database) | `services.nvd.nist.gov/rest/json/cves/2.0` |
| npm / PyPI registries | `registry.npmjs.org/X` · `pypi.org/pypi/X/json` |
| vulnerablemcp.info | Web fetch + search |
| Snyk | `security.snyk.io/package/npm/X` |
| Reddit community | `reddit.com/r/mcp` + WebSearch |
| Local static analysis | `scripts/local-scan.py` |

Reports are saved to `.security/argus-scan-YYYY-MM-DD.md`.

---

## System requirements

| | Claude Code CLI | Claude Desktop | Claude Web |
|---|---|---|---|
| Python 3.8+ | ✅ required | ✅ required | — |
| jq | ✅ required | ✅ required | — |
| git | ✅ required | optional | — |
| `pip install mcp` | — | ✅ required | — |
| OS | macOS · Linux · Windows | macOS · Windows | any browser |
