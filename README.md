# Argus

Security system for Claude — blocks credential theft, reverse shells, data
exfiltration, and prompt injection across Claude Code, Claude Desktop, and Claude Web.

---

## Quick install

```bash
npx argus-security
```

Interactive installer — detects your environment and sets up whichever Claude
platforms you use.

```
  [1] Claude Code CLI    — enforced blocking via hooks
  [2] Claude Desktop     — MCP server with 4 security tools
  [3] Claude Web         — copy security policy to clipboard
  [4] All of the above
```

Other commands:
```bash
npx argus-security --all       # install everything, no prompts
npx argus-security status      # check what's installed + audit stats
npx argus-security uninstall   # remove everything cleanly
```

> **From GitHub before npm publish:**
> ```bash
> npx github:nahuelramos/argus
> ```

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
│                                 │
│  Stage 0: trusted integration?  │  ← your AWS/GitHub/etc config
│  Stage 1: regex / IOC checks    │  ← 11 checks, ~1ms, free
│  Stage 2: Claude Haiku (LLM)    │  ← ambiguous cases only, ~300ms
│                                 │
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
   └── Claude sees the block reason and explains it to you
        │
        ▼
┌─────────────────────────────────┐
│  session-report.py  (Stop)      │  ← runs after EVERY response
│  If any events occurred:        │
│  prints a security summary      │
└─────────────────────────────────┘
```

**Runtime:** hooks are 100% local, ~30-80ms per tool call, zero LLM cost.
Stage 2 LLM analysis (~300ms) only activates on ambiguous cases when
`ANTHROPIC_API_KEY` is set. The scanner skill makes outbound requests to
threat intel APIs on demand only.

---

## Three-stage security pipeline

### Stage 0 — Integration check (instant)
If you have AWS, GitHub, Google Calendar etc. configured in your allowlist,
Argus recognizes those operations as trusted and skips all further checks.
`aws s3 ls` with AWS configured → allow immediately.

### Stage 1 — Regex / IOC matching (~1ms)
11 pattern checks against the IOC database. If severity is `critical` or
the match is unambiguous → block immediately without calling the LLM.

### Stage 2 — Claude Haiku analysis (~300ms, optional)
Only triggers for ambiguous cases: medium severity, prompt injection,
obfuscation, or zero-width character detections. Claude Haiku receives the
tool call plus your integration context and decides: false positive or real threat?
Requires `ANTHROPIC_API_KEY` in environment. Silently skipped if not set.

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
├── bin/
│   └── argus.js                 ← npx installer (interactive)
├── hooks/                       ← Claude Code CLI
│   ├── preflight.py             ← PreToolUse: blocks BEFORE execution
│   ├── postcheck.py             ← PostToolUse: DLP scan on outputs
│   ├── session-report.py        ← Stop: security summary after each response
│   ├── llm_analysis.py          ← Stage 2: Claude Haiku second opinion
│   ├── install.sh               ← manual install (alternative to npx)
│   └── uninstall.sh
├── mcp-server/                  ← Claude Desktop
│   ├── server.py                ← MCP server with 4 security tools
│   └── install-desktop.sh       ← manual install for Desktop
├── scripts/
│   └── local-scan.py            ← static file analyzer (shared)
├── data/
│   ├── iocs.json                ← Indicators of Compromise database
│   └── allowlist.json           ← integrations + custom exceptions
├── tests/
│   └── test_hooks.py            ← 120 regression tests
├── SKILL.md                     ← scanner skill (Claude Code + Desktop)
├── WEB_INSTRUCTIONS.md          ← Claude Web: paste into Project Instructions
├── package.json                 ← npm package definition
├── argus-report.py              ← CLI audit log viewer
└── README.md
```

---

## Installation

### Recommended — npx (all platforms)

```bash
npx argus-security
```

Requires: Node.js 16+, Python 3.8+, jq

The installer:
1. Detects your OS and which Claude apps are installed
2. Asks which platforms to set up
3. Copies Python files to `~/.argus/lib/`
4. Registers hooks / MCP server / skill automatically
5. Copies Web instructions to clipboard (if selected)

---

### Manual install — Claude Code CLI

#### macOS

```bash
brew install python3 jq git
git clone https://github.com/nahuelramos/argus.git ~/argus
cd ~/argus && bash hooks/install.sh --user
```

#### Linux

```bash
sudo apt install -y python3 python3-pip jq git   # Ubuntu/Debian
git clone https://github.com/nahuelramos/argus.git ~/argus
cd ~/argus && bash hooks/install.sh --user
```

#### Windows

**Option A — WSL2 (recommended)**
```powershell
wsl --install   # then follow Linux steps inside WSL2
```
Update `%APPDATA%\Claude\settings.json` to use WSL paths:
```json
{
  "hooks": {
    "PreToolUse":  [{"matcher": "", "hooks": [{"type": "command",
      "command": "wsl python3 /home/YOU/argus/hooks/preflight.py"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [{"type": "command",
      "command": "wsl python3 /home/YOU/argus/hooks/postcheck.py"}]}],
    "Stop":        [{"matcher": "", "hooks": [{"type": "command",
      "command": "wsl python3 /home/YOU/argus/hooks/session-report.py"}]}]
  }
}
```

**Option B — Git Bash**
- Install [Git for Windows](https://git-scm.com/download/win), [Python 3](https://python.org/downloads/windows/), [jq](https://jqlang.org/download/)
```bash
git clone https://github.com/nahuelramos/argus.git ~/argus
cd ~/argus && bash hooks/install.sh --user
```

#### Verify

```bash
cat ~/.claude/settings.json | python3 -m json.tool | grep -A5 PreToolUse
cd ~/argus && python3 -m pytest tests/ -v   # Expected: 120 passed
```

#### Uninstall

```bash
bash ~/argus/hooks/uninstall.sh --user
```

---

### Manual install — Claude Desktop

```bash
# macOS / Linux / Windows (Git Bash)
bash ~/argus/mcp-server/install-desktop.sh
```

Config locations:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Restart Claude Desktop after installing. Claude will have these tools:

| Tool | When to call it |
|---|---|
| `argus_check` | Before any shell command, file access, or network request |
| `argus_scan_package` | Before `npm install` or `pip install` |
| `argus_scan_file` | Static IOC analysis on a local file |
| `argus_audit_log` | View recent security events |

---

### Manual install — Claude Web

1. Run `npx github:nahuelramos/argus --web` — copies the security policy to your clipboard
   - Or open `WEB_INSTRUCTIONS.md` from this repo and copy the full content manually
2. Go to **[claude.ai](https://claude.ai)** and open **Projects** in the left sidebar
3. Select an existing project or create a new one
4. Inside the project, click **Edit Instructions** (top-right corner)
5. Paste with `Cmd+V` (macOS) or `Ctrl+V` (Windows/Linux) and click **Save**

> **Note:** Claude Web does not have system-level hooks. The policy works through
> Claude following the instructions cooperatively. For guaranteed enforcement,
> use Argus with **Claude Code CLI** which intercepts every tool call via
> `PreToolUse`/`PostToolUse` hooks before execution.

---

### Install for a single project only

```bash
cd /path/to/your/project
bash ~/argus/hooks/install.sh --project
```

---

## What gets registered in settings.json

```json
{
  "hooks": {
    "PreToolUse":  [{"matcher": "", "hooks": [{"type": "command",
      "command": "python3 ~/.argus/lib/hooks/preflight.py"}]}],
    "PostToolUse": [{"matcher": "", "hooks": [{"type": "command",
      "command": "python3 ~/.argus/lib/hooks/postcheck.py"}]}],
    "Stop":        [{"matcher": "", "hooks": [{"type": "command",
      "command": "python3 ~/.argus/lib/hooks/session-report.py"}]}]
  }
}
```

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
curl/wget piped to bash/sh
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

### 1. Inline block message

When Claude tries something blocked, it explains it to you:
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

If any security events occurred during Claude's response, a summary prints
automatically in the terminal:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡  ARGUS SECURITY REPORT — this response turn
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🚫 BLOCKED (1)
     🟠 [HIGH] Bash → ~/.aws/credentials

  Full log: ~/.argus/logs/audit.jsonl
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 3. Audit log viewer

```bash
python3 ~/argus/argus-report.py            # last 50 entries
python3 ~/argus/argus-report.py --blocks   # blocked events only
python3 ~/argus/argus-report.py --today    # today only
python3 ~/argus/argus-report.py --stats    # statistics summary
```

---

## Allowlist — exceptions and integrations

Argus ships with templates for 12 common integrations. Edit
`~/.argus/allowlist.json` (global) or `.security/argus-allowlist.json`
(per project) to enable them.

### Enable a trusted integration

```json
{
  "integrations": {
    "aws": {
      "description": "AWS CLI — authorized cloud operations",
      "allowed_patterns": ["aws s3 ls", "aws ec2 describe", "aws sts"],
      "blocked_patterns": ["aws iam create-user"],
      "allowed_domains": ["s3.amazonaws.com", "ec2.amazonaws.com"]
    },
    "google_calendar": {
      "description": "Google Calendar API",
      "allowed_domains": ["calendar.googleapis.com", "oauth2.googleapis.com"]
    }
  }
}
```

Pre-configured templates included: `aws`, `google_calendar`, `google_drive`,
`github`, `slack`, `notion`, `linear`, `jira`, `postgres`, `docker`,
`vercel`, `stripe`.

### Add trusted MCPs

```json
{
  "trusted_mcps": ["aws-mcp-server", "google-calendar-mcp"]
}
```

### Add custom paths or domains

```json
{
  "paths":   ["/tmp/", "/home/you/project/.env.local"],
  "domains": ["api.your-company.com", "internal.tools.com"]
}
```

Confirmed malicious domains (`giftshop.club`, etc.) cannot be allowlisted.

---

## Updating the IOC database

Edit `data/iocs.json` to add custom patterns without touching code:

```json
{
  "sensitive_paths": {
    "patterns": ["~/.your-app/secrets/"]
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
| Node.js 16+ | ✅ for npx install | ✅ for npx install | — |
| Python 3.8+ | ✅ required | ✅ required | — |
| jq | ✅ required | ✅ required | — |
| `pip install mcp` | — | ✅ required (auto-installed) | — |
| OS | macOS · Linux · Windows | macOS · Windows · Linux | any browser |

---

## Publishing to npm

```bash
npm login
npm publish
```

After publishing, users install with:
```bash
npx argus-security
```
