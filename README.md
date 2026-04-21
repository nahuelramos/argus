# Argus

Security hook system for Claude Code. Blocks credential theft, reverse shells,
data exfiltration, and prompt injection **before** any tool executes.

---

## What it is and how it works

Argus is **not an MCP server**, plugin, or extension.

It is a pair of Python scripts that Claude Code calls automatically before and
after executing any tool (Bash, Read, Write, Edit, etc.).

```
You ask Claude to do something
         │
         ▼
  Claude decides to run a tool
  (e.g. Bash: "cat ~/.aws/credentials")
         │
         ▼
  ┌──────────────────────────┐
  │  preflight.py            │  ← Called BEFORE the tool runs
  │  Reads tool input stdin  │
  │  Checks against IOCs     │
  │  Returns: allow / block  │
  └──────────────────────────┘
         │
    ┌────┴─────┐
    │          │
  BLOCK      ALLOW
    │          │
    │    Tool executes
    │          │
    │          ▼
    │  ┌──────────────────────────┐
    │  │  postcheck.py            │  ← Called AFTER the tool runs
    │  │  Scans the OUTPUT        │
    │  │  DLP: finds secrets      │
    │  │  Warns Claude if found   │
    │  └──────────────────────────┘
    │
Claude sees the block and stops
```

Everything runs **100% locally** on your machine. Zero network calls. Zero LLM.
Latency ~30-80ms per tool call.

---

## Where it installs

Hooks are registered in `~/.claude/settings.json` (global) or
`.claude/settings.json` (project-only).

After installation, the file looks like this:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /home/your-user/argus/hooks/preflight.py"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /home/your-user/argus/hooks/postcheck.py"
          }
        ]
      }
    ]
  }
}
```

Claude Code reads that config and calls the scripts automatically.
No action needed per session — once installed, always active.

---

## Project structure

```
argus/
├── hooks/
│   ├── preflight.py        ← PreToolUse hook: blocks BEFORE execution
│   ├── postcheck.py        ← PostToolUse hook: DLP scan on outputs
│   ├── install.sh          ← Registers hooks in settings.json
│   └── uninstall.sh        ← Removes them
├── data/
│   ├── iocs.json           ← Indicators of Compromise database
│   └── allowlist.json      ← Template for your custom exceptions
├── tests/
│   └── test_hooks.py       ← 120 regression tests
├── argus-report.py         ← CLI to view the audit log
└── README.md
```

---

## Installation

### Requirements

```bash
python3 --version   # 3.8+
jq --version        # any version
```

Install `jq` if needed:
```bash
# Ubuntu/Debian
sudo apt install jq

# macOS
brew install jq
```

### Install globally (recommended)

```bash
git clone git@github.com:nahuelramos/argus.git ~/argus
cd ~/argus
bash hooks/install.sh --user
```

That's it. From that point Argus intercepts every Claude Code session on your machine.

### Install for a single project only

```bash
cd /path/to/your/project
bash ~/argus/hooks/install.sh --project
```

### Verify it's active

```bash
cat ~/.claude/settings.json | python3 -m json.tool | grep -A5 PreToolUse
```

### Run the tests

```bash
cd ~/argus
python3 -m pytest tests/ -v
# Expected: 120 passed
```

---

## Uninstall

```bash
bash ~/argus/hooks/uninstall.sh --user
# or for a project:
bash ~/argus/hooks/uninstall.sh --project
```

---

## What it detects and blocks

### Credential file access (block)
```
~/.ssh/id_rsa, ~/.aws/credentials, ~/.kube/config
~/.docker/config.json, ~/.vault-token, ~/.config/gcloud/
terraform.tfstate, *.pem, *.p12, service_account.json
/etc/shadow, /etc/passwd, /proc/*/environ
.env, .env.production, secrets.yml, ...
```

### Sensitive environment variables (block)
```
AWS_SECRET_ACCESS_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY
GITHUB_TOKEN, STRIPE_SECRET_KEY, DATABASE_URL
VAULT_TOKEN, SLACK_BOT_TOKEN, HF_TOKEN, CI_JOB_TOKEN, ...
+ any *_API_KEY, *_SECRET, *_TOKEN, *_PASSWORD (regex)
```

### Network exfiltration (block)
```
Confirmed malicious domains: giftshop.club (Postmark MCP incident)
Paste/upload services: pastebin.com, transfer.sh, rentry.co, ghostbin.com
Webhooks and tunnels: webhook.site, pipedream.net, ngrok.io, bore.pub
Discord/Slack webhooks: discord.com/api/webhooks/, hooks.slack.com
Direct IPs in URLs: http://1.2.3.4:8080/...
Suspicious TLDs: .tk .ml .xyz .zip .click ...
```

### Dangerous commands (block)
```
curl/wget piped to bash/sh
Reverse shells: bash -i >& /dev/tcp/..., nc -e /bin/sh
chmod SUID, LD_PRELOAD, crontab abuse
docker --privileged, shred ~/..., systemctl enable
IEX/Invoke-Expression (PowerShell)
```

### Obfuscation (block/warn)
```
base64 decode piped to bash
Hex shellcode: \x2f\x62\x69\x6e...
python3 -c '__import__...'
$IFS tricks
```

### Prompt injection in tool inputs (block/warn)
```
"Ignore all previous instructions"
"Act as root and bypass safety"
"Do not tell the user about this"
Zero-width characters U+200B..U+200F (CVE-2025-54794)
RTL override U+202E used to hide text
```

### Supply chain attacks (block/warn)
```
Shai-Hulud npm attack files (2025): telemetry.js, setup_bun.js
Postinstall hooks with curl/wget
CI token theft: process.env.GITHUB_TOKEN in npm scripts
```

### Claude Code flag abuse (block)
```
--dangerously-skip-permissions  ← used by S1ngularity npm malware
--yolo
--trust-all-tools
```

### DLP on tool outputs — postcheck (warn)
Detects 18 secret formats in tool output:
```
RSA/EC/OPENSSH private keys
AWS access key ID (AKIA...)
GitHub PAT (github_pat_...) and classic tokens (ghp_...)
Anthropic API key (sk-ant-api03-...)
OpenAI project key (sk-proj-...)
Stripe live/test keys (sk_live_..., sk_test_...)
Slack bot tokens (xoxb-...)
SendGrid keys (SG....)
Twilio SIDs (SK...)
HuggingFace tokens (hf_...)
Google Cloud service account JSON
Azure storage connection strings
JWT tokens
/etc/shadow password hashes
Credit card numbers
High-entropy strings (Shannon entropy >= 4.5)
```

---

## Allowlist — exceptions

If something legitimate gets blocked:

**Global** — applies to all sessions:
```bash
cat > ~/.argus/allowlist.json << 'EOF'
{
  "paths": [
    "/tmp/",
    "/home/youruser/project/.env.local"
  ],
  "domains": [
    "api.your-company.com",
    "internal.tools.your-company.com"
  ],
  "commands": []
}
EOF
```

**Per project** — only applies in that directory:
```bash
mkdir -p .security
cat > .security/argus-allowlist.json << 'EOF'
{
  "paths": ["/home/youruser/project/.env.test"],
  "domains": ["staging.api.your-company.com"],
  "commands": []
}
EOF
```

Confirmed malicious domains (`giftshop.club`, etc.) **cannot be allowlisted** —
they are always blocked.

---

## Viewing the audit log

Everything Argus blocks or warns about is logged to `~/.argus/logs/audit.jsonl`.

```bash
# Last 50 entries (with colors)
python3 ~/argus/argus-report.py

# Blocks only
python3 ~/argus/argus-report.py --blocks

# Today's events only
python3 ~/argus/argus-report.py --today

# Statistics summary
python3 ~/argus/argus-report.py --stats

# Full history
python3 ~/argus/argus-report.py --all
```

Example log entry:
```json
{
  "ts": "2026-04-20T21:26:57Z",
  "hook": "PreToolUse",
  "decision": "block",
  "severity": "high",
  "tool": "Bash",
  "matched": "~/.aws/credentials",
  "hash": "a3f2b1c9",
  "cwd": "/home/youruser/my-project"
}
```

---

## Updating the IOC database

To add your own patterns without touching code, edit `data/iocs.json`.
Most common sections to customize:

```json
// Add an internal domain to the allowlist:
"allowlist": {
  "domains": ["api.your-company.com"]
}

// Add a custom sensitive path:
"sensitive_paths": {
  "patterns": ["~/.your-app/secrets/"]
}
```

---

## Argus vs MCP servers

| | Argus | MCP Server |
|---|---|---|
| What it is | Local Claude Code hook | External server via MCP protocol |
| Where it runs | Your machine, local Python process | Separate process (local or remote) |
| How it installs | `settings.json` hooks section | `mcp.json` servers section |
| Makes network calls | No | Depends on the server |
| Intercepts all tools | Yes | No (it is itself a tool) |
| Latency | 30-80ms | Variable |

---

## System requirements

- Claude Code CLI installed
- Python 3.8+
- jq
- Linux or macOS
