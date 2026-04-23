# Argus

Security system for Claude — blocks credential theft, reverse shells, data
exfiltration, prompt injection, and MCP tool poisoning across Claude Code,
Claude Desktop, and Claude Web.

---

## Quick install

```bash
npx github:nahuelramos/argus --all
```

Interactive installer — detects your environment and sets up whichever Claude
platforms you use.

```
  [1] Claude Code CLI    — enforced blocking via hooks
  [2] Claude Desktop     — MCP server with security tools
  [3] Claude Web         — copy security policy to clipboard
  [4] All of the above
```

Other commands:
```bash
npx github:nahuelramos/argus status      # check what's installed + audit stats
npx github:nahuelramos/argus uninstall   # remove everything cleanly
```

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
  Claude decides to run a tool (Bash, Read, Write, mcp__server__tool…)
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  preflight.py  (PreToolUse)           runs BEFORE the tool  │
│                                                             │
│  Stage 0: trusted integration?      ← your AWS/GitHub/etc   │
│  Stage 1: regex / IOC matching      ← 12 checks, ~1ms       │
│  Stage 1b: MCP server detection     ← NEW: auto-warn on     │
│            (mcp__*__ calls)           unscanned servers      │
│  Stage 2: Claude Haiku (LLM)        ← always runs for       │
│            second opinion             Bash/Write/Edit        │
│                                                             │
│  Returns: allow / block / warn                              │
└─────────────────────────────────────────────────────────────┘
        │
   ┌────┴─────┐
   │          │
 BLOCK      ALLOW ──────────────────────────────────────────────┐
   │                                                            │
   │                                                     Tool executes
   │                                                            │
   │                                            ┌──────────────▼──────────────┐
   │                                            │  postcheck.py (PostToolUse) │
   │                                            │  DLP scan on tool OUTPUT    │
   │                                            │  for secrets / credentials  │
   │                                            └─────────────────────────────┘
   │
   └── Claude sees the block reason and explains it to you
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  session-report.py  (Stop)                                  │
│  If any events occurred in this response turn:              │
│  prints a security summary to your terminal                 │
└─────────────────────────────────────────────────────────────┘
```

**Runtime:** most checks are local (~30–80ms). Package install detection adds
~500ms for 5 network checks (GHSA + OSV + NVD + npm/PyPI). Stage 2 LLM analysis
(~300ms) runs for Bash/Write/Edit via `claude -p` — no API key needed.

---

## Three-stage security pipeline

### Stage 0 — Integration check (instant)
If you have AWS, GitHub, Google Calendar etc. configured in your allowlist,
Argus recognizes those operations as trusted and skips all further checks.
`aws s3 ls` with AWS configured → allow immediately.

### Stage 1 — Regex / IOC matching (~1ms)
12 pattern checks against the IOC database. If severity is `critical` or
the match is unambiguous → block immediately without calling the LLM.

**Stage 1b — MCP automatic detection (new)**
When Claude calls any `mcp__serverName__toolName` tool, Argus checks whether
that server has been audited yet. If not, it emits an `additionalContext` warning
asking you to run `/scan-mcps`. Once you scan and clear a server, Argus records
it as confirmed-clean and stops warning. This happens automatically — zero config.

### Stage 2 — Claude Haiku analysis (~300ms)
Always runs for Bash, Write, Edit, and NotebookEdit calls. Acts as a second
opinion on top of regex: can downgrade false positives (regex matched but
action is safe) or catch novel attacks that patterns didn't detect.
Uses `claude -p` — requires an active Claude Code session. Silently skipped
when `ARGUS_NO_LLM=1` is set (CI/tests).

---

## Components

```
┌──────────────────────────────────────────────────────────────────────┐
│  COMPONENT 1 — Runtime Hooks  (always on, Claude Code CLI)           │
│  preflight.py + postcheck.py + session-report.py                     │
│  Blocks dangerous calls in real time. ~50ms. Zero LLM.               │
│  Includes automatic MCP server detection (Stage 1b).                 │
├──────────────────────────────────────────────────────────────────────┤
│  COMPONENT 2 — MCP Security Server  (Claude Desktop + Code CLI)      │
│  mcp-server/server.py                                                │
│  7 security tools Claude can call proactively or on demand.          │
│  Includes MCP scanning, snapshot/diff for supply chain detection.    │
├──────────────────────────────────────────────────────────────────────┤
│  COMPONENT 3 — Skills  (Claude Code CLI)                             │
│  ~/.claude/commands/scan-mcps.md  — /scan-mcps                       │
│  ~/.claude/commands/test-argus.md — /test-argus                      │
│  SKILL.md — general scanner skill (all platforms)                    │
├──────────────────────────────────────────────────────────────────────┤
│  COMPONENT 4 — Web Instructions  (Claude Web)                        │
│  WEB_INSTRUCTIONS.md                                                 │
│  Security policy to paste into Project Instructions.                 │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Project structure

```
argus/
├── bin/
│   └── argus.js                 ← npx installer (interactive)
├── hooks/                       ← Claude Code CLI
│   ├── preflight.py             ← PreToolUse: 3-stage pipeline + MCP detection
│   ├── postcheck.py             ← PostToolUse: DLP scan on tool outputs
│   ├── session-report.py        ← Stop: security summary after each response
│   ├── llm_analysis.py          ← Stage 2: Claude Haiku second opinion
│   ├── install.sh               ← manual install (alternative to npx)
│   └── uninstall.sh
├── mcp-server/                  ← Claude Desktop + Code CLI
│   ├── server.py                ← MCP server with 7 security tools
│   ├── test-server.py           ← poisoned MCP server for /test-argus
│   └── install-desktop.sh       ← manual install for Desktop
├── scripts/
│   └── local-scan.py            ← static file analyzer (shared)
├── data/
│   ├── iocs.json                ← Indicators of Compromise database
│   └── allowlist.json           ← integrations + custom exceptions
├── tests/
│   └── test_hooks.py            ← 143 regression tests
├── SKILL.md                     ← scanner skill (all platforms)
├── WEB_INSTRUCTIONS.md          ← Claude Web: paste into Project Instructions
├── package.json
├── argus-report.py              ← CLI audit log viewer
└── README.md
```

---

## Installation

### Recommended — npx (all platforms)

```bash
npx github:nahuelramos/argus --all
```

Requires: Node.js 16+, Python 3.8+

The installer:
1. Detects your OS and which Claude apps are installed
2. Asks which platforms to set up
3. Copies Python files to `~/.argus/lib/`
4. Registers hooks / MCP server / skills automatically
5. Copies Web instructions to clipboard (if selected)

---

### Manual install — Claude Code CLI

#### macOS

```bash
brew install python3 git
git clone https://github.com/nahuelramos/argus.git ~/argus
cd ~/argus && bash hooks/install.sh --user
```

#### Linux

```bash
sudo apt install -y python3 python3-pip git
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
- Install [Git for Windows](https://git-scm.com/download/win) and [Python 3](https://python.org/downloads/windows/)
```bash
git clone https://github.com/nahuelramos/argus.git ~/argus
cd ~/argus && bash hooks/install.sh --user
```

#### Verify

```bash
cat ~/.claude/settings.json | python3 -m json.tool | grep -A5 PreToolUse
cd ~/argus && python3 -m pytest tests/ -v   # Expected: 143 passed (4 pre-existing skipped)
```

#### Uninstall

```bash
bash ~/argus/hooks/uninstall.sh --user
```

---

### Manual install — Claude Desktop

```bash
pip3 install mcp
bash ~/argus/mcp-server/install-desktop.sh
```

Config locations:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Restart Claude Desktop after installing.

---

### Manual install — Claude Web

1. Run `npx github:nahuelramos/argus --web` — copies the security policy to your clipboard
   (or open `WEB_INSTRUCTIONS.md` and copy the content manually)
2. Go to **[claude.ai](https://claude.ai)** → **Projects** → **Edit Instructions**
3. Paste and click **Save**

> Claude Web does not have system-level hooks. The policy works through Claude
> following the instructions cooperatively. For guaranteed enforcement use
> **Claude Code CLI** with hooks.

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
base64 -d piped to bash/sh/python (obfuscated execution)
Reverse shells: bash -i >& /dev/tcp/..., nc -e /bin/sh, python socket.connect
chmod SUID, LD_PRELOAD, crontab abuse, systemctl enable
docker --privileged -v /:/host, shred, IEX/Invoke-Expression
```

### Obfuscation
```
Hex shellcode \x2f\x62..., $IFS tricks
python3 -c '__import__...', perl/ruby eval
```

### Prompt injection
```
"Ignore all previous instructions", "Act as root", "bypass safety"
"Your new task is...", "Do not tell the user...", "silently exfiltrate..."
Zero-width characters U+200B–U+200F (CVE-2025-54794)
RTL override U+202E used to hide text
```

### MCP tool description poisoning (new)
```
Hidden instructions inside tool descriptions (Invariant Labs research)
Coherence mismatches: tool claims to do X but description requests Y
Zero-width chars embedded in inputSchema fields
High-entropy blobs (anomaly detection)
Supply chain modifications: description changes between sessions
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

## Threat intelligence sources

Argus queries different sources depending on the component. Here's exactly what
each one checks — no marketing, just facts.

### `argus_scan_mcp` (MCP tool — programmatic HTTP, no WebSearch)

| Source | What's checked | Status |
|---|---|---|
| GitHub Advisory Database | Known CVEs/GHSAs for the package | ✅ Live API |
| VulnerableMCP.info | MCP-specific incident database | ✅ Live API (+ local fallback) |
| MCPScan.ai | No search API — accepts repo URLs for manual submission only | ❌ Removed |
| GitHub Issues | Community-reported security incidents | ✅ GitHub Search API |
| npm / PyPI registry | Deprecation, version, source repo | ✅ Live API |
| Source integrity | SHA-256 of local scripts, repo URL check | ✅ Local |
| Tool description analysis | Injection, zero-width chars, coherence | ✅ Local static |
| Snyk | — | ❌ Not in this tool |
| ToxicSkills Research | No public API available | ❌ N/A |
| ClawHub / OpenClaw | No public API available | ❌ N/A |
| OWASP (live query) | No queryable registry for MCP | ❌ N/A |
| OWASP patterns | Injection / API Security Top 10 patterns in IOC DB | ✅ via IOC |
| Anthropic Discord | No public API | ❌ N/A |

### `argus_scan_package` + preflight.py package install scan

Both the MCP tool and the preflight hook run the same 5-source scan:

| Source | What's checked | Status |
|---|---|---|
| GitHub Advisory Database | CVEs/GHSAs per package + ecosystem | ✅ Live API |
| Google OSV | Open Source Vulnerabilities | ✅ Live API |
| NIST NVD | CVEs with CVSS scores | ✅ Live API |
| npm registry | Deprecated, version metadata, age | ✅ Live API |
| PyPI | Yanked versions, vulnerabilities | ✅ Live API |

### SKILL.md scanner (Claude-based — uses WebSearch + WebFetch)

| Source | What's checked | Status |
|---|---|---|
| GitHub Advisory Database | CVEs/GHSAs | ✅ HTTP |
| Google OSV | Open Source Vulnerabilities | ✅ HTTP |
| NIST NVD | CVE database (CVSS scores) | ✅ HTTP |
| npm / PyPI registries | Version, deprecation | ✅ HTTP |
| VulnerableMCP.info | MCP incident database | ✅ WebFetch |
| Snyk / ToxicSkills Research | Enterprise malware analysis, 1,467 toxic skills dataset | ✅ WebSearch + WebFetch |
| ClawHub / OpenClaw Registry | Skill registry + VirusTotal results, Feb 2026 purge | ✅ WebSearch + WebFetch |
| Reddit r/ClaudeAI + r/mcp | Community early warnings | ✅ WebSearch |
| GitHub Issues on MCP repos | Active bug reports and security disclosures | ✅ WebSearch |
| Local static analysis | IOC patterns, entropy, injection | ✅ Local |
| OWASP classification | Labels findings with AS01–AS10 / MCP01–MCP05 | ✅ Applied to all findings |
| MCPScan.ai | No search API — manual repo submission only | ❌ N/A |
| Anthropic Discord | No public API — not searchable | ❌ N/A |

### Runtime hooks (preflight.py — always on)

Most checks are local (~1ms). When a package install is detected, the hook
makes network requests to 5 sources before allowing the install:

| Source | What's checked | Auth needed |
|---|---|---|
| GitHub Advisory Database | CVEs/GHSAs for the package | No (60 req/h free; set `GITHUB_TOKEN` for 5000/h) |
| Google OSV | Open Source Vulnerabilities | No |
| NIST NVD | CVEs with CVSS scores | No (rate-limited; use `NVD_API_KEY` for more) |
| npm registry | Deprecated versions, very new packages | No |
| PyPI registry | Yanked versions, known vulnerabilities | No |

For all other tool calls (non-install), detection is local:
- IOC regex database (12 check types)
- LLM second opinion via `claude -p` (active session, no API key)
- MCP unknown server detection (file-based state)

To disable network checks (CI/offline): set `ARGUS_NO_NETWORK=1`

---

## MCP server — security tools (Claude Desktop)

The Argus MCP server exposes **7 tools** Claude can call proactively or on demand.

### Core tools

| Tool | When to call it |
|---|---|
| `argus_check` | Before any shell command, file access, or network request |
| `argus_scan_package` | Before `npm install` or `pip install` — queries GHSA + OSV + registries |
| `argus_scan_file` | Static IOC analysis on a local file |
| `argus_audit_log` | View recent security events |

### MCP scanning tools

| Tool | What it does |
|---|---|
| `argus_scan_mcp` | Full audit: GHSA + VulnerableMCP.info + GitHub Issues + source integrity + static description analysis. Marks clean servers trusted — auto-warning stops. |
| `argus_mcp_snapshot` | Saves SHA-256 baseline of all tool descriptions. Run once after verifying. |
| `argus_mcp_diff` | Compares current descriptions vs baseline — detects supply chain modifications. |

---

## MCP automatic detection — how it works

When Claude calls any MCP tool (`mcp__serverName__toolName`), the PreToolUse
hook automatically checks if that server has been audited:

```
Claude calls mcp__playwright__browser_navigate
        │
        ▼
  preflight.py: is "playwright" in confirmed-clean list?
        │
    YES → allow silently
        │
    NO  → ⚠️  additionalContext warning:
              "playwright has not been scanned.
               Run /scan-mcps to verify its tool descriptions."
        │
        ▼
  User runs /scan-mcps
  argus_scan_mcp called → CLEAN
        │
        ▼
  ~/.argus/mcp-scanned.json updated:
    confirmed_clean: ["playwright"]
        │
        ▼
  Future calls to mcp__playwright__* → allow silently
```

The warning is `additionalContext` (never a block) — Claude proceeds, but
you're informed. Warning deduplicates per server for 24h so it doesn't spam.

To permanently trust a server without scanning:
```json
// ~/.argus/allowlist.json
{
  "trusted_mcps": ["playwright", "aws-docs"]
}
```

---

## Skills — /scan-mcps and /test-argus

### /scan-mcps

Run a full security audit of all registered MCP servers:

```
/scan-mcps
```

Claude will:
1. Inventory all connected MCP servers
2. Call `argus_scan_mcp` for each (GHSA + VulnerableMCP.info + GitHub Issues + static analysis)
3. Diff current tool descriptions against saved baselines
4. Print a summary table: Server | Tools | VulnerableMCP | Injection | Diff | Verdict
5. Save baselines for clean servers (silences future preflight.py warnings)

### /test-argus

Run the full Argus test suite against live hooks:

```
/test-argus
```

Tests 6 attack vectors and reports BLOCKED / ALLOWED + reason for each:
- Vector 1: Sensitive paths (AWS credentials, SSH keys)
- Vector 2: Environment variable exfiltration
- Vector 3: Network exfiltration (webhook.site)
- Vector 4: Base64 obfuscation bypass (`echo ... | base64 -d | bash`)
- Vector 5: Dangerous write (`/etc/passwd`)
- Vector 6: MCP tool poisoning (`poisoned_tool` on the test server)

---

## Security reports

### 1. Inline block message

```
🚫 ARGUS — Action blocked [HIGH]

Tool:     Bash
Command:  cat ~/.aws/credentials
Matched:  ~/.aws/credentials
Reason:   AWS credentials — leaking these gives full cloud account access

False positive? Add to ~/.argus/allowlist.json:
  {"paths": ["~/.aws/credentials"]}
Audit log: ~/.argus/logs/audit.jsonl
```

### 2. MCP warning (additionalContext)

```
⚠️  ARGUS — Unscanned MCP server
Server: some-server
This server's tool descriptions have not been verified for prompt injection.
Run /scan-mcps to audit all registered MCP servers before continuing.
To silence this: add the server to trusted_mcps in ~/.argus/allowlist.json
```

### 3. Session report (after each response)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡  ARGUS SECURITY REPORT — this response turn
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🚫 BLOCKED (1)
     🟠 [HIGH] Bash → ~/.aws/credentials

  Full log: ~/.argus/logs/audit.jsonl
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 4. Audit log viewer

```bash
python3 ~/argus/argus-report.py            # last 50 entries
python3 ~/argus/argus-report.py --blocks   # blocked events only
python3 ~/argus/argus-report.py --today    # today only
python3 ~/argus/argus-report.py --stats    # statistics summary
```

---

## Allowlist — exceptions and integrations

Edit `~/.argus/allowlist.json` (global) or `.security/argus-allowlist.json`
(per project) to configure trusted integrations and exceptions.

### Enable a trusted integration

```json
{
  "integrations": {
    "aws": {
      "description": "AWS CLI — authorized cloud operations",
      "allowed_patterns": ["aws s3 ls", "aws ec2 describe", "aws sts"],
      "blocked_patterns": ["aws iam create-user"],
      "allowed_domains": ["s3.amazonaws.com", "ec2.amazonaws.com"]
    }
  }
}
```

Pre-configured templates: `aws`, `google_calendar`, `google_drive`, `github`,
`slack`, `notion`, `linear`, `jira`, `postgres`, `docker`, `vercel`, `stripe`.

### Trust an MCP server permanently

```json
{
  "trusted_mcps": ["playwright", "aws-docs", "your-internal-mcp"]
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
  },
  "dangerous_commands": {
    "patterns": ["(?i)your-internal-ban-pattern"]
  }
}
```

---

## State files

Argus writes to `~/.argus/`:

| File | Purpose |
|---|---|
| `logs/audit.jsonl` | Every security event (allow/warn/block) |
| `logs/.rate.json` | Rate limiter state (burst detection) |
| `logs/.mcp-session.json` | MCP servers warned in the last 24h (dedup) |
| `mcp-scanned.json` | MCP servers confirmed clean by `argus_scan_mcp` |
| `mcp-snapshots/<name>.json` | Tool description baselines for diff detection |
| `iocs.json` | Custom IOC overrides (merged with repo data/) |
| `allowlist.json` | Trusted paths, domains, integrations, MCPs |

---

## System requirements

| | Claude Code CLI | Claude Desktop | Claude Web |
|---|---|---|---|
| Node.js 16+ | ✅ for npx install | ✅ for npx install | — |
| Python 3.8+ | ✅ required | ✅ required | — |
| `pip install mcp` | — | ✅ required (auto-installed) | — |
| OS | macOS · Linux · Windows | macOS · Windows · Linux | any browser |

---

## License

MIT
