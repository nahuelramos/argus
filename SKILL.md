# Argus Scanner — MCP & Skill Threat Intelligence

## When to invoke this skill

Invoke when the user mentions any of:
- "scan", "security scan", "argus scan"
- "is this MCP safe", "is this skill safe", "safe to install"
- "check vulnerabilities", "CVE", "backdoor", "malicious MCP"
- "audit my MCPs", "audit my skills", "threat scan"
- "supply chain", "compromised package"
- "scan [name]" where name is an MCP or skill

---

## What this skill does

Scans installed MCPs and Claude Code skills against 10 threat intelligence sources
and performs local static analysis. Reports findings with severity ratings and
OWASP classification for each vulnerability found.

**Sources checked:**
1. GitHub Advisory Database (GHSA) — formal CVE database
2. Google OSV Database — open source vulnerabilities
3. NIST NVD (CVE database) — authoritative CVSS scores
4. npm / PyPI registries — deprecation, version alerts
5. VulnerableMCP.info — MCP-specific incident tracker
6. Snyk / ToxicSkills Research — enterprise malware analysis
7. ClawHub / OpenClaw Registry — skill registry with VirusTotal
8. Reddit r/ClaudeAI + r/mcp — community early warnings
9. GitHub Issues on MCP repos — active bug reports and disclosures
10. Local static analysis — IOC patterns, injection, entropy, coherence

---

## STEP 1 — Discover installed MCPs and skills

Run the discovery script:

```bash
python3 ~/argus/scripts/local-scan.py --discover
```

Parse the JSON output. For each item in `discovered[]`, extract:
- `name` — the MCP/skill name
- `type` — "mcp_server" or "skill"
- `source_file` — path to config or skill file
- `package_info.npm` — npm package name if applicable
- `package_info.pip` — pip package name if applicable
- `package_info.github` — GitHub repo if applicable
- `package_info.version` — installed version if known

If no items are discovered, tell the user no MCPs or skills were found and
ask if they want to scan a specific file or path instead.

---

## STEP 2 — For each discovered item, run threat intel checks

Run ALL checks for each item. Use the item's name, npm package, and pip package
as search terms. Run checks in parallel when possible.

---

### CHECK A: GitHub Advisory Database

**URL:** `https://api.github.com/advisories?per_page=10&ecosystem={ecosystem}&package={package}`

- If `package_info.npm` is set: fetch with `ecosystem=npm`
- If `package_info.pip` is set: fetch with `ecosystem=pip`
- Replace `{package}` with the URL-encoded package name

Fetch the URL and parse the JSON array. For each advisory:
- Note the `ghsa_id`, `severity`, `summary`, `cve_id`
- Note affected version ranges from `vulnerabilities[].vulnerable_version_range`
- Flag if the installed version falls within a vulnerable range

**What to report:** Any advisory found = HIGH or CRITICAL finding depending on severity.

---

### CHECK B: Google OSV Database

**URL:** POST `https://api.osv.dev/v1/query`

**Body for npm:**
```json
{"package": {"ecosystem": "npm", "name": "{package_name}"}}
```

**Body for pip:**
```json
{"package": {"ecosystem": "PyPI", "name": "{package_name}"}}
```

Use Bash with curl:
```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package": {"ecosystem": "npm", "name": "PACKAGE_NAME"}}'
```

Parse the response. If `vulns` array is non-empty, extract:
- `id` (OSV ID)
- `summary`
- `affected[].ranges[]` for version ranges
- `severity[].score` for CVSS score

**What to report:** Any vuln found = HIGH finding minimum.

---

### CHECK C: NIST NVD (CVE database)

**URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={name}+MCP&resultsPerPage=5`

Replace `{name}` with the MCP/package name (URL-encoded, spaces as +).

Parse `vulnerabilities[].cve` for:
- `id` (CVE ID)
- `descriptions[0].value` (description)
- `metrics.cvssMetricV31[0].cvssData.baseScore` (CVSS score)
- `metrics.cvssMetricV31[0].cvssData.baseSeverity`

**What to report:** Any CVE with score >= 7.0 = HIGH. Score >= 9.0 = CRITICAL.

---

### CHECK D: npm Registry (for npm packages)

**URL:** `https://registry.npmjs.org/{package_name}`

Only run if `package_info.npm` is set.

Check:
- `dist-tags.latest` — is there a newer version than installed?
- `versions.{installed_version}.deprecated` — is it deprecated?
- `time.{installed_version}` — when was this version published? Old versions with known issues.
- Look for any `deprecated` flag in the installed version's metadata.

**What to report:**
- Deprecated package = MEDIUM finding
- Version significantly behind latest AND there are known CVEs = HIGH
- Package published very recently (< 30 days) with no community track record = LOW warning

---

### CHECK E: PyPI Registry (for Python packages)

**URL:** `https://pypi.org/pypi/{package_name}/json`

Only run if `package_info.pip` is set.

Check:
- `info.version` — latest version vs installed
- `info.yanked` — if true, this version was pulled for security reasons
- `vulnerabilities[]` — any known vulnerabilities listed

**What to report:** Yanked version = CRITICAL. Any vulnerability listed = HIGH.

---

### CHECK F: vulnerablemcp.info

**URL:** `https://vulnerablemcp.info`

Fetch the page and search for the MCP name in the content. Also fetch:
- `https://vulnerablemcp.info/stats.html`
- `https://vulnerablemcp.info/taxonomy.html`

Search the page text for the MCP or package name (case-insensitive).
If found, extract the vulnerability title, description, and severity.

**What to report:** Any mention = CRITICAL finding (this site only lists confirmed MCP incidents).

---

### CHECK G: Snyk / ToxicSkills Research

**Primary URL:** `https://security.snyk.io/package/npm/{package_name}` (for npm)
**Primary URL:** `https://security.snyk.io/package/pip/{package_name}` (for pip)

Fetch the page and look for:
- Vulnerability count and severity breakdown (critical/high/medium/low)
- Any CVE IDs mentioned
- Whether it appears in the ToxicSkills dataset

Also run these web searches (ToxicSkills identified 1,467 malicious skills in registries):
```
site:snyk.io "{name}" vulnerability
site:snyk.io toxicskills "{name}"
"{name}" toxicskills malicious MCP skill
snyk "{package_name}" malware supply chain
```

**What to report:** Any high/critical Snyk finding = HIGH. ToxicSkills mention = CRITICAL.

---

### CHECK H: ClawHub / OpenClaw Registry

**URL:** `https://openclaw.ai`

ClawHub is a skill registry with VirusTotal integration. In February 2026, 13,729
skills were purged down to 3,286 after a mass security review — check if the item
was affected.

Fetch the OpenClaw page for the skill if it exists:
```
https://openclaw.ai/skills/{name}
```

Also run these web searches:
```
site:openclaw.ai "{name}"
"{name}" ClawHub VirusTotal malicious
"{name}" openclaw security rating
"{name}" skill purge february 2026
```

Look for:
- VirusTotal scan results (any detections = HIGH)
- Community safety ratings
- Whether it was removed in the February 2026 purge
- Any "unverified" or "flagged" status badges

**What to report:** VirusTotal detections = CRITICAL. Purge removal = HIGH. Unverified status = MEDIUM.

---

### CHECK I: Reddit community alerts

Run these web searches:

```
"{name}" MCP malicious OR backdoor OR vulnerability OR compromised site:reddit.com
"{name}" MCP site:reddit.com/r/mcp OR site:reddit.com/r/ClaudeAI
"{package_name}" npm malicious backdoor supply chain 2025 2026 site:reddit.com
"{name}" site:reddit.com/r/ClaudeAI security warning
```

Also search broadly:
```
"{name}" MCP security warning 2025 2026
"{package_name}" npm backdoor credential theft
```

Look for posts reporting malicious behavior, data theft, or suspicious activity.
Cross-reference community reports before escalating — a single unverified post = MEDIUM.

**What to report:** Confirmed community report = HIGH. Unverified single post = MEDIUM.

---

### CHECK J: GitHub Issues on MCP repos

Search for security reports in official and third-party MCP repositories:

```
repo:modelcontextprotocol/servers label:security "{name}"
repo:modelcontextprotocol/servers "vulnerability" OR "CVE" "{name}"
repo:{owner}/{repo} "vulnerability" OR "security" OR "CVE"
```

Replace `{owner}/{repo}` with the actual repository if known from the package metadata.

Also search GitHub broadly:
```
"{name}" MCP "security" OR "vulnerability" OR "backdoor" site:github.com
```

Look for:
- Open security issues (especially with no response from maintainer)
- Closed issues that reference CVEs or malicious behavior
- PRs that fixed security problems (read the diff for context)

**What to report:** Open unacknowledged security issue = HIGH. Closed fixed = LOW (note the fix).

---

### CHECK K: Local static analysis

Run the local scanner against the skill/MCP source files:

```bash
python3 ~/argus/scripts/local-scan.py "{source_file}"
```

If the MCP is an npm package installed globally, also scan:
```bash
python3 ~/argus/scripts/local-scan.py "$(npm root -g)/{package_name}" 2>/dev/null
```

Parse the JSON output:
- `findings[]` — list of static analysis findings
- `risk_level` — clean/low/medium/high/critical
- `risk_score` — numeric score

**What to report:** All findings from static analysis, grouped by severity.

---

## STEP 2b — OWASP classification

For every finding from STEP 2, classify it using the relevant OWASP framework.
Do NOT search OWASP — use it only to label what you already found.

**OWASP Agentic Skills Top 10** (use when the item is a skill or MCP tool):
- **AS01** Skill poisoning / backdoors
- **AS02** Excessive permission requests
- **AS03** Data exfiltration via tool calls
- **AS04** Prompt injection through skill content
- **AS05** Supply chain attacks
- **AS06** Credential harvesting
- **AS07** Sandbox escapes
- **AS08** Cross-skill contamination
- **AS09** Privilege escalation
- **AS10** Insufficient input validation

**OWASP MCP Top 10** (use when the item is an MCP server):
- **MCP01** Tool description poisoning
- **MCP02** Unauthorized data access
- **MCP03** Excessive tool permissions
- **MCP04** Insecure transport
- **MCP05** Supply chain compromise

Add the OWASP reference to each finding in the report, e.g.:
`[GHSA-xxxx] Remote code execution — OWASP AS05 (Supply chain attack)`

---

## STEP 3 — Version integrity check

For each npm package, compare installed vs latest:

```bash
npm list -g --depth=0 --json 2>/dev/null | python3 -c "
import json,sys
data = json.load(sys.stdin)
deps = data.get('dependencies', {})
for name, info in deps.items():
    print(f'{name}@{info.get(\"version\",\"unknown\")}')
"
```

For each package found, fetch `https://registry.npmjs.org/{name}/latest` to get
the latest version. Flag if installed version is more than 2 major versions behind
AND there are known CVEs in the installed version range.

---

## STEP 4 — Compile results and assign overall risk

For each scanned item, compile all findings from all checks.

**Risk levels:**
- **CRITICAL**: Known malicious domain, confirmed backdoor, CVSS >= 9.0, tool poisoning, zero-width chars
- **HIGH**: CVE with CVSS >= 7.0, OSV vulnerability, deprecated package, community-confirmed issue
- **MEDIUM**: Unverified community report, suspicious patterns, outdated version
- **LOW**: Minor warnings, best-practice suggestions
- **CLEAN**: No findings across all checks

---

## STEP 5 — Write the report

Create the directory if it doesn't exist:
```bash
mkdir -p .security
```

Write a markdown report to `.security/argus-scan-{YYYY-MM-DD}.md` with this structure:

```markdown
# Argus Security Scan Report
Date: {date}
Project: {cwd}
Items scanned: {count}

## Summary
| Item | Type | Risk | Findings | OWASP |
|------|------|------|----------|-------|
| name | mcp_server | CRITICAL | 3 findings | AS05, MCP01 |
...

## Critical Findings
### [item name]
**Source:** GitHub Advisory / OSV / Snyk / ClawHub / Static Analysis / etc.
**Finding:** Description
**CVE/GHSA:** if applicable
**OWASP:** AS01–AS10 / MCP01–MCP05 reference
**Affected versions:** if applicable
**Recommendation:** Update to X / Remove / Allowlist

## High Findings
...

## Medium Findings
...

## Clean Items
- item1 ✓
- item2 ✓

## Sources Checked
- GitHub Advisory DB: {timestamp}
- Google OSV: {timestamp}
- NIST NVD: {timestamp}
- npm / PyPI Registry: {timestamp}
- VulnerableMCP.info: {timestamp}
- Snyk / ToxicSkills: {timestamp}
- ClawHub / OpenClaw: {timestamp}
- Reddit r/ClaudeAI + r/mcp: {timestamp}
- GitHub Issues: {timestamp}
- Local static analysis: {timestamp}
- OWASP classification: applied to all findings
```

Also update the local threat database:
```bash
# Append to .security/threat-db.json
```

Write a JSON threat DB entry:
```json
{
  "scan_date": "{ISO timestamp}",
  "items": [
    {
      "name": "...",
      "risk_level": "...",
      "findings_count": 0,
      "sources_checked": ["github_advisory", "osv", "nvd", "npm", "vulnerablemcp", "snyk_toxicskills", "clawhub", "reddit", "github_issues", "local"]
    }
  ]
}
```

---

## STEP 6 — Present results to the user

Show a clear summary:

```
Argus Scan Complete — {date}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanned: {count} MCPs/skills
Sources: GHSA · OSV · NVD · npm/PyPI · VulnerableMCP · Snyk/ToxicSkills · ClawHub · Reddit · GitHub Issues · Static

CRITICAL  ▸ [item names]
HIGH      ▸ [item names]
MEDIUM    ▸ [item names]
CLEAN     ▸ [item names]

Full report: .security/argus-scan-{date}.md
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

For each CRITICAL or HIGH item, give a one-line recommendation:
- "Remove immediately" — if confirmed malicious
- "Update to version X" — if patched version exists
- "Review and monitor" — if unconfirmed / low confidence

---

## Error handling

- If an API returns an error or times out, log it in the report as "source unavailable" and continue with other sources.
- If no MCPs or skills are found, say so clearly and offer to scan a specific path.
- If the user asks to scan a specific MCP by name that isn't installed, run CHECK A through CHECK K using that name directly.
- Never stop the scan because one source failed — always run all available checks.

---

## Pre-installation scan (when user asks "is X safe to install?")

If the user mentions installing a new MCP or skill, run all checks BEFORE installation:

1. Extract the package name from the install command
2. Run CHECK A (GitHub Advisory)
3. Run CHECK B (OSV)
4. Run CHECK C (NVD)
5. Run CHECK D or E (registry metadata)
6. Run CHECK F (VulnerableMCP.info)
7. Run CHECK G (Snyk / ToxicSkills)
8. Run CHECK H (ClawHub / OpenClaw)
9. Run CHECK I (Reddit)
10. Run CHECK J (GitHub Issues)
11. Apply OWASP classification (STEP 2b) to any findings

Report findings BEFORE the user installs anything.
If CRITICAL findings exist, strongly recommend against installation.
If HIGH findings exist, warn and ask user to confirm.
If clean, confirm it's safe to proceed.
