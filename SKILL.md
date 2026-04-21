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

Scans installed MCPs and Claude Code skills against 7 threat intelligence sources
and performs local static analysis. Reports findings with severity ratings.

**Sources checked:**
1. GitHub Advisory Database (GHSA)
2. Google OSV Database
3. NIST NVD (CVE database)
4. npm / PyPI registries (deprecation, version alerts)
5. vulnerablemcp.info (MCP-specific incidents)
6. Snyk security database
7. Reddit community alerts (/r/mcp, /r/ClaudeAI, /r/MachineLearning)
8. Local static analysis (IOC pattern matching, coherence check, entropy)

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

### CHECK G: Snyk Security Database

**URL:** `https://security.snyk.io/package/npm/{package_name}` (for npm)
**URL:** `https://security.snyk.io/package/pip/{package_name}` (for pip)

Fetch the page and look for:
- Vulnerability count in the page
- Severity breakdown (critical/high/medium/low)
- Any CVE IDs mentioned

**What to report:** Any high/critical vulnerabilities found = HIGH finding.

---

### CHECK H: Reddit community alerts

Run these web searches:

```
"{name}" MCP malicious OR backdoor OR vulnerability OR compromised site:reddit.com
"{name}" MCP site:reddit.com/r/mcp OR site:reddit.com/r/ClaudeAI
"{package_name}" npm malicious backdoor supply chain 2025 site:reddit.com
```

Also search for general community reports:
```
"{name}" MCP security warning 2025 2026
"{package_name}" npm backdoor credential theft
```

Look for posts reporting malicious behavior, data theft, or security incidents.

**What to report:** Any confirmed community report = HIGH. Unverified reports = MEDIUM.

---

### CHECK I: Local static analysis

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
| Item | Type | Risk | Findings |
|------|------|------|----------|
| name | mcp_server | CRITICAL | 3 findings |
...

## Critical Findings
### [item name]
**Source:** GitHub Advisory / OSV / Static Analysis / etc.
**Finding:** Description
**CVE/GHSA:** if applicable
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
- npm Registry: {timestamp}
- vulnerablemcp.info: {timestamp}
- Snyk: {timestamp}
- Reddit community: {timestamp}
- Local static analysis: {timestamp}
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
      "sources_checked": ["github_advisory", "osv", "nvd", "npm", "vulnerablemcp", "snyk", "reddit", "local"]
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
Sources: GitHub GHSA · OSV · NVD · npm · vulnerablemcp.info · Snyk · Reddit

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
- If the user asks to scan a specific MCP by name that isn't installed, run CHECK A through CHECK H using that name directly.
- Never stop the scan because one source failed — always run all available checks.

---

## Pre-installation scan (when user asks "is X safe to install?")

If the user mentions installing a new MCP or skill, run all checks BEFORE installation:

1. Extract the package name from the install command
2. Run CHECK A (GitHub Advisory)
3. Run CHECK B (OSV)
4. Run CHECK C (NVD)
5. Run CHECK D or E (registry metadata)
6. Run CHECK F (vulnerablemcp.info)
7. Run CHECK G (Snyk)
8. Run CHECK H (Reddit)

Report findings BEFORE the user installs anything.
If CRITICAL findings exist, strongly recommend against installation.
If HIGH findings exist, warn and ask user to confirm.
If clean, confirm it's safe to proceed.
