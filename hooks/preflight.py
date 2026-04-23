#!/usr/bin/env python3
"""
Argus — PreToolUse security hook for Claude Code.

Three-stage pipeline:
  Stage 0 — Integration check: is this an explicitly trusted operation?
  Stage 1 — Regex/IOC matching: fast local pattern checks
  Stage 2 — LLM analysis (Claude Haiku): intelligent review of ambiguous cases

Fails open — any bug in Argus lets Claude proceed normally.
"""
import json
import math
import os
import re
import sys
import time
import hashlib
import urllib.request
import urllib.parse
from collections import Counter
from pathlib import Path as _Path

# Ensure the hooks directory is in Python path so llm_analysis can be found
# (needed when the script is invoked as an absolute path by Claude Code hooks)
_HOOKS_DIR = str(_Path(__file__).resolve().parent)
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

# Stage 2 LLM analysis (optional — only runs when ANTHROPIC_API_KEY is set)
try:
    import llm_analysis as _llm
    _LLM_AVAILABLE = True
except Exception:
    _LLM_AVAILABLE = False

# Checks where LLM second opinion adds the most value (high false-positive rate)
_LLM_ELIGIBLE_CHECKS = {
    "prompt_injection", "obfuscation", "tool_description_poisoning",
    "zero_width_char", "supply_chain",
}
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

ARGUS_HOME  = Path.home() / ".argus"
_SCRIPT_DIR = Path(__file__).resolve().parent

IOC_SEARCH = [
    _SCRIPT_DIR.parent / "data" / "iocs.json",
    ARGUS_HOME / "iocs.json",
]
ALLOWLIST_SEARCH = [
    Path.cwd() / ".security" / "argus-allowlist.json",
    Path.home() / ".argus" / "allowlist.json",
]
AUDIT_LOG    = ARGUS_HOME / "logs" / "audit.jsonl"
RATE_STATE   = ARGUS_HOME / "logs" / ".rate.json"
MCP_SCANNED  = ARGUS_HOME / "mcp-scanned.json"
MCP_SESSION  = ARGUS_HOME / "logs" / ".mcp-session.json"
MCP_WARN_TTL = 24 * 3600  # re-warn after 24h if server still not scanned

RATE_WINDOW = 60
RATE_BURST  = 5

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}

# Zero-width / invisible Unicode characters used to hide prompt injections
# (CVE-2025-54794, Invariant Labs research)
ZERO_WIDTH_CHARS = {
    "​", "‌", "‍", "‎", "‏",
    "⁠", "⁡", "⁢", "⁣", "⁤",
    "﻿", "‮", "‭",
}


# ── Loaders ───────────────────────────────────────────────────────────────────

def _load_json(paths: list) -> dict:
    for p in paths:
        if Path(p).exists():
            try:
                return json.loads(Path(p).read_text())
            except Exception:
                continue
    return {}


def _iocs() -> dict:
    return _load_json(IOC_SEARCH)


def _allowlist() -> dict:
    return _load_json(ALLOWLIST_SEARCH)


# ── String extraction ─────────────────────────────────────────────────────────

def _strings(obj, depth: int = 0) -> list:
    if depth > 12:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_strings(v, depth + 1))
        return out
    if isinstance(obj, (list, tuple)):
        out = []
        for v in obj:
            out.extend(_strings(v, depth + 1))
        return out
    return []


# ── Path helpers ──────────────────────────────────────────────────────────────

def _expand(p: str) -> str:
    return os.path.normpath(os.path.expandvars(os.path.expanduser(p)))


def _path_hit(candidate: str, pattern: str) -> bool:
    ec, ep = _expand(candidate), _expand(pattern)
    if ep in ec or ec.startswith(ep):
        return True
    # raw substring — catches patterns embedded in shell commands like "cat ~/.aws/credentials"
    if pattern in candidate or ep in candidate:
        return True
    return False


# ── Shannon entropy ───────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if len(s) < 8:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _looks_like_secret(value: str) -> bool:
    """High-entropy string of sufficient length — likely a raw credential value."""
    return len(value) >= 20 and _entropy(value) >= 4.5


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_sensitive_paths(strings: list, iocs: dict, allowlist: dict):
    allowed = allowlist.get("paths", [])
    cfg = iocs.get("sensitive_paths", {})
    for s in strings:
        if any(_path_hit(s, a) for a in allowed):
            continue
        for pat in cfg.get("patterns", []):
            if _path_hit(s, pat):
                return pat, "high"
        for rx in cfg.get("regex_patterns", []):
            if re.search(rx, s):
                return rx, "high"
    return None, ""


def _check_env_vars(strings: list, iocs: dict):
    cfg  = iocs.get("sensitive_env_vars", {})
    blob = " ".join(strings)
    for pat in cfg.get("patterns", []):
        if re.search(r'\b' + re.escape(pat) + r'\b', blob):
            return pat, "high"
    for rx in cfg.get("regex_patterns", []):
        if re.search(rx, blob):
            return rx, "high"
    return None, ""


def _check_network(strings: list, iocs: dict, allowlist: dict):
    cfg  = iocs.get("suspicious_network", {})
    ok   = {d.lower() for d in allowlist.get("domains", [])}
    blob = " ".join(strings)

    for entry in cfg.get("known_malicious_domains", []):
        domain = entry["domain"] if isinstance(entry, dict) else entry
        if domain.lower() in blob.lower():
            return domain, "critical"

    def _allowed(s: str) -> bool:
        return any(d in s.lower() for d in ok)

    for s in strings:
        if _allowed(s):
            continue
        for svc in cfg.get("exfil_services", []):
            if svc.lower() in s.lower():
                return svc, "high"
        for tld in cfg.get("suspicious_tlds", []):
            if re.search(re.escape(tld) + r'(/|$|\?|#)', s, re.I):
                return tld, "medium"
        for rx in cfg.get("suspicious_patterns", []):
            if re.search(rx, s):
                return rx, "high"
    for rx in cfg.get("exfil_patterns", []):
        if re.search(rx, blob):
            return rx, "high"
    return None, ""


def _check_dangerous_commands(strings: list, iocs: dict):
    cfg  = iocs.get("dangerous_commands", {})
    blob = " ".join(strings)
    for rx in cfg.get("patterns", []):
        if re.search(rx, blob):
            return rx, "high"
    return None, ""


def _check_obfuscation(strings: list, iocs: dict):
    cfg  = iocs.get("obfuscation", {})
    blob = " ".join(strings)
    for rx in cfg.get("patterns", []):
        if re.search(rx, blob):
            return rx, "medium"
    return None, ""


def _check_prompt_injection(strings: list, iocs: dict):
    cfg  = iocs.get("prompt_injection", {})
    blob = " ".join(strings)
    for rx in cfg.get("patterns", []):
        if re.search(rx, blob):
            return rx, "high"
    return None, ""


def _check_zero_width_chars(strings: list):
    """
    Detect invisible Unicode characters used to hide malicious instructions
    inside file contents, tool descriptions, or MCP responses.
    (CVE-2025-54794 — InversePrompt attack)
    """
    for s in strings:
        for ch in ZERO_WIDTH_CHARS:
            if ch in s:
                return f"zero-width char U+{ord(ch):04X} detected", "high"
    return None, ""


def _check_claude_code_flags(strings: list, iocs: dict):
    """
    Detect flags that disable Claude Code safety mechanisms.
    Used by S1ngularity npm supply chain attack (2025) to run Claude
    with --dangerously-skip-permissions after installing malicious packages.
    """
    cfg  = iocs.get("claude_code_abuse", {})
    blob = " ".join(strings)
    for flag in cfg.get("patterns", []):
        if flag.lower() in blob.lower():
            return flag, "critical"
    return None, ""


def _check_supply_chain(strings: list, iocs: dict):
    """
    Detect patterns from confirmed npm/pip supply chain attacks:
    Shai-Hulud, S1ngularity, telemetry.js pattern, postinstall CI token theft.
    """
    cfg  = iocs.get("supply_chain", {})
    blob = " ".join(strings)

    for fname in cfg.get("malicious_files", []):
        if fname.lower() in blob.lower():
            return fname, "high"

    for rx in cfg.get("postinstall_patterns", []) + cfg.get("npm_ci_leak_patterns", []):
        if re.search(rx, blob):
            return rx, "high"

    return None, ""


def _check_tool_description_poisoning(strings: list, iocs: dict):
    """
    Detect tool poisoning patterns in MCP tool descriptions.
    (Invariant Labs research — hidden instructions in tool metadata)
    """
    cfg  = iocs.get("tool_description_poisoning", {})
    blob = " ".join(strings)
    for rx in cfg.get("patterns", []):
        if re.search(rx, blob):
            return rx, "high"
    return None, ""


def _load_mcp_scanned() -> set:
    """Return set of server names confirmed clean by argus_scan_mcp."""
    try:
        if MCP_SCANNED.exists():
            return set(json.loads(MCP_SCANNED.read_text()).get("confirmed_clean", []))
    except Exception:
        pass
    return set()


def _mcp_warned_recently(server: str) -> bool:
    """True if we warned about this server within MCP_WARN_TTL."""
    try:
        if MCP_SESSION.exists():
            ts = json.loads(MCP_SESSION.read_text()).get(server)
            if ts and (time.time() - ts) < MCP_WARN_TTL:
                return True
    except Exception:
        pass
    return False


def _record_mcp_warned(server: str):
    try:
        MCP_SESSION.parent.mkdir(parents=True, exist_ok=True)
        data: dict = {}
        if MCP_SESSION.exists():
            try:
                data = json.loads(MCP_SESSION.read_text())
            except Exception:
                pass
        now = time.time()
        data = {k: v for k, v in data.items() if (now - v) < MCP_WARN_TTL}
        data[server] = now
        MCP_SESSION.write_text(json.dumps(data))
    except Exception:
        pass


def _check_unknown_mcp(tool_name: str, allowlist: dict) -> tuple:
    """
    Detect first-time calls to MCP servers that haven't been scanned yet.
    Returns (warning_message, "medium") so it surfaces as additionalContext.
    Skips servers in the allowlist trusted_mcps list or already confirmed clean.
    """
    if not tool_name.startswith("mcp__"):
        return None, ""

    parts = tool_name.split("__")
    if len(parts) < 2:
        return None, ""

    server = parts[1]
    if not server:
        return None, ""

    # Allowlisted by user → trust it
    if server in set(allowlist.get("trusted_mcps", [])):
        return None, ""

    # Explicitly scanned and confirmed clean → trust it
    if server in _load_mcp_scanned():
        return None, ""

    # Already warned recently → deduplicate, stay silent
    if _mcp_warned_recently(server):
        return None, ""

    _record_mcp_warned(server)
    return (
        f"unscanned MCP server '{server}' — tool descriptions not yet verified",
        "medium",
    )


# ── Package install scanning ──────────────────────────────────────────────────

_INSTALL_RE = [
    (r'(?:^|\s)npm\s+(?:install|i)\s+((?:@[^\s/]+/)?[^\s\-@][^\s@]*)', "npm"),
    (r'(?:^|\s)yarn\s+add\s+((?:@[^\s/]+/)?[^\s\-@][^\s@]*)',           "npm"),
    (r'(?:^|\s)pnpm\s+add\s+((?:@[^\s/]+/)?[^\s\-@][^\s@]*)',           "npm"),
    (r'(?:^|\s)pip3?\s+install\s+([^\s\-][^\s]*)',                       "pip"),
    (r'(?:^|\s)pip3?\s+install\s+--\S+\s+([^\s\-][^\s]*)',              "pip"),
    (r'(?:^|\s)uv\s+add\s+([^\s\-][^\s]*)',                              "pip"),
]


def _strip_version(pkg: str) -> str:
    """Remove @version suffix while preserving @scope/name for scoped packages."""
    if pkg.startswith("@") and "/" in pkg:
        # @scope/name@version → @scope/name
        scope, rest = pkg.split("/", 1)
        return scope + "/" + rest.split("@")[0]
    return pkg.split("@")[0]


def _detect_install(cmd: str):
    """Return (package, ecosystem) if cmd is a package install, else (None, None)."""
    for rx, eco in _INSTALL_RE:
        m = re.search(rx, cmd, re.IGNORECASE)
        if m:
            pkg = _strip_version(m.group(1).rstrip(";").strip())
            if pkg and not pkg.startswith("-"):
                return pkg, eco
    return None, None


def _http_json(url: str, *, method: str = "GET", body: dict | None = None, timeout: int = 7):
    """Minimal HTTP helper — returns parsed JSON or None on any error."""
    try:
        data = json.dumps(body).encode() if body else None
        headers = {"User-Agent": "argus-security/1.0"}
        if body:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _scan_package(package: str, ecosystem: str) -> dict:
    """
    Pre-install scan against GitHub Advisory, OSV, NVD, npm registry, and PyPI.
    Returns {"findings": [...], "verdict": "clean"|"warn"|"block"}.
    """
    findings = []
    eco_ghsa = {"npm": "npm", "pip": "pip"}
    eco_osv  = {"npm": "npm", "pip": "PyPI"}

    # ── GitHub Advisory Database ───────────────────────────────────────────────
    ghsa = _http_json(
        f"https://api.github.com/advisories"
        f"?per_page=5&ecosystem={eco_ghsa.get(ecosystem,'npm')}"
        f"&package={urllib.parse.quote(package)}"
    )
    if ghsa and isinstance(ghsa, list):
        for adv in ghsa[:3]:
            sev     = (adv.get("severity") or "unknown").upper()
            summ    = (adv.get("summary") or "")[:100]
            ghsa_id = adv.get("ghsa_id", "?")
            findings.append({"source": "GHSA", "severity": sev,
                             "detail": f"{ghsa_id}: {summ}"})

    # ── Google OSV ─────────────────────────────────────────────────────────────
    osv = _http_json(
        "https://api.osv.dev/v1/query",
        method="POST",
        body={"package": {"ecosystem": eco_osv.get(ecosystem, "npm"), "name": package}},
    )
    if osv:
        for v in (osv.get("vulns") or [])[:3]:
            findings.append({"source": "OSV", "severity": "HIGH",
                             "detail": f"{v.get('id','?')}: {v.get('summary','')[:80]}"})

    # ── npm registry ───────────────────────────────────────────────────────────
    if ecosystem == "npm":
        npm_meta = _http_json(f"https://registry.npmjs.org/{urllib.parse.quote(package, safe='@/')}")
        if npm_meta and isinstance(npm_meta, dict):
            latest = (npm_meta.get("dist-tags") or {}).get("latest", "")
            versions = npm_meta.get("versions") or {}
            # Check if any version is deprecated
            if latest and versions.get(latest, {}).get("deprecated"):
                findings.append({
                    "source": "npm",
                    "severity": "MEDIUM",
                    "detail": f"deprecated: {str(versions[latest]['deprecated'])[:100]}",
                })
            # Check if published very recently (< 7 days) with no prior history
            times = npm_meta.get("time") or {}
            created_str = times.get("created", "")
            if created_str:
                try:
                    from datetime import timezone as _tz
                    created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                    age_days = (datetime.now(_tz.utc) - created).days
                    if age_days < 7 and len(versions) <= 2:
                        findings.append({
                            "source": "npm",
                            "severity": "LOW",
                            "detail": f"very new package — published {age_days}d ago, {len(versions)} version(s)",
                        })
                except Exception:
                    pass

    # ── PyPI registry ──────────────────────────────────────────────────────────
    if ecosystem == "pip":
        pypi_meta = _http_json(f"https://pypi.org/pypi/{urllib.parse.quote(package)}/json")
        if pypi_meta and isinstance(pypi_meta, dict):
            info = pypi_meta.get("info") or {}
            if info.get("yanked"):
                findings.append({
                    "source": "PyPI",
                    "severity": "CRITICAL",
                    "detail": f"yanked: {str(info.get('yanked_reason',''))[:100] or 'version pulled by maintainer'}",
                })
            for vuln in (pypi_meta.get("vulnerabilities") or [])[:3]:
                findings.append({
                    "source": "PyPI",
                    "severity": "HIGH",
                    "detail": f"{vuln.get('id','?')}: {str(vuln.get('details',''))[:80]}",
                })

    # ── NIST NVD ───────────────────────────────────────────────────────────────
    nvd = _http_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={urllib.parse.quote(package)}&resultsPerPage=3",
        timeout=6,
    )
    if nvd and isinstance(nvd, dict):
        for item in (nvd.get("vulnerabilities") or [])[:3]:
            cve  = item.get("cve") or {}
            cve_id = cve.get("id", "?")
            desc = next(
                (d["value"] for d in (cve.get("descriptions") or []) if d.get("lang") == "en"),
                "",
            )[:80]
            metrics = cve.get("metrics") or {}
            score = None
            sev   = "MEDIUM"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key)
                if metric_list:
                    data = metric_list[0].get("cvssData") or {}
                    score = data.get("baseScore")
                    sev   = (data.get("baseSeverity") or "MEDIUM").upper()
                    break
            if score and float(score) >= 7.0:
                findings.append({
                    "source": "NVD",
                    "severity": "CRITICAL" if float(score) >= 9.0 else "HIGH",
                    "detail": f"{cve_id} (CVSS {score}): {desc}",
                })

    # Deduplicate: same CVE ID from multiple sources → keep highest severity
    seen: dict = {}
    deduped = []
    for f in findings:
        key = f["detail"][:30]
        if key not in seen or SEVERITY_RANK.get(f["severity"].lower(), 0) > SEVERITY_RANK.get(seen[key].lower(), 0):
            seen[key] = f["severity"]
            deduped.append(f)
    findings = deduped

    verdict = (
        "block" if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings) else
        "warn"  if findings else
        "clean"
    )
    return {"package": package, "ecosystem": ecosystem,
            "findings": findings, "verdict": verdict}


_SCAN_BAR = "━" * 50


def _print_scan(result: dict):
    """Print package scan result to stderr → appears in terminal immediately."""
    pkg     = result["package"]
    eco     = result["ecosystem"]
    verdict = result["verdict"]
    findings = result["findings"]

    icon  = {"block": "🚫", "warn": "⚠️ ", "clean": "✅"}[verdict]
    label = {"block": "BLOCKED", "warn": "WARNING", "clean": "CLEAN"}[verdict]

    lines = [
        f"\n{_SCAN_BAR}",
        f"  {icon}  ARGUS — Package scan: {pkg} ({eco})",
        _SCAN_BAR,
    ]
    if findings:
        for f in findings:
            lines.append(f"  [{f['source']}] [{f['severity']}] {f['detail']}")
    else:
        sources = "GHSA · OSV · NVD"
        sources += " · npm" if eco == "npm" else " · PyPI"
        lines.append(f"  {sources}: no vulnerabilities found")
    lines += [f"  Verdict: {label}", _SCAN_BAR, ""]

    print("\n".join(lines), file=sys.stderr, flush=True)


def _audit_scan(package: str, ecosystem: str, verdict: str, count: int):
    """Write a package scan event to the audit log."""
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts":       datetime.now(timezone.utc).isoformat(),
            "hook":     "PreToolUse/PackageScan",
            "decision": verdict,
            "severity": "high" if verdict == "block" else "medium" if verdict == "warn" else "none",
            "tool":     "Bash",
            "matched":  f"{package} ({ecosystem}) — {count} finding(s)",
            "sources":  ["GHSA", "OSV", "NVD", "npm_registry", "PyPI_registry"],
            "cwd":      str(Path.cwd()),
        }
        with AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass


def _check_tool_specific(tool_name: str, tool_input: dict):
    """Extra checks specific to particular tool types."""
    if tool_name in ("Bash",):
        cmd = tool_input.get("command") or ""

        if re.search(r'>\s*/etc/(cron|init\.d|rc\d\.d|systemd)', cmd, re.I):
            return "write to system init/cron path", "high"

        if re.search(r'/proc/\d+/environ', cmd):
            return "/proc/*/environ access", "high"

        if re.search(r'shred\s+.*-[a-z]*[vfz]', cmd, re.I):
            return "shred (destructive wipe)", "high"

        if re.search(r'history\s+-[cw]', cmd, re.I):
            return "shell history wipe", "medium"

    if tool_name in ("Write", "Edit", "NotebookEdit"):
        path = tool_input.get("file_path", "") or ""
        content = tool_input.get("content", "") or tool_input.get("new_string", "") or ""
        critical = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/hosts", "~/.ssh/authorized_keys", "/etc/cron",
        ]
        for c in critical:
            if _path_hit(path, c):
                return f"write to critical file: {c}", "critical"

        # Detect postinstall hooks with suspicious content in package.json
        if "package.json" in path and re.search(r'"postinstall"\s*:', content, re.I):
            if re.search(r'(curl|wget|fetch|http)', content, re.I):
                return "suspicious postinstall hook in package.json", "high"

    return None, ""


# ── Rate limiter ──────────────────────────────────────────────────────────────

def _escalate_if_burst(severity: str) -> str:
    if severity not in ("medium", "low"):
        return severity
    now = time.time()
    state: dict = {}
    if RATE_STATE.exists():
        try:
            state = json.loads(RATE_STATE.read_text())
        except Exception:
            pass
    events = [t for t in state.get("events", []) if now - t < RATE_WINDOW]
    events.append(now)
    try:
        RATE_STATE.parent.mkdir(parents=True, exist_ok=True)
        RATE_STATE.write_text(json.dumps({"events": events}))
    except Exception:
        pass
    return "high" if len(events) >= RATE_BURST else severity


# ── Audit log ─────────────────────────────────────────────────────────────────

def _audit(decision: str, severity: str, tool: str, matched: str, tool_input: dict):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts":       datetime.now(timezone.utc).isoformat(),
            "hook":     "PreToolUse",
            "decision": decision,
            "severity": severity,
            "tool":     tool,
            "matched":  matched,
            "hash":     hashlib.sha256(
                            json.dumps(tool_input, sort_keys=True).encode()
                        ).hexdigest()[:16],
            "cwd":      str(Path.cwd()),
        }
        with AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass


# ── Human-readable messages ───────────────────────────────────────────────────

# Maps pattern types to plain-English explanations
_EXPLANATIONS = {
    "~/.ssh":                    "SSH private keys — reading these enables impersonation and server access",
    "~/.aws":                    "AWS credentials — leaking these gives full cloud account access",
    "~/.kube":                   "Kubernetes config — contains cluster credentials and access tokens",
    "~/.docker":                 "Docker Hub credentials",
    "~/.vault-token":            "HashiCorp Vault token — grants access to all secrets in Vault",
    "~/.config/gcloud":          "Google Cloud credentials",
    "~/.azure":                  "Azure credentials",
    ".env":                      "Environment file — likely contains API keys and secrets",
    "tfstate":                   "Terraform state — contains infrastructure secrets in plaintext",
    ".pem":                      "Private key or certificate file",
    "/etc/shadow":               "Linux password hashes for all system users",
    "/etc/passwd":               "Linux user account database",
    "/proc/":                    "Live process environment — can expose secrets of running processes",
    "curl":                      "Remote code execution — downloading and running untrusted code",
    "wget":                      "Remote code execution — downloading and running untrusted code",
    "/dev/tcp/":                 "Reverse shell — opens a backdoor connection to a remote host",
    "nc ":                       "Netcat reverse shell",
    "base64":                    "Obfuscated payload — decoding and executing hidden commands",
    "\\x":                       "Hex-encoded shellcode",
    "pastebin":                  "Data exfiltration via paste service",
    "transfer.sh":               "Data exfiltration via file sharing service",
    "webhook.site":              "Data exfiltration via webhook service",
    "ngrok":                     "Tunnel to external server — used to exfiltrate data",
    "discord.com/api/webhooks":  "Data exfiltration via Discord webhook",
    "giftshop.club":             "CONFIRMED MALICIOUS — Postmark MCP backdoor (Sept 2025)",
    "ignore previous":           "Prompt injection — attempt to override Claude's instructions",
    "zero-width":                "Invisible Unicode chars — used to hide malicious instructions",
    "--dangerously-skip":        "Disables Claude Code safety mechanisms (used by S1ngularity malware)",
    "telemetry.js":              "Known supply chain attack file (Shai-Hulud npm campaign 2025)",
    "chmod":                     "Privilege escalation — making files executable as root (SUID)",
    "LD_PRELOAD":                "Library injection — used to intercept system calls",
    "crontab":                   "Persistence — adding malicious scheduled tasks",
    "systemctl enable":          "Persistence — registering a malicious system service",
    "shred":                     "Destructive wipe — permanently destroying files",
    "history -c":                "Covering tracks — erasing shell command history",
    "/etc/sudoers":              "Privilege escalation — modifying sudo permissions",
    "authorized_keys":           "Backdoor — adding attacker's SSH key for permanent access",
    "postinstall":               "Supply chain hook — code running automatically on package install",
}

def _explain(match: str) -> str:
    """Return a plain-English explanation for a matched pattern."""
    m = match.lower()
    for key, explanation in _EXPLANATIONS.items():
        if key.lower() in m:
            return explanation
    return "matches a known attack pattern"


def _allowlist_hint(match: str, tool_name: str, tool_input: dict) -> str:
    """Suggest how to allowlist this if it's a false positive."""
    m = match.lower()
    if any(p in m for p in ["~/.ssh", "~/.aws", "~/.kube", ".env", ".pem", "/etc/"]):
        path = tool_input.get("file_path") or tool_input.get("command") or ""
        return (
            f'If this is intentional, add to ~/.argus/allowlist.json:\n'
            f'  {{"paths": ["{match}"]}}'
        )
    if any(d in m for d in ["http", "webhook", "ngrok", "discord"]):
        return (
            f'If this domain is trusted, add to ~/.argus/allowlist.json:\n'
            f'  {{"domains": ["{match}"]}}'
        )
    return "If this is a false positive, add it to ~/.argus/allowlist.json"


def _block_message(tool_name: str, tool_input: dict, match: str, severity: str) -> str:
    explanation = _explain(match)
    hint        = _allowlist_hint(match, tool_name, tool_input)
    sev_upper   = severity.upper()

    # Show what was attempted
    preview = ""
    if tool_name == "Bash":
        cmd = (tool_input.get("command") or "")[:120]
        preview = f"\nCommand: {cmd}"
    elif tool_name in ("Read", "Write", "Edit"):
        path = tool_input.get("file_path", "")[:120]
        preview = f"\nFile: {path}"

    return (
        f"🚫 ARGUS — Action blocked [{sev_upper}]\n"
        f"\n"
        f"Tool:     {tool_name}{preview}\n"
        f"Matched:  {match}\n"
        f"Reason:   {explanation}\n"
        f"\n"
        f"Tell the user what was blocked and why. Do not retry this action.\n"
        f"\n"
        f"False positive? {hint}\n"
        f"Audit log: ~/.argus/logs/audit.jsonl"
    )


def _warn_message(tool_name: str, match: str, severity: str) -> str:
    explanation = _explain(match)
    return (
        f"⚠️  ARGUS WARNING [{severity.upper()}]\n"
        f"Suspicious pattern detected: {match}\n"
        f"Reason: {explanation}\n"
        f"Proceed only if you are certain this is intentional. "
        f"Tell the user what you are about to do and why before continuing."
    )


# ── Stage 0: Integration check ───────────────────────────────────────────────

def _check_trusted_integrations(strings: list, tool_name: str, allowlist: dict) -> bool:
    """
    Return True if this operation matches an explicitly configured trusted integration.
    If True, skip all further checks — the user said this is OK.
    """
    integrations = allowlist.get("integrations", {})
    if not integrations:
        return False

    blob = " ".join(strings).lower()

    for name, cfg in integrations.items():
        if not isinstance(cfg, dict):
            continue

        # Check allowed domains
        for domain in cfg.get("allowed_domains", []):
            if domain.lower() in blob:
                # Make sure it's not in the blocked list too
                blocked = cfg.get("blocked_patterns", [])
                if not any(b.lower() in blob for b in blocked):
                    return True

        # Check allowed command patterns
        for pattern in cfg.get("allowed_patterns", []):
            if pattern.lower() in blob:
                # Make sure it's not blocked
                blocked = cfg.get("blocked_patterns", [])
                if not any(b.lower() in blob for b in blocked):
                    return True

    return False


# ── Decision engine ───────────────────────────────────────────────────────────

def _best(*pairs) -> tuple:
    winner = (None, "")
    for match, sev in pairs:
        if match and SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(winner[1], 0):
            winner = (match, sev)
    return winner


_DOC_EXTENSIONS = {".md", ".txt", ".rst", ".adoc", ".mdx"}


def _is_doc_write(tool_name: str, tool_input: dict) -> bool:
    """True when writing/editing a documentation file — content may mention sensitive paths as examples."""
    if tool_name not in ("Write", "Edit", "NotebookEdit"):
        return False
    path = tool_input.get("file_path", "") or ""
    return any(path.lower().endswith(ext) for ext in _DOC_EXTENSIONS)


def decide(tool_name: str, tool_input: dict) -> dict:
    iocs      = _iocs()
    allowlist = _allowlist()
    strings   = _strings(tool_input)

    # ── Stage 0: Trusted integration? Allow immediately ───────────────────────
    if _check_trusted_integrations(strings, tool_name, allowlist):
        return {}

    # ── Stage 0b: Package install scan ────────────────────────────────────────
    # Runs before IOC checks so install commands get threat intel results
    # printed to terminal AND logged, regardless of what the regex finds.
    # Skip when ARGUS_NO_NETWORK=1 (CI/offline) or ARGUS_NO_LLM=1.
    if tool_name == "Bash" and not os.environ.get("ARGUS_NO_NETWORK") and not os.environ.get("ARGUS_NO_LLM"):
        cmd = tool_input.get("command") or ""
        _pkg, _eco = _detect_install(cmd)
        if _pkg:
            _scan = _scan_package(_pkg, _eco)
            _print_scan(_scan)
            _audit_scan(_pkg, _eco, _scan["verdict"], len(_scan["findings"]))
            if _scan["verdict"] == "block":
                _audit("block", "high", tool_name, f"[PackageScan] {_pkg}", tool_input)
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"🚫 ARGUS — Package blocked: {_pkg} ({_eco})\n\n"
                            f"Known vulnerabilities:\n" +
                            "\n".join(f"  • [{f['source']}] {f['detail']}"
                                      for f in _scan["findings"]) +
                            f"\n\nFull details printed to terminal.\n"
                            f"Audit log: ~/.argus/logs/audit.jsonl"
                        ),
                    }
                }
            # warn → continue to regular checks; scan already printed to terminal

    # ── Stage 1: Regex / IOC checks ───────────────────────────────────────────
    # Two content-scan levels for Write/Edit:
    #
    #   trusted_path (allowlist.paths) — user explicitly said "I own this dir".
    #     Skip ALL regex content checks. Zero-width chars still checked (invisible
    #     chars have no legitimate use even in source code). LLM still runs.
    #
    #   is_doc (.md/.txt/etc) — documentation files.
    #     Skip path/env/network regex on content (legitimate examples).
    #     Keep injection checks (prompt injection in docs IS a real attack vector).
    #
    file_path    = tool_input.get("file_path", "") or ""
    trusted_path = (
        tool_name in ("Write", "Edit", "NotebookEdit")
        and any(_path_hit(file_path, a) for a in allowlist.get("paths", []))
    )
    is_doc = _is_doc_write(tool_name, tool_input)

    # Always write debug info so we can inspect what's happening
    try:
        _dbg = Path.home() / ".argus" / "debug-decide.json"
        _dbg.write_text(json.dumps({
            "tool_name": tool_name,
            "file_path": file_path,
            "is_doc": is_doc,
            "trusted_path": trusted_path,
            "tool_input_keys": list(tool_input.keys()),
            "content_preview": str(list(tool_input.values()))[:200],
        }, indent=2))
    except Exception:
        pass

    if trusted_path:
        # Trusted dev path — skip all content regex, only check the file_path
        scan_strings   = [file_path]
        inject_strings = []
        poison_strings = []
    elif is_doc:
        # Doc file — skip path/env/network/exfil on content (legit doc examples).
        # Keep prompt_injection and tool_description_poisoning on full content —
        # both are real attack vectors even in doc files.
        scan_strings   = [file_path]
        inject_strings = strings
        poison_strings = strings
    else:
        scan_strings   = strings
        inject_strings = strings
        poison_strings = strings

    match, severity = _best(
        _check_sensitive_paths(scan_strings, iocs, allowlist),
        _check_env_vars(scan_strings, iocs),
        _check_network(scan_strings, iocs, allowlist),
        _check_dangerous_commands(scan_strings, iocs),
        _check_obfuscation(scan_strings, iocs),
        _check_claude_code_flags(scan_strings, iocs),
        _check_supply_chain(scan_strings, iocs),
        _check_prompt_injection(inject_strings, iocs),
        _check_tool_description_poisoning(poison_strings, iocs),
        _check_zero_width_chars(strings),   # always — no legitimate use for invisible chars
        _check_tool_specific(tool_name, tool_input),
    )

    # ── Stage 2: LLM analysis (only when useful) ──────────────────────────────
    llm_result = None
    use_llm    = (
        _LLM_AVAILABLE
        and not os.environ.get("ARGUS_NO_LLM")  # set this in tests or CI
    )

    if use_llm:
        # LLM always runs for Bash/Write/Edit — acts as a second opinion on top of regex.
        # For regex blocks: LLM can downgrade false positives or confirm/upgrade severity.
        # For regex misses: LLM catches novel attacks that patterns didn't detect.
        if tool_name in ("Bash", "Write", "Edit", "NotebookEdit"):
            findings = ([{"match": match, "severity": severity, "tool": tool_name}]
                        if match else [])
            llm_result = _llm.analyze(tool_name, tool_input, findings, is_doc=is_doc)

            # LLM says block → always block regardless of regex result
            if llm_result["decision"] == "block" and llm_result.get("confidence", 0) >= 0.85:
                matched = llm_result.get("reason", "LLM detected threat")
                _audit("block", "high", tool_name, f"[LLM] {matched}", tool_input)
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"🚫 ARGUS — Action blocked [HIGH — LLM analysis]\n\n"
                            f"Tool: {tool_name}\n"
                            f"Reason: {matched}\n"
                            f"({'No regex pattern matched, but ' if not match else ''}Claude Haiku flagged this as malicious)\n\n"
                            f"Audit log: ~/.argus/logs/audit.jsonl"
                        ),
                    }
                }

            # LLM says false positive on a regex match → downgrade to allow
            if match and llm_result["decision"] == "allow" and llm_result.get("confidence", 0) >= 0.85:
                _audit("allow_llm_override", severity, tool_name,
                       f"[LLM override] {llm_result.get('reason','')}", tool_input)
                return {}

            # LLM confirms regex match → upgrade severity to high
            if match and llm_result["decision"] == "block" and llm_result.get("confidence", 0) >= 0.75:
                severity = "high"

    # ── MCP unknown server check (always runs, never blocks — additionalContext only) ──
    mcp_match, _ = _check_unknown_mcp(tool_name, allowlist)

    if not match:
        if mcp_match:
            _audit("warn", "medium", tool_name, mcp_match, tool_input)
            return {
                "additionalContext": (
                    f"⚠️  ARGUS — Unscanned MCP server\n"
                    f"Server: {tool_name.split('__')[1] if '__' in tool_name else tool_name}\n"
                    f"This server's tool descriptions have not been verified for prompt injection.\n"
                    f"Run /scan-mcps to audit all registered MCP servers before continuing.\n"
                    f"To silence this: add the server to trusted_mcps in ~/.argus/allowlist.json"
                )
            }
        return {}

    severity = _escalate_if_burst(severity)
    rank     = SEVERITY_RANK.get(severity, 0)

    llm_note = ""
    if llm_result and llm_result.get("source") == "llm":
        conf = int(llm_result.get("confidence", 0) * 100)
        llm_note = f"\nLLM confirmation: {llm_result.get('reason','')} ({conf}% confidence)"

    if rank >= SEVERITY_RANK["high"]:
        _audit("block", severity, tool_name, match, tool_input)
        reason = _block_message(tool_name, tool_input, match, severity) + llm_note
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

    warn_text = _warn_message(tool_name, match, severity) + llm_note
    if mcp_match:
        warn_text += (
            f"\n\n⚠️  Additionally: '{tool_name.split('__')[1] if '__' in tool_name else tool_name}' "
            f"has not been scanned. Run /scan-mcps to verify its tool descriptions."
        )
    _audit("warn", severity, tool_name, match, tool_input)
    return {"additionalContext": warn_text}


def _check_type_from_match(match: str) -> str:
    """Infer which check produced a match, to decide if LLM review is useful."""
    m = match.lower()
    if "ignore" in m or "bypass" in m or "previous" in m or "system" in m:
        return "prompt_injection"
    if "base64" in m or "\\x" in m or "__import__" in m or "iex" in m:
        return "obfuscation"
    if "zero-width" in m or "u+200" in m:
        return "zero_width_char"
    if "telemetry" in m or "setup_bun" in m or "postinstall" in m:
        return "supply_chain"
    if "<important>" in m or "hidden instructions" in m:
        return "tool_description_poisoning"
    return "other"


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    try:
        event      = json.load(sys.stdin)
        # Debug mode: dump raw event to file when ARGUS_DEBUG is set
        if os.environ.get("ARGUS_DEBUG"):
            debug_path = Path.home() / ".argus" / "debug-event.json"
            debug_path.write_text(json.dumps(event, indent=2))
        tool_name  = event.get("tool_name", "")
        tool_input = event.get("tool_input", {})
        result     = decide(tool_name, tool_input)
        print(json.dumps(result))
    except Exception:
        print(json.dumps({}))


if __name__ == "__main__":
    main()
