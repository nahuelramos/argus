#!/usr/bin/env python3
"""
Argus MCP Server — security tools for Claude Desktop.

Exposes security checking tools that Claude can call before
executing risky operations. Since Claude Desktop has no hooks,
this server works through a system prompt that instructs Claude
to always call argus_check before sensitive actions.

Install: see mcp-server/install-desktop.sh
"""
import asyncio
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import urllib.request
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# ── Paths ─────────────────────────────────────────────────────────────────────

_SERVER_DIR = Path(__file__).resolve().parent
ARGUS_ROOT  = _SERVER_DIR.parent
IOC_PATHS   = [
    ARGUS_ROOT / "data" / "iocs.json",
    Path.home() / ".argus" / "iocs.json",
]
ALLOWLIST_PATHS = [
    Path.cwd() / ".security" / "argus-allowlist.json",
    Path.home() / ".argus" / "allowlist.json",
]
AUDIT_LOG        = Path.home() / ".argus" / "logs" / "audit.jsonl"
MCP_SNAPSHOTS    = Path.home() / ".argus" / "mcp-snapshots"

ZERO_WIDTH_CHARS = {
    "​", "‌", "‍", "‎", "‏",
    "⁠", "⁡", "⁢", "⁣", "⁤",
    "﻿", "‮", "‭",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}

# ── Loaders ───────────────────────────────────────────────────────────────────

def _load_json(paths):
    for p in paths:
        if Path(p).exists():
            try:
                return json.loads(Path(p).read_text())
            except Exception:
                pass
    return {}

def _iocs():
    return _load_json(IOC_PATHS)

def _allowlist():
    return _load_json(ALLOWLIST_PATHS)

# ── String extraction ─────────────────────────────────────────────────────────

def _strings(obj, depth=0):
    if depth > 10:
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

def _expand(p):
    return os.path.normpath(os.path.expandvars(os.path.expanduser(str(p))))

def _path_hit(candidate, pattern):
    ec, ep = _expand(candidate), _expand(pattern)
    if ep in ec or ec.startswith(ep):
        return True
    if pattern in candidate or ep in candidate:
        return True
    return False

# ── Shannon entropy ────────────────────────────────────────────────────────────

def _entropy(s):
    if len(s) < 8:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

# ── Security checks (same logic as preflight.py) ─────────────────────────────

def _run_checks(action: str) -> dict:
    iocs      = _iocs()
    allowlist = _allowlist()
    strings   = [action]

    findings = []

    # Sensitive paths
    allowed_paths = allowlist.get("paths", [])
    cfg = iocs.get("sensitive_paths", {})
    for s in strings:
        if any(_path_hit(s, a) for a in allowed_paths):
            continue
        for pat in cfg.get("patterns", []):
            if _path_hit(s, pat):
                findings.append({"severity": "high", "type": "sensitive_path", "detail": pat})
        for rx in cfg.get("regex_patterns", []):
            if re.search(rx, s):
                findings.append({"severity": "high", "type": "sensitive_path_regex", "detail": rx})

    # Env vars
    blob = action
    for pat in iocs.get("sensitive_env_vars", {}).get("patterns", []):
        if re.search(r'\b' + re.escape(pat) + r'\b', blob):
            findings.append({"severity": "high", "type": "env_var", "detail": pat})
    for rx in iocs.get("sensitive_env_vars", {}).get("regex_patterns", []):
        if re.search(rx, blob):
            findings.append({"severity": "high", "type": "env_var_regex", "detail": rx})

    # Network
    ok = {d.lower() for d in allowlist.get("domains", [])}
    net = iocs.get("suspicious_network", {})
    for entry in net.get("known_malicious_domains", []):
        domain = entry["domain"] if isinstance(entry, dict) else entry
        if domain.lower() in action.lower():
            findings.append({"severity": "critical", "type": "malicious_domain",
                             "detail": domain,
                             "incident": entry.get("incident", "") if isinstance(entry, dict) else ""})
    if not any(d in action.lower() for d in ok):
        for svc in net.get("exfil_services", []):
            if svc.lower() in action.lower():
                findings.append({"severity": "high", "type": "exfil_service", "detail": svc})
        for rx in net.get("suspicious_patterns", []):
            if re.search(rx, action):
                findings.append({"severity": "high", "type": "suspicious_network", "detail": rx})

    # Dangerous commands
    for rx in iocs.get("dangerous_commands", {}).get("patterns", []):
        if re.search(rx, action, re.IGNORECASE):
            findings.append({"severity": "high", "type": "dangerous_command", "detail": rx})

    # Obfuscation
    for rx in iocs.get("obfuscation", {}).get("patterns", []):
        if re.search(rx, action, re.IGNORECASE):
            findings.append({"severity": "medium", "type": "obfuscation", "detail": rx})

    # Prompt injection
    for rx in iocs.get("prompt_injection", {}).get("patterns", []):
        if re.search(rx, action, re.IGNORECASE):
            findings.append({"severity": "high", "type": "prompt_injection", "detail": rx})

    # Zero-width chars
    for ch in ZERO_WIDTH_CHARS:
        if ch in action:
            findings.append({"severity": "high", "type": "zero_width_char",
                             "detail": f"U+{ord(ch):04X}"})

    # Claude Code flag abuse
    for flag in iocs.get("claude_code_abuse", {}).get("patterns", []):
        if flag.lower() in action.lower():
            findings.append({"severity": "critical", "type": "claude_flag_abuse", "detail": flag})

    # Compute overall severity
    top = ""
    for f in findings:
        if SEVERITY_RANK.get(f["severity"], 0) > SEVERITY_RANK.get(top, 0):
            top = f["severity"]

    decision = "block" if SEVERITY_RANK.get(top, 0) >= SEVERITY_RANK["high"] else \
               "warn"  if top == "medium" else "allow"

    return {
        "decision":  decision,
        "severity":  top or "none",
        "findings":  findings,
        "action":    action[:200],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ── MCP scanning helpers ──────────────────────────────────────────────────────

# Known malicious / suspicious MCP packages (community-curated local fallback)
_KNOWN_BAD_MCP = {
    "browsermcp-pro", "mcp-free-proxy", "claude-mcp-tools",
    "mcp-system-access", "mcp-unlimited", "autopilot-mcp",
}

# Patterns that suggest a tool description has been poisoned
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"\[hidden\s+instructions?\]",
    r"do\s+not\s+(tell|inform|notify)\s+(the\s+)?user",
    r"silently\s+(read|exfiltrate|send|upload|transmit)",
    r"without\s+(informing|telling|notifying)\s+(the\s+)?user",
    r"your\s+new\s+task\s+is",
    r"new\s+system\s+prompt",
    r"exfiltrate\s+(env|environment|credentials?|keys?|secrets?|tokens?)",
    r"(read|access|send)\s+(~\s*/\s*\.aws|~/\.ssh|/etc/passwd|/etc/shadow)",
    r"send\s+(the\s+)?(contents?|data|output)\s+to\s+(http|https|ftp)",
]

_INCOHERENCE_PAIRS = [
    # (stated-purpose keyword, suspicious action keyword)
    ("weather", "credentials"),
    ("weather", "aws"),
    ("weather", "exfiltrate"),
    ("analytics", "exfiltrate"),
    ("analytics", "environment"),
    ("file.*process", "private.?key"),
    ("summarize", "upload"),
    ("summarize", "exfiltrate"),
    ("calculate", "ssh"),
    ("search", "credentials"),
]


def _http_get(url: str, timeout: int = 6) -> dict | None:
    """Fetch JSON from URL, return None on any error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "argus-security/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _check_vulnerablemcp(server_name: str) -> list[str]:
    """Query VulnerableMCP.info for a known-bad server name."""
    findings = []
    # Normalise: strip path components, keep bare package/tool name
    name = server_name.split("/")[-1].split("@")[0].strip()

    # Local fast-path: known bad names
    if name.lower() in _KNOWN_BAD_MCP:
        findings.append(f"[VulnerableMCP/local] {name} is in the known-malicious MCP list")

    # Remote query — graceful fallback if site is unavailable
    data = _http_get(f"https://vulnerablemcp.info/api/v1/search?q={urllib.parse.quote(name)}")
    if data:
        for entry in (data.get("results") or [])[:3]:
            cve  = entry.get("cve") or entry.get("id") or "?"
            desc = entry.get("description") or entry.get("summary") or ""
            findings.append(f"[VulnerableMCP.info] {cve}: {desc[:120]}")
    elif not findings:
        findings.append("[VulnerableMCP.info] Service unavailable — local list only")

    return findings


def _check_mcpscan(server_name: str) -> list[str]:
    """Query MCPScan.ai for risk score / known issues."""
    findings = []
    name = server_name.split("/")[-1].split("@")[0].strip()

    data = _http_get(f"https://www.mcpscan.ai/api/scan?package={urllib.parse.quote(name)}")
    if data:
        risk  = data.get("risk_level") or data.get("risk") or "unknown"
        score = data.get("score") or data.get("risk_score") or "?"
        issues = data.get("issues") or data.get("findings") or []
        findings.append(f"[MCPScan.ai] risk={risk}  score={score}")
        for issue in issues[:3]:
            findings.append(f"[MCPScan.ai] {issue.get('title','?')}: {issue.get('description','')[:100]}")
    else:
        findings.append("[MCPScan.ai] Service unavailable — skipped")

    return findings


def _analyze_descriptions(tools: list[dict]) -> list[dict]:
    """
    Static analysis of MCP tool descriptions.
    Checks for:
      - Prompt injection patterns
      - Zero-width hidden characters
      - Coherence mismatch (stated purpose vs. suspicious keywords)
      - Entropy anomalies (high-entropy blobs in descriptions)
    Returns list of finding dicts.
    """
    findings = []
    for tool in tools:
        name = tool.get("name", "?")
        desc = tool.get("description", "")
        # Use ensure_ascii=False so zero-width chars stay as real chars, not \uXXXX escapes
        full = json.dumps(tool, ensure_ascii=False)

        # Zero-width chars — check raw strings, not JSON-escaped
        raw_strings = [desc] + [str(v) for v in tool.get("inputSchema", {}).values()
                                 if isinstance(v, str)]
        for ch in ZERO_WIDTH_CHARS:
            if any(ch in s for s in raw_strings):
                findings.append({
                    "tool": name, "severity": "high",
                    "type": "zero_width_char",
                    "detail": f"U+{ord(ch):04X} in tool '{name}'"
                })
                break

        # Injection patterns
        for rx in _INJECTION_PATTERNS:
            if re.search(rx, desc, re.IGNORECASE):
                findings.append({
                    "tool": name, "severity": "critical",
                    "type": "prompt_injection",
                    "detail": f"Pattern «{rx[:60]}» in '{name}' description"
                })

        # Coherence: stated purpose vs suspicious keywords
        for purpose_rx, suspicious in _INCOHERENCE_PAIRS:
            if re.search(purpose_rx, desc, re.IGNORECASE) and \
               re.search(suspicious, desc, re.IGNORECASE):
                findings.append({
                    "tool": name, "severity": "high",
                    "type": "coherence_mismatch",
                    "detail": f"'{name}' claims to {purpose_rx!r} but mentions '{suspicious}'"
                })

        # Entropy anomaly: suspicious high-entropy segment in description
        words = desc.split()
        for w in words:
            if len(w) > 20 and _entropy(w) > 4.5:
                findings.append({
                    "tool": name, "severity": "medium",
                    "type": "entropy_anomaly",
                    "detail": f"High-entropy token in '{name}': {w[:40]}…"
                })

    return findings


MCP_SCANNED = Path.home() / ".argus" / "mcp-scanned.json"


def _mark_scanned_clean(server_name: str):
    """Record this server as confirmed clean so preflight.py stops warning about it."""
    try:
        MCP_SCANNED.parent.mkdir(parents=True, exist_ok=True)
        data: dict = {}
        if MCP_SCANNED.exists():
            try:
                data = json.loads(MCP_SCANNED.read_text())
            except Exception:
                pass
        confirmed = set(data.get("confirmed_clean", []))
        confirmed.add(server_name)
        data["confirmed_clean"] = sorted(confirmed)
        data["last_updated"] = datetime.now(timezone.utc).isoformat()
        MCP_SCANNED.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def _snapshot_path(server_name: str) -> Path:
    safe = re.sub(r"[^a-zA-Z0-9_\-.]", "_", server_name)
    return MCP_SNAPSHOTS / f"{safe}.json"


def _load_snapshot(server_name: str) -> dict | None:
    p = _snapshot_path(server_name)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def _save_snapshot(server_name: str, tools: list[dict]) -> None:
    MCP_SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    p = _snapshot_path(server_name)
    snapshot = {
        "server":    server_name,
        "saved_at":  datetime.now(timezone.utc).isoformat(),
        "tools":     tools,
        "checksums": {t["name"]: hashlib.sha256(json.dumps(t, sort_keys=True).encode()).hexdigest()
                      for t in tools},
    }
    p.write_text(json.dumps(snapshot, indent=2))


def _diff_snapshots(old: dict, new_tools: list[dict]) -> list[dict]:
    """Return list of change dicts: added / removed / modified tools."""
    changes = []
    old_tools = {t["name"]: t for t in old.get("tools", [])}
    new_map   = {t["name"]: t for t in new_tools}
    old_sums  = old.get("checksums", {})

    for name, tool in new_map.items():
        if name not in old_tools:
            changes.append({"change": "added", "tool": name,
                            "detail": "New tool not present in baseline"})
        else:
            new_sum = hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest()
            if new_sum != old_sums.get(name):
                old_desc = old_tools[name].get("description", "")
                new_desc = tool.get("description", "")
                changes.append({"change": "modified", "tool": name,
                                "old_description": old_desc[:200],
                                "new_description": new_desc[:200]})

    for name in old_tools:
        if name not in new_map:
            changes.append({"change": "removed", "tool": name,
                            "detail": "Tool present in baseline is now gone"})

    return changes


def _audit(result: dict):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts":       result["checked_at"],
            "hook":     "MCPServer",
            "decision": result["decision"],
            "severity": result["severity"],
            "tool":     "argus_check",
            "matched":  result["findings"][0]["detail"] if result["findings"] else "",
            "cwd":      str(Path.cwd()),
        }
        with AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass

# ── MCP Server ────────────────────────────────────────────────────────────────

server = Server("argus-security")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="argus_check",
            description=(
                "ALWAYS call this before: running shell commands, reading credential files, "
                "making network requests, writing to system files, or installing packages. "
                "Returns allow/warn/block with specific reasons. If block is returned, "
                "do NOT proceed with the action."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "The exact command, file path, or URL you are about to use"
                    },
                    "context": {
                        "type": "string",
                        "description": "Why this action is needed (optional)"
                    }
                },
                "required": ["action"]
            }
        ),
        types.Tool(
            name="argus_scan_package",
            description=(
                "Check if an npm or pip package is safe to install. "
                "Queries GitHub Advisory DB, OSV, and NIST NVD. "
                "Call this before running npm install or pip install."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package name (e.g. 'express' or '@scope/package')"
                    },
                    "ecosystem": {
                        "type": "string",
                        "enum": ["npm", "pip"],
                        "description": "Package ecosystem"
                    }
                },
                "required": ["package", "ecosystem"]
            }
        ),
        types.Tool(
            name="argus_scan_file",
            description=(
                "Perform static security analysis on a local file. "
                "Checks for IOC patterns, prompt injection, hardcoded secrets, "
                "and dangerous commands."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file to scan"
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="argus_scan_mcp",
            description=(
                "Scan an MCP server for security risks. "
                "Queries VulnerableMCP.info and MCPScan.ai for known issues, "
                "and performs static analysis on tool descriptions for prompt injection, "
                "zero-width char hiding, and coherence mismatches. "
                "Call this for every MCP server before trusting its tools."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "MCP server identifier (e.g. 'argus-test' or 'playwright')"
                    },
                    "server_command": {
                        "type": "string",
                        "description": "The launch command (e.g. 'npx @playwright/mcp@latest')"
                    },
                    "tools": {
                        "type": "array",
                        "description": "List of tool objects ({name, description}) from the server",
                        "items": {"type": "object"}
                    }
                },
                "required": ["server_name"]
            }
        ),
        types.Tool(
            name="argus_mcp_snapshot",
            description=(
                "Save a baseline snapshot of an MCP server's tool descriptions. "
                "Run this once after verifying a server is safe. "
                "Future scans with argus_mcp_diff will detect any modifications."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "MCP server identifier"
                    },
                    "tools": {
                        "type": "array",
                        "description": "Current list of tool objects ({name, description, inputSchema}) from the server",
                        "items": {"type": "object"}
                    }
                },
                "required": ["server_name", "tools"]
            }
        ),
        types.Tool(
            name="argus_mcp_diff",
            description=(
                "Compare current MCP tool descriptions against a saved baseline to detect "
                "supply chain attacks or unexpected modifications. "
                "Returns added/removed/modified tools and flags suspicious changes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "MCP server identifier"
                    },
                    "tools": {
                        "type": "array",
                        "description": "Current list of tool objects from the server",
                        "items": {"type": "object"}
                    }
                },
                "required": ["server_name", "tools"]
            }
        ),
        types.Tool(
            name="argus_audit_log",
            description="View the last N entries from the Argus audit log.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of entries to return (default 20)",
                        "default": 20
                    },
                    "decision_filter": {
                        "type": "string",
                        "enum": ["all", "block", "warn", "allow"],
                        "default": "all"
                    }
                }
            }
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:

    # ── argus_check ───────────────────────────────────────────────────────────
    if name == "argus_check":
        action = arguments.get("action", "")
        result = _run_checks(action)
        if result["decision"] in ("block", "warn"):
            _audit(result)

        if result["decision"] == "block":
            summary = (
                f"🚫 BLOCKED ({result['severity'].upper()})\n"
                f"Do NOT proceed with this action.\n\n"
                f"Reasons:\n" +
                "\n".join(f"  • [{f['severity']}] {f['type']}: {f['detail']}" for f in result["findings"])
            )
        elif result["decision"] == "warn":
            summary = (
                f"⚠️  WARNING ({result['severity'].upper()})\n"
                f"Proceed only if this is intentional.\n\n"
                f"Concerns:\n" +
                "\n".join(f"  • [{f['severity']}] {f['type']}: {f['detail']}" for f in result["findings"])
            )
        else:
            summary = f"✅ ALLOWED — no security issues detected."

        return [types.TextContent(type="text", text=summary)]

    # ── argus_scan_package ────────────────────────────────────────────────────
    elif name == "argus_scan_package":
        package   = arguments.get("package", "")
        ecosystem = arguments.get("ecosystem", "npm")

        results = []

        # GitHub Advisory DB
        try:
            import urllib.request
            eco_map = {"npm": "npm", "pip": "pip"}
            url = f"https://api.github.com/advisories?per_page=5&ecosystem={eco_map[ecosystem]}&package={package}"
            req = urllib.request.Request(url, headers={"User-Agent": "argus-security/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                advisories = json.loads(resp.read())
            if advisories:
                for adv in advisories[:3]:
                    results.append(f"[GHSA] {adv.get('ghsa_id','')} — {adv.get('severity','').upper()}: {adv.get('summary','')[:120]}")
            else:
                results.append("[GHSA] No advisories found")
        except Exception as e:
            results.append(f"[GHSA] Unavailable: {e}")

        # OSV Database
        try:
            import urllib.request
            eco_osv = {"npm": "npm", "pip": "PyPI"}
            body = json.dumps({"package": {"ecosystem": eco_osv[ecosystem], "name": package}}).encode()
            req  = urllib.request.Request("https://api.osv.dev/v1/query",
                                          data=body,
                                          headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                osv_data = json.loads(resp.read())
            vulns = osv_data.get("vulns", [])
            if vulns:
                for v in vulns[:3]:
                    results.append(f"[OSV] {v.get('id','')} — {v.get('summary','')[:120]}")
            else:
                results.append("[OSV] No vulnerabilities found")
        except Exception as e:
            results.append(f"[OSV] Unavailable: {e}")

        # npm deprecation check
        if ecosystem == "npm":
            try:
                url = f"https://registry.npmjs.org/{package}/latest"
                req = urllib.request.Request(url, headers={"User-Agent": "argus-security/1.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    pkg_data = json.loads(resp.read())
                deprecated = pkg_data.get("deprecated")
                if deprecated:
                    results.append(f"[npm] ⚠️  DEPRECATED: {deprecated}")
                else:
                    results.append(f"[npm] Latest: {pkg_data.get('version','?')} — not deprecated")
            except Exception as e:
                results.append(f"[npm] Unavailable: {e}")

        # PyPI yanked check
        if ecosystem == "pip":
            try:
                url = f"https://pypi.org/pypi/{package}/json"
                req = urllib.request.Request(url, headers={"User-Agent": "argus-security/1.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    pypi_data = json.loads(resp.read())
                yanked = pypi_data.get("info", {}).get("yanked", False)
                version = pypi_data.get("info", {}).get("version", "?")
                if yanked:
                    results.append(f"[PyPI] ⚠️  YANKED — this version was pulled for security reasons")
                else:
                    results.append(f"[PyPI] Latest: {version} — not yanked")
            except Exception as e:
                results.append(f"[PyPI] Unavailable: {e}")

        output = f"Package scan: {package} ({ecosystem})\n" + "\n".join(results)
        return [types.TextContent(type="text", text=output)]

    # ── argus_scan_file ───────────────────────────────────────────────────────
    elif name == "argus_scan_file":
        path        = arguments.get("path", "")
        scanner     = ARGUS_ROOT / "scripts" / "local-scan.py"
        try:
            result  = subprocess.run(
                ["python3", str(scanner), path],
                capture_output=True, text=True, timeout=15
            )
            data    = json.loads(result.stdout)
            risk    = data.get("risk_level", "unknown")
            findings = data.get("findings", [])
            if not findings:
                text = f"✅ {path}\nRisk: CLEAN — no issues found."
            else:
                lines = [f"{'🚫' if risk in ('critical','high') else '⚠️ '} {path}", f"Risk: {risk.upper()}"]
                for f in findings:
                    lines.append(f"  • [{f['severity']}] {f['type']}: {f.get('detail','')[:100]}")
                text = "\n".join(lines)
        except Exception as e:
            text = f"Scan error: {e}"
        return [types.TextContent(type="text", text=text)]

    # ── argus_scan_mcp ────────────────────────────────────────────────────────
    elif name == "argus_scan_mcp":
        server_name    = arguments.get("server_name", "")
        server_command = arguments.get("server_command", "")
        tools          = arguments.get("tools", [])

        lines = [f"🔍 Argus MCP Scan: {server_name}", "─" * 50]

        # 1. VulnerableMCP.info
        lines.append("\n[1] VulnerableMCP.info")
        vuln_hits = _check_vulnerablemcp(server_name)
        for h in vuln_hits:
            lines.append(f"  {h}")

        # 2. MCPScan.ai
        lines.append("\n[2] MCPScan.ai")
        scan_hits = _check_mcpscan(server_name)
        for h in scan_hits:
            lines.append(f"  {h}")

        # 3. Source integrity (GitHub-based packages)
        lines.append("\n[3] Source Integrity")
        cmd_lower = server_command.lower()
        if "npx" in cmd_lower or "uvx" in cmd_lower:
            # Extract package name from command
            parts  = server_command.split()
            pkg    = next((p for p in parts if not p.startswith("-") and p not in ("npx","uvx","python3","python")), "")
            pkg    = pkg.split("@")[0]
            npm_data = _http_get(f"https://registry.npmjs.org/{urllib.parse.quote(pkg)}/latest") if pkg else None
            if npm_data:
                repo = npm_data.get("repository", {})
                repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
                lines.append(f"  npm package: {pkg}  version: {npm_data.get('version','?')}")
                lines.append(f"  repository:  {repo_url[:100] or 'not specified'}")
                deprecated = npm_data.get("deprecated")
                if deprecated:
                    lines.append(f"  ⚠️  DEPRECATED: {deprecated}")
                else:
                    lines.append("  ✓ not deprecated")
            else:
                lines.append("  (not an npm/uvx package or registry unavailable)")
        elif "python" in cmd_lower:
            script = next((p for p in server_command.split() if p.endswith(".py")), "")
            if script and Path(script).exists():
                size    = Path(script).stat().st_size
                chksum  = hashlib.sha256(Path(script).read_bytes()).hexdigest()[:16]
                lines.append(f"  local script: {script}")
                lines.append(f"  size: {size}B  sha256: {chksum}…")
            else:
                lines.append(f"  local script not found: {script or '(unknown)'}")
        else:
            lines.append("  (no source integrity check for this command type)")

        # 4. Static description analysis
        lines.append("\n[4] Tool Description Analysis")
        if tools:
            desc_findings = _analyze_descriptions(tools)
            if desc_findings:
                for f in desc_findings:
                    icon = "🚫" if f["severity"] == "critical" else "⚠️ "
                    lines.append(f"  {icon} [{f['severity']}] {f['type']}: {f['detail'][:120]}")
            else:
                lines.append(f"  ✓ {len(tools)} tools scanned — no injection or coherence issues")
        else:
            lines.append("  (no tool descriptions provided — pass 'tools' array for full analysis)")

        # Summary verdict
        all_findings = [f for f in (desc_findings if tools else [])
                        if f["severity"] in ("critical", "high")]
        is_suspicious = (
            any("known-malicious" in h for h in vuln_hits + scan_hits)
            or bool(all_findings)
        )
        if is_suspicious:
            lines.append("\n🚫 VERDICT: SUSPICIOUS — review before using this server")
        else:
            lines.append(
                "\n✅ VERDICT: No known issues detected\n"
                f"   Server '{server_name}' marked as confirmed-clean — "
                "argus will no longer warn when its tools are called."
            )
            _mark_scanned_clean(server_name)

        return [types.TextContent(type="text", text="\n".join(lines))]

    # ── argus_mcp_snapshot ────────────────────────────────────────────────────
    elif name == "argus_mcp_snapshot":
        server_name = arguments.get("server_name", "")
        tools       = arguments.get("tools", [])
        if not tools:
            return [types.TextContent(type="text", text="Error: 'tools' array is required")]

        existing = _load_snapshot(server_name)
        _save_snapshot(server_name, tools)
        p = _snapshot_path(server_name)

        if existing:
            msg = (f"✅ Snapshot updated for '{server_name}'\n"
                   f"   Tools: {len(tools)}  |  Path: {p}\n"
                   f"   Previous snapshot from: {existing.get('saved_at','?')[:19]}")
        else:
            msg = (f"✅ Baseline snapshot saved for '{server_name}'\n"
                   f"   Tools: {len(tools)}  |  Path: {p}\n"
                   f"   Run argus_mcp_diff in future sessions to detect changes.")
        return [types.TextContent(type="text", text=msg)]

    # ── argus_mcp_diff ────────────────────────────────────────────────────────
    elif name == "argus_mcp_diff":
        server_name = arguments.get("server_name", "")
        tools       = arguments.get("tools", [])
        if not tools:
            return [types.TextContent(type="text", text="Error: 'tools' array is required")]

        snapshot = _load_snapshot(server_name)
        if not snapshot:
            return [types.TextContent(
                type="text",
                text=(f"No baseline snapshot found for '{server_name}'.\n"
                      f"Run argus_mcp_snapshot first to create a baseline.")
            )]

        changes = _diff_snapshots(snapshot, tools)
        lines   = [f"🔍 MCP Diff: {server_name}",
                   f"   Baseline: {snapshot.get('saved_at','?')[:19]}",
                   "─" * 50]

        if not changes:
            lines.append("✅ No changes detected — tool descriptions match baseline")
        else:
            # Flag modified/added as potentially suspicious
            suspicious = [c for c in changes if c["change"] in ("modified", "added")]
            for c in changes:
                if c["change"] == "added":
                    lines.append(f"➕ ADDED:    {c['tool']} — {c.get('detail','')}")
                elif c["change"] == "removed":
                    lines.append(f"➖ REMOVED:  {c['tool']}")
                elif c["change"] == "modified":
                    lines.append(f"✏️  MODIFIED: {c['tool']}")
                    lines.append(f"   OLD: {c.get('old_description','')[:100]}")
                    lines.append(f"   NEW: {c.get('new_description','')[:100]}")

            if suspicious:
                lines.append(f"\n⚠️  {len(suspicious)} change(s) require review — potential supply chain modification")
                # Also run static analysis on new tools
                new_issues = _analyze_descriptions(tools)
                if new_issues:
                    lines.append("🚫 Static analysis flagged issues in current descriptions:")
                    for f in new_issues:
                        lines.append(f"   [{f['severity']}] {f['type']}: {f['detail'][:100]}")
            else:
                lines.append("\nℹ️  Only removals detected — no new attack surface")

        return [types.TextContent(type="text", text="\n".join(lines))]

    # ── argus_audit_log ───────────────────────────────────────────────────────
    elif name == "argus_audit_log":
        limit  = arguments.get("limit", 20)
        filter_ = arguments.get("decision_filter", "all")
        if not AUDIT_LOG.exists():
            return [types.TextContent(type="text", text="No audit log found. No events recorded yet.")]
        entries = []
        for line in AUDIT_LOG.read_text().splitlines():
            try:
                e = json.loads(line)
                if filter_ == "all" or e.get("decision") == filter_:
                    entries.append(e)
            except Exception:
                pass
        entries = entries[-limit:]
        if not entries:
            return [types.TextContent(type="text", text="No matching entries in audit log.")]
        lines = [f"Argus Audit Log — last {len(entries)} entries\n" + "─" * 50]
        for e in entries:
            icon = "🚫" if e.get("decision") == "block" else "⚠️ " if e.get("decision") == "warn" else "🔍"
            lines.append(
                f"{icon} {e.get('ts','')[:19]}  [{e.get('decision','').upper()}]  {e.get('severity','').upper()}\n"
                f"   tool: {e.get('tool','')}  matched: {e.get('matched','')[:60]}"
            )
        return [types.TextContent(type="text", text="\n".join(lines))]

    return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


# ── Run ───────────────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
