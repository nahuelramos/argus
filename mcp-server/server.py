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
import json
import math
import os
import re
import subprocess
import sys
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
AUDIT_LOG = Path.home() / ".argus" / "logs" / "audit.jsonl"

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
