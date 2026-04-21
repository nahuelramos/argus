#!/usr/bin/env python3
"""
Argus local scanner — static analysis of MCP server and skill files.
Called by the Argus Scanner skill. Returns structured JSON.

Usage:
  python3 local-scan.py <path-to-file-or-directory>
  python3 local-scan.py --discover          # find all installed MCPs/skills
"""
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

ARGUS_HOME  = Path.home() / ".argus"
_SCRIPT_DIR = Path(__file__).resolve().parent
IOC_PATHS   = [
    _SCRIPT_DIR.parent / "data" / "iocs.json",
    ARGUS_HOME / "iocs.json",
]

ZERO_WIDTH_CHARS = {
    "​", "‌", "‍", "‎", "‏",
    "⁠", "⁡", "⁢", "⁣", "⁤",
    "﻿", "‮", "‭",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_iocs() -> dict:
    for p in IOC_PATHS:
        if Path(p).exists():
            try:
                return json.loads(Path(p).read_text())
            except Exception:
                pass
    return {}


def _entropy(s: str) -> float:
    if len(s) < 8:
        return 0.0
    counts = Counter(s)
    total  = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ── Discovery ─────────────────────────────────────────────────────────────────

def discover_mcps() -> list:
    """Find all installed MCPs and skills across standard locations."""
    found = []

    # Claude Code MCP config files
    mcp_config_paths = [
        Path.home() / ".claude" / "settings.json",
        Path.cwd() / ".mcp.json",
        Path.cwd() / ".claude" / "settings.json",
    ]

    for cfg_path in mcp_config_paths:
        if not cfg_path.exists():
            continue
        try:
            data = json.loads(cfg_path.read_text())
            servers = data.get("mcpServers", {})
            for name, config in servers.items():
                found.append({
                    "name": name,
                    "type": "mcp_server",
                    "source_file": str(cfg_path),
                    "config": config,
                    "command": config.get("command", ""),
                    "args": config.get("args", []),
                })
        except Exception:
            pass

    # Claude Code skills directories
    skill_dirs = [
        Path.home() / ".claude" / "skills",
        Path.cwd() / ".claude" / "skills",
    ]
    for skill_dir in skill_dirs:
        if not skill_dir.exists():
            continue
        for skill_file in skill_dir.rglob("*.md"):
            found.append({
                "name": skill_file.parent.name or skill_file.stem,
                "type": "skill",
                "source_file": str(skill_file),
                "config": {},
            })
        for skill_file in skill_dir.rglob("*.skill"):
            found.append({
                "name": skill_file.stem,
                "type": "skill",
                "source_file": str(skill_file),
                "config": {},
            })

    return found


def extract_package_info(item: dict) -> dict:
    """Extract npm/pip package name and version from MCP config."""
    info = {"npm": None, "pip": None, "github": None, "local": None, "version": None}

    args = item.get("args", [])
    cmd  = item.get("command", "")

    # npx @scope/package or npx package
    for i, arg in enumerate(args):
        if arg in ("-y", "--yes"):
            continue
        if arg.startswith("@") or (i > 0 and args[i-1] in ("npx", "-y")):
            info["npm"] = arg
            break
        if i > 0 and args[i-1] == "npx":
            info["npm"] = arg
            break

    # uvx or pip: python -m package
    if cmd == "uvx" and args:
        info["pip"] = args[0]
    if cmd == "python" or cmd == "python3":
        for i, arg in enumerate(args):
            if arg == "-m" and i + 1 < len(args):
                info["pip"] = args[i + 1]

    # GitHub repo reference
    for arg in args:
        if re.match(r'[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+', arg):
            info["github"] = arg

    # Local path
    if cmd and (cmd.startswith("/") or cmd.startswith("~") or cmd.startswith(".")):
        info["local"] = cmd

    # Version from @scope/package@1.2.3 or package@1.2.3
    pkg = info.get("npm") or info.get("pip") or ""
    if "@" in pkg and not pkg.startswith("@"):
        parts = pkg.rsplit("@", 1)
        info["version"] = parts[1]
    elif pkg.startswith("@") and pkg.count("@") == 2:
        parts = pkg.rsplit("@", 1)
        info["version"] = parts[1]

    return info


# ── Static analysis ────────────────────────────────────────────────────────────

def scan_file(path: str) -> dict:
    """Full static analysis of a single file. Returns structured findings."""
    p       = Path(path)
    result  = {
        "file":          str(p),
        "exists":        p.exists(),
        "size_bytes":    0,
        "findings":      [],
        "risk_level":    "clean",
        "risk_score":    0,
    }

    if not p.exists():
        return result

    try:
        content = p.read_text(errors="replace")
    except Exception as e:
        result["findings"].append({"severity": "info", "type": "read_error", "detail": str(e)})
        return result

    result["size_bytes"] = len(content.encode())
    iocs = _load_iocs()

    # ── Zero-width characters ────────────────────────────────────────────────
    for ch in ZERO_WIDTH_CHARS:
        if ch in content:
            result["findings"].append({
                "severity": "critical",
                "type":     "zero_width_char",
                "detail":   f"Invisible Unicode char U+{ord(ch):04X} — used to hide prompt injection (CVE-2025-54794)",
                "line":     _find_line(content, ch),
            })

    # ── Prompt injection phrases ──────────────────────────────────────────────
    for rx in iocs.get("prompt_injection", {}).get("patterns", []):
        m = re.search(rx, content, re.IGNORECASE)
        if m:
            result["findings"].append({
                "severity": "high",
                "type":     "prompt_injection",
                "detail":   f"Injection phrase: {m.group(0)[:80]}",
                "line":     _find_line(content, m.group(0)),
                "pattern":  rx,
            })

    # ── Tool description poisoning ────────────────────────────────────────────
    for rx in iocs.get("tool_description_poisoning", {}).get("patterns", []):
        m = re.search(rx, content, re.IGNORECASE)
        if m:
            result["findings"].append({
                "severity": "critical",
                "type":     "tool_poisoning",
                "detail":   f"Tool poisoning pattern: {m.group(0)[:80]}",
                "line":     _find_line(content, m.group(0)),
            })

    # ── Dangerous commands ────────────────────────────────────────────────────
    for rx in iocs.get("dangerous_commands", {}).get("patterns", []):
        m = re.search(rx, content, re.IGNORECASE)
        if m:
            result["findings"].append({
                "severity": "high",
                "type":     "dangerous_command",
                "detail":   f"Dangerous pattern: {m.group(0)[:80]}",
                "line":     _find_line(content, m.group(0)),
            })

    # ── Sensitive path access ─────────────────────────────────────────────────
    for pat in iocs.get("sensitive_paths", {}).get("patterns", []):
        if pat in content:
            result["findings"].append({
                "severity": "high",
                "type":     "sensitive_path_access",
                "detail":   f"References sensitive path: {pat}",
                "line":     _find_line(content, pat),
            })

    # ── Suspicious network destinations ──────────────────────────────────────
    cfg = iocs.get("suspicious_network", {})
    for entry in cfg.get("known_malicious_domains", []):
        domain = entry["domain"] if isinstance(entry, dict) else entry
        if domain.lower() in content.lower():
            result["findings"].append({
                "severity": "critical",
                "type":     "known_malicious_domain",
                "detail":   f"References confirmed malicious domain: {domain}",
                "incident": entry.get("incident", "") if isinstance(entry, dict) else "",
                "line":     _find_line(content, domain),
            })
    for svc in cfg.get("exfil_services", []):
        if svc.lower() in content.lower():
            result["findings"].append({
                "severity": "high",
                "type":     "exfil_service",
                "detail":   f"References known exfiltration service: {svc}",
                "line":     _find_line(content, svc),
            })

    # ── Obfuscation ───────────────────────────────────────────────────────────
    for rx in iocs.get("obfuscation", {}).get("patterns", []):
        m = re.search(rx, content, re.IGNORECASE)
        if m:
            result["findings"].append({
                "severity": "medium",
                "type":     "obfuscation",
                "detail":   f"Obfuscated pattern: {m.group(0)[:80]}",
                "line":     _find_line(content, m.group(0)),
            })

    # ── High-entropy strings (potential hardcoded secrets) ────────────────────
    secret_rx = r'(?i)(?:key|secret|token|password|auth)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{20,})["\']?'
    for m in re.finditer(secret_rx, content):
        val = m.group(1)
        if _entropy(val) >= 4.5:
            result["findings"].append({
                "severity": "high",
                "type":     "hardcoded_secret",
                "detail":   f"High-entropy value near '{m.group(0)[:50]}...'",
                "line":     _find_line(content, m.group(0)[:20]),
            })

    # ── Coherence check (for skill/markdown files) ────────────────────────────
    if p.suffix in (".md", ".skill"):
        _check_coherence(content, p.name, result["findings"])

    # ── Claude Code flag abuse ────────────────────────────────────────────────
    for flag in iocs.get("claude_code_abuse", {}).get("patterns", []):
        if flag.lower() in content.lower():
            result["findings"].append({
                "severity": "critical",
                "type":     "claude_flag_abuse",
                "detail":   f"References dangerous Claude Code flag: {flag}",
                "line":     _find_line(content, flag),
            })

    # ── Supply chain indicators ───────────────────────────────────────────────
    for fname in iocs.get("supply_chain", {}).get("malicious_files", []):
        if fname.lower() in content.lower():
            result["findings"].append({
                "severity": "high",
                "type":     "supply_chain",
                "detail":   f"References known malicious supply chain file: {fname}",
            })

    # ── Compute risk score and level ──────────────────────────────────────────
    score = 0
    severity_weights = {"critical": 40, "high": 20, "medium": 10, "low": 2, "info": 0}
    for f in result["findings"]:
        score += severity_weights.get(f.get("severity", ""), 0)
    result["risk_score"] = score
    if score >= 40:
        result["risk_level"] = "critical"
    elif score >= 20:
        result["risk_level"] = "high"
    elif score >= 10:
        result["risk_level"] = "medium"
    elif score > 0:
        result["risk_level"] = "low"

    return result


def _find_line(content: str, needle: str) -> int:
    """Return 1-based line number of first occurrence."""
    try:
        idx = content.lower().find(needle.lower())
        if idx == -1:
            return 0
        return content[:idx].count("\n") + 1
    except Exception:
        return 0


def _check_coherence(content: str, filename: str, findings: list):
    """
    Coherence check: flag if a skill's stated purpose doesn't match its actions.
    E.g. a 'markdown formatter' that accesses SSH keys is suspicious.
    """
    content_lower = content.lower()

    # Extract stated purpose from first heading or description
    purpose_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    purpose = purpose_match.group(1).lower() if purpose_match else ""

    # Low-risk stated purposes that should NOT touch credentials
    safe_purposes = [
        "format", "markdown", "lint", "style", "prettier",
        "translate", "summarize", "spelling", "grammar",
        "diagram", "chart", "image", "document",
    ]

    if any(kw in purpose for kw in safe_purposes):
        credential_refs = [
            "~/.ssh", "~/.aws", "credentials", "private_key",
            "api_key", "secret", "token", "password",
        ]
        for ref in credential_refs:
            if ref in content_lower:
                findings.append({
                    "severity": "high",
                    "type":     "coherence_violation",
                    "detail":   f"Skill claims to '{purpose}' but references '{ref}' — suspicious mismatch",
                })
                break


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: local-scan.py <path> OR local-scan.py --discover"}))
        sys.exit(1)

    if sys.argv[1] == "--discover":
        items = discover_mcps()
        for item in items:
            item["package_info"] = extract_package_info(item)
        print(json.dumps({"discovered": items}, indent=2))
        return

    target = Path(sys.argv[1])

    if target.is_dir():
        results = []
        for f in target.rglob("*"):
            if f.is_file() and f.suffix in (".md", ".skill", ".py", ".js", ".ts", ".sh", ".json"):
                results.append(scan_file(str(f)))
        print(json.dumps({"path": str(target), "files": results}, indent=2))
    else:
        print(json.dumps(scan_file(str(target)), indent=2))


if __name__ == "__main__":
    main()
