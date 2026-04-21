#!/usr/bin/env python3
"""
Argus — PreToolUse security hook for Claude Code.
Blocks credential theft, reverse shells, obfuscated payloads, exfiltration,
supply chain abuse, and invisible-character prompt injection before execution.
Zero LLM cost, ~30-80ms locally. Fails open — never blocks Claude due to our bugs.
"""
import json
import math
import os
import re
import sys
import time
import hashlib
from collections import Counter
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
AUDIT_LOG  = ARGUS_HOME / "logs" / "audit.jsonl"
RATE_STATE = ARGUS_HOME / "logs" / ".rate.json"

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


# ── Decision engine ───────────────────────────────────────────────────────────

def _best(*pairs) -> tuple:
    winner = (None, "")
    for match, sev in pairs:
        if match and SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(winner[1], 0):
            winner = (match, sev)
    return winner


def decide(tool_name: str, tool_input: dict) -> dict:
    iocs      = _iocs()
    allowlist = _allowlist()
    strings   = _strings(tool_input)

    match, severity = _best(
        _check_sensitive_paths(strings, iocs, allowlist),
        _check_env_vars(strings, iocs),
        _check_network(strings, iocs, allowlist),
        _check_dangerous_commands(strings, iocs),
        _check_obfuscation(strings, iocs),
        _check_prompt_injection(strings, iocs),
        _check_zero_width_chars(strings),
        _check_claude_code_flags(strings, iocs),
        _check_supply_chain(strings, iocs),
        _check_tool_description_poisoning(strings, iocs),
        _check_tool_specific(tool_name, tool_input),
    )

    if not match:
        return {}

    severity = _escalate_if_burst(severity)
    rank     = SEVERITY_RANK.get(severity, 0)

    if rank >= SEVERITY_RANK["high"]:
        _audit("block", severity, tool_name, match, tool_input)
        return {
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"[Argus] Blocked ({severity}): {match!r}"
                ),
            }
        }

    _audit("warn", severity, tool_name, match, tool_input)
    return {
        "additionalContext": (
            f"[Argus] Warning ({severity}): suspicious pattern — {match!r}. "
            "Only proceed if this is intentional."
        )
    }


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    try:
        event      = json.load(sys.stdin)
        tool_name  = event.get("tool_name", "")
        tool_input = event.get("tool_input", {})
        result     = decide(tool_name, tool_input)
        print(json.dumps(result))
    except Exception:
        print(json.dumps({}))


if __name__ == "__main__":
    main()
