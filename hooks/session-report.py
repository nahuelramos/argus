#!/usr/bin/env python3
"""
Argus — Stop hook for Claude Code.
Runs when Claude finishes a response. If any security events occurred
during this session turn, prints a summary to the terminal.
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG  = Path.home() / ".argus" / "logs" / "audit.jsonl"
SESSION_TS = Path.home() / ".argus" / "logs" / ".session_start.txt"

# Events younger than this (seconds) belong to the current response turn
TURN_WINDOW = 30


def _load_recent_events() -> list:
    if not AUDIT_LOG.exists():
        return []
    now    = time.time()
    cutoff = now - TURN_WINDOW
    events = []
    for line in AUDIT_LOG.read_text().splitlines():
        try:
            e  = json.loads(line)
            ts = datetime.fromisoformat(e["ts"]).timestamp()
            if ts >= cutoff:
                events.append(e)
        except Exception:
            pass
    return events


def _severity_icon(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")


def _decision_icon(dec: str) -> str:
    return {"block": "🚫", "warn": "⚠️ ", "dlp_alert": "🔍"}.get(dec, "✅")


def main():
    try:
        events = _load_recent_events()
        if not events:
            sys.exit(0)

        # Only show blocks, warns, and DLP alerts — not allows
        notable = [e for e in events if e.get("decision") in ("block", "warn", "dlp_alert")]
        if not notable:
            sys.exit(0)

        blocks = [e for e in notable if e.get("decision") == "block"]
        warns  = [e for e in notable if e.get("decision") == "warn"]
        dlp    = [e for e in notable if e.get("decision") == "dlp_alert"]

        lines = [
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "  🛡  ARGUS SECURITY REPORT — this response turn",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ]

        if blocks:
            lines.append(f"\n  🚫 BLOCKED ({len(blocks)})")
            for e in blocks:
                sev  = e.get("severity", "")
                tool = e.get("tool", "?")
                mat  = e.get("matched", "?")[:60]
                lines.append(f"     {_severity_icon(sev)} [{sev.upper()}] {tool} → {mat}")

        if dlp:
            lines.append(f"\n  🔍 DLP ALERTS ({len(dlp)}) — sensitive data in tool output")
            for e in dlp:
                sev = e.get("severity", "")
                mat = e.get("matched", "?")[:60]
                lines.append(f"     {_severity_icon(sev)} [{sev.upper()}] {mat}")

        if warns:
            lines.append(f"\n  ⚠️  WARNINGS ({len(warns)})")
            for e in warns:
                sev  = e.get("severity", "")
                tool = e.get("tool", "?")
                mat  = e.get("matched", "?")[:60]
                lines.append(f"     {_severity_icon(sev)} [{sev.upper()}] {tool} → {mat}")

        lines += [
            "",
            f"  Full log: ~/.argus/logs/audit.jsonl",
            f"  View:     python3 ~/argus/argus-report.py --blocks",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
        ]

        print("\n".join(lines))

    except Exception:
        pass  # never crash Claude's session


if __name__ == "__main__":
    main()
