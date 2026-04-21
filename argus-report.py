#!/usr/bin/env python3
"""
argus-report — CLI viewer for the Argus audit log.

Usage:
  python3 argus-report.py           # last 50 entries
  python3 argus-report.py --all     # all entries
  python3 argus-report.py --blocks  # blocked events only
  python3 argus-report.py --today   # today's events only
  python3 argus-report.py --stats   # statistics summary
"""
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG = Path.home() / ".argus" / "logs" / "audit.jsonl"

COLORS = {
    "critical": "\033[91m",
    "high":     "\033[91m",
    "medium":   "\033[93m",
    "low":      "\033[94m",
    "block":    "\033[91m",
    "warn":     "\033[93m",
    "dlp_alert":"\033[91m",
    "reset":    "\033[0m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
    "green":    "\033[92m",
    "cyan":     "\033[96m",
}

def c(color: str, text: str) -> str:
    return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"


def load_entries() -> list:
    if not AUDIT_LOG.exists():
        return []
    entries = []
    for line in AUDIT_LOG.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            pass
    return entries


def fmt_ts(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts


def fmt_entry(e: dict) -> str:
    decision = e.get("decision", "?")
    severity = e.get("severity", "")
    tool     = e.get("tool", "?")
    matched  = e.get("matched", "")
    hook     = e.get("hook", "")
    cwd      = e.get("cwd", "")

    dec_col = "block" if decision in ("block", "dlp_alert") else "warn"
    sev_col = severity if severity in COLORS else "dim"
    icon    = "🚫" if decision == "block" else "⚠️ " if decision == "warn" else "🔍"

    lines = [
        f"{icon}  {c('bold', fmt_ts(e.get('ts','')))}  [{c(dec_col, decision.upper())}]  {c(sev_col, severity.upper())}",
        f"   {c('dim','hook')}     {hook}",
        f"   {c('dim','tool')}     {c('cyan', tool)}",
        f"   {c('dim','matched')}  {c('bold', matched[:80])}",
        f"   {c('dim','project')}  {cwd[:60]}",
    ]
    if e.get("hash"):
        lines.append(f"   {c('dim','hash')}     {e['hash']}")
    return "\n".join(lines)


def stats(entries: list):
    total  = len(entries)
    blocks = sum(1 for e in entries if e.get("decision") == "block")
    warns  = sum(1 for e in entries if e.get("decision") == "warn")
    dlp    = sum(1 for e in entries if e.get("decision") == "dlp_alert")
    crits  = sum(1 for e in entries if e.get("severity") == "critical")

    by_tool  = Counter(e.get("tool","?") for e in entries if e.get("decision") == "block")
    by_match = Counter(e.get("matched","?") for e in entries)

    print(f"\n{c('bold','── Argus Audit Statistics ──────────────────────────')}")
    print(f"  Total events  : {c('bold', str(total))}")
    print(f"  Blocks        : {c('block', str(blocks))}")
    print(f"  Warnings      : {c('warn', str(warns))}")
    print(f"  DLP alerts    : {c('block', str(dlp))}")
    print(f"  Critical      : {c('critical', str(crits))}")

    if by_tool:
        print(f"\n{c('bold','  Most blocked tools:')}")
        for tool, count in by_tool.most_common(5):
            print(f"    {count:3d}x  {c('cyan', tool)}")

    if by_match:
        print(f"\n{c('bold','  Most triggered patterns:')}")
        for match, count in by_match.most_common(5):
            print(f"    {count:3d}x  {match[:60]}")
    print()


def main():
    args  = sys.argv[1:]
    all_e = load_entries()

    if not all_e:
        print(f"{c('dim','No audit log found at')} {AUDIT_LOG}")
        print(f"Install Argus hooks first: {c('cyan','bash hooks/install.sh --user')}")
        return

    if "--stats" in args:
        stats(all_e)
        return

    entries = all_e

    if "--blocks" in args:
        entries = [e for e in entries if e.get("decision") in ("block", "dlp_alert")]

    if "--today" in args:
        today = datetime.now(timezone.utc).date()
        entries = [e for e in entries
                   if datetime.fromisoformat(e.get("ts","1970")).date() == today]

    if "--all" not in args:
        entries = entries[-50:]

    if not entries:
        print(c("green", "No matching events found."))
        return

    print(f"\n{c('bold','── Argus Audit Log')} {c('dim',f'({len(entries)} events shown)')}")
    print(c("dim", "─" * 60))
    for e in entries:
        print(fmt_entry(e))
        print(c("dim", "─" * 60))


if __name__ == "__main__":
    main()
