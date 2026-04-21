#!/usr/bin/env python3
"""
Argus — PostToolUse DLP hook for Claude Code.
Scans tool output for secrets, credentials, and sensitive data.
Warns Claude not to forward, log, or transmit what it finds.
Uses precise 2025 API key formats from Gitleaks/TruffleHog research.
"""
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ARGUS_HOME = Path.home() / ".argus"
AUDIT_LOG  = ARGUS_HOME / "logs" / "audit.jsonl"

# Zero-width chars — same set as preflight
ZERO_WIDTH_CHARS = {
    "​", "‌", "‍", "‎", "‏",
    "⁠", "⁡", "⁢", "⁣", "⁤",
    "﻿", "‮", "‭",
}

# ── DLP rules: (regex, label, severity) ──────────────────────────────────────
# Patterns based on Gitleaks v8 rules + 2025 API key format research
DLP_RULES = [
    # ── Private key material ─────────────────────────────────────────────────
    (r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP|PRIVATE)\s+(PRIVATE\s+)?KEY-----",
     "private_key", "critical"),

    # ── AWS ──────────────────────────────────────────────────────────────────
    (r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}(?![A-Z0-9])",
     "aws_access_key_id", "critical"),
    (r"(?i)aws.{0,20}secret.{0,20}['\"]?[A-Za-z0-9/+=]{40}['\"]?",
     "aws_secret_key", "critical"),

    # ── GitHub ───────────────────────────────────────────────────────────────
    (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
     "github_fine_grained_pat", "critical"),
    (r"gh[pousr]_[A-Za-z0-9_]{36,255}",
     "github_classic_token", "critical"),

    # ── Anthropic ────────────────────────────────────────────────────────────
    (r"sk-ant-(?:api03|admin|oat)-[A-Za-z0-9_\-]{20,}",
     "anthropic_api_key", "critical"),

    # ── OpenAI ───────────────────────────────────────────────────────────────
    (r"sk-proj-[A-Za-z0-9_\-]{20,}",
     "openai_project_key", "critical"),
    (r"sk-svcacct-[A-Za-z0-9_\-]{20,}",
     "openai_service_account_key", "critical"),
    (r"\bsk-[A-Za-z0-9]{48,}\b",
     "openai_legacy_key", "high"),

    # ── Stripe ───────────────────────────────────────────────────────────────
    (r"sk_live_[0-9a-zA-Z]{20,}",
     "stripe_live_key", "critical"),
    (r"sk_test_[0-9a-zA-Z]{20,}",
     "stripe_test_key", "high"),

    # ── Slack ────────────────────────────────────────────────────────────────
    (r"xoxb-[0-9A-Za-z\-]{10,}",
     "slack_bot_token", "critical"),
    (r"xoxp-[0-9A-Za-z\-]{10,}",
     "slack_user_token", "critical"),
    (r"xox[aorse]-[0-9A-Za-z\-]{10,}",
     "slack_token", "high"),

    # ── SendGrid ─────────────────────────────────────────────────────────────
    (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
     "sendgrid_api_key", "critical"),

    # ── Twilio ───────────────────────────────────────────────────────────────
    (r"(?:SK|AC|YK)[0-9a-fA-F]{32}",
     "twilio_sid", "critical"),

    # ── HuggingFace ──────────────────────────────────────────────────────────
    (r"hf_[A-Za-z0-9_]{30,}",
     "huggingface_token", "critical"),

    # ── Google Cloud ─────────────────────────────────────────────────────────
    (r'"type"\s*:\s*"service_account"',
     "gcloud_service_account_json", "critical"),
    (r"ya29\.[A-Za-z0-9_\-]{60,}",
     "google_oauth_token", "critical"),

    # ── Azure ────────────────────────────────────────────────────────────────
    (r"sig=[A-Za-z0-9%/\+=]{20,}",
     "azure_sas_token", "high"),
    (r"DefaultEndpointsProtocol=https;AccountName=",
     "azure_storage_connection_string", "critical"),

    # ── JWT ──────────────────────────────────────────────────────────────────
    (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
     "jwt_token", "high"),

    # ── Generic bearer / Authorization headers ────────────────────────────────
    (r"(?i)(Bearer|Authorization)\s*:\s*[A-Za-z0-9_\-\.]{20,}",
     "auth_header", "high"),

    # ── Credit cards ─────────────────────────────────────────────────────────
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
     "credit_card", "high"),

    # ── /etc/shadow entries ───────────────────────────────────────────────────
    (r"[a-z_][a-z0-9_-]*:\$[156y]?\$[A-Za-z0-9./]+\$",
     "shadow_hash", "critical"),

    # ── Generic API key assignment ────────────────────────────────────────────
    (r"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
     "generic_api_key", "high"),
]

# ── Entropy ───────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if len(s) < 8:
        return 0.0
    counts = Counter(s)
    total  = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _high_entropy_strings(content: str):
    """Find assignment-style patterns with high-entropy values (likely raw secrets)."""
    pattern = r'(?i)(?:key|secret|token|password|credential|auth)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-]{20,})["\']?'
    for m in re.finditer(pattern, content):
        val = m.group(1)
        if _entropy(val) >= 4.5:
            return f"high-entropy value near '{m.group(0)[:30]}...'", "high"
    return None, ""


# ── Flatten output ────────────────────────────────────────────────────────────

def _flatten(obj, depth: int = 0) -> str:
    if depth > 8:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten(v, depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten(v, depth + 1) for v in obj)
    return str(obj)


# ── Scan ──────────────────────────────────────────────────────────────────────

def scan(content: str):
    for rx, label, severity in DLP_RULES:
        if re.search(rx, content):
            return label, severity

    # Check for invisible chars (could be injecting hidden instructions via output)
    for ch in ZERO_WIDTH_CHARS:
        if ch in content:
            return f"zero-width char in output U+{ord(ch):04X}", "high"

    # Entropy-based fallback
    label, severity = _high_entropy_strings(content)
    if label:
        return label, severity

    return None, ""


# ── Audit ─────────────────────────────────────────────────────────────────────

def _audit(severity: str, tool: str, label: str):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts":       datetime.now(timezone.utc).isoformat(),
            "hook":     "PostToolUse",
            "decision": "dlp_alert",
            "severity": severity,
            "tool":     tool,
            "matched":  label,
            "cwd":      str(Path.cwd()),
        }
        with AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    try:
        event    = json.load(sys.stdin)
        tool     = event.get("tool_name", "")
        response = event.get("tool_response", "")
        content  = _flatten(response)

        label, severity = scan(content)

        if label and severity in ("critical", "high", "medium"):
            _audit(severity, tool, label)
            print(json.dumps({
                "additionalContext": (
                    f"[Argus DLP] Sensitive data in output: {label} ({severity}). "
                    "Do NOT copy, forward, log, or include in any network request."
                )
            }))
        else:
            print(json.dumps({}))
    except Exception:
        print(json.dumps({}))


if __name__ == "__main__":
    main()
