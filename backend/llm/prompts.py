"""Security-specific prompts. The LLM explains pipeline output — it must never
override it. All prompts state the pipeline verdict as ground truth.

The LLM is the 10% — it adds value through:
1. Natural language explanation of alerts
2. MITRE ATT&CK context enrichment
3. Containment recommendations
4. False positive likelihood assessment
"""
from __future__ import annotations

SYSTEM_ANALYST = (
    "You are CyberGuard, a senior SOC analyst assistant. Answer precisely, "
    "cite MITRE ATT&CK technique IDs when relevant, and never invent "
    "telemetry. If you do not have data, say so. Your responses should be "
    "concise, actionable, and formatted in Markdown. The detection pipeline "
    "is deterministic — you explain its verdicts, you never override them."
)

SYSTEM_ARABIC = (
    "أنت CyberGuard، مساعد محلل أمن سيبراني أول. أجب بدقة، واذكر معرفات "
    "تقنيات MITRE ATT&CK عند الصلة. لا تخترع بيانات. خط أنابيب الكشف حتمي — "
    "أنت تشرح نتائجه فقط، ولا تتجاوزه أبداً."
)


def explain_alert(alert: dict, mitre_context: str) -> list[dict]:
    """Build a prompt for the LLM to explain a pipeline alert.

    The alert dict is presented as ground truth — the LLM must not
    contradict the pipeline verdict.
    """
    return [
        {"role": "system", "content": SYSTEM_ANALYST},
        {"role": "user", "content": (
            "The deterministic detection pipeline produced this alert "
            "(ground truth — do not contradict it):\n"
            f"```json\n{alert}\n```\n\n"
            f"MITRE ATT&CK context:\n{mitre_context}\n\n"
            "Explain:\n"
            "1. **What this attack is** — in plain language\n"
            "2. **Why the flagged features indicate it** — reference specific feature values\n"
            "3. **Recommended containment steps** — actionable, prioritized\n"
            "4. **False-positive likelihood** — low/medium/high with reasoning\n\n"
            "Use concise Markdown. Keep it under 300 words.")},
    ]


def threat_briefing(alerts_summary: str, mitre_context: str) -> list[dict]:
    """Build a prompt for a daily/session threat briefing."""
    return [
        {"role": "system", "content": SYSTEM_ANALYST},
        {"role": "user", "content": (
            "Generate a threat briefing based on these pipeline results:\n"
            f"{alerts_summary}\n\n"
            f"MITRE ATT&CK context:\n{mitre_context}\n\n"
            "Include:\n"
            "1. Executive summary (3 sentences)\n"
            "2. Top threats by severity\n"
            "3. Recommended actions (prioritized)\n"
            "4. Zero-day signals requiring analyst review\n\n"
            "Format as a Markdown report.")},
    ]


def ioc_extraction(log_text: str) -> list[dict]:
    """Build a prompt to extract IOCs from log text."""
    return [
        {"role": "system", "content": SYSTEM_ANALYST},
        {"role": "user", "content": (
            "Extract all Indicators of Compromise (IOCs) from this log data:\n"
            f"```\n{log_text[:3000]}\n```\n\n"
            "Return a structured list of:\n"
            "- IP addresses (mark internal vs external)\n"
            "- Domains/URLs\n"
            "- File hashes\n"
            "- Suspicious ports\n"
            "- Patterns indicating C2, exfiltration, or lateral movement\n\n"
            "Format as a Markdown table.")},
    ]
