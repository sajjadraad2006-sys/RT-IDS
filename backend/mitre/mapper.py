"""Map detection labels to MITRE ATT&CK technique IDs.

Static core mapping (works offline immediately); enriched by attack_db.py
after the first TAXII sync. Covers all CICIDS2017 attack classes plus
known classifier labels. Autoencoder anomalies intentionally receive no
technique: reconstruction error alone cannot infer attacker behavior.
"""
from __future__ import annotations

MAPPING_VERSION = "classifier-label-candidate-v1"

# ── Label → Technique mapping ─────────────────────────────────────────────────
# Each CyberGuard detection class maps to the most relevant ATT&CK techniques.
# These are used for:
# 1. Immediate offline mapping (no sync needed)
# 2. MITRE browser "detected" badges
# 3. LLM context enrichment

_LABEL_TO_TECHNIQUES: dict[str, list[str]] = {
    "DDoS": ["T1498", "T1499"],                     # Network/Endpoint DoS
    "DoS": ["T1499", "T1499.002", "T1498"],          # Endpoint DoS variants
    "PortScan": ["T1046", "T1595"],                  # Network Service Discovery / Active Scanning
    "BruteForce": ["T1110", "T1110.001", "T1110.003"],  # Brute Force variants
    "WebAttack": ["T1190", "T1059", "T1059.007"],    # Exploit Public-Facing App + scripting
    "Bot": ["T1071", "T1071.001", "T1105"],          # C2 / Ingress Tool Transfer
    "Infiltration": ["T1041", "T1020", "T1048"],     # Exfil over C2 / alt protocol
    "Heartbleed": ["T1190", "T1212"],                # Exploit + Credential Access
}

# ── Reverse mapping: technique → labels ──────────────────────────────────────
_TECHNIQUE_TO_LABELS: dict[str, list[str]] = {}
for _label, _techs in _LABEL_TO_TECHNIQUES.items():
    for _t in _techs:
        _TECHNIQUE_TO_LABELS.setdefault(_t, []).append(_label)


def map_alert_to_techniques(label: str) -> list[str]:
    """Map a classifier label to possible MITRE ATT&CK technique IDs.

    This is a heuristic taxonomy hypothesis.  It is not evidence that an
    attacker performed the mapped behavior.

    Args:
        label: Detection class (e.g., "DDoS", "PortScan").

    Returns:
        List of technique IDs (e.g., ["T1498", "T1499"]).
    """
    return list(_LABEL_TO_TECHNIQUES.get(label, []))


def map_technique_to_labels(technique_id: str) -> list[str]:
    """Reverse lookup: which attack classes can trigger this technique?

    Args:
        technique_id: MITRE technique ID (e.g., "T1498").

    Returns:
        List of CyberGuard detection labels.
    """
    return list(_TECHNIQUE_TO_LABELS.get(technique_id, []))


def get_all_mapped_techniques() -> set[str]:
    """Return all technique IDs that have a detection mapping."""
    techniques = set()
    for techs in _LABEL_TO_TECHNIQUES.values():
        techniques.update(techs)
    return techniques


def get_technique_context(label: str) -> str:
    """Generate a short context string for LLM prompts.

    Args:
        label: Detection class.

    Returns:
        Markdown-formatted context about the mapped techniques.
    """
    techs = map_alert_to_techniques(label)
    if not techs:
        return f"No MITRE ATT&CK mapping for label '{label}'."
    lines = [
        f"**Candidate ATT&CK mapping for classifier label {label}** "
        f"(`{MAPPING_VERSION}`; heuristic, not observed behavior):"
    ]
    for t in techs:
        lines.append(f"- `{t}` — see attack.mitre.org/techniques/{t.replace('.', '/')}")
    return "\n".join(lines)
