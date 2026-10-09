"""Grounded Defense RAG for CyberGuard.

Connects observed detection telemetry to MITRE ATT&CK techniques,
correlates them with official MITRE D3FEND defensive countermeasures,
and grounds AI decision-making to eliminate hallucination.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ..config import DB_PATH
from .d3fend import D3fendStore
from .mapper import map_alert_to_techniques

logger = logging.getLogger(__name__)

# Fallback curated D3FEND mappings for offline or pre-sync execution
_OFFLINE_D3FEND_MAPPINGS: Dict[str, List[Dict[str, str]]] = {
    "T1498": [  # Network Denial of Service
        {
            "d3fend_id": "D3-NIPF",
            "name": "Network Ingress Packet Filtering",
            "action": "block_ip",
            "actuator": "firewall",
            "description": "Drop incoming packets matching the offending source IP at the edge or host firewall.",
        },
        {
            "d3fend_id": "D3-RBF",
            "name": "Rate-based Filtering",
            "action": "rate_limit",
            "actuator": "firewall",
            "description": "Throttle packet throughput from the source address to mitigate volumetric exhaustion.",
        },
    ],
    "T1499": [  # Endpoint Denial of Service
        {
            "d3fend_id": "D3-NIPF",
            "name": "Network Ingress Packet Filtering",
            "action": "block_ip",
            "actuator": "firewall",
            "description": "Block source IP to terminate endpoint resource exhaustion.",
        },
    ],
    "T1046": [  # Network Service Discovery / Port Scan
        {
            "d3fend_id": "D3-ITR",
            "name": "Inbound Traffic Filtering",
            "action": "block_ip",
            "actuator": "firewall",
            "description": "Temporarily block scanning IP to blind reconnaissance sweeps.",
        },
    ],
    "T1110": [  # Brute Force
        {
            "d3fend_id": "D3-NIPF",
            "name": "Network Ingress Packet Filtering",
            "action": "block_ip",
            "actuator": "firewall",
            "description": "Blacklist authentication brute-force origin IP.",
        },
    ],
    "T1071": [  # Application Layer Protocol / C2
        {
            "d3fend_id": "D3-NIPF",
            "name": "Network Ingress Packet Filtering",
            "action": "block_ip",
            "actuator": "firewall",
            "description": "Block command-and-control connection destination IP/port.",
        },
        {
            "d3fend_id": "D3-DNSF",
            "name": "DNS Sinkholing / Signature Drop",
            "action": "drop_suricata_signature",
            "actuator": "suricata",
            "description": "Drop C2 communication matching behavioral signature or domain.",
        },
    ],
    "T1190": [  # Exploit Public-Facing Application
        {
            "d3fend_id": "D3-NIPF",
            "name": "Network Ingress Packet Filtering",
            "action": "block_ip",
            "actuator": "firewall",
            "description": "Block exploiting remote IP at host firewall.",
        },
    ],
}


class DefenseRAG:
    """Retrieves grounded ATT&CK and D3FEND countermeasures for security events."""

    def __init__(self, d3fend_store: Optional[D3fendStore] = None):
        self.d3fend_store = d3fend_store or D3fendStore(DB_PATH)

    def retrieve_defense_playbook(
        self,
        label: str,
        techniques: Optional[List[str]] = None,
        telemetry: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Produce a grounded, hallucination-resistant mitigation context.

        Args:
            label: Detection label (e.g. DDoS, Bot, PortScan)
            techniques: Explicit ATT&CK techniques, if available
            telemetry: Extracted flow or event metadata (e.g. src_ip, dest_port)
        """
        tech_list = list(techniques or map_alert_to_techniques(label))
        telemetry = telemetry or {}

        mitre_entries: List[Dict[str, Any]] = []
        d3fend_countermeasures: List[Dict[str, Any]] = []

        # 1. Retrieve D3FEND candidates from store or offline map
        for tid in tech_list:
            db_candidates = []
            try:
                db_candidates = self.d3fend_store.candidate_defenses(tid, attack_verified=True)
            except Exception as e:
                logger.debug("D3fendStore query for %s failed: %s", tid, e)

            if db_candidates:
                for c in db_candidates:
                    d3fend_countermeasures.append({
                        "attack_id": tid,
                        "d3fend_id": c.get("d3fend_technique_id"),
                        "name": c.get("name"),
                        "action": "block_ip",  # Default inferred mitigation
                        "description": f"D3FEND defensive technique {c.get('name')} for {tid}",
                    })
            elif tid in _OFFLINE_D3FEND_MAPPINGS:
                for offline_c in _OFFLINE_D3FEND_MAPPINGS[tid]:
                    d3fend_countermeasures.append({
                        "attack_id": tid,
                        **offline_c
                    })

            mitre_entries.append({"technique_id": tid, "label": label})

        # 2. Derive concrete recommended action based on telemetry
        src_ip = telemetry.get("src_ip") or telemetry.get("source_ip") or "unknown"
        dest_port = telemetry.get("dest_port") or telemetry.get("destination_port")

        recommended_actions = []
        for cm in d3fend_countermeasures:
            action_name = cm.get("action", "block_ip")
            target = src_ip if action_name in {"block_ip", "rate_limit"} else str(dest_port or src_ip)
            recommended_actions.append({
                "action": action_name,
                "target": target,
                "d3fend_id": cm.get("d3fend_id"),
                "countermeasure_name": cm.get("name"),
                "params": {"port": dest_port} if dest_port else {},
            })

        return {
            "label": label,
            "techniques": tech_list,
            "d3fend_countermeasures": d3fend_countermeasures,
            "concrete_actions": recommended_actions,
            "telemetry": telemetry,
        }

    def format_prompt_context(self, defense_playbook: Dict[str, Any]) -> str:
        """Format the retrieved defense knowledge into a strict grounding prompt."""
        lines = [
            "### GROUNDED DEFENSIVE INTELLIGENCE (MITRE ATT&CK & D3FEND):",
            f"Observed Threat Label: {defense_playbook.get('label')}",
            f"Associated ATT&CK Techniques: {', '.join(defense_playbook.get('techniques', [])) or 'None'}",
            "",
            "Verified Defensive Countermeasures (MITRE D3FEND):"
        ]
        for cm in defense_playbook.get("d3fend_countermeasures", []):
            lines.append(
                f"- [{cm.get('d3fend_id')}] {cm.get('name')}: "
                f"Action={cm.get('action')}, Description={cm.get('description')}"
            )

        lines.extend([
            "",
            "Valid Autonomous Actuator Actions Available:",
            "- block_ip (Target: offending source IP)",
            "- isolate_port (Target: targeted local port)",
            "- rate_limit (Target: offending source IP)",
            "- drop_suricata_signature (Target: signature ID)",
            "",
            "INSTRUCTION: Choose your recommended_action exclusively from the verified actions above. "
            "Do not hallucinate imaginary firewalls, scripts, or manual procedures."
        ])
        return "\n".join(lines)


# Global singleton
default_defense_rag = DefenseRAG()
