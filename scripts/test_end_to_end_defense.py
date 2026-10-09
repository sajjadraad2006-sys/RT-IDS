"""End-to-End Autonomous Active Defense Verification Script.

Tests the full autonomous loop:
1. Threat Alert -> SmartLog Evidence
2. GeniusDefenseRAG -> ATT&CK & D3FEND Countermeasure Grounding
3. AI Decision Evaluation -> Valid JSON Verdict
4. SafetyGuardrails & Autonomous Actuation -> Firewall / Suricata Execution
5. Rollback Token Verification & Atomic Rollback
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.actuators.router import default_router
from backend.decision.engine import build_smart_log, decision_messages, parse_and_guard_ai_decision
from backend.decision.models import RecommendedAction, SmartLog, Verdict
from backend.mitre.defense_rag import default_defense_rag


class MockAlertRecord:
    def __init__(self, alert_id: int, threat_type: str, severity: str, confidence: float, evidence: dict, mitre_techniques: list):
        self.id = alert_id
        self.type = threat_type
        self.severity = severity
        self.stage = "classifier"
        self.route = "autonomous_containment"
        self.confidence = confidence
        self.anomaly_score = 0.95
        self.created_at = time.time()
        self.evidence_json = json.dumps(evidence)
        self.input_schema_json = json.dumps({"detected_input_profile": "production_telemetry", "feature_coverage_percentage": 100.0})
        self.mitre_techniques = json.dumps(mitre_techniques)
        self.top_features = json.dumps([["syn_count", 95000.0], ["flow_duration", 0.05]])


def test_ddos_autonomous_mitigation_flow():
    print("\n[TEST 1] Testing Volumetric SYN Flood Autonomous Mitigation Flow...")
    record = MockAlertRecord(
        alert_id=101,
        threat_type="DDoS",
        severity="critical",
        confidence=0.96,
        evidence={"src_ip": "203.0.113.77", "dest_port": 80, "protocol": "tcp"},
        mitre_techniques=["T1498.001"],
    )

    smart_log = build_smart_log(record)
    smart_log.source["src_ip"] = "203.0.113.77"

    # 1. RAG Retrieval
    playbook = default_defense_rag.retrieve_defense_playbook("SYN flood attack", telemetry={"src_ip": "203.0.113.77", "dest_port": 80})
    defense_context = default_defense_rag.format_prompt_context(playbook)
    assert playbook["total_techniques_matched"] >= 1
    assert any(a["action"] in {"block_ip", "rate_limit"} for a in playbook["concrete_actions"])
    print("  -> GeniusDefenseRAG successfully retrieved D3FEND countermeasures")

    # 2. Simulated LLM Output following strict grounding
    llm_output = json.dumps({
        "verdict": "malicious",
        "confidence": 0.95,
        "recommended_action": "block_ip",
        "rationale": "Volumetric SYN flood packet saturation matches MITRE T1498.001. Grounded D3FEND D3-NIPF mandates ingress blocking.",
        "evidence": ["syn_count=95000", "T1498.001", "D3-NIPF"],
        "containment": ["block_ip 203.0.113.77"],
        "limitations": ["Host firewall simulation active"]
    })

    # 3. Autonomous Decision & Actuation
    guarded = parse_and_guard_ai_decision(
        raw=llm_output,
        smart_log=smart_log,
        provider="local_llama",
        model_version="Foundation-Sec-8B-Instruct.Q4_K_M",
        autonomous_actuate=True,
        execution_mode="simulation",
        target="203.0.113.77",
    )

    assert guarded.verdict == Verdict.malicious
    assert guarded.executed_action == "simulated:block_ip"
    assert guarded.rollback_token is not None
    assert guarded.requires_human is False
    print(f"  -> Autonomous Actuation Success: {guarded.executed_action}")
    print(f"  -> Rollback Token issued: {guarded.rollback_token}")

    # 4. Rollback
    rollback_res = default_router.rollback_action(guarded.rollback_token)
    assert rollback_res is True
    print(f"  -> Atomic Rollback verified successfully with token {guarded.rollback_token}")


def test_active_directory_kerberoast_mitigation_flow():
    print("\n[TEST 2] Testing Active Directory Kerberoasting Attack Defense Flow...")
    record = MockAlertRecord(
        alert_id=102,
        threat_type="Kerberoasting",
        severity="high",
        confidence=0.92,
        evidence={"src_ip": "198.51.100.99", "dest_port": 88, "protocol": "tcp"},
        mitre_techniques=["T1558.003"],
    )

    smart_log = build_smart_log(record)
    smart_log.source["src_ip"] = "198.51.100.99"

    playbook = default_defense_rag.retrieve_defense_playbook("Kerberoasting attack EventID 4669", telemetry={"src_ip": "198.51.100.99", "dest_port": 88})
    tids = [t["technique_id"] for t in playbook["techniques"]]
    assert "T1558.003" in tids or "T1558" in tids
    print("  -> GeniusDefenseRAG correlated Kerberoasting with T1558.003 and D3FEND")

    llm_output = json.dumps({
        "verdict": "malicious",
        "confidence": 0.92,
        "recommended_action": "block_ip",
        "rationale": "High frequency of RC4 Kerberos TGS tickets requested from source IP. Mitigated via D3-NIPF.",
        "evidence": ["EventID 4669", "T1558.003"],
        "containment": ["block_ip 198.51.100.99"],
        "limitations": []
    })

    guarded = parse_and_guard_ai_decision(
        raw=llm_output,
        smart_log=smart_log,
        provider="local_llama",
        model_version="Foundation-Sec-8B-Instruct.Q4_K_M",
        autonomous_actuate=True,
        execution_mode="simulation",
        target="198.51.100.99",
    )

    assert guarded.executed_action == "simulated:block_ip"
    print(f"  -> Autonomous Actuation Success: {guarded.executed_action} with token {guarded.rollback_token}")


if __name__ == "__main__":
    test_ddos_autonomous_mitigation_flow()
    test_active_directory_kerberoast_mitigation_flow()
    print("\n>>> ALL END-TO-END AUTONOMOUS ACTIVE DEFENSE TESTS PASSED SUCCESSFULLY! <<<")
