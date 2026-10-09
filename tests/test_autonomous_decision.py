"""Tests for autonomous decision engine with active defense actuation."""
import json
import pytest

from backend.decision.engine import parse_and_guard_ai_decision, decision_messages
from backend.decision.models import (
    SmartLog,
    DetectionEvidence,
    Verdict,
    RecommendedAction,
)


def _make_dummy_smart_log(threat="DDoS", src_ip="203.0.113.60"):
    return SmartLog(
        event_id="test-event-01",
        alert_id=101,
        created_at=1700000000.0,
        source={"kind": "flow", "src_ip": src_ip, "remote_ip": src_ip},
        detection=DetectionEvidence(
            type=threat,
            severity="critical",
            stage="classifier",
            confidence=0.96,
            anomaly_score=4.2,
            mitre_techniques=["T1498"],
        ),
        operational_mode="evaluation_only",
        review_required=True,
        review_reason="classifier_alert",
        evidence_fingerprint="abc123fingerprint",
    )


def test_parse_and_guard_autonomous_actuation_simulation():
    smart_log = _make_dummy_smart_log()
    llm_payload = json.dumps({
        "verdict": "malicious",
        "confidence": 0.95,
        "recommended_action": "block_ip",
        "rationale": "High-confidence volumetric DDoS observed from source IP.",
        "evidence": ["flow_packets_s=90000"],
        "containment": ["Block remote source IP"],
        "limitations": [],
    })

    decision = parse_and_guard_ai_decision(
        llm_payload,
        smart_log,
        provider="test-provider",
        autonomous_actuate=True,
        execution_mode="simulation",
    )

    assert decision.verdict == Verdict.malicious
    assert decision.confidence == 0.95
    assert decision.recommended_action == RecommendedAction.block_ip
    assert decision.executed_action == "simulated:block_ip"
    assert decision.execution_mode == "simulation"
    assert decision.actuator_result is not None
    assert decision.actuator_result["simulated"] is True
    assert decision.rollback_token is not None
    assert decision.requires_human is False


def test_parse_and_guard_rejects_loopback_autonomous_attack():
    # If LLM attempts to block localhost (prompt injection or hallucination)
    smart_log = _make_dummy_smart_log(src_ip="127.0.0.1")
    llm_payload = json.dumps({
        "verdict": "malicious",
        "confidence": 0.99,
        "recommended_action": "block_ip",
        "rationale": "Attempt to block loopback",
        "evidence": [],
        "containment": [],
        "limitations": [],
    })

    decision = parse_and_guard_ai_decision(
        llm_payload,
        smart_log,
        provider="test-provider",
        autonomous_actuate=True,
        execution_mode="simulation",
        target="127.0.0.1",
    )

    # Must be intercepted by guardrail
    assert decision.requires_human is True
    assert decision.executed_action == "none"
    assert any("guardrail" in lim.lower() for lim in decision.limitations)


def test_decision_messages_includes_defense_grounding():
    smart_log = _make_dummy_smart_log()
    defense_ctx = "GROUNDED D3FEND: D3-NIPF Network Ingress Packet Filtering"
    msgs = decision_messages(smart_log, mitre_context="T1498 details", defense_context=defense_ctx)

    assert len(msgs) == 2
    assert "D3-NIPF" in msgs[1]["content"]
    assert "autonomous defense decision engine" in msgs[0]["content"]
