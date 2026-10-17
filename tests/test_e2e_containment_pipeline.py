"""End-to-End Integration Test: Real-Time Stream -> Smart Log -> Two-Person Rule -> Cryptographic Containment & Rollback.

Validates Task 4:
1. Multi-stage attack stream ingested via Suricata EVE bridge.
2. Smart Log generation and D3FEND-aligned mitigation recommendation.
3. Strict Two-Person Rule enforcement blocking single-analyst rogue actuation.
4. Dual-authorized containment execution under Neuro-Symbolic Safety Gate.
5. Cryptographic HMAC-SHA256 receipt tracking and atomic state rollback.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
import pytest

from backend.actuators.firewall import FirewallActuator
from backend.actuators.process import ProcessActuator
from backend.actuators.router import ActuatorRouter
from backend.actuators.suricata_rules import SuricataActuator
from backend.db.models import AlertRecord, SecurityEventRecord, SessionLocal
from backend.decision.engine import build_smart_log, policy_decision
from backend.detection.pipeline import DetectionPipeline
from backend.safety.formal_verifier import FormalSafetyVerifier
from backend.suricata.tailer import SuricataLiveTailer, SyntheticEveReplayer


@pytest.fixture
def clean_actuator_router() -> ActuatorRouter:
    """Provide a fresh ActuatorRouter with Two-Person Rule explicitly enforced."""
    verifier = FormalSafetyVerifier()
    router = ActuatorRouter(
        firewall=FirewallActuator(is_windows=True),
        suricata=SuricataActuator(),
        process=ProcessActuator(is_windows=True),
        safety_verifier=verifier,
        require_two_person=True,
    )
    router.clear_all()
    return router


def test_e2e_stream_to_containment_and_dual_authorization(clean_actuator_router: ActuatorRouter, monkeypatch: pytest.MonkeyPatch):
    """Full lifecycle verification from EVE ingest to dual-authorized containment and atomic rollback."""
    # ── Step 1: Ingest multi-stage attack events via Suricata Bridge ──
    tailer = SuricataLiveTailer(
        feed_pipeline_worker=False,
        persist_events=True,
        sensor_id="e2e-sensor-01",
    )

    attacker_ip = "198.51.100.77"
    victim_ip = "10.0.0.1"

    # Ingest synthetic alert: Apache Struts RCE (T1190)
    alert_raw = SyntheticEveReplayer.generate_eve_alert_event(
        sig="ET EXPLOIT Apache Struts RCE Vulnerability",
        sid=2024099,
        sev=1,
        src_ip=attacker_ip,
        dest_ip=victim_ip,
        src_port=44444,
        dest_port=8080,
    )
    event, feats = tailer.process_line(alert_raw)
    assert event is not None
    assert event.source_event_type == "alert"
    assert event.src_ip == attacker_ip

    # Persist an associated alert record in the database
    with SessionLocal() as session:
        alert_rec = AlertRecord(
            severity="critical",
            type="WebAttack",
            confidence=0.96,
            anomaly_score=0.88,
            stage="classifier",
            route="known_attack",
            mitre_techniques=json.dumps(["T1190"]),
            top_features=json.dumps([["Destination Port", 8080.0], ["Total Fwd Packets", 15.0]]),
            source_file="suricata-live-e2e.json",
        )
        session.add(alert_rec)
        session.commit()
        alert_id = alert_rec.id

    try:
        # ── Step 2: Smart Log Generation & D3FEND-Aligned Policy Decision ──
        record_obj = SimpleNamespace(
            id=alert_id,
            created_at=1000.0,
            severity="critical",
            type="WebAttack",
            confidence=0.96,
            anomaly_score=0.88,
            stage="classifier",
            route="known_attack",
            mitre_techniques=json.dumps(["T1190"]),
            top_features=json.dumps([["Destination Port", 8080.0]]),
            source_file="suricata-live-e2e.json",
        )
        smart_log = build_smart_log(record_obj)
        assert smart_log.schema_version == "smart-log-v2"
        assert "T1190" in smart_log.detection.mitre_techniques

        decision = policy_decision(smart_log)
        assert decision.verdict == "malicious"
        assert decision.recommended_action in ("alert", "block_recommended", "block_ip") or decision.recommended_action.value in ("alert", "block_recommended", "block_ip")

        # ── Step 3: Two-Person Rule Enforces Dual Authorization ──
        # Scenario A: Rogue single analyst attempts self-approval
        rogue_result = clean_actuator_router.execute_action(
            action="block_ip",
            target=attacker_ip,
            params={
                "initiator_id": "analyst-john",
                "approver_id": "analyst-john",  # Self-approval prohibited
                "severity": "critical",
                "confidence": 0.96,
            },
            mode="enforcement",
        )
        assert rogue_result.success is False
        assert "Two-Person Rule violation" in (rogue_result.error or "")
        assert rogue_result.metadata.get("two_person_rule_violated") is True

        # Scenario B: Missing approver completely
        missing_approver_result = clean_actuator_router.execute_action(
            action="block_ip",
            target=attacker_ip,
            params={
                "initiator_id": "analyst-john",
                "severity": "critical",
                "confidence": 0.96,
            },
            mode="enforcement",
        )
        assert missing_approver_result.success is False
        assert "Two-Person Rule violation" in (missing_approver_result.error or "")

        # ── Step 4: Authorized Dual-Person Containment Execution ──
        # Mock OS admin privilege & subprocess command execution for safe test environment
        monkeypatch.setattr(clean_actuator_router.firewall, "is_elevated", lambda: True)
        monkeypatch.setattr(
            "backend.actuators.firewall.subprocess.run",
            lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="NetFirewallRule added successfully", stderr=""),
        )

        legit_result = clean_actuator_router.execute_action(
            action="block_ip",
            target=attacker_ip,
            params={
                "initiator_id": "analyst-john",
                "approver_id": "security-lead-sarah",  # Distinct approver
                "severity": "critical",
                "confidence": 0.96,
                "direction": "Inbound",
            },
            mode="enforcement",
        )


        assert legit_result.success is True
        assert legit_result.rollback_token is not None
        assert legit_result.rollback_token.startswith("cg-proof-")

        # ── Step 5: Verify Active Block Registry & Invariant I_3 Invertibility ──
        active_blocks = clean_actuator_router.list_active_blocks()
        assert len(active_blocks) == 1
        assert active_blocks[0]["target"] == attacker_ip
        assert active_blocks[0]["rollback_token"] == legit_result.rollback_token

        # ── Step 6: Atomic Rollback via Cryptographic HMAC Proof Token ──
        rollback_ok = clean_actuator_router.rollback_action(legit_result.rollback_token)
        assert rollback_ok is True

        # Registry must be cleanly cleared
        remaining_blocks = clean_actuator_router.list_active_blocks()
        assert len(remaining_blocks) == 0

        # Idempotent second rollback attempt should safely fail
        second_rollback = clean_actuator_router.rollback_action(legit_result.rollback_token)
        assert second_rollback is False

    finally:
        # Cleanup test DB records
        with SessionLocal() as session:
            session.query(AlertRecord).filter_by(id=alert_id).delete()
            session.query(SecurityEventRecord).filter_by(sensor_id="e2e-sensor-01").delete()
            session.commit()
