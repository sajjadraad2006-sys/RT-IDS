"""Incident correlation, triage, and transparent risk tests."""
from __future__ import annotations

import math
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest


def _event(ref: str, timestamp: float, **overrides):
    event = {
        "event_ref": ref,
        "source_kind": "suricata_eve",
        "timestamp": timestamp,
        "sensor_id": "sensor-a",
        "community_id": "1:test",
        "signature_id": 2100498,
        "severity": "high",
    }
    event.update(overrides)
    return event


def test_correlation_is_deterministic_deduplicated_and_bounded(tmp_path):
    from backend.operations.incidents import IncidentStore

    store = IncidentStore(
        tmp_path / "incidents.sqlite", window_seconds=300, max_evidence_per_incident=2
    )
    first = store.ingest(_event("event-1", 1000))
    second = store.ingest(_event("event-2", 1100))
    duplicate = store.ingest(_event("event-2", 1100))
    rotated = store.ingest(_event("event-3", 1200))

    assert first["incident_id"] == second["incident_id"]
    assert duplicate["incident_id"] == first["incident_id"]
    assert duplicate["duplicate"] is True
    assert rotated["incident_id"] != first["incident_id"]
    incidents = store.list_incidents()
    assert [item["first_seen"] for item in incidents] == [1200, 1000]
    assert sum(item["evidence_count"] for item in incidents) == 3
    assert sum(item["duplicate_count"] for item in incidents) == 1


def test_triage_respects_artifact_approval_and_never_executes_action():
    from backend.operations.triage import triage_evidence

    approved = triage_evidence({
        "route": "known_attack",
        "confidence": 0.99,
        "artifact_approved": True,
        "artifact_status": "production_approved",
        "evidence_refs": ["alert:1"],
        "source_provenance": ["uploaded_flow"],
    })
    assert approved["state"] == "auto_escalated_known_attack"
    assert approved["human_review_required"] is False

    evaluation = triage_evidence({
        "route": "known_attack",
        "confidence": 0.99,
        "artifact_approved": False,
        "artifact_status": "evaluation_only",
        "evidence_refs": ["alert:2"],
        "source_provenance": ["uploaded_flow"],
    })
    assert evaluation["state"] == "review_required_uncertain"
    assert evaluation["human_review_required"] is True

    unknown = triage_evidence({
        "route": "unknown_anomaly_review",
        "confidence": 0.0,
        "artifact_approved": False,
        "artifact_status": "evaluation_only",
        "evidence_refs": ["alert:3"],
        "source_provenance": ["uploaded_flow"],
    })
    assert unknown["state"] == "review_required_unknown_anomaly"
    assert unknown["attack_candidates"] == []
    assert unknown["cves"] == []
    assert all(item["executed_action"] == "none" for item in (approved, evaluation, unknown))


def test_risk_score_is_finite_versioned_and_fully_decomposed():
    from backend.operations.risk import calculate_risk

    result = calculate_risk({
        "sensor_severity": "high",
        "classifier_confidence": 0.8,
        "statistical_score": 1e12,
        "statistical_calibrated": False,
        "asset_criticality": 0.5,
        "kev": True,
        "epss_score": 0.7,
        "intelligence_freshness": "stale",
        "attack_verified": True,
        "uncertainty": 0.25,
    })
    assert result["formula_version"] == "transparent-risk-v1"
    assert math.isfinite(result["score"])
    assert 0 <= result["score"] <= 100
    assert result["components"]["statistical_ood"]["contribution"] == 0
    assert result["components"]["statistical_ood"]["warning"]
    assert result["components"]["freshness_penalty"]["contribution"] < 0
    assert sum(item["contribution"] for item in result["components"].values()) == result["raw_score"]
    assert result["containment_authorized"] is False


def test_incident_triage_and_analyst_resolution_are_persisted_and_audited(tmp_path):
    from backend.operations.incidents import IncidentStore
    from backend.operations.triage import triage_evidence

    store = IncidentStore(tmp_path / "incidents.sqlite")
    incident_id = store.ingest(_event("event-audit", 2000))["incident_id"]
    triage = triage_evidence({
        "route": "unknown_anomaly_review",
        "confidence": 0,
        "artifact_approved": False,
        "artifact_status": "evaluation_only",
        "evidence_refs": ["event-audit"],
        "source_provenance": ["suricata_eve"],
        "timestamp": 2000,
    })
    store.record_triage(incident_id, triage)
    assert store.list_incidents()[0]["triage_state"] == (
        "review_required_unknown_anomaly"
    )

    result = store.resolve_by_analyst(
        incident_id, actor="analyst:test", verdict="suspicious", notes="correlated"
    )
    assert result["state"] == "resolved_by_analyst"
    assert result["executed_action"] == "none"
    audit = store.analyst_audit(incident_id)
    assert audit[0]["actor"] == "analyst:test"
    assert audit[0]["verdict"] == "suspicious"
    store.record_triage(incident_id, triage)
    incident = store.list_incidents()[0]
    assert incident["triage_state"] == "resolved_by_analyst"
    assert incident["analyst_status"] == "resolved"
    with pytest.raises(ValueError, match="already resolved"):
        store.resolve_by_analyst(
            incident_id, actor="analyst:test", verdict="benign", notes="repeat"
        )
    assert len(store.analyst_audit(incident_id)) == 1


def test_incident_store_fails_closed_at_unresolved_capacity(tmp_path):
    from backend.operations.incidents import IncidentCapacityError, IncidentStore

    store = IncidentStore(tmp_path / "incidents.sqlite", max_incidents=2)
    store.ingest(_event("cap-1", 1, community_id="1:one"))
    store.ingest(_event("cap-2", 2, community_id="1:two"))
    with pytest.raises(IncidentCapacityError, match="capacity"):
        store.ingest(_event("cap-3", 3, community_id="1:three"))
    assert len(store.list_incidents()) == 2


def test_concurrent_incident_ingestion_serializes_group_creation(tmp_path):
    from backend.operations.incidents import IncidentStore

    store = IncidentStore(tmp_path / "incidents.sqlite")
    workers = 8
    barrier = threading.Barrier(workers)

    def ingest(index):
        barrier.wait()
        return store.ingest(_event(f"concurrent-{index}", 3000))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(ingest, range(workers)))
    assert len({result["incident_id"] for result in results}) == 1
    incident = store.list_incidents()[0]
    assert incident["evidence_count"] == workers


def test_concurrent_analyst_resolution_appends_exactly_one_audit(tmp_path):
    from backend.operations.incidents import IncidentStore

    store = IncidentStore(tmp_path / "incidents.sqlite")
    incident_id = store.ingest(_event("resolve-race", 4000))["incident_id"]
    workers = 8
    barrier = threading.Barrier(workers)

    def resolve(index):
        barrier.wait()
        try:
            store.resolve_by_analyst(
                incident_id, actor=f"analyst:{index}", verdict="suspicious"
            )
            return "resolved"
        except ValueError as exc:
            assert "already resolved" in str(exc)
            return "rejected"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(resolve, range(workers)))
    assert results.count("resolved") == 1
    assert results.count("rejected") == workers - 1
    assert len(store.analyst_audit(incident_id)) == 1
