"""MITRE ATT&CK integration tests: mapper, technique context, and attack_db."""
import json

from backend.api import mitre as mitre_api
from backend.db.init_db import init_all
from backend.db.models import AlertRecord, SessionLocal
from backend.mitre.mapper import (
    map_alert_to_techniques,
    map_technique_to_labels,
    get_all_mapped_techniques,
    get_technique_context,
)


def test_ddos_maps_to_t1498():
    techs = map_alert_to_techniques("DDoS")
    assert "T1498" in techs
    assert "T1499" in techs


def test_unknown_anomaly_does_not_invent_exploitation_mapping():
    techs = map_alert_to_techniques("unknown-anomaly")
    assert techs == []


def test_portscan_maps_to_discovery():
    techs = map_alert_to_techniques("PortScan")
    assert "T1046" in techs


def test_brute_force_maps_correctly():
    techs = map_alert_to_techniques("BruteForce")
    assert "T1110" in techs
    assert "T1110.001" in techs


def test_unknown_label_returns_empty():
    assert map_alert_to_techniques("UnknownAttack") == []


def test_reverse_mapping():
    labels = map_technique_to_labels("T1498")
    assert "DDoS" in labels
    assert "DoS" in labels  # T1498 is in both DDoS and DoS


def test_all_mapped_techniques():
    techs = get_all_mapped_techniques()
    assert isinstance(techs, set)
    assert len(techs) >= 15
    assert "T1498" in techs
    assert "T1203" not in techs


def test_technique_context_generates_markdown():
    ctx = get_technique_context("DDoS")
    assert "T1498" in ctx
    assert "classifier label DDoS" in ctx
    assert "heuristic, not observed behavior" in ctx
    assert "attack.mitre.org" in ctx


def test_technique_context_unknown_label():
    ctx = get_technique_context("FakeAttack")
    assert "No MITRE" in ctx


def test_all_cicids2017_classes_mapped():
    """Every CICIDS2017 attack class must have at least one MITRE mapping."""
    classes = ["DDoS", "DoS", "PortScan", "BruteForce",
               "WebAttack", "Bot", "Infiltration", "Heartbleed"]
    for cls in classes:
        techs = map_alert_to_techniques(cls)
        assert len(techs) >= 1, f"{cls} has no MITRE mapping!"


def test_web_attack_includes_exploit_and_execution():
    techs = map_alert_to_techniques("WebAttack")
    assert "T1190" in techs  # Exploit Public-Facing App
    assert "T1059" in techs  # Command and Scripting Interpreter


def test_local_rag_indexes_all_mitre_and_retrieves_known_technique():
    from backend.llm.rag import MitreRAG
    from backend.mitre.attack_db import list_techniques

    rag = MitreRAG()
    techniques = list_techniques(limit=5000)
    assert rag.index(techniques) == len(techniques)
    results = rag.query("T1498 network denial of service DDoS", k=3)
    assert results
    assert any(row["id"] == "T1498" for row in results)
    assert rag.count() == len(techniques)


def test_persisted_classifier_alert_updates_mitre_view_with_provenance():
    from backend.mitre.attack_db import get_candidate_mappings

    init_all()
    with SessionLocal() as session:
        record = AlertRecord(
            severity="high", type="DDoS", confidence=0.98,
            anomaly_score=0.0, stage="classifier", route="known_attack",
            mitre_techniques='["T1498","T1499"]', top_features="[]",
            source_file="mitre-provenance-test.csv",
        )
        session.add(record)
        session.commit()
        alert_id = record.id
    try:
        mappings = get_candidate_mappings(alert_id=alert_id)
        assert {item["technique_id"] for item in mappings} == {"T1498", "T1499"}
        assert all(item["classifier_label"] == "DDoS" for item in mappings)
        assert all(item["observed_evidence"] == 0 for item in mappings)
        assert all(item["evidence_kind"] == "heuristic_hypothesis" for item in mappings)
        rows = mitre_api.techniques(tactic=None, q="T1498", limit=10)
        technique = next(item for item in rows if item["id"] == "T1498")
        assert technique["candidate_mapping"] is True
        assert technique["mapping_semantics"] == (
            "possible technique based on classifier label"
        )
    finally:
        with SessionLocal() as session:
            stored = session.get(AlertRecord, alert_id)
            if stored:
                session.delete(stored)
            session.commit()


def test_unknown_anomaly_persists_no_invented_mitre_mapping():
    from backend.mitre.attack_db import get_candidate_mappings

    init_all()
    with SessionLocal() as session:
        record = AlertRecord(
            severity="high", type="unknown-anomaly", confidence=0.0,
            anomaly_score=5.0, stage="autoencoder",
            route="unknown_anomaly_review",
            # Even stale legacy JSON must not create provenance rows.
            mitre_techniques='["T1203"]', top_features="[]",
            source_file="unknown-mapping-test.csv",
        )
        session.add(record)
        session.commit()
        alert_id = record.id
    try:
        assert get_candidate_mappings(alert_id=alert_id) == []
    finally:
        with SessionLocal() as session:
            stored = session.get(AlertRecord, alert_id)
            if stored:
                session.delete(stored)
            session.commit()


def test_snapshot_uses_mitre_reference_and_removes_revoked_rows(tmp_path, monkeypatch):
    from backend.mitre import attack_db

    monkeypatch.setattr(attack_db, "DB_PATH", tmp_path / "mitre.sqlite")
    attack_db.init()
    first = tmp_path / "enterprise-attack-v-test-1.json"
    first.write_text(json.dumps({"objects": [{
        "type": "attack-pattern",
        "id": "attack-pattern--unit",
        "name": "Correct reference",
        "external_references": [
            {"source_name": "not-mitre", "external_id": "T1111"},
            {"source_name": "mitre-attack", "external_id": "T9999",
             "url": "https://attack.mitre.org/techniques/T9999/"},
        ],
        "kill_chain_phases": [],
    }]}), encoding="utf-8")
    assert attack_db.index_snapshot(first) == 1
    assert attack_db.get_technique("T9999")["name"] == "Correct reference"
    assert attack_db.get_technique("T1111") is None

    second = tmp_path / "enterprise-attack-v-test-2.json"
    second.write_text(json.dumps({"objects": [{
        "type": "attack-pattern",
        "id": "attack-pattern--unit",
        "name": "Revoked",
        "revoked": True,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T9999"}
        ],
    }]}), encoding="utf-8")
    assert attack_db.index_snapshot(second) == 0
    assert attack_db.get_technique("T9999") is None
    assert attack_db.get_stats()["latest_sync"]["version"] == "v-test-2"
