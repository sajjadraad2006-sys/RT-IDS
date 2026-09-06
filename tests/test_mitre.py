"""MITRE ATT&CK integration tests: mapper, technique context, and attack_db."""
import json

import pytest

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


def test_fresh_temporary_mitre_index_and_rag_retrieve_known_technique(tmp_path):
    from backend.llm.rag import MitreRAG
    from backend.mitre.attack_db import get_technique, list_techniques
    from backend.mitre.verification import verify_snapshot_index

    database = tmp_path / "fresh-mitre.sqlite"
    verified = verify_snapshot_index(database)
    assert verified["technique_count"] > 0
    assert verified["sqlite_indexed"] == verified["technique_count"]
    assert verified["rag_indexed"] == verified["technique_count"]
    assert "T1498" in verified["rag_match_ids"]
    assert get_technique("T1498", db_path=database)["id"] == "T1498"

    techniques = list_techniques(limit=5000, db_path=database)
    rag = MitreRAG()
    assert rag.index(techniques) == len(techniques)
    results = rag.query("T1498 network denial of service DDoS", k=3)
    assert results
    assert any(row["id"] == "T1498" for row in results)
    assert rag.count() == len(techniques)


def test_persisted_classifier_alert_updates_mitre_view_with_provenance():
    from backend.mitre.attack_db import get_candidate_mappings, index_snapshot

    init_all()
    assert index_snapshot() > 0
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


def test_technique_detail_exposes_d3fend_candidates_without_execution(monkeypatch):
    from backend.api import mitre

    monkeypatch.setattr(mitre.attack_db, "get_technique", lambda _tid: {
        "id": "T1071.001", "name": "Web Protocols", "tactics": "[]"
    })
    monkeypatch.setattr(mitre.attack_db, "get_candidate_mappings", lambda *_args: [])
    monkeypatch.setattr(
        mitre.attack_db,
        "check_technique_status",
        lambda _tid: ("active_validated", {"id": "T1071.001"}),
    )

    class Store:
        def candidate_defenses(self, _tid, *, attack_verified):
            assert attack_verified is True
            return [{
                "d3fend_technique_id": "D3-NTA",
                "name": "Network Traffic Analysis",
                "executed_action": False,
            }]

        def health(self):
            return {"active_version": "1.5.0", "available": True}

    monkeypatch.setattr(mitre, "_d3fend_store", Store(), raising=False)
    detail = mitre.technique_detail("T1071.001")
    assert detail["d3fend"]["mapping_semantics"] == "candidate defensive techniques"
    assert detail["d3fend"]["executed_action"] == "none"
    assert detail["d3fend"]["candidates"][0]["d3fend_technique_id"] == "D3-NTA"


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


def test_unverified_active_snapshot_does_not_validate_technique(tmp_path):
    from backend.mitre import attack_db

    database = tmp_path / "mitre.sqlite"
    snapshot = tmp_path / "enterprise-attack-v-local.json"
    snapshot.write_text(json.dumps({"objects": [{
        "type": "attack-pattern", "id": "attack-pattern--local", "name": "Local",
        "external_references": [{
            "source_name": "mitre-attack", "external_id": "T9992"
        }],
    }]}), encoding="utf-8")
    attack_db.init(database)
    attack_db.index_snapshot(snapshot, db_path=database)

    status, _ = attack_db.check_technique_status("T9992", db_path=database)
    assert status == "active_unverified"


def test_failed_snapshot_activation_preserves_last_known_good(tmp_path):
    from backend.mitre import attack_db

    database = tmp_path / "mitre.sqlite"
    good = tmp_path / "enterprise-attack-v-test-good.json"
    good.write_text(json.dumps({"objects": [{
        "type": "x-mitre-collection",
        "name": "Enterprise ATT&CK",
        "x_mitre_version": "9.9",
    }, {
        "type": "attack-pattern",
        "id": "attack-pattern--good",
        "name": "Last known good",
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": "T9998",
        }],
    }]}), encoding="utf-8")
    provenance = {
        "source_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/test.json",
        "source_kind": "official_github_release",
        "release": "v9.9",
        "retrieved_at": 1_700_000_000.0,
        "verification_status": "official_release_verified",
    }

    result = attack_db.activate_snapshot(
        good, provenance=provenance, db_path=database, minimum_objects=1
    )
    assert result["activated"] is True
    assert attack_db.get_technique("T9998", db_path=database) is not None

    malformed = tmp_path / "enterprise-attack-v-test-bad.json"
    malformed.write_text('{"objects":[', encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        attack_db.activate_snapshot(
            malformed,
            provenance={**provenance, "release": "v9.10"},
            db_path=database,
            minimum_objects=1,
        )

    assert attack_db.get_technique("T9998", db_path=database) is not None
    stats = attack_db.get_stats(db_path=database)
    assert stats["active_version"] == "v9.9"
    assert stats["source_kind"] == "official_github_release"
    assert stats["official_release_verified"] is True
    assert stats["last_successful_sync"] is not None
    assert stats["last_sync_error"]


def test_activation_rejects_release_mismatch_before_replacing_active_snapshot(tmp_path):
    from backend.mitre import attack_db

    snapshot = tmp_path / "enterprise-attack-v19.1.json"
    snapshot.write_text(json.dumps({"objects": [{
        "type": "x-mitre-collection",
        "name": "Enterprise ATT&CK",
        "x_mitre_version": "19.2",
    }, {
        "type": "attack-pattern",
        "id": "attack-pattern--mismatch",
        "name": "Mismatch",
        "external_references": [{
            "source_name": "mitre-attack", "external_id": "T9997"
        }],
    }]}), encoding="utf-8")

    with pytest.raises(ValueError, match="release.*mismatch"):
        attack_db.activate_snapshot(
            snapshot,
            provenance={
                "source_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json",
                "source_kind": "official_github_release",
                "release": "v19.1",
                "retrieved_at": 1_700_000_000.0,
                "verification_status": "official_release_verified",
            },
            db_path=tmp_path / "mitre.sqlite",
            minimum_objects=1,
        )


def test_attack_sync_uses_pinned_official_release_url():
    from backend.mitre.taxii_sync import official_release_url

    assert official_release_url("v19.1") == (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack-19.1.json"
    )
    with pytest.raises(ValueError, match="release"):
        official_release_url("master")


def test_attack_sync_cli_activates_downloaded_snapshot(monkeypatch, capsys):
    from backend.mitre import lifecycle, taxii_sync

    monkeypatch.setattr(taxii_sync, "sync_attack", lambda force=False: {
        "status": "synced", "path": "/tmp/attack.json",
        "provenance": {"release": "v-test"},
    })
    monkeypatch.setattr(
        lifecycle,
        "activate_with_rag",
        lambda path, provenance: ({
            "activated": True, "technique_count": 1,
            "rag_indexed": 1, "rag_synchronized": True,
        }, object()),
    )

    assert taxii_sync.main([]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["activation"]["rag_synchronized"] is True


def test_attack_activation_rejects_provenance_hash_mismatch(tmp_path):
    from backend.mitre import attack_db

    snapshot = tmp_path / "enterprise-attack-v-test.json"
    snapshot.write_text(json.dumps({"objects": [{
        "type": "attack-pattern",
        "id": "attack-pattern--hash",
        "name": "Hash test",
        "external_references": [{
            "source_name": "mitre-attack", "external_id": "T9994"
        }],
    }]}), encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256"):
        attack_db.activate_snapshot(
            snapshot,
            provenance={
                "source_url": "https://example.invalid/release.json",
                "source_kind": "official_github_release",
                "release": "v-test",
                "retrieved_at": 1_700_000_000.0,
                "sha256": "0" * 64,
                "verification_status": "official_release_verified",
            },
            db_path=tmp_path / "mitre.sqlite",
            minimum_objects=1,
        )


def test_attack_activation_rejects_zero_technique_bundle_before_lkg_replacement(tmp_path):
    from backend.mitre import attack_db

    database = tmp_path / "mitre.sqlite"
    good = tmp_path / "enterprise-attack-v-good.json"
    good.write_text(json.dumps({"objects": [{
        "type": "attack-pattern", "id": "attack-pattern--good", "name": "Good",
        "external_references": [{
            "source_name": "mitre-attack", "external_id": "T9993"
        }],
    }]}), encoding="utf-8")
    provenance = {
        "source_url": "fixture", "source_kind": "offline_fixture",
        "release": "v-good", "retrieved_at": 1.0,
        "verification_status": "fixture_verified",
    }
    attack_db.activate_snapshot(
        good, provenance=provenance, db_path=database, minimum_objects=1
    )
    empty = tmp_path / "enterprise-attack-v-empty.json"
    empty.write_text(json.dumps({"objects": [{
        "type": "identity", "id": f"identity--{index}"
    } for index in range(1000)]}), encoding="utf-8")

    with pytest.raises(ValueError, match="active techniques"):
        attack_db.activate_snapshot(
            empty,
            provenance={**provenance, "release": "v-empty"},
            db_path=database,
            minimum_objects=1000,
        )
    assert attack_db.get_technique("T9993", db_path=database) is not None


def test_attack_snapshot_cache_preserves_downloaded_bytes(tmp_path):
    import hashlib
    from backend.mitre.taxii_sync import _write_bytes_atomic

    raw = b'{"type":"bundle","objects":[]}\n'
    target = tmp_path / "snapshot.json"
    _write_bytes_atomic(target, raw)

    assert target.read_bytes() == raw
    assert hashlib.sha256(target.read_bytes()).hexdigest() == hashlib.sha256(raw).hexdigest()


def test_rag_failure_does_not_replace_active_attack_snapshot(tmp_path):
    from backend.mitre import attack_db
    from backend.mitre.lifecycle import activate_with_rag

    database = tmp_path / "active.sqlite"
    old = tmp_path / "enterprise-attack-v-old.json"
    old.write_text(json.dumps({"objects": [{
        "type": "attack-pattern",
        "id": "attack-pattern--old",
        "name": "Old active",
        "external_references": [{
            "source_name": "mitre-attack", "external_id": "T9996"
        }],
    }]}), encoding="utf-8")
    base_provenance = {
        "source_url": "https://example.invalid/old.json",
        "source_kind": "offline_fixture",
        "release": "v-old",
        "retrieved_at": 1_700_000_000.0,
        "verification_status": "fixture_verified",
    }
    attack_db.activate_snapshot(
        old, provenance=base_provenance, db_path=database, minimum_objects=1
    )

    new = tmp_path / "enterprise-attack-v-new.json"
    new.write_text(json.dumps({"objects": [{
        "type": "attack-pattern",
        "id": "attack-pattern--new",
        "name": "New candidate",
        "external_references": [{
            "source_name": "mitre-attack", "external_id": "T9995"
        }],
    }]}), encoding="utf-8")

    class BrokenRag:
        def index(self, _techniques):
            raise RuntimeError("rag build failed")

    with pytest.raises(RuntimeError, match="rag build failed"):
        activate_with_rag(
            new,
            provenance={**base_provenance, "release": "v-new"},
            db_path=database,
            rag_factory=BrokenRag,
            minimum_objects=1,
        )

    assert attack_db.get_technique("T9996", db_path=database) is not None
    assert attack_db.get_technique("T9995", db_path=database) is None


def test_mitre_rag_candidate_indexes_are_instance_isolated():
    from backend.llm.rag import MitreRAG

    first = MitreRAG(min_relevance=0)
    second = MitreRAG(min_relevance=0)
    first.index([{"id": "T0001", "name": "First", "description": "one"}])
    second.index([{"id": "T0002", "name": "Second", "description": "two"}])

    assert first.count() == 1
    assert first.query("T0001", k=1)[0]["id"] == "T0001"
    assert second.query("T0002", k=1)[0]["id"] == "T0002"


def test_shared_rag_publish_reaches_chat_and_decision_consumers():
    from backend.api import chat, decision
    from backend.llm.mitre_index import publish_mitre_rag
    from backend.llm.rag import MitreRAG

    candidate = MitreRAG(min_relevance=0)
    candidate.index([{"id": "T0003", "name": "Shared", "description": "shared"}])
    publish_mitre_rag(candidate)

    assert chat._get_rag() is candidate
    assert decision._get_rag() is candidate


def test_mitre_verification_fails_when_valid_snapshot_indexes_zero(
    tmp_path, monkeypatch
):
    from backend.mitre import attack_db
    from backend.mitre.verification import (
        MitreVerificationError,
        verify_snapshot_index,
    )

    monkeypatch.setattr(attack_db, "index_snapshot", lambda *args, **kwargs: 0)
    with pytest.raises(MitreVerificationError, match="indexed zero") as failure:
        verify_snapshot_index(tmp_path / "empty.sqlite")
    assert failure.value.stage == "sqlite_indexing"


def test_mitre_verification_fails_explicitly_for_corrupt_snapshot(tmp_path):
    from backend.mitre.verification import (
        MitreVerificationError,
        verify_snapshot_index,
    )

    corrupt = tmp_path / "enterprise-attack-corrupt.json"
    corrupt.write_text('{"objects":[', encoding="utf-8")
    with pytest.raises(MitreVerificationError, match="malformed") as failure:
        verify_snapshot_index(
            tmp_path / "corrupt.sqlite", snapshot_path=corrupt
        )
    assert failure.value.stage == "snapshot_validation"
    assert not (tmp_path / "corrupt.sqlite").exists()
