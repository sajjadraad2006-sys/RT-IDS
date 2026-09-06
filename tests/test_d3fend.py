"""D3FEND official-format relationship lifecycle tests."""
from __future__ import annotations

import hashlib
import json

import pytest


def _write_sources(tmp_path):
    ontology = {
        "@context": {},
        "@graph": [
            {
                "@id": "d3f:NetworkTrafficAnalysis",
                "d3f:d3fend-id": "D3-NTA",
                "rdfs:label": "Network Traffic Analysis",
                "d3f:definition": "Analyze network traffic.",
            },
            {
                "@id": "d3f:DeprecatedDefense",
                "d3f:d3fend-id": "D3-OLD",
                "rdfs:label": "Old defense",
                "owl:deprecated": True,
            },
        ],
    }
    mappings = {
        "head": {"vars": ["off_tech_id", "def_tech"]},
        "results": {"bindings": [
            {
                "off_tech_id": {"type": "literal", "value": "T1071.001"},
                "def_tech": {
                    "type": "uri",
                    "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#NetworkTrafficAnalysis",
                },
                "off_artifact_rel_label": {"type": "literal", "value": "uses"},
                "def_artifact_rel_label": {"type": "literal", "value": "analyzes"},
            },
            {
                "off_tech_id": {"type": "literal", "value": "T1000"},
                "def_tech": {
                    "type": "uri",
                    "value": "http://d3fend.mitre.org/ontologies/d3fend.owl#DeprecatedDefense",
                },
            },
        ]},
    }
    ontology_path = tmp_path / "d3fend.json"
    mappings_path = tmp_path / "d3fend-full-mappings.json"
    ontology_path.write_text(json.dumps(ontology), encoding="utf-8")
    mappings_path.write_text(json.dumps(mappings), encoding="utf-8")
    return ontology_path, mappings_path


def test_d3fend_refresh_indexes_only_active_official_relationships(tmp_path):
    from backend.mitre.d3fend import D3fendStore

    ontology, mappings = _write_sources(tmp_path)
    store = D3fendStore(tmp_path / "d3fend.sqlite")
    result = store.refresh(
        ontology,
        mappings,
        source_version="1.5.0",
        source_url="https://d3fend.mitre.org/ontologies/d3fend/1.5.0/",
    )

    assert result["technique_count"] == 1
    assert result["relationship_count"] == 1
    candidates = store.candidate_defenses("T1071.001", attack_verified=True)
    assert candidates == [{
        "attack_technique_id": "T1071.001",
        "d3fend_technique_id": "D3-NTA",
        "name": "Network Traffic Analysis",
        "relationship_type": "uses->analyzes",
        "source_version": "1.5.0",
        "source_hash": hashlib.sha256(mappings.read_bytes()).hexdigest(),
        "ontology_hash": hashlib.sha256(ontology.read_bytes()).hexdigest(),
        "mapping_version": "d3fend-inferred-v1",
        "evidence_source": "official_d3fend_inferred_relationship",
        "confidence_semantics": "candidate_defensive_technique",
        "executed_action": False,
    }]
    assert store.candidate_defenses("T9999", attack_verified=True) == []
    assert store.candidate_defenses("T1071.001", attack_verified=False) == []


def test_d3fend_failed_refresh_retains_last_known_good(tmp_path):
    from backend.mitre.d3fend import D3fendStore

    ontology, mappings = _write_sources(tmp_path)
    store = D3fendStore(tmp_path / "d3fend.sqlite")
    store.refresh(ontology, mappings, source_version="1.5.0", source_url="official")
    mappings.write_text('{"results":', encoding="utf-8")

    with pytest.raises(ValueError, match="malformed"):
        store.refresh(ontology, mappings, source_version="broken", source_url="official")

    assert store.candidate_defenses("T1071.001", attack_verified=True)
    health = store.health()
    assert health["active_version"] == "1.5.0"
    assert health["last_error"]


def test_d3fend_empty_refresh_cannot_replace_last_known_good(tmp_path):
    from backend.mitre.d3fend import D3fendStore

    ontology, mappings = _write_sources(tmp_path)
    store = D3fendStore(tmp_path / "d3fend.sqlite")
    store.refresh(ontology, mappings, source_version="1.5.0", source_url="official")
    ontology.write_text(json.dumps({"@graph": []}), encoding="utf-8")
    mappings.write_text(json.dumps({
        "head": {"vars": []}, "results": {"bindings": []}
    }), encoding="utf-8")

    with pytest.raises(ValueError, match="no active defensive techniques"):
        store.refresh(ontology, mappings, source_version="empty", source_url="official")
    assert store.health()["active_version"] == "1.5.0"
    assert store.candidate_defenses("T1071.001", attack_verified=True)


def test_d3fend_sync_uses_versioned_official_release_urls():
    from backend.mitre.d3fend_sync import official_d3fend_urls

    urls = official_d3fend_urls("1.5.0")
    assert urls == {
        "ontology": "https://d3fend.mitre.org/ontologies/d3fend/1.5.0/d3fend.json",
        "mappings": "https://d3fend.mitre.org/ontologies/d3fend/1.5.0/d3fend-full-mappings.json",
    }
    with pytest.raises(ValueError, match="version"):
        official_d3fend_urls("latest")


def test_d3fend_sync_invalid_candidate_retains_cached_files(tmp_path):
    from backend.mitre.d3fend import D3fendStore
    from backend.mitre.d3fend_sync import sync_d3fend

    source_ontology, source_mappings = _write_sources(tmp_path)
    cache = tmp_path / "cache"
    cache.mkdir()
    ontology_cache = cache / "d3fend-1.5.0.json"
    mappings_cache = cache / "d3fend-full-mappings-1.5.0.json"
    ontology_cache.write_bytes(source_ontology.read_bytes())
    mappings_cache.write_bytes(source_mappings.read_bytes())
    database = tmp_path / "d3fend.sqlite"
    D3fendStore(database).refresh(
        ontology_cache, mappings_cache, source_version="1.5.0", source_url="official"
    )
    original_ontology = ontology_cache.read_bytes()
    original_mappings = mappings_cache.read_bytes()

    class Downloader:
        calls = 0

        def fetch(self, _url):
            self.calls += 1
            body = (
                json.dumps({"@graph": []}).encode() if self.calls == 1
                else json.dumps({"head": {}, "results": {"bindings": []}}).encode()
            )
            return {"status": "downloaded", "body": body, "attempts": 1}

    result = sync_d3fend(
        version="1.5.0", db_path=database, cache_dir=cache,
        downloader=Downloader(),
    )
    assert result["status"] == "degraded_last_known_good_retained"
    assert ontology_cache.read_bytes() == original_ontology
    assert mappings_cache.read_bytes() == original_mappings
