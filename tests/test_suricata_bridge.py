"""Comprehensive test suite for Suricata Evidence Bridge v1."""
from __future__ import annotations

import io
import json
import os
try:
    import resource
    def _get_rss_kb() -> int:
        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
except ImportError:
    resource = None
    def _get_rss_kb() -> int:
        try:
            import psutil
            return int(psutil.Process().memory_info().rss / 1024)
        except Exception:
            return 0
import tempfile
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.limiter import limiter
from backend.db.models import (
    SecurityEventRecord,
    SecurityEventTechniqueMapping,
    SuricataIngestionRecord,
    SessionLocal,
    Setting,
)
from backend.suricata.schema import (
    SECURITY_EVENT_SCHEMA_VERSION,
    SURICATA_ADAPTER_VERSION,
    AttackValidationStatus,
)
from backend.suricata.parser import (
    iter_eve_stream,
    parse_iso_timestamp,
    SuricataParseError,
)
from backend.suricata.event_ref import compute_event_ref
from backend.suricata.attack_extractor import (
    extract_raw_attack_metadata,
    validate_and_map_attack_metadata,
)
from backend.suricata.advisory import (
    build_suricata_alert_prompt,
    deterministic_suricata_summary,
)

client = TestClient(app)
error_client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_rate_limits():
    limiter._limiter.storage.reset()
    yield
    limiter._limiter.storage.reset()


def make_eve_alert(
    sig="ET MALWARE CobaltStrike C2",
    sid=2024001,
    cat="Trojan Activity",
    sev=1,
    action="allowed",
    metadata=None,
    ts="2026-08-30T14:10:00.123456+0000",
    src_ip="192.168.1.100",
    src_port=49200,
    dest_ip="198.51.100.42",
    dest_port=443,
    proto="TCP",
    flow_id=123456789,
):
    if metadata is None:
        metadata = {
            "mitre_technique_id": ["T1071.001"],
            "mitre_tactic_id": ["TA0011"],
        }
    return {
        "timestamp": ts,
        "flow_id": flow_id,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "app_proto": "tls",
        "alert": {
            "action": action,
            "gid": 1,
            "signature_id": sid,
            "rev": 1,
            "signature": sig,
            "category": cat,
            "severity": sev,
            "metadata": metadata,
        },
    }


def make_eve_flow(ts="2026-08-30T14:10:01.000000+0000", flow_id=123456789):
    return {
        "timestamp": ts,
        "flow_id": flow_id,
        "event_type": "flow",
        "src_ip": "192.168.1.100",
        "src_port": 49200,
        "dest_ip": "198.51.100.42",
        "dest_port": 443,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 15,
            "pkts_toclient": 22,
            "bytes_toserver": 1420,
            "bytes_toclient": 18900,
            "start": "2026-08-30T14:09:50.000000+0000",
            "end": ts,
            "age": 11,
            "state": "closed",
            "reason": "shutdown",
        },
    }


def make_eve_dns(ts="2026-08-30T14:10:02.000000+0000", query="bad-domain.example.com"):
    return {
        "timestamp": ts,
        "event_type": "dns",
        "src_ip": "192.168.1.100",
        "src_port": 53535,
        "dest_ip": "1.1.1.1",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "answer",
            "id": 1001,
            "rrname": query,
            "rrtype": "A",
            "rcode": "NOERROR",
            "answers": ["198.51.100.42"],
        },
    }


def make_eve_tls(ts="2026-08-30T14:10:03.000000+0000", sni="bad-domain.example.com"):
    return {
        "timestamp": ts,
        "event_type": "tls",
        "src_ip": "192.168.1.100",
        "src_port": 49200,
        "dest_ip": "198.51.100.42",
        "dest_port": 443,
        "proto": "TCP",
        "tls": {
            "subject": f"CN={sni}",
            "issuerdn": "CN=Let's Encrypt",
            "sni": sni,
            "version": "TLS 1.3",
            "ja3": {"hash": "51c64c77e60f3980eea90869b68c58a8"},
            "ja4": "t13d1516h2_8daaf6152771_019a7590829f",
            "fingerprint": "12:34:56:78:90:ab:cd:ef",
        },
    }


# =========================================================================
# 1. Parsing & Supported Event Types
# =========================================================================

def test_parse_valid_suricata_alert():
    doc = make_eve_alert()
    stream = io.BytesIO((json.dumps(doc) + "\n").encode("utf-8"))
    items = list(iter_eve_stream(stream, "eve.json", "sensor-1", 1024*1024, 1000))
    assert len(items) == 1
    ev = items[0].event
    assert ev is not None
    assert ev.schema_version == SECURITY_EVENT_SCHEMA_VERSION
    assert ev.adapter_version == SURICATA_ADAPTER_VERSION
    assert ev.source_event_type == "alert"
    assert ev.alert_signature_id == 2024001
    assert ev.alert_severity == "high"
    assert ev.source_sensor_action == "allowed"
    assert ev.executed_action == "none"
    assert len(ev.mitre_techniques) >= 1
    assert ev.mitre_techniques[0].technique_id == "T1071.001"
    assert ev.mitre_techniques[0].tactic_id == "TA0011"
    assert ev.mitre_techniques[0].rule_match_observed is True
    assert ev.mitre_techniques[0].technique_observed is False


def test_parse_valid_suricata_flow():
    doc = make_eve_flow()
    stream = io.BytesIO((json.dumps(doc) + "\n").encode("utf-8"))
    items = list(iter_eve_stream(stream, "eve.json", "sensor-1", 1024*1024, 1000))
    assert len(items) == 1
    ev = items[0].event
    assert ev is not None
    assert ev.source_event_type == "flow"
    assert ev.evidence["bytes_toserver"] == 1420
    assert ev.evidence["bytes_toclient"] == 18900


def test_parse_valid_suricata_dns():
    doc = make_eve_dns()
    stream = io.BytesIO((json.dumps(doc) + "\n").encode("utf-8"))
    items = list(iter_eve_stream(stream, "eve.json", "sensor-1", 1024*1024, 1000))
    assert len(items) == 1
    ev = items[0].event
    assert ev is not None
    assert ev.source_event_type == "dns"
    assert ev.evidence["rrname"] == "bad-domain.example.com"
    assert ev.evidence["answers"] == ["198.51.100.42"]


def test_parse_valid_suricata_tls():
    doc = make_eve_tls()
    stream = io.BytesIO((json.dumps(doc) + "\n").encode("utf-8"))
    items = list(iter_eve_stream(stream, "eve.json", "sensor-1", 1024*1024, 1000))
    assert len(items) == 1
    ev = items[0].event
    assert ev is not None
    assert ev.source_event_type == "tls"
    assert ev.evidence["sni"] == "bad-domain.example.com"
    assert ev.evidence["ja4"] == "t13d1516h2_8daaf6152771_019a7590829f"


def test_mixed_event_types_preserves_input_order():
    docs = [
        make_eve_dns(ts="2026-08-30T14:10:00.000000+0000"),
        make_eve_tls(ts="2026-08-30T14:10:01.000000+0000"),
        make_eve_alert(ts="2026-08-30T14:10:02.000000+0000"),
        make_eve_flow(ts="2026-08-30T14:10:03.000000+0000"),
    ]
    raw = "\n".join(json.dumps(d) for d in docs).encode("utf-8") + b"\n"
    items = list(iter_eve_stream(io.BytesIO(raw), "eve.json", "sensor-1", 1024*1024, 1000))
    assert len(items) == 4
    assert [item.event.source_event_type for item in items] == ["dns", "tls", "alert", "flow"]
    assert [item.event.source_line_number for item in items] == [1, 2, 3, 4]


def test_ignored_unsupported_event_types():
    stats_event = {"timestamp": "2026-08-30T14:10:00.000000+0000", "event_type": "stats", "stats": {}}
    http_event = {"timestamp": "2026-08-30T14:10:01.000000+0000", "event_type": "http", "http": {}}
    alert_event = make_eve_alert()
    raw = "\n".join(json.dumps(d) for d in [stats_event, http_event, alert_event]).encode("utf-8") + b"\n"
    items = list(iter_eve_stream(io.BytesIO(raw), "eve.json", "sensor-1", 1024*1024, 1000))
    assert len(items) == 3
    assert items[0].is_ignored and items[0].ignored_type == "stats"
    assert items[1].is_ignored and items[1].ignored_type == "http"
    assert items[2].event is not None and items[2].event.source_event_type == "alert"


# =========================================================================
# 2. Rejection, Errors & Edge Cases
# =========================================================================

def test_malformed_ndjson_line_is_counted_and_bounded():
    lines = [
        json.dumps(make_eve_alert(sid=1)),
        "not valid json {{{",
        json.dumps(make_eve_alert(sid=2)),
        '{"timestamp":"2026-08-30T14:00:00Z","a":1,"a":2}',  # duplicate key
        json.dumps(make_eve_alert(sid=3)),
    ]
    raw = "\n".join(lines).encode("utf-8") + b"\n"
    items = list(iter_eve_stream(io.BytesIO(raw), "eve.json", "sensor-1", 1024*1024, 1000))
    assert len(items) == 5
    assert items[0].event is not None
    assert items[1].error_reason == "invalid_json_syntax"
    assert items[2].event is not None
    assert items[3].error_reason == "duplicate_json_key"
    assert items[4].event is not None


def test_invalid_utf8_fails_safely():
    bad_bytes = b'{"event_type":"alert","timestamp":"2026-08-30T14:00:00Z","alert":{"signature":"\xff\xfe bad"}}\n'
    items = list(iter_eve_stream(io.BytesIO(bad_bytes), "eve.json", "sensor-1", 1024*1024, 1000))
    assert len(items) == 1
    assert items[0].error_reason == "invalid_utf8"


def test_binary_input_is_rejected():
    binary_bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    with pytest.raises(SuricataParseError) as exc_info:
        list(iter_eve_stream(io.BytesIO(binary_bytes), "eve.json", "sensor-1", 1024*1024, 1000))
    assert str(exc_info.value) == "binary_content_not_supported"


def test_unsupported_extension_rejected():
    with pytest.raises(SuricataParseError) as exc_info:
        list(iter_eve_stream(io.BytesIO(b'{"a":1}\n'), "eve.pcap", "sensor-1", 1024*1024, 1000))
    assert str(exc_info.value) == "unsupported_file_extension"


def test_empty_upload_rejected():
    with pytest.raises(SuricataParseError) as exc_info:
        list(iter_eve_stream(io.BytesIO(b""), "eve.json", "sensor-1", 1024*1024, 1000))
    assert str(exc_info.value) == "empty_upload"


def test_upload_byte_limit_enforced():
    large_payload = (json.dumps(make_eve_alert()) + "\n").encode("utf-8") * 100
    max_bytes = 500  # very small limit
    with pytest.raises(SuricataParseError) as exc_info:
        list(iter_eve_stream(io.BytesIO(large_payload), "eve.json", "sensor-1", max_bytes, 1000))
    assert str(exc_info.value) == "upload_byte_limit_exceeded"


# =========================================================================
# 3. ATT&CK Extraction & Provenance Semantics
# =========================================================================

def test_valid_technique_id_accepted_with_explicit_semantics():
    meta = {
        "mitre_technique_id": ["T1071.001"],
        "mitre_tactic_id": ["TA0011"],
    }
    mappings = validate_and_map_attack_metadata(meta, signature_id=200001)
    assert len(mappings) == 1
    m = mappings[0]
    assert m.technique_id == "T1071.001"
    assert m.tactic_id == "TA0011"
    assert m.rule_match_observed is True
    assert m.mapping_evidence_present is True
    assert m.technique_observed is False
    assert m.evidence_kind == "suricata_rule_metadata"
    assert m.mapping_semantics == "evidence-supported candidate ATT&CK mapping"


def test_tactic_ids_not_stored_as_techniques():
    meta = {
        "mitre_technique_id": ["TA0011", "T1071"],
        "mitre_tactic_id": ["TA0011"],
    }
    mappings = validate_and_map_attack_metadata(meta, signature_id=200002)
    # TA0011 should be identified as a tactic and not stored in technique_id
    technique_ids = [m.technique_id for m in mappings]
    assert "TA0011" not in technique_ids
    assert "T1071" in technique_ids


def test_tag_syntax_parsing():
    meta = {
        "tag": ["attack.t1059_001", "attack.ta0002", "some_unrelated_tag"],
    }
    mappings = validate_and_map_attack_metadata(meta, signature_id=200003)
    technique_ids = [m.technique_id for m in mappings]
    assert "T1059.001" in technique_ids
    assert "TA0002" not in technique_ids
    assert "some_unrelated_tag" not in technique_ids


def test_invalid_technique_syntax_is_flagged():
    meta = {
        "mitre_technique_id": ["invalid-technique-string", "T9999999"],
    }
    mappings = validate_and_map_attack_metadata(meta, signature_id=200004)
    invalid_mappings = [m for m in mappings if m.validation_status == AttackValidationStatus.SYNTACTICALLY_INVALID]
    assert len(invalid_mappings) == 2


def test_unknown_to_snapshot_technique():
    # T9999 is valid syntax but unknown to official snapshot
    meta = {"mitre_technique_id": ["T9999"]}
    mappings = validate_and_map_attack_metadata(meta, signature_id=200005)
    assert len(mappings) == 1
    assert mappings[0].validation_status in (
        AttackValidationStatus.UNKNOWN_TO_SNAPSHOT,
        AttackValidationStatus.SNAPSHOT_UNAVAILABLE,
        AttackValidationStatus.SNAPSHOT_UNVERIFIED,
    )


def test_missing_technique_metadata_does_not_invent_mapping():
    meta = {"signature_severity": "Major", "updated_at": "2026_01_01"}
    mappings = validate_and_map_attack_metadata(meta, signature_id=200006)
    assert len(mappings) == 0


def test_no_technique_derived_from_signature_text_or_category():
    # Even if signature mentions "DDoS" or "PortScan", no technique is inferred without rule metadata
    alert_doc = {
        "timestamp": "2026-08-30T14:00:00Z",
        "event_type": "alert",
        "alert": {
            "signature": "ET DOS Possible SYN Flood DDoS In Progress",
            "category": "Attempted Denial of Service",
            "severity": 1,
            # No metadata key
        }
    }
    raw = (json.dumps(alert_doc) + "\n").encode("utf-8")
    items = list(iter_eve_stream(io.BytesIO(raw), "eve.json", "s1", 1024*1024, 10))
    assert len(items) == 1
    assert len(items[0].event.mitre_techniques) == 0


# =========================================================================
# 4. API Endpoints & Transactional Behavior
# =========================================================================

def test_api_upload_suricata_eve_success():
    events = [
        make_eve_alert(sid=300001, ts="2026-08-30T15:00:01.000000+0000"),
        make_eve_flow(ts="2026-08-30T15:00:02.000000+0000"),
        make_eve_dns(ts="2026-08-30T15:00:03.000000+0000"),
        make_eve_tls(ts="2026-08-30T15:00:04.000000+0000"),
    ]
    payload = "\n".join(json.dumps(e) for e in events).encode("utf-8") + b"\n"
    res = client.post(
        "/api/events/suricata/upload?sensor_id=test-sensor-alpha",
        files={"file": ("suricata_test.jsonl", payload, "application/jsonl")},
    )
    assert res.status_code == 200
    report = res.json()
    assert report["status"] == "completed"
    assert report["total_parsed"] == 4
    assert report["accepted"] == 4
    assert report["persisted"] == 4
    assert report["alert_events_accepted"] == 1
    assert report["counts_by_event_type"]["alert"] == 1
    assert report["counts_by_event_type"]["flow"] == 1
    assert report["counts_by_event_type"]["dns"] == 1
    assert report["counts_by_event_type"]["tls"] == 1
    assert report["executed_action"] == "none"
    assert len(report["events"]) == 4


def test_api_duplicate_upload_accounting():
    events = [make_eve_alert(sid=300010, ts="2026-08-30T15:10:00.000000+0000")]
    payload = (json.dumps(events[0]) + "\n").encode("utf-8")

    # First upload
    res1 = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-dup-test",
        files={"file": ("dup1.json", payload, "application/json")},
    )
    assert res1.status_code == 200
    rep1 = res1.json()
    assert rep1["newly_persisted_events"] == 1
    assert rep1["duplicates_already_persisted"] == 0

    # Second upload of exact same event
    res2 = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-dup-test",
        files={"file": ("dup2.json", payload, "application/json")},
    )
    assert res2.status_code == 200
    rep2 = res2.json()
    assert rep2["duplicates_already_persisted"] == 1
    assert rep2["newly_persisted_events"] == 0


def test_duplicate_events_inside_same_file():
    ev = make_eve_alert(sid=300020, ts="2026-08-30T15:20:00.000000+0000")
    payload = (json.dumps(ev) + "\n" + json.dumps(ev) + "\n").encode("utf-8")
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-same-file-dup",
        files={"file": ("internal_dup.json", payload, "application/json")},
    )
    assert res.status_code == 200
    rep = res.json()
    assert rep["total_parsed"] == 2
    assert rep["accepted"] == 2
    assert rep["duplicates_in_upload"] == 1
    assert rep["newly_persisted_events"] == 1


def test_legitimate_similar_events_not_incorrectly_deduplicated():
    # Two alerts at exact same timestamp on same sensor, but different ports/SIDs
    ev1 = make_eve_alert(sid=300031, src_port=10001, ts="2026-08-30T15:30:00.000000+0000")
    ev2 = make_eve_alert(sid=300032, src_port=10002, ts="2026-08-30T15:30:00.000000+0000")
    payload = (json.dumps(ev1) + "\n" + json.dumps(ev2) + "\n").encode("utf-8")
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-distinct",
        files={"file": ("distinct.json", payload, "application/json")},
    )
    assert res.status_code == 200
    rep = res.json()
    assert rep["accepted"] == 2
    assert rep["newly_persisted_events"] == 2
    assert rep["duplicates_in_upload"] == 0


def test_fatal_error_rolls_back_entire_transaction():
    # Valid lines followed by an unrecoverable fatal byte-limit violation
    # To test transaction rollback, we simulate a fatal parse failure
    # Valid event followed by binary content
    valid_line = (json.dumps(make_eve_alert(sid=400001, ts="2026-08-30T16:00:00.000000+0000")) + "\n").encode("utf-8")
    binary_line = b"\x00\x01\x02\x03\x04"
    payload = valid_line + binary_line

    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-rollback",
        files={"file": ("rollback.json", payload, "application/json")},
    )
    assert res.status_code == 400

    # Ensure the valid event was NOT persisted due to transaction rollback
    with SessionLocal() as s:
        rec = s.query(SecurityEventRecord).filter_by(sensor_id="sensor-rollback").first()
        assert rec is None


def test_api_list_and_get_event_detail():
    ev = make_eve_alert(sid=500001, ts="2026-08-30T16:10:00.000000+0000")
    payload = (json.dumps(ev) + "\n").encode("utf-8")
    upload_res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-detail-test",
        files={"file": ("detail.json", payload, "application/json")},
    )
    assert upload_res.status_code == 200

    # List events
    list_res = client.get("/api/events/suricata/events?sensor_id=sensor-detail-test")
    assert list_res.status_code == 200
    events_data = list_res.json()
    assert events_data["total"] >= 1
    target_event = events_data["events"][0]
    db_id = target_event["id"]
    event_ref = target_event["event_ref"]

    # Assert separation of DB PK and deterministic event_ref
    assert isinstance(db_id, int)
    assert isinstance(event_ref, str) and len(event_ref) == 64

    # Get single event detail
    detail_res = client.get(f"/api/events/suricata/events/{db_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == db_id
    assert detail["event_ref"] == event_ref
    assert len(detail["mitre_techniques"]) >= 1
    tech = detail["mitre_techniques"][0]
    assert tech["technique_id"] == "T1071.001"
    assert tech["rule_match_observed"] is True
    assert tech["technique_observed"] is False


def test_advisory_explain_suricata_event():
    """Verify deterministic fallback with LLM disabled/unavailable on unique new event."""
    ev = make_eve_alert(sid=600001, ts="2026-08-30T16:20:00.000000+0000")
    payload = (json.dumps(ev) + "\n").encode("utf-8")
    upload_res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-explain",
        files={"file": ("explain.json", payload, "application/json")},
    )
    assert upload_res.status_code == 200
    db_id = upload_res.json()["events"][0]["id"]

    # First call on new event with no cached explanation and LLM unavailable
    explain_res = client.post(f"/api/events/suricata/explain/{db_id}")
    assert explain_res.status_code == 200
    data = explain_res.json()
    assert "explanation" in data
    assert len(data["explanation"]) > 0
    assert data["provider"] == "deterministic_fallback"
    assert data["cached"] is False
    assert data["degraded"] is True
    assert data["executed_action"] == "none"

    # Second call returns cached explanation
    cached_res = client.post(f"/api/events/suricata/explain/{db_id}")
    assert cached_res.status_code == 200
    cached_data = cached_res.json()
    assert cached_data["cached"] is True
    assert cached_data["provider"] == "cached"
    assert cached_data["executed_action"] == "none"
    assert cached_data["explanation"] == data["explanation"]


def test_raw_network_identifiers_excluded_from_llm_prompt():
    event_dict = {
        "event_ref": "abcdef1234567890",
        "source_kind": "suricata_eve",
        "source_event_type": "alert",
        "timestamp_iso": "2026-08-30T14:00:00Z",
        "src_ip": "10.123.45.67",
        "dest_ip": "198.51.100.99",
        "alert_signature": "ET MALWARE C2",
        "alert_signature_id": 2001,
        "mitre_techniques": [{"technique_id": "T1071.001"}],
    }
    prompt_msgs = build_suricata_alert_prompt(event_dict)
    prompt_str = json.dumps(prompt_msgs)
    # Check that raw src_ip and dest_ip were not embedded in the prompt
    assert "10.123.45.67" not in prompt_str
    assert "198.51.100.99" not in prompt_str


def test_suricata_stats_endpoint():
    res = client.get("/api/events/suricata/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "counts_by_type" in data
    assert "active_attack_snapshot" in data
    assert data["executed_action"] == "none"


# =========================================================================
# 5. Memory Boundedness Verification
# =========================================================================

def test_parser_memory_bounded_comparison():
    """Verify that parsing a 5,000-event fixture does not scale memory proportionally with file size."""
    small_count = 100
    large_count = 5000

    small_lines = [json.dumps(make_eve_alert(sid=i, ts=f"2026-08-30T14:00:{i%60:02d}.000000Z")) for i in range(small_count)]
    small_bytes = ("\n".join(small_lines) + "\n").encode("utf-8")

    large_lines = [json.dumps(make_eve_alert(sid=i, ts=f"2026-08-30T14:00:{i%60:02d}.000000Z")) for i in range(large_count)]
    large_bytes = ("\n".join(large_lines) + "\n").encode("utf-8")

    # Measure small parse
    rss_before_small = _get_rss_kb()
    small_stream = io.BytesIO(small_bytes)
    small_parsed = 0
    for item in iter_eve_stream(small_stream, "small.json", "s1", 50*1024*1024, 10000):
        if item.event:
            small_parsed += 1
    rss_after_small = _get_rss_kb()

    # Measure large parse (50x more records)
    rss_before_large = _get_rss_kb()
    large_stream = io.BytesIO(large_bytes)
    large_parsed = 0
    for item in iter_eve_stream(large_stream, "large.json", "s1", 50*1024*1024, 10000):
        if item.event:
            large_parsed += 1
    rss_after_large = _get_rss_kb()

    assert small_parsed == small_count
    assert large_parsed == large_count
    # Large file is 50x larger, but resident memory delta should remain within bounded buffer range (< 50MB RSS increase)
    delta_kb = rss_after_large - rss_before_large
    assert delta_kb < 50000, f"Memory grew unexpectedly: {delta_kb} KB"


# =========================================================================
# 6. SQLite Foreign Keys & Cascade Integrity
# =========================================================================

def test_sqlite_foreign_keys_pragma_enabled():
    from backend.db.models import engine
    with engine.connect() as conn:
        fk_status = conn.exec_driver_sql("PRAGMA foreign_keys;").scalar()
        assert fk_status == 1, f"Expected PRAGMA foreign_keys=1, got {fk_status}"


def test_foreign_key_invalid_reference_fails():
    from sqlalchemy.exc import IntegrityError
    with SessionLocal() as s:
        # Attempt to insert a technique mapping referencing non-existent security_event_id=999999999
        mapping = SecurityEventTechniqueMapping(
            security_event_id=999999999,
            technique_id="T1071.001",
            tactic_id="TA0011",
            validation_status="active_validated",
            rule_match_observed=True,
            mapping_evidence_present=True,
            technique_observed=False,
            evidence_kind="suricata_rule_metadata",
            mapping_semantics="evidence-supported candidate ATT&CK mapping",
            mapping_version="suricata-rule-metadata-v1",
            metadata_extraction_confidence=1.0,
            technique_occurrence_confidence=None,
        )
        s.add(mapping)
        with pytest.raises(IntegrityError):
            s.commit()
        s.rollback()


def test_cascade_delete_removes_technique_mappings():
    with SessionLocal() as s:
        # Create security event
        ev_rec = SecurityEventRecord(
            event_ref="test_cascade_ref_12345",
            ingestion_id="test_cascade_ingest",
            schema_version="cyberguard-security-event-v1",
            adapter_version="cyberguard-suricata-eve-v1",
            source_kind="suricata_eve",
            source_event_type="alert",
            sensor_id="sensor-cascade",
            source_line_number=1,
            timestamp=1788102600.0,
            timestamp_iso="2026-08-30T14:10:00Z",
            alert_signature="ET CASCADE TEST",
            alert_signature_id=999001,
            alert_severity="high",
            source_sensor_action="allowed",
            executed_action="none",
            evidence_json="{}",
            mitre_techniques_json="[]",
            source_file="cascade.json",
        )
        s.add(ev_rec)
        s.flush()

        mapping = SecurityEventTechniqueMapping(
            security_event_id=ev_rec.id,
            technique_id="T1071.001",
            validation_status="active_validated",
            rule_match_observed=True,
            mapping_evidence_present=True,
            technique_observed=False,
            evidence_kind="suricata_rule_metadata",
            mapping_semantics="evidence-supported candidate ATT&CK mapping",
            mapping_version="suricata-rule-metadata-v1",
            metadata_extraction_confidence=1.0,
            technique_occurrence_confidence=None,
        )
        s.add(mapping)
        s.commit()
        ev_id = ev_rec.id
        mapping_id = mapping.id

    # Verify rows exist
    with SessionLocal() as s:
        assert s.query(SecurityEventRecord).filter_by(id=ev_id).first() is not None
        assert s.query(SecurityEventTechniqueMapping).filter_by(id=mapping_id).first() is not None

        # Delete the security event
        ev_to_del = s.query(SecurityEventRecord).filter_by(id=ev_id).first()
        s.delete(ev_to_del)
        s.commit()

    # Verify cascade deletion of technique mapping
    with SessionLocal() as s:
        assert s.query(SecurityEventRecord).filter_by(id=ev_id).first() is None
        assert s.query(SecurityEventTechniqueMapping).filter_by(id=mapping_id).first() is None


def test_deleting_one_ingestion_preserves_other_ingestions():
    with SessionLocal() as s:
        ing1 = SuricataIngestionRecord(
            ingestion_id="ingest_alpha_1",
            source_file="alpha.json",
            sensor_id="sensor-1",
            status="completed",
            total_parsed=1,
            accepted=1,
            persisted=1,
            report_json="{}",
        )
        ing2 = SuricataIngestionRecord(
            ingestion_id="ingest_beta_2",
            source_file="beta.json",
            sensor_id="sensor-2",
            status="completed",
            total_parsed=1,
            accepted=1,
            persisted=1,
            report_json="{}",
        )
        s.add_all([ing1, ing2])
        s.commit()

        # Delete ing1
        s.delete(ing1)
        s.commit()

        assert s.query(SuricataIngestionRecord).filter_by(ingestion_id="ingest_alpha_1").first() is None
        assert s.query(SuricataIngestionRecord).filter_by(ingestion_id="ingest_beta_2").first() is not None
        s.delete(ing2)
        s.commit()


# =========================================================================
# 7. Granular ATT&CK Snapshot States & Tag Restrictions
# =========================================================================

def test_tag_metadata_strict_allowlist_and_rejections():
    # Valid allowlisted tag prefixes
    valid_meta = {
        "tag": [
            "attack.t1071_001",
            "attack.T1046",
            "mitre.t1059.001",
            "attack.ta0011",
            # Arbitrary tags containing T-patterns that MUST be rejected:
            "POST1071",
            "ET1071",
            "some_text_T1071",
            "http://example.com/T1071",
            "c2_traffic_T1071_detected",
            "random_tag",
        ]
    }
    raw_tech, raw_tac, invalid = extract_raw_attack_metadata(valid_meta)
    assert "T1071.001" in raw_tech
    assert "T1046" in raw_tech
    assert "T1059.001" in raw_tech
    assert "TA0011" in raw_tac
    # Verify rejected patterns are not extracted
    assert "POST1071" not in raw_tech
    assert "ET1071" not in raw_tech
    assert "some_text_T1071" not in raw_tech
    assert "T1071" not in raw_tech or len(raw_tech) == 3


def test_granular_attack_validation_states():
    from backend.suricata.attack_extractor import get_active_attack_snapshot_info
    snapshot_info = get_active_attack_snapshot_info()
    has_snapshot = snapshot_info.get("technique_count", 0) > 0
    verified_snapshot = bool(snapshot_info.get("official_release_verified", False))

    # 1. Valid technique — status depends on whether snapshot is populated
    res_active = validate_and_map_attack_metadata({"mitre_technique_id": ["T1071.001"]}, signature_id=101)
    assert len(res_active) == 1
    if verified_snapshot:
        assert res_active[0].validation_status == AttackValidationStatus.ACTIVE_VALIDATED
    elif has_snapshot:
        assert res_active[0].validation_status == AttackValidationStatus.SNAPSHOT_UNVERIFIED
    else:
        assert res_active[0].validation_status == AttackValidationStatus.SNAPSHOT_UNAVAILABLE

    # 2. Syntactically Invalid — always SYNTACTICALLY_INVALID regardless of snapshot
    res_inv = validate_and_map_attack_metadata({"mitre_technique_id": ["INVALID-SYNTAX"]}, signature_id=102)
    assert len(res_inv) == 1
    assert res_inv[0].validation_status == AttackValidationStatus.SYNTACTICALLY_INVALID
    assert res_inv[0].metadata_extraction_confidence == 0.0

    # 3. Unknown to Snapshot — depends on snapshot
    res_unk = validate_and_map_attack_metadata({"mitre_technique_id": ["T9999"]}, signature_id=103)
    assert len(res_unk) == 1
    if verified_snapshot:
        assert res_unk[0].validation_status == AttackValidationStatus.UNKNOWN_TO_SNAPSHOT
    elif has_snapshot:
        assert res_unk[0].validation_status == AttackValidationStatus.SNAPSHOT_UNVERIFIED
    else:
        assert res_unk[0].validation_status == AttackValidationStatus.SNAPSHOT_UNAVAILABLE


def test_invalid_attack_metadata_output_order_is_stable():
    mappings = validate_and_map_attack_metadata({
        "mitre_technique_id": ["bad-b", "bad-a", "bad-b"]
    })
    assert [item.technique_id for item in mappings] == ["bad-a", "bad-b"]


def test_multi_batch_streaming_full_rollback_leaves_zero_committed_rows():
    """Verify that a stream exceeding multiple flush batches (550 items > 500 batch size) rolls back completely on fatal error."""
    # Create 550 valid alerts (crossing the BATCH_SIZE=500 flush boundary) followed by fatal binary content
    valid_lines = [
        json.dumps(make_eve_alert(sid=700000 + i, ts=f"2026-08-30T17:{i//60:02d}:{i%60:02d}.000000Z"))
        for i in range(550)
    ]
    payload = ("\n".join(valid_lines) + "\n").encode("utf-8") + b"\x00\x01\x02\x03\x04"

    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-multi-rollback",
        files={"file": ("multi_rollback.json", payload, "application/json")},
    )
    assert res.status_code == 400

    # Ensure zero events and zero mappings were committed
    with SessionLocal() as s:
        cnt = s.query(SecurityEventRecord).filter_by(sensor_id="sensor-multi-rollback").count()
        assert cnt == 0, f"Expected 0 committed records after rollback, found {cnt}"
        ingest_cnt = s.query(SuricataIngestionRecord).filter_by(sensor_id="sensor-multi-rollback").count()
        assert ingest_cnt == 0, f"Expected 0 committed ingestion records after rollback, found {ingest_cnt}"


def test_confidence_semantics_extraction_fidelity():
    meta = {"mitre_technique_id": ["T1071.001"]}
    mappings = validate_and_map_attack_metadata(meta, signature_id=200001)
    assert len(mappings) == 1
    m = mappings[0]
    assert m.metadata_extraction_confidence == 1.0
    assert m.technique_occurrence_confidence is None
    assert m.technique_observed is False


def test_stored_data_minimization():
    """Verify that persisted database records minimize data and store no raw packet payload or raw uploaded JSON."""
    ev = make_eve_alert(sid=800001, ts="2026-08-30T17:20:00.000000+0000")
    # Add fake raw fields to raw input to ensure parser excludes them
    ev["payload"] = "VGhpcyBpcyBhIHJhdyBwYWNrZXQgcGF5bG9hZA=="
    ev["payload_printable"] = "This is a raw packet payload"
    ev["packet"] = "0001020304050607"
    payload = (json.dumps(ev) + "\n").encode("utf-8")

    upload_res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-min-test",
        files={"file": ("min.json", payload, "application/json")},
    )
    assert upload_res.status_code == 200

    with SessionLocal() as s:
        rec = s.query(SecurityEventRecord).filter_by(sensor_id="sensor-min-test").first()
        assert rec is not None
        # Check evidence JSON does not contain packet payload
        evidence = json.loads(rec.evidence_json)
        assert "payload" not in evidence
        assert "payload_printable" not in evidence
        assert "packet" not in evidence
        # Verify model has no raw_json column
        assert not hasattr(rec, "raw_json")
        assert not hasattr(rec, "raw_uploaded_json")


# ──────────────────── §6 Severity Type Consistency ────────────────────

def test_severity_integer_round_trip():
    """Suricata integer severity round-trips through DB as integer in API."""
    ev = make_eve_alert(sid=600001, sev=1, ts="2026-08-30T18:00:00.000000+0000")
    payload = (json.dumps(ev) + "\n").encode()
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-sev-int",
        files={"file": ("sev_int.json", payload, "application/json")},
    )
    assert res.status_code == 200
    events = res.json()["events"]
    assert len(events) >= 1
    assert events[0]["source_sensor_severity_raw"] == 1


def test_severity_missing_is_null():
    """Missing severity produces null in API output."""
    ev = make_eve_alert(sid=600002, sev=None, ts="2026-08-30T18:01:00.000000+0000")
    del ev["alert"]["severity"]
    payload = (json.dumps(ev) + "\n").encode()
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-sev-null",
        files={"file": ("sev_null.json", payload, "application/json")},
    )
    assert res.status_code == 200
    events = res.json()["events"]
    assert len(events) >= 1
    assert events[0]["source_sensor_severity_raw"] is None


def test_severity_string_via_api():
    """Non-integer severity stored as string is returned as string."""
    ev = make_eve_alert(sid=600003, ts="2026-08-30T18:02:00.000000+0000")
    ev["alert"]["severity"] = "critical"
    payload = (json.dumps(ev) + "\n").encode()
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-sev-str",
        files={"file": ("sev_str.json", payload, "application/json")},
    )
    assert res.status_code == 200
    events = res.json()["events"]
    assert len(events) >= 1
    raw = events[0]["source_sensor_severity_raw"]
    assert isinstance(raw, str) and raw == "critical"
    assert events[0]["alert_severity"] is None, "Non-standard string severity must not normalize to valid severity"


def test_severity_out_of_range_no_normalized_severity():
    """Out-of-range numeric severity (e.g. 99) preserves raw value but does not normalize to misleading level."""
    ev = make_eve_alert(sid=600004, sev=99, ts="2026-08-30T18:02:30.000000+0000")
    payload = (json.dumps(ev) + "\n").encode()
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-sev-oor",
        files={"file": ("sev_oor.json", payload, "application/json")},
    )
    assert res.status_code == 200
    events = res.json()["events"]
    assert len(events) >= 1
    assert events[0]["source_sensor_severity_raw"] == 99
    assert events[0]["alert_severity"] is None, "Out-of-range severity must not produce misleading normalized severity"


def test_severity_invalid_type_handling():
    """Invalid severity types (e.g. list/dict) are safely handled as None."""
    ev = make_eve_alert(sid=600005, ts="2026-08-30T18:02:45.000000+0000")
    ev["alert"]["severity"] = ["invalid", "type"]
    payload = (json.dumps(ev) + "\n").encode()
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-sev-inv",
        files={"file": ("sev_inv.json", payload, "application/json")},
    )
    assert res.status_code == 200
    events = res.json()["events"]
    assert len(events) >= 1
    assert events[0]["source_sensor_severity_raw"] is None
    assert events[0]["alert_severity"] is None


# ──────────────────── §7 Counter Naming ────────────────────

def test_alert_events_accepted_in_report():
    """Upload report uses alert_events_accepted (not alerts_generated)."""
    ev = make_eve_alert(sid=700001, ts="2026-08-30T18:03:00.000000+0000")
    payload = (json.dumps(ev) + "\n").encode()
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-counter-name",
        files={"file": ("counter.json", payload, "application/json")},
    )
    assert res.status_code == 200
    report = res.json()
    assert "alert_events_accepted" in report
    assert "alerts_generated" not in report
    assert report["alert_events_accepted"] == 1


# ──────────────────── §5 Confidence Removal ────────────────────

def test_api_does_not_expose_confidence():
    """GET event detail must not include generic 'confidence' field in technique mappings."""
    ev = make_eve_alert(sid=500001, ts="2026-08-30T18:04:00.000000+0000")
    payload = (json.dumps(ev) + "\n").encode()
    upload_res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-no-conf",
        files={"file": ("noconf.json", payload, "application/json")},
    )
    assert upload_res.status_code == 200
    events = upload_res.json()["events"]
    assert len(events) >= 1
    ev_id = events[0].get("id")
    if ev_id:
        detail = client.get(f"/api/events/suricata/events/{ev_id}")
        assert detail.status_code == 200
        for tech in detail.json().get("mitre_techniques", []):
            assert "confidence" not in tech, "Generic 'confidence' must not appear in API"
            assert "metadata_extraction_confidence" in tech
            assert "technique_occurrence_confidence" in tech


# ──────────────────── §9 Concurrency Test ────────────────────

def test_sqlite_concurrency_and_pragmas():
    """Bounded concurrency: simultaneous reads + writes with FK enforcement and WAL."""
    import threading
    import sqlalchemy as sa
    errors = []

    def reader(n):
        try:
            for _ in range(n):
                with SessionLocal() as s:
                    s.execute(sa.text("SELECT count(*) FROM security_events")).fetchone()
                    fk_row = s.execute(sa.text("PRAGMA foreign_keys")).fetchone()
                    assert fk_row[0] == 1, f"foreign_keys not active: {fk_row}"
        except Exception as e:
            errors.append(("reader", str(e)))

    def writer():
        try:
            ev = make_eve_alert(sid=900001, ts="2026-08-30T18:05:00.000000+0000")
            payload = (json.dumps(ev) + "\n").encode()
            res = client.post(
                "/api/events/suricata/upload?sensor_id=sensor-conc",
                files={"file": ("conc.json", payload, "application/json")},
            )
            if res.status_code != 200:
                errors.append(("writer", f"status={res.status_code}"))
        except Exception as e:
            errors.append(("writer", str(e)))

    threads = []
    for i in range(4):
        threads.append(threading.Thread(target=reader, args=(5,)))
    threads.append(threading.Thread(target=writer))

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"Concurrency errors: {errors}"

    with SessionLocal() as s:
        journal = s.execute(sa.text("PRAGMA journal_mode")).fetchone()
        assert journal[0] == "wal", f"Expected WAL journal mode, got: {journal[0]}"


# ──────────────────── §4 Provenance Status ────────────────────

def test_attack_status_no_absolute_path():
    """ATT&CK status endpoints must not leak absolute file paths and must return HTTP 200."""
    res = client.get("/api/events/suricata/attack-status")
    assert res.status_code == 200, f"Expected 200 from suricata attack-status, got {res.status_code}"
    data = res.json()
    assert "source" not in data, "Raw 'source' path must not appear in API"
    if data.get("latest_sync"):
        assert "source" not in data["latest_sync"], "Raw 'source' in latest_sync must not appear"
    assert data.get("official_release_verified") is False
    assert "version_status" in data
    assert data["version_status"] != "verified", "Must not use bare 'verified' status"

    # Also test MITRE general status endpoint
    res_mitre = client.get("/api/mitre/status")
    assert res_mitre.status_code == 200, f"Expected 200 from /api/mitre/status, got {res_mitre.status_code}"
    mitre_data = res_mitre.json()
    assert "source" not in mitre_data


# ──────────────────── CG-SUR-001 Ingestion Record Persistence ────────────────────

def test_ingestion_record_persisted_with_completed_status():
    """Verify that SuricataIngestionRecord is updated to 'completed' with accurate counts in fresh DB session (CG-SUR-001)."""
    ev = make_eve_alert(sid=900001, ts="2026-08-30T18:30:00.000000+0000")
    payload = (json.dumps(ev) + "\n").encode()
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-ingest-verify",
        files={"file": ("ingest_verify.json", payload, "application/json")},
    )
    assert res.status_code == 200
    rep = res.json()
    ingestion_id = rep["ingestion_id"]

    # Query from completely new DB session
    with SessionLocal() as s:
        rec = s.query(SuricataIngestionRecord).filter_by(ingestion_id=ingestion_id).first()
        assert rec is not None, "Ingestion record must exist in database"
        assert rec.status == "completed", f"Expected status='completed', got '{rec.status}'"
        assert rec.total_parsed == 1
        assert rec.accepted == 1
        assert rec.persisted == 1
        assert rec.completed_at is not None
        assert rec.completed_at > 0
        assert rec.report_json is not None
        saved_rep = json.loads(rec.report_json)
        assert saved_rep["status"] == "completed"


# ──────────────────── CG-SUR-002 Oversized Line Bounded Memory ────────────────────

def test_oversized_line_without_newlines_bounded_memory():
    """Verify that lines exceeding 1MB without newlines are bounded and rejected without crashing (CG-SUR-002)."""
    # Create 2MB of valid JSON prefix without newline
    large_garbage = "a" * (2 * 1024 * 1024)
    oversized_line = f'{{"timestamp":"2026-08-30T18:31:00.000000Z","event_type":"alert","padding":"{large_garbage}"}}\n'.encode()
    valid_ev = (json.dumps(make_eve_alert(sid=900002, ts="2026-08-30T18:32:00.000000+0000")) + "\n").encode()

    payload = oversized_line + valid_ev
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-oversized-line",
        files={"file": ("oversized.json", payload, "application/json")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["rejected_lines"] >= 1
    assert data["rejection_reasons"].get("line_too_large", 0) >= 1
    assert data["accepted"] == 1


# ──────────────────── CG-SUR-003 Timestamp Fail-Closed ────────────────────

def test_timestamp_missing_and_invalid_fail_closed():
    """Missing or unparseable timestamps fail closed with clear error reasons, not datetime.now (CG-SUR-003)."""
    # 1. Missing timestamp
    ev_no_ts = make_eve_alert(sid=900003)
    del ev_no_ts["timestamp"]

    # 2. Invalid timestamp
    ev_bad_ts = make_eve_alert(sid=900004)
    ev_bad_ts["timestamp"] = "not-a-valid-timestamp-string"

    # 3. Valid alert to ensure response is 200
    ev_valid = make_eve_alert(sid=900005, ts="2026-08-30T18:33:00.000000+0000")

    payload = (
        json.dumps(ev_no_ts) + "\n" +
        json.dumps(ev_bad_ts) + "\n" +
        json.dumps(ev_valid) + "\n"
    ).encode()

    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-ts-check",
        files={"file": ("ts_check.json", payload, "application/json")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["rejection_reasons"].get("missing_timestamp", 0) == 1
    assert data["rejection_reasons"].get("invalid_timestamp", 0) == 1
    assert data["accepted"] == 1


# ──────────────────── CG-SUR-004 Trailing Line Max-Lines Boundary ────────────────────

def test_max_lines_boundary_on_trailing_buffer_without_newline():
    """Verify max_lines limit is enforced on trailing line without newline (CG-SUR-004)."""
    ev1 = json.dumps(make_eve_alert(sid=900006, ts="2026-08-30T18:34:00.000000+0000"))
    ev2 = json.dumps(make_eve_alert(sid=900007, ts="2026-08-30T18:34:01.000000+0000"))

    # 2 lines, second has no newline
    payload = f"{ev1}\n{ev2}".encode()

    # Streaming with max_lines=1 should reject
    from backend.suricata.parser import iter_eve_stream, SuricataParseError
    import io

    stream = io.BytesIO(payload)
    gen = iter_eve_stream(stream, "test.json", "s1", max_bytes=1000000, max_lines=1)
    
    # First line yields OK
    res1 = next(gen)
    assert res1.event is not None
    
    # Second line without newline raises line limit exceeded
    try:
        next(gen)
        assert False, "Should have raised SuricataParseError('upload_line_limit_exceeded')"
    except SuricataParseError as exc:
        assert str(exc) == "upload_line_limit_exceeded"


# ──────────────────── CG-SUR-005 Tactic Unambiguity Check ────────────────────

def test_multiple_tactics_yields_none_tactic_id():
    """When multiple tactics are present in metadata without pairwise mapping, tactic_id is None (CG-SUR-005)."""
    meta = {
        "mitre_technique_id": ["T1071.001"],
        "mitre_tactic_id": ["TA0011", "TA0001"],
    }
    mappings = validate_and_map_attack_metadata(meta, signature_id=900008)
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1071.001"
    assert mappings[0].tactic_id is None, "Multiple tactics must not be arbitrarily mapped to technique"

    # Exactly one tactic is mapped unambiguously
    meta_single = {
        "mitre_technique_id": ["T1071.001"],
        "mitre_tactic_id": ["TA0011"],
    }
    mappings_single = validate_and_map_attack_metadata(meta_single, signature_id=900009)
    assert len(mappings_single) == 1
    assert mappings_single[0].tactic_id == "TA0011"


# ──────────────────── CG-SUR-006 NaN/Infinity Rejection ────────────────────

def test_nan_and_infinity_in_json_rejected():
    """Non-standard JSON constants (NaN, Infinity) are rejected (CG-SUR-006)."""
    ev_nan = '{"timestamp":"2026-08-30T18:35:00.000000Z","event_type":"flow","flow":{"bytes_toserver": NaN}}\n'.encode()
    ev_valid = (json.dumps(make_eve_alert(sid=900010, ts="2026-08-30T18:35:01.000000+0000")) + "\n").encode()

    payload = ev_nan + ev_valid
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-nan-check",
        files={"file": ("nan_check.json", payload, "application/json")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["rejected_lines"] >= 1
    assert data["rejection_reasons"].get("invalid_json_syntax", 0) >= 1
    assert data["accepted"] == 1


# ──────────────────── CG-SUR-007 Missing Alert Action is None ────────────────────

def test_missing_alert_action_is_none():
    """Missing action in alert field maps to None/null, not 'allowed' (CG-SUR-007)."""
    ev = make_eve_alert(sid=900011, ts="2026-08-30T18:36:00.000000+0000")
    del ev["alert"]["action"]
    payload = (json.dumps(ev) + "\n").encode()

    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-action-null",
        files={"file": ("action_null.json", payload, "application/json")},
    )
    assert res.status_code == 200
    events = res.json()["events"]
    assert len(events) >= 1
    assert events[0]["source_sensor_action"] is None
    assert events[0]["evidence"]["source_action"] is None


# ──────────────────── CG-RE-001 Duplicate Ingestion Accounting ────────────────────

def test_duplicate_accounting_matches_ingestion_source():
    """Verify duplicate in current ingestion is counted in duplicates_in_upload (CG-RE-001)."""
    ev1 = make_eve_alert(sid=910001, ts="2026-08-30T18:40:00.000000+00:00")
    ev2 = make_eve_alert(sid=910002, ts="2026-08-30T18:40:01.000000+00:00")
    # ev1 repeated again
    ev3 = make_eve_alert(sid=910001, ts="2026-08-30T18:40:00.000000+00:00")

    payload = (
        json.dumps(ev1) + "\n" +
        json.dumps(ev2) + "\n" +
        json.dumps(ev3) + "\n"
    ).encode()

    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-dedup-audit",
        files={"file": ("dedup_audit.json", payload, "application/json")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["accepted"] == 3
    assert data["persisted"] == 2
    assert data["duplicates_in_upload"] == 1
    assert data["duplicates_already_persisted"] == 0

    # Re-uploading the same file must count as duplicates_already_persisted
    res2 = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-dedup-audit",
        files={"file": ("dedup_audit_2.json", payload, "application/json")},
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["accepted"] == 3
    assert data2["persisted"] == 0
    assert data2["duplicates_in_upload"] == 1
    assert data2["duplicates_already_persisted"] == 2


# ──────────────────── CG-RE-002 Confidence Drop Migration ────────────────────

def test_confidence_column_migration_drops_column():
    """Verify SQLite migration drops legacy 'confidence' column while preserving table data and constraints (CG-RE-002)."""
    from sqlalchemy import create_engine, inspect, text
    import tempfile
    from pathlib import Path
    from backend.db.init_db import init_application_tables

    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = Path(tmpdir) / "test_migration.db"
        test_eng = create_engine(f"sqlite:///{test_db}")

        # Create old schema with confidence column
        with test_eng.begin() as conn:
            conn.execute(text("""
                CREATE TABLE security_events (
                    id INTEGER PRIMARY KEY,
                    event_ref VARCHAR(64) UNIQUE NOT NULL,
                    ingestion_id VARCHAR(64) NOT NULL,
                    schema_version VARCHAR(32) NOT NULL,
                    adapter_version VARCHAR(32) NOT NULL,
                    source_kind VARCHAR(32) NOT NULL,
                    source_event_type VARCHAR(32) NOT NULL,
                    sensor_id VARCHAR(64) NOT NULL,
                    source_line_number INTEGER NOT NULL,
                    timestamp FLOAT NOT NULL,
                    timestamp_iso VARCHAR(64) NOT NULL,
                    created_at FLOAT NOT NULL
                );
            """))
            conn.execute(text("""
                CREATE TABLE security_event_technique_mappings (
                    id INTEGER PRIMARY KEY,
                    security_event_id INTEGER NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
                    technique_id VARCHAR(32) NOT NULL,
                    tactic_id VARCHAR(32),
                    signature_id INTEGER,
                    validation_status VARCHAR(32) NOT NULL,
                    rule_match_observed BOOLEAN NOT NULL,
                    mapping_evidence_present BOOLEAN NOT NULL,
                    technique_observed BOOLEAN NOT NULL,
                    evidence_kind VARCHAR(32) NOT NULL,
                    mapping_semantics VARCHAR(64) NOT NULL,
                    mapping_version VARCHAR(64) NOT NULL,
                    metadata_extraction_confidence FLOAT NOT NULL,
                    technique_occurrence_confidence FLOAT,
                    confidence FLOAT NOT NULL DEFAULT 1.0,
                    evidence_ref VARCHAR(128) NOT NULL,
                    snapshot_version VARCHAR(64),
                    snapshot_source VARCHAR(256),
                    snapshot_indexed_time FLOAT,
                    created_at FLOAT NOT NULL
                );
            """))
            conn.execute(text("""
                INSERT INTO security_events (id, event_ref, ingestion_id, schema_version, adapter_version, source_kind, source_event_type, sensor_id, source_line_number, timestamp, timestamp_iso, created_at)
                VALUES (1, 'ref-1', 'ing-1', 'v1', 'v1', 'suricata_eve', 'alert', 's1', 1, 100.0, '2026-08-30T18:00:00Z', 100.0);
            """))
            conn.execute(text("""
                INSERT INTO security_event_technique_mappings (id, security_event_id, technique_id, tactic_id, validation_status, rule_match_observed, mapping_evidence_present, technique_observed, evidence_kind, mapping_semantics, mapping_version, metadata_extraction_confidence, confidence, evidence_ref, created_at)
                VALUES (1, 1, 'T1071.001', 'TA0011', 'active_validated', 1, 1, 0, 'suricata_rule_metadata', 'candidate', 'v1', 1.0, 1.0, 'ref', 100.0);
            """))

        # Verify old DB has confidence
        insp_before = inspect(test_eng)
        cols_before = {c["name"] for c in insp_before.get_columns("security_event_technique_mappings")}
        assert "confidence" in cols_before

        # Run migration
        init_application_tables(test_eng)

        # Verify confidence is gone, data is preserved
        insp_after = inspect(test_eng)
        cols_after = {c["name"] for c in insp_after.get_columns("security_event_technique_mappings")}
        assert "confidence" not in cols_after
        assert "metadata_extraction_confidence" in cols_after

        with test_eng.connect() as conn:
            row = conn.execute(text("SELECT technique_id, metadata_extraction_confidence FROM security_event_technique_mappings WHERE id=1")).fetchone()
            assert row[0] == "T1071.001"
            assert row[1] == 1.0


# ──────────────────── CG-RE-003 Timezone Required Fail-Closed ────────────────────

def test_timestamp_without_timezone_fails_closed():
    """Timestamp lacking timezone indicator (Z or offset) fails closed with invalid_timestamp (CG-RE-003)."""
    ev_no_tz = make_eve_alert(sid=920001)
    ev_no_tz["timestamp"] = "2026-08-30T18:00:00"  # Missing Z or +00:00
    ev_valid = make_eve_alert(sid=920002, ts="2026-08-30T18:00:00+00:00")

    payload = (json.dumps(ev_no_tz) + "\n" + json.dumps(ev_valid) + "\n").encode()
    res = client.post(
        "/api/events/suricata/upload?sensor_id=sensor-notz-check",
        files={"file": ("notz_check.json", payload, "application/json")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["rejected_lines"] >= 1
    assert data["rejection_reasons"].get("invalid_timestamp", 0) >= 1
    assert data["accepted"] == 1


# ──────────────────── CG-RE-004 Suricata Frontend DOM Safety ────────────────────

def test_suricata_frontend_zero_inner_html():
    """Verify frontend/js/suricata.js uses safe DOM APIs and contains zero innerHTML sink invocations (CG-RE-004)."""
    from pathlib import Path
    import re
    js_path = Path("frontend/js/suricata.js")
    assert js_path.exists()
    content = js_path.read_text(encoding="utf-8")
    
    # Strip block comments and line comments
    clean_code = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    clean_code = re.sub(r"//.*$", "", clean_code, flags=re.MULTILINE)
    assert ".innerHTML" not in clean_code, "frontend/js/suricata.js must not invoke .innerHTML"
    assert "eval(" not in clean_code, "frontend/js/suricata.js must not invoke eval"


