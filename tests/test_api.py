"""API integration tests for strict flow uploads and health reporting."""
import json

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.limiter import limiter
from backend.db.models import (
    AlertRecord,
    AlertTechniqueMapping,
    DecisionCase,
    SessionLocal,
)
from tests.helpers import canonical_csv, canonical_flow, canonical_json

client = TestClient(app)
error_client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_rate_limits():
    limiter._limiter.storage.reset()
    yield
    limiter._limiter.storage.reset()


def test_health_check_endpoint():
    res = client.get("/api/detect/health")
    assert res.status_code == 200
    data = res.json()
    assert "ready" in data and "stages" in data
    assert data["artifact_pipeline_version"] == "cyberguard-pipeline-legacy-v1"
    assert data["routing_version"] == "cyberguard-routing-v2"
    assert data["calibration_status"] == "legacy_unvalidated_evaluation_only"
    assert data["anomaly_thresholds_independently_validated"] is False
    assert isinstance(data["zero_variance_feature_count"], int)
    assert data["zero_variance_feature_count"] >= 0


def test_live_operations_snapshot_separates_sources_and_reports_honest_state():
    response = client.get("/api/operations/snapshot")
    assert response.status_code == 200
    data = response.json()
    assert data["refresh_mode"] == "bounded_polling"
    assert data["poll_interval_seconds"] == 4
    assert data["executed_action"] == "none"
    assert data["operational_mode"] in {"evaluation_only", "production", "unavailable"}
    assert set(data["evidence_by_source"]) == {
        "uploaded_flow_records", "suricata_eve", "demo_data", "future_adapters"
    }
    assert data["evidence_by_source"]["demo_data"]["records"] == []
    assert data["evidence_by_source"]["future_adapters"]["status"] == "not_configured"
    serialized = json.dumps(data).lower()
    assert "live packet capture" not in serialized
    assert "automated containment" not in serialized


def test_intelligence_api_requires_valid_identifiers_and_package_context():
    invalid_cve = client.get("/api/operations/vulnerabilities/not-a-cve")
    assert invalid_cve.status_code == 200
    assert invalid_cve.json()["reason"] == "valid_cve_required"

    osv = client.post("/api/operations/osv/query", json={})
    assert osv.status_code == 200
    assert osv.json()["reason"] == "insufficient_package_context"


def test_upload_csv_flow_returns_200():
    content = canonical_csv(
        canonical_flow(flow_duration=120000, total_fwd_packets=6),
        canonical_flow(flow_duration=999999, syn_flag_count=50),
    )
    files = {"file": ("friday_traffic.csv", content, "text/csv")}
    res = client.post("/api/detect/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["flows"] == 2
    assert data["total_parsed"] == data["accepted"] == data["analyzed"] == 2
    assert data["rejected"] == 0
    assert data["schema_validation"]["feature_coverage_percentage"] == 100.0
    assert data["schema_validation"]["detected_input_profile"] == (
        "cyberguard-canonical-tabular-v1"
    )
    assert "alerts" in data
    assert "stage_counts" in data
    assert "feature_importance" in data


def test_upload_uppercase_extension_accepted():
    files = {
        "file": (
            "TRAFFIC.CSV",
            canonical_csv(canonical_flow(flow_duration=1000, syn_flag_count=1)),
            "text/csv",
        )
    }
    res = client.post("/api/detect/upload", files=files)
    assert res.status_code == 200


def test_upload_empty_file_returns_400():
    files = {"file": ("empty.csv", b"", "text/csv")}
    res = client.post("/api/detect/upload", files=files)
    assert res.status_code == 400


def test_headerless_raw_text_extension_is_rejected():
    files = {"file": ("blank.log", b"   \n  \n ", "text/plain")}
    res = client.post("/api/detect/upload", files=files)
    assert res.status_code == 422


def test_arbitrary_json_object_is_rejected_with_schema_report():
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "message.json",
                b'{"message":"failed login"}',
                "application/json",
            )
        },
    )
    assert response.status_code == 422
    report = response.json()["detail"]["schema_validation"]
    assert report["detected_input_profile"] == "unsupported"
    assert report["usable_row_count"] == 0
    assert report["missing_required_features"]


def test_headerless_col_number_csv_is_rejected():
    response = client.post(
        "/api/detect/upload",
        files={"file": ("raw.csv", b"col_0,col_1\n1,2\n", "text/csv")},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["schema_validation"]["usable_row_count"] == 0


def test_invalid_numeric_row_never_reaches_inference(monkeypatch):
    from backend.api import detection

    def must_not_load_pipeline():
        raise AssertionError("invalid row reached inference")

    monkeypatch.setattr(detection, "_get_pipeline", must_not_load_pipeline)
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "invalid.json",
                canonical_json(canonical_flow(flow_duration="NaN")),
                "application/json",
            )
        },
    )
    assert response.status_code == 422
    report = response.json()["detail"]["schema_validation"]
    assert report["rows_rejected"] == 1
    assert report["usable_row_count"] == 0


def test_per_upload_metrics_are_not_polluted_by_previous_upload():
    first = client.post(
        "/api/detect/upload",
        files={"file": ("one.csv", canonical_csv(canonical_flow()), "text/csv")},
    ).json()
    second = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "two.csv",
                canonical_csv(canonical_flow(), canonical_flow()),
                "text/csv",
            )
        },
    ).json()
    assert first["pipeline_stats"]["total_parsed"] == 1
    assert second["pipeline_stats"]["total_parsed"] == 2
    assert second["pipeline_stats"]["accepted"] == 2
    assert second["process_lifetime_stats"]["total_flows"] >= 3


def _persistent_detection_counts():
    with SessionLocal() as session:
        return {
            "alerts": session.query(AlertRecord).count(),
            "mitre_mappings": session.query(AlertTechniqueMapping).count(),
            "decision_cases": session.query(DecisionCase).count(),
        }


def _large_json_rows(row_count, *, malformed_tail=b""):
    row = canonical_json(canonical_flow())[1:-1]
    body = b",".join([row] * row_count)
    if malformed_tail:
        body += b"," + malformed_tail
    return b"[" + body + b"]"


def _duplicate_json_member(row, key, second_value):
    encoded = json.dumps(row, separators=(",", ":"))
    return (encoded[:-1] + f",{json.dumps(key)}:{json.dumps(second_value)}}}").encode()


def test_duplicate_json_key_fails_closed_with_stable_parse_reason():
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "duplicate.json",
                _duplicate_json_member(canonical_flow(), "flow_duration", 5),
                "application/json",
            )
        },
    )
    assert response.status_code == 400
    assert "duplicate_json_key" in response.text


def test_duplicate_ndjson_alias_is_reported_as_recoverable_row_rejection():
    row = canonical_flow()
    row.pop("flow_duration")
    aliased = {"Flow Duration": 1, **row}
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "duplicate-alias.ndjson",
                canonical_json(aliased)[1:-1]
                + b"\n"
                + _duplicate_json_member(aliased, "Flow Duration", 2),
                "application/x-ndjson",
            )
        },
    )
    assert response.status_code == 200
    report = response.json()["schema_validation"]
    assert report["usable_row_count"] == 1
    assert report["rows_rejected"] == 1
    assert report["rejection_reasons"] == {"duplicate_json_key": 1}


def test_recoverable_ndjson_error_preserves_accepted_row_order(monkeypatch):
    from backend.api import detection

    pipe = detection._get_pipeline()
    observed = []
    original = pipe.detect_batch

    def ordered(rows):
        observed.extend(int(row["flow_duration"]) for row in rows)
        return original(rows)

    monkeypatch.setattr(pipe, "detect_batch", ordered)
    lines = [
        canonical_json(canonical_flow(flow_duration=11))[1:-1],
        b'{"flow_duration":',
        canonical_json(canonical_flow(flow_duration=22))[1:-1],
        canonical_json(canonical_flow(flow_duration=33))[1:-1],
    ]
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "recoverable.ndjson",
                b"\n".join(lines),
                "application/x-ndjson",
            )
        },
    )
    assert response.status_code == 200
    report = response.json()["schema_validation"]
    assert observed == [11, 22, 33]
    assert report["total_parsed"] == 4
    assert report["usable_row_count"] == 3
    assert report["rows_rejected"] == 1
    assert report["rejection_reasons"] == {"invalid_ndjson_line": 1}


def test_fatal_json_after_5000_rows_has_no_statistics_or_persistence_side_effects(
    monkeypatch,
):
    from backend.api import detection

    pipe = detection._get_pipeline()
    before_stats = pipe.get_stats()
    before_db = _persistent_detection_counts()
    calls = 0
    original = pipe.detect_batch

    def counted(rows):
        nonlocal calls
        calls += 1
        return original(rows)

    monkeypatch.setattr(pipe, "detect_batch", counted)
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "late-malformed.json",
                _large_json_rows(5000, malformed_tail=b'{"flow_duration":'),
                "application/json",
            )
        },
    )
    assert response.status_code == 400
    assert calls >= 1
    assert pipe.get_stats() == before_stats
    assert _persistent_detection_counts() == before_db
    assert "process_lifetime_stats" not in response.text
    assert "smart_logs_created" not in response.text


def test_fatal_row_limit_after_processed_batch_has_no_side_effects(
    monkeypatch,
):
    from backend import config
    from backend.api import detection

    monkeypatch.setattr(config, "MAX_UPLOAD_ROWS", 5001)
    monkeypatch.setattr(detection, "BATCH_SIZE", 1000)
    pipe = detection._get_pipeline()
    before_stats = pipe.get_stats()
    before_db = _persistent_detection_counts()
    calls = 0
    original = pipe.detect_batch

    def counted(rows):
        nonlocal calls
        calls += 1
        return original(rows)

    monkeypatch.setattr(pipe, "detect_batch", counted)
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "over-row-limit.json",
                _large_json_rows(5002),
                "application/json",
            )
        },
    )
    assert response.status_code == 413
    assert calls >= 1
    assert pipe.get_stats() == before_stats
    assert _persistent_detection_counts() == before_db
    assert "process_lifetime_stats" not in response.text


def test_valid_upload_commits_process_statistics_once():
    from backend.api import detection

    pipe = detection._get_pipeline()
    before = pipe.get_stats()["total_flows"]
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "successful.json",
                canonical_json(canonical_flow(), canonical_flow()),
                "application/json",
            )
        },
    )
    assert response.status_code == 200
    assert response.json()["analyzed"] == 2
    assert pipe.get_stats()["total_flows"] - before == 2


def test_fatal_byte_limit_has_no_statistics_or_persistence_side_effects(
    monkeypatch,
):
    from backend import config
    from backend.api import detection

    pipe = detection._get_pipeline()
    before_stats = pipe.get_stats()
    before_db = _persistent_detection_counts()
    monkeypatch.setattr(config, "MAX_UPLOAD_MB", 0)
    response = client.post(
        "/api/detect/upload",
        files={"file": ("too-large.json", canonical_json(canonical_flow()), "application/json")},
    )
    assert response.status_code == 413
    assert pipe.get_stats() == before_stats
    assert _persistent_detection_counts() == before_db
    assert "process_lifetime_stats" not in response.text


@pytest.mark.parametrize(
    "payload",
    [
        b'{"message":"not flow telemetry"}',
        canonical_json(canonical_flow(flow_duration="NaN")),
    ],
)
def test_fatal_schema_failure_has_no_statistics_or_persistence_side_effects(
    payload,
):
    from backend.api import detection

    pipe = detection._get_pipeline()
    before_stats = pipe.get_stats()
    before_db = _persistent_detection_counts()
    response = client.post(
        "/api/detect/upload",
        files={"file": ("invalid-schema.json", payload, "application/json")},
    )
    assert response.status_code == 422
    assert pipe.get_stats() == before_stats
    assert _persistent_detection_counts() == before_db
    assert "process_lifetime_stats" not in response.text


def test_later_batch_inference_failure_is_atomic_and_closes_parser(monkeypatch):
    from backend.api import detection
    from backend.api.upload_stream import PreparedUpload

    pipe = detection._get_pipeline()
    before_stats = pipe.get_stats()
    before_db = _persistent_detection_counts()
    original_detect = pipe.detect_batch
    original_close = PreparedUpload.close
    calls = 0
    closed = 0

    def fail_later(rows):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic later-batch inference failure")
        return original_detect(rows)

    def tracked_close(prepared):
        nonlocal closed
        closed += 1
        return original_close(prepared)

    monkeypatch.setattr(detection, "BATCH_SIZE", 2)
    monkeypatch.setattr(pipe, "detect_batch", fail_later)
    monkeypatch.setattr(PreparedUpload, "close", tracked_close)
    response = error_client.post(
        "/api/detect/upload",
        files={
            "file": (
                "later-inference.json",
                canonical_json(*(canonical_flow(flow_duration=i) for i in range(5))),
                "application/json",
            )
        },
    )
    assert response.status_code == 500
    assert calls == 2
    assert closed == 1
    assert pipe.get_stats() == before_stats
    assert _persistent_detection_counts() == before_db
    assert "process_lifetime_stats" not in response.text


def test_feature_importance_failure_occurs_before_commit(monkeypatch):
    from backend.api import detection

    pipe = detection._get_pipeline()
    before_stats = pipe.get_stats()
    before_db = _persistent_detection_counts()

    def fail_feature_importance(_limit):
        raise RuntimeError("synthetic response preparation failure")

    monkeypatch.setattr(pipe.clf, "feature_importance", fail_feature_importance)
    response = error_client.post(
        "/api/detect/upload",
        files={
            "file": (
                "feature-importance-failure.csv",
                canonical_csv(canonical_flow(
                    flow_duration=1_000_000,
                    total_fwd_packets=1_000_000,
                    syn_flag_count=100_000,
                    bytes_per_sec=10_000_000_000,
                )),
                "text/csv",
            )
        },
    )
    assert response.status_code == 500
    assert pipe.get_stats() == before_stats
    assert _persistent_detection_counts() == before_db


def test_final_database_commit_failure_rolls_back_every_upload_side_effect(
    monkeypatch,
):
    from backend.api import detection

    pipe = detection._get_pipeline()
    before_stats = pipe.get_stats()
    before_db = _persistent_detection_counts()
    real_factory = detection.SessionLocal

    def failing_session_factory():
        session = real_factory()

        def fail_commit():
            raise RuntimeError("synthetic database commit failure")

        session.commit = fail_commit
        return session

    monkeypatch.setattr(detection, "SessionLocal", failing_session_factory)
    response = error_client.post(
        "/api/detect/upload",
        files={
            "file": (
                "persistence-failure.csv",
                canonical_csv(canonical_flow(
                    flow_duration=1_000_000,
                    total_fwd_packets=1_000_000,
                    syn_flag_count=100_000,
                    bytes_per_sec=10_000_000_000,
                )),
                "text/csv",
            )
        },
    )
    assert response.status_code == 500
    assert pipe.get_stats() == before_stats
    assert _persistent_detection_counts() == before_db
    assert "process_lifetime_stats" not in response.text


def test_export_alerts_csv_endpoint():
    res = client.get("/api/detect/export")
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", "")
