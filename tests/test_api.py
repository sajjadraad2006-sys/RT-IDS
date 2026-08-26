"""API integration tests for strict flow uploads and health reporting."""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.limiter import limiter
from tests.helpers import canonical_csv, canonical_flow, canonical_json

client = TestClient(app)


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


def test_export_alerts_csv_endpoint():
    res = client.get("/api/detect/export")
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", "")
