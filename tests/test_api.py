"""API endpoint integration tests — upload CSV/JSON, health checks, settings."""
import io
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health_check_endpoint():
    res = client.get("/api/detect/health")
    assert res.status_code == 200
    data = res.json()
    assert "ready" in data and "stages" in data


def test_upload_csv_flow_returns_200():
    csv_content = """Flow Duration,Total Fwd Packets,SYN Flag Count,Flow Bytes/s
120000,6,2,1500.5
999999,500,50,900000
"""
    files = {"file": ("friday_traffic.csv", csv_content.encode("utf-8"), "text/csv")}
    res = client.post("/api/detect/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["flows"] == 2
    assert "alerts" in data
    assert "stage_counts" in data
    assert "feature_importance" in data


def test_upload_uppercase_extension_accepted():
    csv_content = "Flow Duration,SYN Flag Count\n1000,1\n"
    files = {"file": ("TRAFFIC.CSV", csv_content.encode("utf-8"), "text/csv")}
    res = client.post("/api/detect/upload", files=files)
    assert res.status_code == 200


def test_upload_empty_file_returns_400():
    files = {"file": ("empty.csv", b"", "text/csv")}
    res = client.post("/api/detect/upload", files=files)
    assert res.status_code == 400


def test_upload_whitespace_file_returns_400():
    files = {"file": ("blank.log", b"   \n  \n ", "text/plain")}
    res = client.post("/api/detect/upload", files=files)
    assert res.status_code == 400


def test_export_alerts_csv_endpoint():
    res = client.get("/api/detect/export")
    assert res.status_code == 200
    assert "text/csv" in res.headers.get("content-type", "")
