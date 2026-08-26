"""Regression tests for web, input, egress, and export security controls."""
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.security import safe_llm_url, validate_llm_url
from backend.api.detection import _safe_csv_cell
from backend.mitre.taxii_sync import _validate_bundle

client = TestClient(app)


def test_security_headers_are_present():
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["referrer-policy"] == "no-referrer"


def test_untrusted_host_is_blocked():
    assert client.get("/api/settings", headers={"Host": "evil.example"}).status_code == 400


def test_cross_origin_api_request_is_blocked():
    response = client.post(
        "/api/settings",
        headers={"Origin": "https://evil.example"},
        json={"llm_provider": "local"},
    )
    assert response.status_code == 403


def test_remote_client_requires_api_token():
    remote = TestClient(app, client=("198.51.100.8", 41000))
    assert remote.get("/api/settings").status_code == 403


def test_configured_api_token_is_constant_time_guard(monkeypatch):
    import backend.security as security

    monkeypatch.setattr(security, "API_TOKEN", "correct-horse-battery-staple")
    assert client.get("/api/settings").status_code == 401
    assert client.get(
        "/api/settings", headers={"X-CyberGuard-Token": "wrong"}
    ).status_code == 401
    assert client.get(
        "/api/settings",
        headers={"Authorization": "Bearer correct-horse-battery-staple"},
    ).status_code == 200


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.1:8080",
    "http://2130706433:8080",
    "file:///etc/passwd",
    "http://localhost:22",
    "http://user:pass@127.0.0.1:8080",
])
def test_local_llm_ssrf_payloads_are_blocked(url):
    with pytest.raises(ValueError):
        validate_llm_url(url, local=True)


@pytest.mark.parametrize("url", [
    "http://api.deepseek.com/v1",
    "https://api.deepseek.com.evil.example/v1",
    "https://127.0.0.1/v1",
    "https://169.254.169.254/latest",
    "https://api.deepseek.com:8443/v1",
    "https://user:pass@api.deepseek.com/v1",
])
def test_cloud_llm_ssrf_and_key_exfiltration_payloads_are_blocked(url):
    with pytest.raises(ValueError):
        validate_llm_url(url, local=False)


def test_expected_provider_urls_are_allowed():
    assert validate_llm_url("http://127.0.0.1:8080", local=True)
    assert validate_llm_url("http://[::1]:8080", local=True)
    assert validate_llm_url("https://api.deepseek.com/v1", local=False)
    assert validate_llm_url("https://api.openai.com/v1", local=False)


def test_legacy_unsafe_url_falls_back_without_egress():
    assert safe_llm_url(
        "http://169.254.169.254/latest",
        "http://127.0.0.1:8080",
        local=True,
    ) == "http://127.0.0.1:8080"


def test_settings_reject_ssrf_before_storage():
    local = client.post(
        "/api/settings",
        json={"llm_provider": "local", "llama_url": "http://169.254.169.254"},
    )
    cloud = client.post(
        "/api/settings",
        json={"llm_provider": "api", "api_base_url": "https://evil.example/v1"},
    )
    assert local.status_code == 422
    assert cloud.status_code == 422


def test_chat_and_query_limits_reject_resource_abuse():
    chat = client.post(
        "/api/chat",
        json={"session_id": "session-valid", "message": "x" * 8001},
    )
    alerts = client.get("/api/detect/alerts?limit=100000000")
    history = client.get("/api/chat/history/session-valid?limit=100000000")
    assert chat.status_code == 422
    assert alerts.status_code == 422
    assert history.status_code == 422


def test_upload_rejects_non_object_json_and_binary():
    primitive = client.post(
        "/api/detect/upload",
        files={"file": ("bad.json", b"[1,2,3]", "application/json")},
    )
    binary = client.post(
        "/api/detect/upload",
        files={"file": ("bad.csv", b"\x00" * 100, "text/csv")},
    )
    assert primitive.status_code == 422
    assert binary.status_code == 400


def test_upload_byte_limit_is_enforced(monkeypatch):
    import backend.config as config

    monkeypatch.setattr(config, "MAX_UPLOAD_MB", 0)
    response = client.post(
        "/api/detect/upload",
        files={"file": ("flow.csv", b"a,b\n1,2\n", "text/csv")},
    )
    assert response.status_code == 413


@pytest.mark.parametrize("payload", ["=CMD()", "+1+1", "-2+3", "@SUM(A1:A2)"])
def test_csv_formula_injection_is_neutralized(payload):
    assert _safe_csv_cell(payload).startswith("'")


def test_mitre_search_is_parameterized_against_sql_injection():
    response = client.get(
        "/api/mitre/techniques", params={"q": "%' OR 1=1 --", "limit": 10}
    )
    assert response.status_code == 200
    assert len(response.json()) <= 10


def test_mitre_supply_chain_rejects_tiny_or_invalid_bundle():
    with pytest.raises(ValueError):
        _validate_bundle({"objects": []})
    with pytest.raises(ValueError):
        _validate_bundle({"not_objects": []})


def test_numeric_overflow_payload_stays_json_safe():
    from tests.helpers import canonical_flow, canonical_json

    payload = canonical_flow(flow_duration="1e309")
    response = client.post(
        "/api/detect/upload",
        files={
            "file": (
                "overflow.json",
                canonical_json(payload),
                "application/json",
            )
        },
    )
    assert response.status_code == 422
    assert "Infinity" not in response.text
    assert "NaN" not in response.text
    report = response.json()["detail"]["schema_validation"]
    assert report["invalid_numeric_cell_counts"]["non_finite"] == 1


def test_upload_rate_limit_blocks_request_flood():
    statuses = [
        client.post(
            "/api/detect/upload",
            files={"file": ("empty.csv", b"", "text/csv")},
        ).status_code
        for _ in range(12)
    ]
    assert 429 in statuses


def test_oversized_headers_url_and_json_body_are_rejected():
    assert client.get("/", headers={"X-Fill": "A" * 20_000}).status_code == 431
    assert client.get("/api/mitre/techniques?q=" + ("a" * 5000)).status_code == 414
    assert client.post(
        "/api/settings",
        content=b"x" * (1024 * 1024 + 1),
        headers={"Content-Type": "application/json"},
    ).status_code == 413
