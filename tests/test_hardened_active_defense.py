"""Comprehensive test suite for Hardened Active Defense, IPS Safety Gates, RBAC, and Durability."""
import json
import os
import time
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.actuators.guardrails import SafetyGuardrails, discover_protected_local_assets
from backend.actuators.router import ActuatorRouter
from backend.safety.formal_verifier import FormalSafetyVerifier
from backend.detection.pipeline import Alert
from backend.detection.scan_correlator import ScanCorrelator
from backend.detection.live_worker import LiveFlowWorker

client = TestClient(app)


def test_truthful_containment_recording():
    """Verify live worker truthfully records simulated vs executed vs blocked_by_policy."""
    worker = LiveFlowWorker()

    # Simulated known attack with high confidence
    alert = Alert(
        severity="high",
        type="DDoS",
        confidence=0.95,
        route="known_attack",
        evidence={"production_approved": True},
    )
    class MockPipe:
        def detect_batch(self, batch):
            return [alert]

    worker.set_pipeline_getter(lambda: MockPipe())
    flow = {"src_ip": "203.0.113.5", "dst_ip": "10.0.0.1", "dst_port": 80}

    # In simulation mode (default)
    os.environ["CG_ACTIVE_DEFENSE_MODE"] = "simulation"
    alerts = worker.process_flows([flow])
    assert len(alerts) == 1
    assert alerts[0]["executed_action"] == "simulated:block_ip"
    assert "simulated" in alerts[0]["explanation"]
    assert alerts[0]["rollback_token"].startswith("cg-proof-")


def test_cidr_matching_in_protected_ips(monkeypatch):
    """Verify CIDR notation in CG_PROTECTED_IPS protects all subnet IPs."""
    monkeypatch.setenv("CG_PROTECTED_IPS", "192.168.100.0/24, 10.50.0.0/16")
    guardrails = SafetyGuardrails()

    # 192.168.100.55 belongs to 192.168.100.0/24
    valid, reason = guardrails.validate_action("block_ip", "192.168.100.55")
    assert valid is False
    assert "belongs to protected subnet" in reason or "protected" in reason

    # 10.50.12.34 belongs to 10.50.0.0/16
    valid2, reason2 = guardrails.validate_action("block_ip", "10.50.12.34")
    assert valid2 is False

    # External IP not in subnet
    valid3, _ = guardrails.validate_action("block_ip", "198.51.100.99")
    assert valid3 is True


def test_routing_table_gateway_discovery():
    """Verify local gateways and host IPs are in protected assets."""
    assets = discover_protected_local_assets()
    assert "127.0.0.1" in assets
    assert "localhost" in assets
    # Common gateways or local interfaces are discovered
    assert any(gw in assets for gw in ("192.168.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1"))


def test_unauthenticated_lan_client_cannot_execute_state_changing_methods():
    """Verify LAN clients (RFC1918) without token can read but cannot POST/DELETE."""
    lan_client = TestClient(app, client=("192.168.1.45", 50000))

    # Safe GET should be admitted in development mode without token
    res_get = lan_client.get("/api/settings")
    assert res_get.status_code == 200

    # State-changing POST should be strictly rejected without token
    res_post = lan_client.post("/api/settings", json={"llm_provider": "local"})
    assert res_post.status_code == 401
    assert "State-changing operations require authenticated" in res_post.text


def test_actuate_endpoint_sanitizes_injected_params():
    """Verify approver_id cannot be injected via params to bypass validation."""
    # 1. Attempt to inject fake approver inside params in enforcement mode
    res = client.post(
        "/api/decision/actuate/1",
        json={
            "action": "block_ip",
            "target": "203.0.113.10",
            "mode": "enforcement",
            "params": {"approver_id": "fake_unverified_approver"},
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert "Two-Person Rule violation" in data["error"]

    # 2. Attempt to supply unrecognized approver_id top-level field
    res_fake = client.post(
        "/api/decision/actuate/1",
        json={
            "action": "block_ip",
            "target": "203.0.113.10",
            "mode": "enforcement",
            "approver_id": "unknown_attacker_identity",
        },
    )
    assert res_fake.status_code == 400
    assert "not a recognized authorized identity" in res_fake.text


def test_cross_process_rollback_persistence():
    """Verify that rollback receipts persist in SQLite across separate router instances."""
    verifier = FormalSafetyVerifier()
    router1 = ActuatorRouter(safety_verifier=verifier, require_two_person=False)

    res = router1.execute_action("block_ip", "203.0.113.88", mode="simulation")
    assert res.success is True
    token = res.rollback_token
    assert token is not None
    assert token.startswith("cg-proof-")

    # Simulate process restart by creating a completely fresh router with empty in-memory state
    router2 = ActuatorRouter(safety_verifier=verifier, require_two_person=False)
    assert token not in router2._receipt_map  # In-memory dict is completely empty

    # Rollback must succeed by fetching and verifying from SQLite
    rolled_back = router2.rollback_action(token)
    assert rolled_back is True


def test_scan_correlator_eliminates_benign_multitarget_false_positives():
    """Verify client browsing multiple external sites does not trigger PortScan."""
    correlator = ScanCorrelator(window_sec=2.0, min_ports_for_vertical_scan=5)
    client_ip = "192.168.1.75"

    # Client visits 3 different external destinations on different ports (e.g. HTTP, HTTPS, DNS)
    probes = [
        ("142.250.180.206", 443),
        ("151.101.1.140", 80),
        ("1.1.1.1", 53),
    ]

    for dst_h, dst_p in probes:
        alert = Alert(severity="none", type="Benign", confidence=0.99, route="benign")
        meta = {
            "src_ip": client_ip,
            "dst_ip": dst_h,
            "dst_port": dst_p,
            "syn_flag_count": 1.0,
            "bwd_pkts": 5,
            "bwd_bytes": 1200,
        }
        res = correlator.correlate_alert(alert, meta, timestamp=time.time())
        # Must remain Benign, never overridden to PortScan
        assert res.type == "Benign"
        assert res.severity == "none"
        assert res.route == "benign"


def test_evaluation_only_model_blocks_enforcement(monkeypatch):
    """Verify serving model with production_approved=False refuses live enforcement."""
    worker = LiveFlowWorker()

    # High severity attack, but evaluation_only model
    alert = Alert(
        severity="high",
        type="PortScan",
        confidence=0.92,
        route="known_attack",
        evidence={"production_approved": False},
    )
    class MockPipe:
        def detect_batch(self, batch):
            return [alert]

    worker.set_pipeline_getter(lambda: MockPipe())
    flow = {"src_ip": "203.0.113.77", "dst_ip": "10.0.0.1", "dst_port": 22}

    monkeypatch.setenv("CG_ACTIVE_DEFENSE_MODE", "enforcement")
    monkeypatch.setenv("CG_ALLOW_EVALUATION_ENFORCEMENT", "false")

    alerts = worker.process_flows([flow])
    assert len(alerts) == 1
    assert alerts[0]["executed_action"] == "blocked_by_policy:block_ip"
    assert "evaluation-only" in alerts[0]["explanation"]
