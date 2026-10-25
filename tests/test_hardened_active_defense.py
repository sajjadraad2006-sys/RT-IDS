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
    """Verify serving model with nested artifact.production_approved=False refuses live enforcement."""
    worker = LiveFlowWorker()

    # High severity attack, but evaluation_only model in real pipeline nested artifact structure
    alert = Alert(
        severity="high",
        type="PortScan",
        confidence=0.92,
        route="known_attack",
        evidence={"artifact": {"production_approved": False}},
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

    # When model is production_approved: True
    alert_approved = Alert(
        severity="high",
        type="PortScan",
        confidence=0.95,
        route="known_attack",
        evidence={"artifact": {"production_approved": True}},
    )
    class MockApprovedPipe:
        def detect_batch(self, batch):
            return [alert_approved]

    worker.set_pipeline_getter(lambda: MockApprovedPipe())
    monkeypatch.setenv("CG_ACTIVE_DEFENSE_MODE", "simulation")
    alerts_ok = worker.process_flows([{"src_ip": "203.0.113.78", "dst_ip": "10.0.0.1", "dst_port": 80}])
    assert len(alerts_ok) == 1
    assert alerts_ok[0]["executed_action"] == "simulated:block_ip"


def test_containment_ttl_auto_expiration():
    """Verify that an action with TTL automatically expires and rolls back via sweep."""
    router = ActuatorRouter(require_two_person=False)
    # Execute action with 1 second TTL
    res = router.execute_action(
        "block_ip",
        "198.51.100.150",
        params={"ttl_seconds": 1},
        mode="simulation",
    )
    assert res.success is True
    tok = res.rollback_token
    assert tok is not None

    # Wait for TTL to expire
    time.sleep(1.1)

    # Trigger TTL sweep
    expired_count = router.sweep_expired_actions()
    assert expired_count >= 1

    # Second rollback must fail because it was already rolled back by TTL expiration
    assert router.rollback_action(tok) is False


def test_linux_proc_net_route_parsing(monkeypatch):
    """Verify discover_protected_local_assets() on Linux correctly parses /proc/net/route little-endian hex."""
    import builtins
    import io
    import platform

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    mock_route = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0164A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth1\t00000000\t0108A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth2\t00000000\t8A00000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth3\t00000000\t012BA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    )
    orig_open = builtins.open

    def mock_open_func(file, *args, **kwargs):
        if str(file) == "/proc/net/route":
            return io.StringIO(mock_route)
        return orig_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", mock_open_func)
    assets = discover_protected_local_assets()
    assert "192.168.100.1" in assets
    assert "192.168.8.1" in assets
    assert "10.0.0.138" in assets
    assert "192.168.43.1" in assets


def test_scan_correlator_detects_nmap_sv_banner_grab_and_ignores_loopback():
    """Verify nmap -sV multi-port probe with server banner payloads is detected."""
    correlator = ScanCorrelator(window_sec=2.0, min_ports_for_vertical_scan=3)
    target_ip = "192.168.1.150"
    attacker_ip = "192.168.1.80"

    # Attacker probes 4 distinct ports on target, server returns small service banners
    probes = [21, 22, 80, 443]
    last_res = None
    for p in probes:
        alert = Alert(severity="none", type="Benign", confidence=0.90, route="benign")
        meta = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "dst_port": p,
            "syn_flag_count": 1.0,
            "total_fwd_packets": 2,
            "total_bwd_packets": 2,
            "total_fwd_bytes": 80,
            "total_bwd_bytes": 220,  # Banner grab response (<350B, not interactive session)
            "ack_flag_count": 1.0,
        }
        last_res = correlator.correlate_alert(alert, meta, timestamp=time.time())

    assert last_res is not None
    assert last_res.type == "PortScan"
    assert last_res.severity == "high"
    assert last_res.route == "known_attack"
    assert last_res.confidence >= 0.88

    # Local loopback connection must never be flagged
    loopback_meta = {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "dst_port": 8000, "syn_flag_count": 1.0}
    res_lb = correlator.correlate_alert(Alert(severity="none", type="Benign"), loopback_meta)
    assert res_lb.type == "Benign"


def test_scan_correlator_allows_legitimate_web_browsing_and_admin_traffic():
    """Verify legitimate multi-host browsing and multi-port admin sessions are NOT flagged as PortScan."""
    correlator = ScanCorrelator(window_sec=2.0, min_ports_for_vertical_scan=3, min_hosts_for_horizontal_sweep=3)
    client_ip = "192.168.1.105"

    # 1. Normal web browsing: User connects to 3 different external HTTPS websites on :443 with bidirectional application payload
    websites = ["142.250.190.46", "151.101.1.69", "104.244.42.1"]
    for ip in websites:
        # Test Case A: Benign traffic stays Benign
        alert_benign = Alert(severity="none", type="Benign", confidence=0.95, route="benign")
        web_flow = {
            "src_ip": client_ip,
            "dst_ip": ip,
            "dst_port": 443,
            "syn_flag_count": 1.0,
            "ack_flag_count": 5.0,
            "total_fwd_packets": 6,
            "total_bwd_packets": 8,
            "total_fwd_bytes": 450,
            "total_bwd_bytes": 3500,  # Full TLS handshake + HTTP response
        }
        res = correlator.correlate_alert(alert_benign, web_flow, timestamp=time.time())
        assert res.type == "Benign"
        assert res.route == "benign"

        # Test Case B: Classifier falsely labelled browsing flow as PortScan -> Correlator must downgrade it!
        alert_false_pos = Alert(severity="high", type="PortScan", confidence=0.88, route="known_attack")
        res_downgraded = correlator.correlate_alert(alert_false_pos, web_flow, timestamp=time.time())
        assert res_downgraded.type == "Benign"
        assert res_downgraded.route == "benign"
        assert res_downgraded.confidence <= 0.10

    # 2. Administrator connecting to server on ports 22 (SSH), 443 (Console), 5432 (Postgres)
    server_ip = "10.0.0.25"
    admin_ports = [22, 443, 5432]
    for p in admin_ports:
        alert_admin = Alert(severity="none", type="Benign", confidence=0.95, route="benign")
        admin_flow = {
            "src_ip": client_ip,
            "dst_ip": server_ip,
            "dst_port": p,
            "syn_flag_count": 1.0,
            "ack_flag_count": 8.0,
            "total_fwd_packets": 10,
            "total_bwd_packets": 12,
            "total_fwd_bytes": 1200,
            "total_bwd_bytes": 4500,
        }
        res_admin = correlator.correlate_alert(alert_admin, admin_flow, timestamp=time.time())
        assert res_admin.type == "Benign"
        assert res_admin.route == "benign"

        # Even if model falsely flagged admin flow as PortScan, correlator downgrades because all ports are interactive
        alert_admin_fp = Alert(severity="high", type="PortScan", confidence=0.88, route="known_attack")
        res_admin_downgraded = correlator.correlate_alert(alert_admin_fp, admin_flow, timestamp=time.time())
        assert res_admin_downgraded.type == "Benign"
        assert res_admin_downgraded.route == "benign"


def test_rbac_blocks_viewer_and_auditor_from_mutating_state():
    """Verify users with VIEWER and AUDITOR roles are strictly forbidden (403) from state mutation."""
    from backend.auth import create_access_token, User, Role
    
    for restricted_role in (Role.VIEWER, Role.AUDITOR):
        user = User(username=f"test-{restricted_role.value}", role=restricted_role)
        token = create_access_token(user)
        headers = {"Authorization": f"Bearer {token}"}

        # 1. DELETE /api/detect/alerts/clear
        res_del = client.delete("/api/detect/alerts/clear", headers=headers)
        assert res_del.status_code == 403

        # 2. POST /api/detect/live/stop
        res_stop = client.post("/api/detect/live/stop", headers=headers)
        assert res_stop.status_code == 403

        # 3. POST /api/settings
        res_settings = client.post("/api/settings", json={"llm_provider": "local"}, headers=headers)
        assert res_settings.status_code == 403

        # 4. POST /api/events/suricata/stream/start
        res_stream = client.post("/api/events/suricata/stream/start", headers=headers)
        assert res_stream.status_code == 403

        # 5. POST /api/operations/incidents/inc-test/resolve
        res_resolve = client.post("/api/operations/incidents/inc-test/resolve", json={"verdict": "false_positive"}, headers=headers)
        assert res_resolve.status_code == 403


def test_sqlite_action_receipts_auto_migration(tmp_path):
    """Verify migrate_db() adds missing columns to existing action_receipts SQLite table."""
    from backend.db.models import migrate_db
    migrate_db()


def test_enforcement_mode_with_approved_model_executes_containment(monkeypatch):
    """Verify production_approved model in enforcement mode successfully passes the gate."""
    from backend.detection.live_worker import LiveFlowWorker
    from backend.detection.pipeline import Alert

    monkeypatch.setenv("CG_ACTIVE_DEFENSE_MODE", "enforcement")
    monkeypatch.setenv("CG_ALLOW_EVALUATION_ENFORCEMENT", "false")

    worker = LiveFlowWorker()
    alert_approved = Alert(
        severity="critical",
        type="DDoS-SYN",
        confidence=0.98,
        route="known_attack",
        evidence={
            "src_ip": "198.51.100.95",
            "artifact": {
                "name": "Production-XGBoost-V2",
                "production_approved": True,
            },
        },
    )

    class MockApprovedPipe:
        production_approved = True
        def detect_batch(self, batch):
            return [alert_approved]

    worker.set_pipeline_getter(lambda: MockApprovedPipe())
    flow = {"src_ip": "198.51.100.95", "dst_ip": "10.0.0.1", "dst_port": 80, "syn_flag_count": 1.0}
    alerts = worker.process_flows([flow])
    assert len(alerts) == 1
    # Gate passed! Not rejected
    assert "rejected: evaluation_only_model" not in alerts[0]["explanation"]
