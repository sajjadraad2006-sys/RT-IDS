"""Tests for autonomous defense actuators, deterministic safety guardrails, and rollback."""
from pathlib import Path
import tempfile
import pytest

from backend.actuators.guardrails import SafetyGuardrails, VALID_AUTONOMOUS_ACTIONS
from backend.actuators.firewall import FirewallActuator
from backend.actuators.suricata_rules import SuricataActuator
from backend.actuators.router import ActuatorRouter


def test_guardrails_prevent_self_dos_on_loopback():
    rails = SafetyGuardrails()
    for protected in ["127.0.0.1", "127.0.0.5", "localhost", "::1"]:
        is_safe, reason = rails.validate_action("block_ip", protected)
        assert not is_safe, f"Loopback {protected} must be rejected"
        assert "protected" in reason.lower() or "allowlist" in reason.lower()


def test_guardrails_protect_core_dns():
    rails = SafetyGuardrails()
    for dns_ip in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]:
        is_safe, reason = rails.validate_action("block_ip", dns_ip)
        assert not is_safe, f"Core DNS {dns_ip} must not be blocked"


def test_guardrails_reject_unapproved_actions():
    rails = SafetyGuardrails()
    for bad_action in ["reboot_server", "format_drive", "delete_all", "exploit"]:
        is_safe, reason = rails.validate_action(bad_action, "203.0.113.5")
        assert not is_safe
        assert "not in approved" in reason


def test_guardrails_approve_safe_external_threat():
    rails = SafetyGuardrails()
    is_safe, reason = rails.validate_action("block_ip", "203.0.113.19")
    assert is_safe
    assert "passed" in reason.lower()


def test_firewall_actuator_simulation_mode():
    fw = FirewallActuator(is_windows=True)
    res = fw.execute("block_ip", "198.51.100.42", dry_run=True)
    assert res.success is True
    assert res.simulated is True
    assert "New-NetFirewallRule" in res.command_executed
    assert "198.51.100.42" in res.command_executed
    assert res.rollback_token is not None
    assert res.rollback_token.startswith("cg-fw-")

    # Test simulated rollback
    rolled_back = fw.rollback(res.rollback_token)
    assert rolled_back is True


def test_firewall_actuator_linux_syntax():
    fw = FirewallActuator(is_windows=False)
    res = fw.execute("block_ip", "198.51.100.42", params={"port": 80}, dry_run=True)
    assert res.success is True
    assert "iptables -I INPUT -s 198.51.100.42 -j DROP" in res.command_executed
    assert "--dport 80" in res.command_executed


def test_firewall_actuator_rate_limit_differentiation():
    # Linux rate limiting uses hashlimit
    fw_linux = FirewallActuator(is_windows=False)
    res_linux = fw_linux.execute("rate_limit", "198.51.100.42", dry_run=True)
    assert res_linux.success is True
    assert "hashlimit" in res_linux.command_executed
    assert "RateLimit" in res_linux.command_executed or "hashlimit" in res_linux.command_executed

    # Windows rate limiting rule naming
    fw_win = FirewallActuator(is_windows=True)
    res_win = fw_win.execute("rate_limit", "198.51.100.42", dry_run=True)
    assert res_win.success is True
    assert "CyberGuard-RateLimit" in res_win.command_executed



def test_firewall_actuator_elevation_check(monkeypatch):
    fw = FirewallActuator(is_windows=True)
    # Simulate unprivileged execution
    monkeypatch.setattr(fw, "is_elevated", lambda: False)
    res = fw.execute("block_ip", "198.51.100.42", dry_run=False)
    assert res.success is False
    assert res.simulated is False
    assert "Insufficient OS privileges" in res.error
    assert res.metadata.get("privilege_check") == "failed_unprivileged"


def test_suricata_actuator_generates_valid_drop_rule():
    with tempfile.TemporaryDirectory() as tmpdir:
        rules_path = Path(tmpdir) / "dynamic.rules"
        suri = SuricataActuator(rules_file_path=rules_path)

        res = suri.execute("drop_suricata_signature", "203.0.113.88", params={"protocol": "tcp"}, dry_run=False)
        assert res.success is True
        assert res.simulated is False
        assert res.rollback_token is not None

        content = rules_path.read_text(encoding="utf-8")
        assert "drop tcp 203.0.113.88 any -> any any" in content
        assert "sid:9900001" in content

        # Test rollback
        rolled_back = suri.rollback(res.rollback_token)
        assert rolled_back is True
        new_content = rules_path.read_text(encoding="utf-8")
        assert "203.0.113.88" not in new_content


def test_actuator_router_guardrail_blocking():
    router = ActuatorRouter()
    # Try blocking protected IP
    res = router.execute_action("block_ip", "127.0.0.1", mode="simulation")
    assert res.success is False
    assert "Guardrail violation" in res.error
    assert len(router.list_active_blocks()) == 0


def test_actuator_router_execution_and_rollback():
    router = ActuatorRouter()
    # Safe IP
    res = router.execute_action("block_ip", "203.0.113.77", mode="simulation")
    assert res.success is True
    assert res.simulated is True
    assert res.rollback_token is not None

    blocks = router.list_active_blocks()
    assert len(blocks) >= 1
    assert any(b["target"] == "203.0.113.77" for b in blocks)

    # Rollback
    rb_res = router.rollback_action(res.rollback_token)
    assert rb_res is True
    assert not any(b["rollback_token"] == res.rollback_token for b in router.list_active_blocks())


def test_guardrails_reject_command_injection_target():
    rails = SafetyGuardrails()
    malicious_targets = [
        "203.0.113.10; rm -rf /",
        "203.0.113.10 | calc",
        "203.0.113.10\" `whoami`",
        "invalid_ip_string",
        "999.999.999.999",
    ]
    for target in malicious_targets:
        is_safe, reason = rails.validate_action("block_ip", target)
        assert not is_safe, f"Target '{target}' should have been rejected"
        assert "not a valid IP address" in reason or "invalid" in reason


def test_guardrails_validate_port_isolation():
    rails = SafetyGuardrails()
    # Valid port
    is_safe, _ = rails.validate_action("isolate_port", "8080")
    assert is_safe

    # Invalid ports
    assert not rails.validate_action("isolate_port", "0")[0]
    assert not rails.validate_action("isolate_port", "70000")[0]
    assert not rails.validate_action("isolate_port", "ssh_port")[0]


def test_guardrails_validate_suricata_signature_format():
    rails = SafetyGuardrails()
    # Valid signature targets
    assert rails.validate_action("drop_suricata_signature", "2000001")[0]
    assert rails.validate_action("drop_suricata_signature", "ET_MALWARE_C2")[0]

    # Malicious or invalid characters
    assert not rails.validate_action("drop_suricata_signature", "signature; drop table")[0]
    assert not rails.validate_action("drop_suricata_signature", "sig`whoami`")[0]

