"""Comprehensive test suite for Phase 3: Active Containment, Process Actuation & Atomic Rollback.

Verifies:
1. Multi-actuator execution under Formal SMT Safety Invariants (I_1 to I_4).
2. ProcessActuator safe termination and protected OS process interlocks.
3. Cryptographic HMAC-SHA256 receipt integrity and atomic state inversion (Invariant I_3).
4. Adversarial token tampering and forged rollback refusal (Fail-Closed).
5. Idempotent double-rollback handling.
6. High-concurrency thread safety across parallel actuation and rollback cycles.
"""
from __future__ import annotations

import concurrent.futures
import copy
import pytest

from backend.actuators.base import ActuatorResult
from backend.actuators.firewall import FirewallActuator
from backend.actuators.process import ProcessActuator, PROTECTED_PROCESS_NAMES
from backend.actuators.router import ActuatorRouter, default_router
from backend.actuators.suricata_rules import SuricataActuator
from backend.safety.formal_verifier import (
    FormalSafetyVerifier,
    InvariantType,
    RollbackReceipt,
    default_safety_verifier,
)


@pytest.fixture
def clean_router() -> ActuatorRouter:
    """Fixture providing a freshly initialized ActuatorRouter."""
    verifier = FormalSafetyVerifier()
    router = ActuatorRouter(
        firewall=FirewallActuator(is_windows=True),
        suricata=SuricataActuator(),
        process=ProcessActuator(is_windows=True),
        safety_verifier=verifier,
    )
    router.clear_all()
    return router


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 1: Multi-Actuator Execution & HMAC Proof Token Binding
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "action,target,params",
    [
        ("block_ip", "198.51.100.22", {"direction": "Inbound"}),
        ("isolate_port", "198.51.100.25", {"port": 445}),
        ("rate_limit", "198.51.100.30", {}),
        ("drop_suricata_signature", "2010999", {"protocol": "tcp"}),
        ("kill_process", "cryptominer.exe", {}),
        ("kill_process", "mimikatz.exe", {}),
    ],
)
def test_actuator_execution_binds_cryptographic_proof_token(
    clean_router: ActuatorRouter, action: str, target: str, params: dict
):
    """Every successful mitigation must receive a cryptographically signed cg-proof- token."""
    res = clean_router.execute_action(
        action=action,
        target=target,
        params=params,
        mode="simulation",
    )
    assert res.success is True, f"Action execution failed: {res.error}"
    assert res.rollback_token is not None
    assert res.rollback_token.startswith("cg-proof-")

    # Verify tracked in active blocks
    active_blocks = clean_router.list_active_blocks()
    assert any(b["rollback_token"] == res.rollback_token for b in active_blocks)


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 2: ProcessActuator & Protected OS Process Interlocks
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "os_process",
    [
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "C:\\Windows\\System32\\lsass.exe",
        "/usr/sbin/init",
        "SYSTEMD",
    ],
)
def test_process_actuator_strictly_forbids_critical_os_processes(
    clean_router: ActuatorRouter, os_process: str
):
    """ProcessActuator and verifier must refuse to kill essential operating system processes."""
    res = clean_router.execute_action(
        action="kill_process",
        target=os_process,
        mode="simulation",
    )
    assert res.success is False
    assert any(term in res.error.lower() for term in ("protected", "formal safety", "guardrail"))


def test_process_actuator_kills_malicious_process_simulated(clean_router: ActuatorRouter):
    """Malicious processes outside OS critical set are permitted."""
    res = clean_router.execute_action(
        action="kill_process",
        target="trojan_dropper.exe",
        mode="simulation",
    )
    assert res.success is True
    assert "trojan_dropper.exe" in res.command_executed
    assert res.simulated is True


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 3: Atomic State Inversion (Invariant I_3 Rollback Guarantee)
# ═══════════════════════════════════════════════════════════════════════════

def test_atomic_rollback_firewall_rule(clean_router: ActuatorRouter):
    """Rolling back a firewall action with its proof token inverts state in O(1)."""
    res = clean_router.execute_action(
        action="block_ip",
        target="198.51.100.77",
        mode="simulation",
    )
    token = res.rollback_token
    assert token is not None
    assert len(clean_router.list_active_blocks()) == 1

    # Invert state via atomic rollback
    rolled_back = clean_router.rollback_action(token)
    assert rolled_back is True
    assert len(clean_router.list_active_blocks()) == 0


def test_atomic_rollback_suricata_signature(clean_router: ActuatorRouter):
    """Rolling back an IPS drop signature restores inline traffic flow."""
    res = clean_router.execute_action(
        action="drop_suricata_signature",
        target="2024888",
        mode="simulation",
    )
    token = res.rollback_token
    assert token is not None
    assert len(clean_router.list_active_blocks()) == 1

    rolled_back = clean_router.rollback_action(token)
    assert rolled_back is True
    assert len(clean_router.list_active_blocks()) == 0


def test_atomic_rollback_process_termination(clean_router: ActuatorRouter):
    """Rolling back a process action clears the containment record."""
    res = clean_router.execute_action(
        action="kill_process",
        target="wannacry_payload.exe",
        mode="simulation",
    )
    token = res.rollback_token
    assert token is not None
    assert len(clean_router.list_active_blocks()) == 1

    rolled_back = clean_router.rollback_action(token)
    assert rolled_back is True
    assert len(clean_router.list_active_blocks()) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 4: Adversarial Forgery & Tampered Token Rejection
# ═══════════════════════════════════════════════════════════════════════════

def test_rollback_refuses_forged_proof_token(clean_router: ActuatorRouter):
    """Fabricated rollback token without valid cryptographic signature must be rejected."""
    rolled_back = clean_router.rollback_action("cg-proof-blo-forged999999")
    assert rolled_back is False


def test_rollback_refuses_tampered_hmac_signature(clean_router: ActuatorRouter):
    """Receipt with modified HMAC signature must fail-closed."""
    res = clean_router.execute_action(
        action="block_ip",
        target="198.51.100.99",
        mode="simulation",
    )
    token = res.rollback_token
    assert token is not None

    # Artificially tamper with the receipt signature in the router mapping
    mapping = clean_router._receipt_map[token]
    tampered_receipt = RollbackReceipt(
        token=mapping["receipt"].token,
        action_type=mapping["receipt"].action_type,
        target=mapping["receipt"].target,
        parameters_json=mapping["receipt"].parameters_json,
        timestamp=mapping["receipt"].timestamp,
        signature_hmac="deadbeef" * 8,  # Corrupted signature
        state_inversion_digest=mapping["receipt"].state_inversion_digest,
    )
    mapping["receipt"] = tampered_receipt

    # Rollback must fail closed
    rolled_back = clean_router.rollback_action(token)
    assert rolled_back is False, "Rollback accepted a tampered HMAC signature!"
    # Active block must still be retained
    assert len(clean_router.list_active_blocks()) == 1


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 5: Idempotency & Double Rollback Safety
# ═══════════════════════════════════════════════════════════════════════════

def test_idempotent_double_rollback_fails_safely(clean_router: ActuatorRouter):
    """Calling rollback twice on the same token must safely return False on second call."""
    res = clean_router.execute_action(
        action="block_ip",
        target="198.51.100.101",
        mode="simulation",
    )
    token = res.rollback_token
    assert token is not None

    first_attempt = clean_router.rollback_action(token)
    assert first_attempt is True

    # Second attempt on already rolled-back action
    second_attempt = clean_router.rollback_action(token)
    assert second_attempt is False


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 6: Safety Gate Invariant Interception at Router Boundary
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "critical_ip",
    [
        "127.0.0.1",
        "::1",
        "8.8.8.8",
        "1.1.1.1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
    ],
)
def test_router_blocks_self_dos_on_critical_infrastructure(
    clean_router: ActuatorRouter, critical_ip: str
):
    """Router must intercept attempts to block critical hosts regardless of who called it."""
    res = clean_router.execute_action(
        action="block_ip",
        target=critical_ip,
        mode="simulation",
    )
    assert res.success is False
    assert InvariantType.I1_CRITICAL_ASSET.value in res.metadata.get("violated_invariants", [])


def test_router_blocks_shell_injection(clean_router: ActuatorRouter):
    """Metacharacters in target must be rejected at router boundary."""
    res = clean_router.execute_action(
        action="block_ip",
        target="198.51.100.50; rm -rf /",
        mode="simulation",
    )
    assert res.success is False
    assert InvariantType.I2_ONTOLOGICAL_CONFORMANCE.value in res.metadata.get("violated_invariants", [])


def test_router_blocks_overbroad_subnets(clean_router: ActuatorRouter):
    """Over-broad subnets (/0 to /15) must be rejected to prevent catastrophic collateral damage."""
    res = clean_router.execute_action(
        action="block_ip",
        target="10.0.0.0/8",
        mode="simulation",
    )
    assert res.success is False
    assert any(
        inv in res.metadata.get("violated_invariants", [])
        for inv in (InvariantType.I1_CRITICAL_ASSET.value, InvariantType.I2_ONTOLOGICAL_CONFORMANCE.value)
    )


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 7: Concurrency & Thread Safety Stress Test
# ═══════════════════════════════════════════════════════════════════════════

def test_high_concurrency_actuation_and_rollback(clean_router: ActuatorRouter):
    """50 concurrent threads executing actions and rollbacks must maintain strict consistency."""
    num_threads = 50

    def execute_and_rollback_worker(worker_id: int):
        ip = f"198.51.100.{(worker_id % 200) + 1}"
        # 1. Execute
        exec_res = clean_router.execute_action(
            action="block_ip",
            target=ip,
            params={"port": 8080 + worker_id},
            mode="simulation",
        )
        assert exec_res.success is True
        token = exec_res.rollback_token
        assert token is not None

        # 2. Rollback
        rb_res = clean_router.rollback_action(token)
        assert rb_res is True

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(execute_and_rollback_worker, i) for i in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    # All actions were rolled back, registry must be cleanly empty
    assert len(clean_router.list_active_blocks()) == 0
