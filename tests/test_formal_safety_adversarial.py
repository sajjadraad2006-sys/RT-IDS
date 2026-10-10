"""Comprehensive Adversarial and Boundary Stress Tests for the Formal Neuro-Symbolic Safety Gate.

Exhaustively verifies resilience against:
  1. Indirect Prompt Injection & Shell Metacharacters in targets.
  2. Evasive & Obfuscated IP representations (IPv4-mapped IPv6, global /0 blackholes).
  3. Operating System Kernel process protection against path traversal.
  4. Cryptographic HMAC receipt tamper-resistance and replay integrity.
  5. Continuous boundary conditions on proportionality calculus.
"""
import pytest
from backend.safety.formal_verifier import FormalSafetyVerifier, InvariantType


@pytest.fixture
def verifier():
    return FormalSafetyVerifier(
        system_secret_key=b"phd_adversarial_testing_secret_key_32b!",
        proportionality_alpha=1.25,
    )


# ════════════════════════════════════════════════════════════════════════════
# 1. SHELL INJECTION & METACHARACTER FUZZING
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("malicious_target", [
    "192.168.1.50; rm -rf /",
    "192.168.1.50 & calc.exe",
    "192.168.1.50 | cat /etc/passwd",
    "192.168.1.50`id`",
    "192.168.1.50$(whoami)",
    "192.168.1.50 > /dev/null",
    "192.168.1.50 < input.txt",
    "192.168.1.50\nNew-NetFirewallRule",
    "192.168.1.50\r\nDROP",
    "192.168.1.50\x00admin",
])
def test_shell_metacharacters_rejected_immediately(verifier, malicious_target):
    """Any target bearing shell control characters must be rejected under I_1 or I_2."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target=malicious_target,
        severity="critical",
        confidence=1.0,
    )
    assert not res.admitted
    assert any(inv in res.violated_invariants for inv in (InvariantType.I1_CRITICAL_ASSET, InvariantType.I2_ONTOLOGICAL_CONFORMANCE))


# ════════════════════════════════════════════════════════════════════════════
# 2. EVASIVE & OBFUSCATED IP REPRESENTATIONS
# ════════════════════════════════════════════════════════════════════════════

def test_ipv4_mapped_ipv6_loopback_intercepted(verifier):
    """IPv4-mapped IPv6 representation of localhost (::ffff:127.0.0.1) must be intercepted."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target="::ffff:127.0.0.1",
        severity="critical",
        confidence=1.0,
    )
    assert not res.admitted
    assert InvariantType.I1_CRITICAL_ASSET in res.violated_invariants


def test_ipv4_mapped_ipv6_dns_root_intercepted(verifier):
    """IPv4-mapped IPv6 representation of Google DNS (::ffff:8.8.8.8) must be intercepted."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target="::ffff:8.8.8.8",
        severity="critical",
        confidence=1.0,
    )
    assert not res.admitted
    assert InvariantType.I1_CRITICAL_ASSET in res.violated_invariants


@pytest.mark.parametrize("broad_subnet", [
    "0.0.0.0/0",     # Global Internet Blackhole
    "::/0",          # IPv6 Global Internet Blackhole
    "10.0.0.0/8",    # Class A enterprise network
    "172.16.0.0/12", # Class B private network
    "192.168.0.0/15",# Over-broad private network (< /16)
])
def test_overbroad_subnets_prevent_mass_blackhole(verifier, broad_subnet):
    """Subnets broader than /16 must be rejected to prevent catastrophic mass blackholing."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target=broad_subnet,
        severity="critical",
        confidence=1.0,
    )
    assert not res.admitted
    assert InvariantType.I1_CRITICAL_ASSET in res.violated_invariants


def test_granular_adversary_subnet_permitted(verifier):
    """Granular adversary CIDRs (/24, /32) outside K_crit must be admitted."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target="198.51.100.0/24",
        severity="critical",
        confidence=0.95,
    )
    assert res.admitted
    assert len(res.violated_invariants) == 0


# ════════════════════════════════════════════════════════════════════════════
# 3. KERNEL PROCESS PROTECTION & PATH TRAVERSAL
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("critical_proc", [
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "C:\\Windows\\System32\\lsass.exe",
    "/usr/sbin/init",
    "kernel",
    "LSASS.EXE",
])
def test_critical_os_processes_cannot_be_killed(verifier, critical_proc):
    """Invariant I_1 must prevent killing critical operating system processes under all path formats."""
    res = verifier.verify_and_sign(
        action="kill_process",
        target=critical_proc,
        severity="critical",
        confidence=1.0,
    )
    assert not res.admitted
    assert InvariantType.I1_CRITICAL_ASSET in res.violated_invariants


def test_malicious_process_permitted(verifier):
    """Malicious user-space process (e.g. mimikatz.exe, xmrig) must be admitted for termination."""
    res = verifier.verify_and_sign(
        action="kill_process",
        target="mimikatz.exe",
        severity="critical",
        confidence=0.98,
    )
    assert res.admitted
    assert len(res.violated_invariants) == 0


# ════════════════════════════════════════════════════════════════════════════
# 4. CRYPTOGRAPHIC RECEIPT TAMPERING & REPLAY
# ════════════════════════════════════════════════════════════════════════════

def test_tampered_receipt_fails_hmac_verification(verifier):
    """Any modification of receipt fields must cause HMAC verification to fail."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target="203.0.113.10",
        severity="high",
        confidence=0.95,
    )
    receipt = res.rollback_receipt
    assert receipt is not None
    key = b"phd_adversarial_testing_secret_key_32b!"
    assert receipt.verify_signature(key)

    # 1. Tamper with target
    tampered_target = type(receipt)(
        token=receipt.token,
        action_type=receipt.action_type,
        target="203.0.113.99", # altered
        parameters_json=receipt.parameters_json,
        timestamp=receipt.timestamp,
        signature_hmac=receipt.signature_hmac,
        state_inversion_digest=receipt.state_inversion_digest,
    )
    assert not tampered_target.verify_signature(key)

    # 2. Tamper with token
    tampered_token = type(receipt)(
        token=receipt.token + "X",
        action_type=receipt.action_type,
        target=receipt.target,
        parameters_json=receipt.parameters_json,
        timestamp=receipt.timestamp,
        signature_hmac=receipt.signature_hmac,
        state_inversion_digest=receipt.state_inversion_digest,
    )
    assert not tampered_token.verify_signature(key)


# ════════════════════════════════════════════════════════════════════════════
# 5. PROPORTIONALITY CALCULUS CONTINUOUS BOUNDARY
# ════════════════════════════════════════════════════════════════════════════

def test_proportionality_gradient(verifier):
    """Disruption must adhere monotonically to severity and confidence tiers."""
    # Action: block_ip (disruption 0.40)
    # Severity info (0.10) * conf 1.0 * alpha 1.25 = bound 0.125 < 0.40 -> REJECT
    res_info = verifier.verify_and_sign("block_ip", "198.51.100.1", severity="info", confidence=1.0)
    assert not res_info.admitted
    assert InvariantType.I4_PROPORTIONALITY in res_info.violated_invariants

    # Severity low (0.25) * conf 1.0 * alpha 1.25 = bound 0.312 < 0.40 -> REJECT
    res_low = verifier.verify_and_sign("block_ip", "198.51.100.1", severity="low", confidence=1.0)
    assert not res_low.admitted
    assert InvariantType.I4_PROPORTIONALITY in res_low.violated_invariants

    # Severity medium (0.50) * conf 0.90 * alpha 1.25 = bound 0.562 >= 0.40 -> ADMIT
    res_med = verifier.verify_and_sign("block_ip", "198.51.100.1", severity="medium", confidence=0.90)
    assert res_med.admitted
    assert len(res_med.violated_invariants) == 0
