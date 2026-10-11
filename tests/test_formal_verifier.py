"""Automated test suite for the Formal Neuro-Symbolic Safety Gate.

Validates First-Order Logic invariants I_1 (Critical Assets), I_2 (Ontology),
I_3 (HMAC Rollback Receipts), and I_4 (Proportionality Constraints).
"""
import pytest
from backend.safety.formal_verifier import FormalSafetyVerifier, InvariantType


@pytest.fixture
def verifier():
    return FormalSafetyVerifier(
        system_secret_key=b"doctoral_research_secret_key_32b!",
        proportionality_alpha=1.25,
    )


def test_i1_critical_asset_blocks_self_dos(verifier):
    """Invariant I_1 must strictly forbid targeting localhost or DNS root resolvers."""
    # Attempting to block 127.0.0.1
    res1 = verifier.verify_and_sign(
        action="block_ip",
        target="127.0.0.1",
        severity="critical",
        confidence=1.0,
    )
    assert not res1.admitted
    assert InvariantType.I1_CRITICAL_ASSET in res1.violated_invariants

    # Attempting to block Google DNS (8.8.8.8)
    res2 = verifier.verify_and_sign(
        action="block_ip",
        target="8.8.8.8",
        severity="critical",
        confidence=1.0,
    )
    assert not res2.admitted
    assert InvariantType.I1_CRITICAL_ASSET in res2.violated_invariants

    # Attempting to block Broadcast
    res3 = verifier.verify_and_sign(
        action="block_ip",
        target="255.255.255.255",
        severity="critical",
        confidence=1.0,
    )
    assert not res3.admitted
    assert InvariantType.I1_CRITICAL_ASSET in res3.violated_invariants


def test_i1_allows_legitimate_adversary_ip(verifier):
    """Invariant I_1 must admit external malicious IP targets."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target="198.51.100.99",
        severity="critical",
        confidence=0.98,
    )
    assert res.admitted
    assert len(res.violated_invariants) == 0
    assert res.rollback_receipt is not None


def test_i2_ontological_conformance_rejects_hallucinations(verifier):
    """Invariant I_2 must reject non-existent / arbitrary LLM hallucinated actions."""
    res = verifier.verify_and_sign(
        action="format_c_drive",
        target="198.51.100.99",
        severity="critical",
        confidence=1.0,
    )
    assert not res.admitted
    assert InvariantType.I2_ONTOLOGICAL_CONFORMANCE in res.violated_invariants


def test_i2_parameter_boundary_enforcement(verifier):
    """Invariant I_2 enforces physical boundary bounds (e.g. port range 1-65535)."""
    # Port out of physical range (70000)
    res_bad = verifier.verify_and_sign(
        action="drop_port",
        target="70000",
        severity="critical",
        confidence=1.0,
        parameters={"port": 70000},
    )
    assert not res_bad.admitted
    assert InvariantType.I2_ONTOLOGICAL_CONFORMANCE in res_bad.violated_invariants

    # Valid port (443)
    res_good = verifier.verify_and_sign(
        action="drop_port",
        target="443",
        severity="critical",
        confidence=1.0,
        parameters={"port": 443},
    )
    assert res_good.admitted


def test_i3_cryptographic_hmac_receipt_integrity(verifier):
    """Invariant I_3 receipts must be verifiable via the system secret key."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target="203.0.113.50",
        severity="high",
        confidence=0.95,
    )
    assert res.admitted
    receipt = res.rollback_receipt
    assert receipt is not None
    assert receipt.token.startswith("cg-proof-blo-")

    # Verify signature with correct key
    assert receipt.verify_signature(b"doctoral_research_secret_key_32b!")

    # Verify signature fails with wrong key
    assert not receipt.verify_signature(b"tampered_or_wrong_secret_key!")


def test_i4_proportionality_constraint(verifier):
    """Invariant I_4 forbids extreme containment (e.g. isolate_host) on low confidence signals."""
    # Disproportionate: isolate_host (disruption 0.95) on LOW severity with 0.50 confidence
    # Bound = 1.25 * 0.25 (low) * 0.50 = 0.156
    res_disproportionate = verifier.verify_and_sign(
        action="isolate_host",
        target="workstation-04",
        severity="low",
        confidence=0.50,
    )
    assert not res_disproportionate.admitted
    assert InvariantType.I4_PROPORTIONALITY in res_disproportionate.violated_invariants

    # Proportionate: isolate_host on CRITICAL severity with 0.98 confidence
    # Bound = 1.25 * 1.0 (crit) * 0.98 = 1.225 >= 0.95
    res_proportionate = verifier.verify_and_sign(
        action="isolate_host",
        target="compromised-server-01",
        severity="critical",
        confidence=0.98,
    )
    assert res_proportionate.admitted


def test_formal_smt_lib2_certificate_and_model_export(verifier):
    """Verify generation of SMT-LIB2 standard format certificates and SymPy formal models."""
    res = verifier.verify_and_sign(
        action="block_ip",
        target="198.51.100.77",
        severity="high",
        confidence=0.95,
    )
    assert res.admitted
    assert res.smt_lib2_certificate != ""
    assert "(set-logic QF_LRA)" in res.smt_lib2_certificate
    assert "(set-info :status sat)" in res.smt_lib2_certificate
    assert "(assert (<= disruption_cost proportionality_bound))" in res.smt_lib2_certificate
    assert res.formal_model is not None
    assert res.formal_model.get("I1_CriticalAssetPreservation") is True
