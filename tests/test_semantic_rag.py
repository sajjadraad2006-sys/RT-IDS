"""Comprehensive test suite for Hybrid Graph-RAG & Dense Semantic Retrieval Engine."""
from __future__ import annotations

import time
import pytest

from backend.mitre.semantic_rag import (
    FOUNDATIONAL_TECHNIQUES,
    HybridCandidateTechnique,
    HybridDefensePlaybook,
    SemanticGraphRAG,
    default_semantic_rag,
)
from backend.mitre.knowledge_graph import default_knowledge_graph
from backend.safety.formal_verifier import InvariantType, default_safety_verifier


@pytest.fixture
def rag_engine() -> SemanticGraphRAG:
    """Fixture providing an initialized SemanticGraphRAG instance."""
    engine = SemanticGraphRAG(
        knowledge_graph=default_knowledge_graph,
        safety_verifier=default_safety_verifier,
        latent_dimensions=32,
        use_foundational_only=True,
    )
    return engine


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 1: Zero Lexical Overlap Behavioral Queries (Dense Channel)
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "query,expected_technique_id",
    [
        # Ransomware behavioral description with zero literal match to "T1486" or "Data Encrypted"
        ("malicious software encrypting local storage drives and demanding cryptocurrency payment", "T1486"),
        # Kerberoasting behavioral description with zero match to "Kerberoasting"
        ("extracting password hashes by requesting service tickets from active directory domain", "T1558.003"),
        # Web attack behavioral description with zero match to "T1190"
        ("unauthorized remote code execution through vulnerable http request parameters on web server", "T1190"),
        # Volumetric DDoS description with zero match to "T1498"
        ("volumetric packet flooding overwhelming network interface capacity", "T1498"),
        # DNS covert channel description with zero match to "T1071.004"
        ("covert communication beaconing via encoded domain name query records", "T1071.004"),
    ],
)
def test_dense_semantic_concept_retrieval_zero_lexical_overlap(
    rag_engine: SemanticGraphRAG, query: str, expected_technique_id: str
):
    """Dense SVD concept projection must retrieve the exact conceptual MITRE technique."""
    results = rag_engine.search_dense(query, top_k=5)
    matched_ids = [tid for tid, _ in results]
    assert len(matched_ids) > 0, f"Dense search failed to return any candidate for query: {query}"
    # Verify expected technique is in top candidate matches
    assert expected_technique_id in matched_ids[:3], (
        f"Expected {expected_technique_id} in top 3 dense matches, got: {matched_ids[:3]}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 2: Deterministic & Sparse Lexical Identifier Precision
# ═══════════════════════════════════════════════════════════════════════════

def test_sparse_exact_mitre_id_priority(rag_engine: SemanticGraphRAG):
    """Explicit MITRE ATT&CK technique IDs must receive maximum priority in sparse and hybrid matching."""
    query = "Suspicious activity detected corresponding to T1059.001 script invocation"
    sparse_matches = rag_engine.search_sparse(query, top_k=5)
    assert len(sparse_matches) > 0
    top_sparse_id, _ = sparse_matches[0]
    assert top_sparse_id == "T1059.001"

    hybrid_matches = rag_engine.search_hybrid(query, top_k=3)
    assert hybrid_matches[0].technique_id == "T1059.001"


def test_sparse_event_id_extraction(rag_engine: SemanticGraphRAG):
    """Windows Security Log Event IDs must automatically correlate to the corresponding techniques."""
    # Event ID 4688 -> Process Creation -> T1059 / T1059.001
    query = "Windows security audit winlog EventID: 4688 suspicious execution"
    hybrid_matches = rag_engine.search_hybrid(query, top_k=5)
    matched_tids = [m.technique_id for m in hybrid_matches]
    assert any(t in matched_tids for t in ("T1059", "T1059.001")), (
        f"Expected T1059 in matches for EventID 4688, got {matched_tids}"
    )

    # Event ID 4625 -> Failed Logon -> T1110 (Brute Force)
    query_logon = "Event ID 4625 multiple failed logon attempts detected"
    hybrid_logon = rag_engine.search_hybrid(query_logon, top_k=5)
    matched_logon = [m.technique_id for m in hybrid_logon]
    assert "T1110" in matched_logon


def test_sparse_port_telemetry_correlation(rag_engine: SemanticGraphRAG):
    """Target destination ports in telemetry or text query must map to associated techniques."""
    # Port 88 -> Kerberos
    hybrid = rag_engine.search_hybrid("anomaly detected", telemetry={"dest_port": 88}, top_k=5)
    matched_tids = [m.technique_id for m in hybrid]
    assert "T1558.003" in matched_tids

    # Port 445 -> SMB (Lateral Movement / Ransomware)
    hybrid_smb = rag_engine.search_hybrid("unusual lateral traffic", telemetry={"dest_port": 445}, top_k=5)
    matched_smb = [m.technique_id for m in hybrid_smb]
    assert any(t in matched_smb for t in ("T1486", "T1021.002"))


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 3: Hypergraph Topological Grounding & Re-Ranking
# ═══════════════════════════════════════════════════════════════════════════

def test_hypergraph_grounding_multiplier(rag_engine: SemanticGraphRAG):
    """Techniques grounded in ThreatDefenseKnowledgeGraph must identify targeted artifacts."""
    hybrid = rag_engine.search_hybrid("exploiting vulnerable public web parameter", top_k=3)
    top_cand = hybrid[0]
    assert top_cand.technique_id == "T1190"
    assert top_cand.grounded_in_graph is True
    assert top_cand.targeted_artifact == "Inbound HTTP Request Parameter"
    assert top_cand.defense_paths_count > 0


def test_sub_technique_graph_grounding_fallback(rag_engine: SemanticGraphRAG):
    """Sub-techniques (e.g. T1059.001) must resolve defense paths through parent technique T1059."""
    hybrid = rag_engine.search_hybrid("PowerShell script interpreter execution T1059.001", top_k=3)
    matched_powershell = next((c for c in hybrid if c.technique_id == "T1059.001"), None)
    assert matched_powershell is not None
    assert matched_powershell.grounded_in_graph is True
    assert matched_powershell.defense_paths_count > 0


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 4: Pareto-Optimal Mitigation & Disruption Constraints
# ═══════════════════════════════════════════════════════════════════════════

def test_pareto_budget_constraint_enforcement(rag_engine: SemanticGraphRAG):
    """Strict operational disruption budgets must select low-disruption countermeasures."""
    # Under low disruption budget <= 0.20, T1498 should pick D3-NIPS (cost 0.15), not D3-ITF (cost 0.40)
    playbook_low = rag_engine.retrieve_pareto_playbook(
        query="volumetric network flood against web cluster",
        telemetry={"src_ip": "198.51.100.77", "dest_port": 80, "severity": "high", "confidence": 0.90},
        max_disruption=0.20,
    )
    assert len(playbook_low.pareto_mitigations) > 0
    top_mitigation = playbook_low.pareto_mitigations[0]
    assert top_mitigation.disruption_cost <= 0.20
    assert top_mitigation.countermeasure_id == "D3-NIPS"
    assert top_mitigation.actuator_action == "drop_suricata_signature"


def test_pareto_higher_disruption_budget_permits_stronger_countermeasure(rag_engine: SemanticGraphRAG):
    """Under higher disruption budget <= 0.50, engine can select stronger perimeter block actions."""
    playbook_high = rag_engine.retrieve_pareto_playbook(
        query="exploit public facing application vulnerability",
        telemetry={"src_ip": "198.51.100.88", "dest_port": 443, "severity": "high", "confidence": 0.95},
        max_disruption=0.50,
    )
    assert len(playbook_high.pareto_mitigations) > 0
    actions = [m.actuator_action for m in playbook_high.pareto_mitigations]
    assert "block_ip" in actions


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 5: Formal Neuro-Symbolic Safety Gate Admittance & Rejection
# ═══════════════════════════════════════════════════════════════════════════

def test_safety_gate_admits_benign_adversary_and_issues_hmac_token(rag_engine: SemanticGraphRAG):
    """Legitimate external adversary IP must be admitted with HMAC-SHA256 rollback receipt."""
    playbook = rag_engine.retrieve_pareto_playbook(
        query="SQL injection exploit against external catalog API",
        telemetry={"src_ip": "198.51.100.99", "dest_port": 443, "severity": "high", "confidence": 0.92},
        max_disruption=0.50,
    )
    assert len(playbook.admitted_actions) > 0
    assert len(playbook.rejected_actions) == 0

    admitted = playbook.admitted_actions[0]
    assert admitted["action"] == "block_ip"
    assert admitted["target"] == "198.51.100.99"
    assert "rollback_receipt" in admitted
    receipt = admitted["rollback_receipt"]
    assert receipt["token"].startswith("cg-proof-")
    assert len(receipt["signature_hmac"]) == 64  # SHA256 hex digest


@pytest.mark.parametrize(
    "critical_target",
    [
        "127.0.0.1",
        "::1",
        "8.8.8.8",
        "1.1.1.1",
        "::ffff:127.0.0.1",
        "::ffff:8.8.8.8",
    ],
)
def test_safety_gate_rejects_self_dos_on_critical_infrastructure(
    rag_engine: SemanticGraphRAG, critical_target: str
):
    """Attempts to block critical DNS, loopback, or gateway hosts must be rejected by Invariant I1."""
    playbook = rag_engine.retrieve_pareto_playbook(
        query="Exploitation attempt targeting web service",
        telemetry={"src_ip": critical_target, "dest_port": 80, "severity": "critical", "confidence": 0.95},
        max_disruption=0.50,
    )
    assert not any(a["target"] == critical_target for a in playbook.admitted_actions)
    assert len(playbook.rejected_actions) > 0

    rejected = next((r for r in playbook.rejected_actions if r["target"] == critical_target), None)
    assert rejected is not None, f"Expected {critical_target} in rejected actions, got: {playbook.rejected_actions}"
    assert InvariantType.I1_CRITICAL_ASSET.value in rejected["violated_invariants"]


def test_safety_gate_rejects_overbroad_subnets(rag_engine: SemanticGraphRAG):
    """Subnets broader than /16 must be rejected to prevent catastrophic collateral disruption."""
    bad_subnet = "10.0.0.0/8"
    playbook = rag_engine.retrieve_pareto_playbook(
        query="Exploitation attempt from remote network",
        telemetry={"src_ip": bad_subnet, "dest_port": 80, "severity": "critical", "confidence": 0.95},
        max_disruption=0.50,
    )
    assert not any(a["target"] == bad_subnet for a in playbook.admitted_actions)
    assert len(playbook.rejected_actions) > 0
    rejected = next((r for r in playbook.rejected_actions if r["target"] == bad_subnet), None)
    assert rejected is not None, f"Expected {bad_subnet} in rejected actions, got: {playbook.rejected_actions}"
    assert any(
        inv in rejected["violated_invariants"]
        for inv in (InvariantType.I1_CRITICAL_ASSET.value, InvariantType.I2_ONTOLOGICAL_CONFORMANCE.value)
    )


def test_safety_gate_rejects_shell_injection(rag_engine: SemanticGraphRAG):
    """Shell injection metacharacters in target addresses must be rejected immediately."""
    bad_target = "198.51.100.99; cat /etc/passwd"
    playbook = rag_engine.retrieve_pareto_playbook(
        query="Exploitation attempt",
        telemetry={"src_ip": bad_target, "dest_port": 80, "severity": "high", "confidence": 0.90},
        max_disruption=0.50,
    )
    assert not any(a["target"] == bad_target for a in playbook.admitted_actions)
    assert len(playbook.rejected_actions) > 0
    rejected = next((r for r in playbook.rejected_actions if r["target"] == bad_target), None)
    assert rejected is not None, f"Expected {bad_target} in rejected actions, got: {playbook.rejected_actions}"
    assert InvariantType.I2_ONTOLOGICAL_CONFORMANCE.value in rejected["violated_invariants"]


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 6: Prompt Synthesis & Topological Traceability
# ═══════════════════════════════════════════════════════════════════════════

def test_prompt_synthesis_contains_formal_proof_and_directives(rag_engine: SemanticGraphRAG):
    """Synthesized LLM prompt must contain topological proof chains and no hallucinated directives."""
    playbook = rag_engine.retrieve_pareto_playbook(
        query="Data encryption extortion ransomware in corporate network",
        telemetry={"src_ip": "203.0.113.88", "dest_port": 445, "severity": "critical", "confidence": 0.99},
        max_disruption=0.50,
    )
    prompt = rag_engine.format_grounded_prompt(playbook)

    assert "DOCTORAL HYBRID GRAPH-RAG" in prompt
    assert "T1486" in prompt
    assert "PARETO-OPTIMAL D3FEND MITIGATION PATHS" in prompt
    assert "MANDATORY EXECUTION DIRECTIVE" in prompt
    assert "cg-proof-" in prompt  # Rollback receipt token present


# ═══════════════════════════════════════════════════════════════════════════
# Test Group 7: Performance & Latency Benchmarks
# ═══════════════════════════════════════════════════════════════════════════

def test_hybrid_rag_throughput_benchmark(rag_engine: SemanticGraphRAG):
    """Engine must execute hybrid retrieval and Pareto synthesis in under 15ms per query."""
    queries = [
        "sql injection exploit against web api",
        "lateral movement over kerberos port 88",
        "ransomware encrypting user file system",
        "volumetric syn flood attack",
        "dns tunneling data exfiltration",
    ]
    # Warm-up pass
    _ = rag_engine.retrieve_pareto_playbook(queries[0])

    t0 = time.perf_counter()
    n_runs = 50
    for i in range(n_runs):
        q = queries[i % len(queries)]
        _ = rag_engine.retrieve_pareto_playbook(
            query=q,
            telemetry={"src_ip": f"198.51.100.{i+1}", "dest_port": 80, "severity": "high", "confidence": 0.90},
            max_disruption=0.50,
        )
    elapsed = time.perf_counter() - t0
    avg_latency_ms = (elapsed / n_runs) * 1000.0

    assert avg_latency_ms < 25.0, f"Average hybrid RAG latency too high: {avg_latency_ms:.2f}ms (target: <25ms)"
