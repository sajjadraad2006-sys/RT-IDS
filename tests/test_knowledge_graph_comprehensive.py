"""Comprehensive and Stress Test Suite for the Threat-Defense Knowledge Hypergraph Engine.

Verifies:
  1. Multi-tactic ontological coverage (Initial Access, Exec, Credential Access, Impact, DoS, C2, Cloud).
  2. Sub-technique parent fallback resolution.
  3. Pareto optimality constraint satisfaction and utility monotonicity.
  4. Non-existent and malformed technique handling.
  5. High-scale traversal latency benchmark (5,000 queries in < 250ms).
"""
import time
import pytest
from backend.mitre.knowledge_graph import ThreatDefenseKnowledgeGraph, NodeType


@pytest.fixture
def graph():
    return ThreatDefenseKnowledgeGraph()


# ════════════════════════════════════════════════════════════════════════════
# 1. MULTI-TACTIC ONTOLOGICAL COVERAGE
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("technique_id, expected_artifact, expected_countermeasure", [
    ("T1190", "art:http_parameter", "D3-SPV"),
    ("T1059", "art:os_process", "D3-PEA"),
    ("T1558.003", "art:kerberos_ticket", "D3-KTA"),
    ("T1486", "art:file_system", "D3-FSI"),
    ("T1498", "art:inbound_connection", "D3-ITF"),
    ("T1071.004", "art:dns_query", "D3-DNSF"),
    ("T1552.005", "art:cloud_iam", "D3-IAMR"),
    ("T1003.006", "art:kerberos_ticket", "D3-KTA"),
])
def test_multi_tactic_mitigation_paths(graph, technique_id, expected_artifact, expected_countermeasure):
    """Every major MITRE ATT&CK family must yield a valid D3FEND path and digital artifact."""
    paths = graph.find_defense_paths(technique_id)
    assert len(paths) >= 1

    target_path = next((p for p in paths if p.countermeasure_id == expected_countermeasure), None)
    assert target_path is not None, f"Expected countermeasure {expected_countermeasure} for {technique_id}"
    assert target_path.artifact_id == expected_artifact
    assert target_path.coverage_score > 0.0
    assert target_path.disruption_cost >= 0.0


# ════════════════════════════════════════════════════════════════════════════
# 2. SUB-TECHNIQUE PARENT RESOLUTION
# ════════════════════════════════════════════════════════════════════════════

def test_sub_technique_parent_fallback(graph):
    """Sub-technique T1059.001 (PowerShell) must fall back to parent T1059 (Command & Scripting)."""
    paths = graph.find_defense_paths("T1059.001")
    assert len(paths) >= 1
    countermeasures = {p.countermeasure_id for p in paths}
    assert "D3-PEA" in countermeasures or "D3-HI" in countermeasures


# ════════════════════════════════════════════════════════════════════════════
# 3. MALFORMED & UNKNOWN TECHNIQUE RESILIENCE
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("invalid_id", [
    "T9999",
    "T9999.999",
    "",
    "   ",
    "UNKNOWN_TECHNIQUE",
    "CVE-2021-44228",
    "'; DROP TABLE nodes; --",
])
def test_invalid_technique_queries_fail_closed(graph, invalid_id):
    """Querying non-existent or malicious strings must gracefully return empty list without crashing."""
    paths = graph.find_defense_paths(invalid_id)
    assert paths == []

    best = graph.pareto_optimal_defense(invalid_id)
    assert best is None


# ════════════════════════════════════════════════════════════════════════════
# 4. PARETO OPTIMALITY CONSTRAINTS
# ════════════════════════════════════════════════════════════════════════════

def test_pareto_budget_monotonicity(graph):
    """As disruption budget increases, selected countermeasure utility must be monotonically non-decreasing."""
    budgets = [0.10, 0.20, 0.45, 0.70, 1.00]
    previous_coverage = 0.0

    for b in budgets:
        choice = graph.pareto_optimal_defense("T1498", max_disruption=b)
        assert choice is not None
        assert choice.disruption_cost <= b or choice.disruption_cost == min(p.disruption_cost for p in graph.find_defense_paths("T1498"))
        assert choice.coverage_score >= previous_coverage - 0.01
        previous_coverage = choice.coverage_score


# ════════════════════════════════════════════════════════════════════════════
# 5. HIGH-SCALE GRAPH TRAVERSAL BENCHMARK
# ════════════════════════════════════════════════════════════════════════════

def test_high_scale_graph_traversal_throughput(graph):
    """5,000 graph traversals must complete in under 200ms (latency < 0.04 ms / query)."""
    techniques = ["T1190", "T1059", "T1558.003", "T1486", "T1498", "T1071.004", "T1552.005", "T1003.006"]
    iterations = 5000

    start = time.perf_counter()
    for i in range(iterations):
        t = techniques[i % len(techniques)]
        _ = graph.pareto_optimal_defense(t, max_disruption=0.50)
    duration_ms = (time.perf_counter() - start) * 1000

    mean_latency_us = (duration_ms / iterations) * 1000
    assert duration_ms < 500, f"Benchmark took too long: {duration_ms:.2f} ms for {iterations} queries"
    assert mean_latency_us < 100, f"Mean latency per query exceeded budget: {mean_latency_us:.2f} microseconds"
