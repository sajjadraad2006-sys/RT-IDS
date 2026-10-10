"""Unit tests for Threat-Defense Knowledge Hypergraph Engine."""
import pytest
from backend.mitre.knowledge_graph import ThreatDefenseKnowledgeGraph, NodeType


@pytest.fixture
def graph():
    return ThreatDefenseKnowledgeGraph()


def test_knowledge_graph_initialization(graph):
    """Knowledge graph must contain verified ATT&CK, Artifact, and D3FEND nodes."""
    assert len(graph.nodes) > 15
    assert len(graph.edges) > 15

    # Check node types
    types = {n.type for n in graph.nodes.values()}
    assert NodeType.TECHNIQUE in types
    assert NodeType.ARTIFACT in types
    assert NodeType.COUNTERMEASURE in types


def test_multi_hop_defense_path_t1190(graph):
    """T1190 (Exploit Public-Facing App) must map to D3-SPV via Inbound HTTP Parameter."""
    paths = graph.find_defense_paths("T1190")
    assert len(paths) >= 1

    spv_path = next((p for p in paths if p.countermeasure_id == "D3-SPV"), None)
    assert spv_path is not None
    assert spv_path.artifact_id == "art:http_parameter"
    assert spv_path.actuator_action == "block_ip"
    assert "D3FEND countermeasure D3-SPV" in spv_path.explanation_proof


def test_pareto_optimal_defense_tradeoff(graph):
    """Pareto optimization must respect the operational disruption constraint."""
    # Under low disruption budget (max 0.20), should select NIPS drop (cost 0.15)
    best_low = graph.pareto_optimal_defense("T1498", max_disruption=0.20)
    assert best_low is not None
    assert best_low.actuator_action == "drop_suricata_signature"
    assert best_low.disruption_cost <= 0.20

    # Under high disruption budget (max 0.90), can select block_ip (cost 0.40)
    best_high = graph.pareto_optimal_defense("T1498", max_disruption=0.90)
    assert best_high is not None
    assert best_high.actuator_action in {"block_ip", "drop_suricata_signature"}
