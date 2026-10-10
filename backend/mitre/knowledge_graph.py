"""Threat-Defense Knowledge Hypergraph Engine (H-ACD Core).

Formalizes cybersecurity threat and defense relationships as a directed multi-relational
heterogeneous hypergraph:
  G = (V_attack union V_artifact union V_d3fend union V_datasource, E)

Provides:
  1. Multi-hop mitigation path discovery: Technique -> Digital Artifact -> D3FEND Countermeasure.
  2. Pareto-optimal countermeasure calculation balancing attack disruption vs. operational business impact.
  3. Formal topological explanation generation for neuro-symbolic reasoning.
"""
from __future__ import annotations

import dataclasses
import enum
from typing import Any, Dict, List, Optional, Set, Tuple


class NodeType(str, enum.Enum):
    TECHNIQUE = "TECHNIQUE"              # MITRE ATT&CK (e.g. T1190, T1059)
    TACTIC = "TACTIC"                    # MITRE Tactic (e.g. Initial Access, Persistence)
    ARTIFACT = "DIGITAL_ARTIFACT"        # Digital Artifact (e.g. Process, Inbound Connection, Kerberos Ticket)
    COUNTERMEASURE = "COUNTERMEASURE"    # MITRE D3FEND (e.g. D3-SPV, D3-ITF, D3-NIPS)
    DATA_SOURCE = "DATA_SOURCE"          # Telemetry Source (e.g. Windows EVTX 4688, Suricata EVE)


class EdgeType(str, enum.Enum):
    TARGETS_ARTIFACT = "TARGETS_ARTIFACT"
    DEFENDS_ARTIFACT = "DEFENDS_ARTIFACT"
    COUNTERACTS = "COUNTERACTS"
    OBSERVED_IN = "OBSERVED_IN"
    PART_OF_TACTIC = "PART_OF_TACTIC"


@dataclasses.dataclass(frozen=True)
class GraphNode:
    id: str
    type: NodeType
    label: str
    properties: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class GraphEdge:
    source_id: str
    target_id: str
    type: EdgeType
    weight: float = 1.0
    evidence: str = ""


@dataclasses.dataclass
class DefensePath:
    technique_id: str
    technique_name: str
    artifact_id: str
    artifact_name: str
    countermeasure_id: str
    countermeasure_name: str
    actuator_action: str
    disruption_cost: float
    coverage_score: float
    explanation_proof: str


class ThreatDefenseKnowledgeGraph:
    """Multi-relational Knowledge Graph for Threat-Informed Autonomous Defense."""

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._adj_out: Dict[str, List[GraphEdge]] = {}
        self._adj_in: Dict[str, List[GraphEdge]] = {}
        self._build_default_ontology()

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node
        if node.id not in self._adj_out:
            self._adj_out[node.id] = []
        if node.id not in self._adj_in:
            self._adj_in[node.id] = []

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        self._adj_out.setdefault(edge.source_id, []).append(edge)
        self._adj_in.setdefault(edge.target_id, []).append(edge)

    def _build_default_ontology(self) -> None:
        """Populate foundational ATT&CK, Digital Artifact, and D3FEND mappings."""
        # 1. Digital Artifacts
        artifacts = [
            ("art:inbound_connection", "Inbound Network Connection", {"protocol": "TCP/UDP", "layer": "L4"}),
            ("art:http_parameter", "Inbound HTTP Request Parameter", {"protocol": "HTTP", "layer": "L7"}),
            ("art:os_process", "Operating System Process Execution", {"os": "cross-platform"}),
            ("art:kerberos_ticket", "Active Directory Kerberos TGS/TGT Ticket", {"protocol": "Kerberos"}),
            ("art:file_system", "Local File System / Storage Volume", {"storage": "NTFS/ext4"}),
            ("art:dns_query", "Outbound DNS Query Name", {"protocol": "DNS"}),
            ("art:cloud_iam", "Cloud IAM Role & Metadata API", {"cloud": "multi-cloud"}),
        ]
        for aid, label, props in artifacts:
            self.add_node(GraphNode(id=aid, type=NodeType.ARTIFACT, label=label, properties=props))

        # 2. Key ATT&CK Techniques & their targeted artifacts
        attack_mappings = [
            ("T1190", "Exploit Public-Facing Application", "art:http_parameter"),
            ("T1059", "Command and Scripting Interpreter", "art:os_process"),
            ("T1558.003", "Kerberoasting", "art:kerberos_ticket"),
            ("T1486", "Data Encrypted for Impact (Ransomware)", "art:file_system"),
            ("T1498", "Network Denial of Service", "art:inbound_connection"),
            ("T1071.004", "Application Layer Protocol: DNS Tunneling", "art:dns_query"),
            ("T1053.005", "Scheduled Task", "art:os_process"),
            ("T1078", "Valid Accounts", "art:kerberos_ticket"),
            ("T1552.005", "Cloud Instance Metadata API", "art:cloud_iam"),
            ("T1003.006", "DCSync", "art:kerberos_ticket"),
        ]
        for tid, tname, target_art in attack_mappings:
            self.add_node(GraphNode(id=tid, type=NodeType.TECHNIQUE, label=tname))
            self.add_edge(GraphEdge(source_id=tid, target_id=target_art, type=EdgeType.TARGETS_ARTIFACT, weight=1.0))

        # 3. D3FEND Countermeasures & the artifacts they defend
        d3fend_mappings = [
            ("D3-SPV", "Software Parameter Validation", "art:http_parameter", "block_ip", 0.40, 0.95),
            ("D3-ITF", "Inbound Traffic Filtering", "art:inbound_connection", "block_ip", 0.40, 0.98),
            ("D3-PEA", "Process Execution Analysis", "art:os_process", "kill_process", 0.65, 0.90),
            ("D3-HI", "Host Isolation", "art:os_process", "isolate_host", 0.95, 0.99),
            ("D3-KTA", "Kerberos Traffic Analysis", "art:kerberos_ticket", "rate_limit", 0.25, 0.88),
            ("D3-FSI", "File Storage Invalidation", "art:file_system", "isolate_host", 0.95, 0.96),
            ("D3-NIPS", "Network Intrusion Prevention Signature", "art:inbound_connection", "drop_suricata_signature", 0.15, 0.92),
            ("D3-DNSF", "DNS Query Filtering", "art:dns_query", "block_ip", 0.40, 0.94),
            ("D3-IAMR", "IAM Policy Revocation", "art:cloud_iam", "rate_limit", 0.30, 0.91),
        ]
        for did, dname, defended_art, action, cost, coverage in d3fend_mappings:
            self.add_node(GraphNode(
                id=did,
                type=NodeType.COUNTERMEASURE,
                label=dname,
                properties={"action": action, "cost": cost, "coverage": coverage},
            ))
            self.add_edge(GraphEdge(source_id=did, target_id=defended_art, type=EdgeType.DEFENDS_ARTIFACT, weight=1.0))
            # Direct semantic counteracts edge
            self.add_edge(GraphEdge(source_id=did, target_id=defended_art, type=EdgeType.COUNTERACTS, weight=coverage))

    def find_defense_paths(self, technique_id: str) -> List[DefensePath]:
        """Traverse G: Technique -> targets -> Artifact <- defends <- D3FEND Countermeasure."""
        clean_tid = technique_id.strip().upper()
        if clean_tid not in self.nodes:
            # Fallback to parent technique if sub-technique
            if "." in clean_tid:
                clean_tid = clean_tid.split(".")[0]
            if clean_tid not in self.nodes:
                return []

        tech_node = self.nodes[clean_tid]
        paths: List[DefensePath] = []

        # Find artifacts targeted by this technique
        for edge_t_to_a in self._adj_out.get(clean_tid, []):
            if edge_t_to_a.type != EdgeType.TARGETS_ARTIFACT:
                continue
            artifact_id = edge_t_to_a.target_id
            art_node = self.nodes.get(artifact_id)
            if not art_node:
                continue

            # Find D3FEND countermeasures defending this artifact
            for edge_d_to_a in self._adj_out.get(artifact_id, []) + self._adj_in.get(artifact_id, []):
                countermeasure_id = edge_d_to_a.source_id if edge_d_to_a.target_id == artifact_id else edge_d_to_a.target_id
                d_node = self.nodes.get(countermeasure_id)
                if not d_node or d_node.type != NodeType.COUNTERMEASURE:
                    continue

                action = d_node.properties.get("action", "observe")
                cost = d_node.properties.get("cost", 0.5)
                cov = d_node.properties.get("coverage", 0.8)

                proof = (
                    f"Proof: Adversary technique {clean_tid} ({tech_node.label}) targets digital artifact "
                    f"'{art_node.label}'. D3FEND countermeasure {d_node.id} ({d_node.label}) formally defends "
                    f"'{art_node.label}'. Concretely realized via actuator action '{action}'."
                )

                paths.append(DefensePath(
                    technique_id=clean_tid,
                    technique_name=tech_node.label,
                    artifact_id=artifact_id,
                    artifact_name=art_node.label,
                    countermeasure_id=d_node.id,
                    countermeasure_name=d_node.label,
                    actuator_action=action,
                    disruption_cost=cost,
                    coverage_score=cov,
                    explanation_proof=proof,
                ))

        # Sort by coverage descending, then disruption cost ascending
        paths.sort(key=lambda p: (-p.coverage_score, p.disruption_cost))
        return paths

    def pareto_optimal_defense(
        self,
        technique_id: str,
        max_disruption: float = 0.50,
        tradeoff_lambda: float = 0.5,
    ) -> Optional[DefensePath]:
        """Calculates Pareto-optimal mitigation maximizing (Coverage - lambda * Disruption)."""
        paths = self.find_defense_paths(technique_id)
        if not paths:
            return None

        # Filter by hard disruption limit
        candidates = [p for p in paths if p.disruption_cost <= max_disruption]
        if not candidates:
            # Fall back to minimal disruption path if all exceed max
            candidates = sorted(paths, key=lambda p: p.disruption_cost)

        # Objective function: Utility = Coverage - (lambda * Cost)
        best = max(candidates, key=lambda p: p.coverage_score - (tradeoff_lambda * p.disruption_cost))
        return best


# Global default knowledge graph instance
default_knowledge_graph = ThreatDefenseKnowledgeGraph()
