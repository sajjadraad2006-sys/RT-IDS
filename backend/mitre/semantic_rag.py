"""Hybrid Graph-RAG & Dense Semantic Retrieval Engine (H-ACD Core).

Implements Phase 2 of the Doctoral Active Defense Framework:
1. Dual-Channel Semantic Retrieval:
   - Channel A: Sparse Lexical / Deterministic Inverted Index (BM25, exact CVEs, ports, ATT&CK/D3FEND IDs).
   - Channel B: Dense Latent Concept Space (LSA / TruncatedSVD cosine projection over technique text).
2. Reciprocal Rank Fusion (RRF) & Hybrid Fusion:
   - Harmonizes lexical precision with semantic/behavioral generalization.
3. Ontological Hypergraph Grounding:
   - Leverages ThreatDefenseKnowledgeGraph to enforce technique -> digital artifact -> D3FEND countermeasure topology.
   - Rewards candidate techniques with verified multi-hop defensive paths.
4. Pareto-Optimal Mitigation & Autonomous Playbook Synthesis:
   - Computes Pareto frontier balancing threat coverage vs. operational disruption budget.
   - Pre-verifies candidate actions through FormalSafetyVerifier (Invariants I_1 through I_4).
   - Emits HMAC-SHA256 cryptographic rollback tokens for certified state inversion.
5. Zero-Hallucination Grounded Prompt Generation.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import math
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer

from ..config import DB_PATH
from .knowledge_graph import (
    DefensePath,
    ThreatDefenseKnowledgeGraph,
    default_knowledge_graph,
)
from ..safety.formal_verifier import (
    FormalSafetyVerifier,
    VerificationResult,
    default_safety_verifier,
)

logger = logging.getLogger("cyberguard.semantic_rag")

# ---------------------------------------------------------------------------
# Deterministic Regex Identifiers
# ---------------------------------------------------------------------------
_ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_D3FEND_ID_PATTERN = re.compile(r"\bD3-[A-Z0-9]+\b", re.IGNORECASE)
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_EVENT_ID_PATTERN = re.compile(r"(?:event\s*id|eventcode|winlog)\s*[:=]?\s*(\d{4,5})\b", re.IGNORECASE)
_PORT_PATTERN = re.compile(r"(?:port|dst_port|dest_port)\s*[:=]?\s*(\d{1,5})\b", re.IGNORECASE)

# Windows Event ID to ATT&CK Technique Mapping
WIN_EVENT_ID_MAP: Dict[str, List[str]] = {
    "4624": ["T1078"],
    "4625": ["T1110"],
    "4672": ["T1078"],
    "4688": ["T1059", "T1059.001"],
    "4697": ["T1543.003"],
    "7045": ["T1543.003"],
    "4698": ["T1053.005"],
    "4720": ["T1136.001"],
    "4728": ["T1098"],
    "4738": ["T1098"],
    "4768": ["T1558"],
    "4769": ["T1558.003"],
    "4776": ["T1110"],
}

# Well-Known Port to ATT&CK Mapping
WELL_KNOWN_PORTS_MAP: Dict[str, List[str]] = {
    "21": ["T1071.002"],
    "22": ["T1021.004", "T1110"],
    "53": ["T1071.004"],
    "80": ["T1190"],
    "88": ["T1558.003"],
    "135": ["T1021.003"],
    "443": ["T1190", "T1071.001"],
    "445": ["T1021.002", "T1486"],
    "1433": ["T1190", "T1110"],
    "3306": ["T1190", "T1110"],
    "3389": ["T1021.001", "T1110"],
    "5985": ["T1021.006"],
}

# Foundational Default Techniques (ensures robust zero-cold-start performance)
FOUNDATIONAL_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
        "platforms": ["Linux", "Windows", "Network"],
        "description": "Adversaries may exploit a weakness in an Internet-facing computer or program using software vulnerabilities, SQL injection, buffer overflows, or remote code execution parameters.",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "platforms": ["Linux", "Windows", "macOS"],
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries through PowerShell, cmd, bash, or VBScript.",
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactics": ["Execution"],
        "platforms": ["Windows"],
        "description": "Adversaries may abuse PowerShell commands and scripts for execution, memory injection, downloading remote tools, or administrative automation.",
    },
    "T1558.003": {
        "id": "T1558.003",
        "name": "Kerberoasting",
        "tactics": ["Credential Access"],
        "platforms": ["Windows"],
        "description": "Adversaries may abuse a valid Kerberos ticket-granting service (TGS) request to harvest password hashes for Active Directory service principal accounts.",
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactics": ["Impact"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": "Adversaries may encrypt data on target systems or storage volumes to interrupt availability of system and network resources, commonly seen in ransomware attacks demanding payment.",
    },
    "T1498": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactics": ["Impact"],
        "platforms": ["Network", "Windows", "Linux"],
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks, volumetric packet flooding, SYN flooding, or amplification to degrade or block targeted network availability.",
    },
    "T1071.004": {
        "id": "T1071.004",
        "name": "DNS Tunneling",
        "tactics": ["Command and Control"],
        "platforms": ["Linux", "Windows", "macOS"],
        "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to conceal command and control traffic or exfiltrate data through encoded query records.",
    },
    "T1053.005": {
        "id": "T1053.005",
        "name": "Scheduled Task",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "platforms": ["Windows"],
        "description": "Adversaries may abuse task scheduling functionality in Windows via schtasks or Task Scheduler to facilitate initial or recurring execution of malicious code.",
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        "platforms": ["Linux", "Windows", "Cloud"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
    },
    "T1552.005": {
        "id": "T1552.005",
        "name": "Cloud Instance Metadata API",
        "tactics": ["Credential Access"],
        "platforms": ["IaaS"],
        "description": "Adversaries may access the instance metadata API to harvest credentials, access tokens, and configuration data associated with cloud compute instances.",
    },
    "T1003.006": {
        "id": "T1003.006",
        "name": "DCSync",
        "tactics": ["Credential Access"],
        "platforms": ["Windows"],
        "description": "Adversaries may simulate domain controller replication behavior through Directory Replication Service Remote Protocol (MS-DRSR) to extract Active Directory password hashes.",
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactics": ["Discovery"],
        "platforms": ["Linux", "Windows", "macOS"],
        "description": "Adversaries may attempt to get a listing of services running on remote hosts, including port scans, SYN scanning, Nmap scans, and banner grabbing.",
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["Credential Access"],
        "platforms": ["Linux", "Windows", "Cloud"],
        "description": "Adversaries may use brute force techniques to attempt authentication by iteratively guessing passwords, performing credential stuffing, or password spraying.",
    },
    "T1490": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactics": ["Impact"],
        "platforms": ["Windows", "Linux"],
        "description": "Adversaries may delete or disable system recovery mechanisms, such as deleting Windows Volume Shadow Copies using vssadmin or disabling boot repair policies.",
    },
}


@dataclasses.dataclass
class HybridCandidateTechnique:
    technique_id: str
    name: str
    tactics: List[str]
    platforms: List[str]
    description: str
    sparse_score: float
    dense_score: float
    hybrid_score: float
    grounded_in_graph: bool
    targeted_artifact: Optional[str]
    defense_paths_count: int


@dataclasses.dataclass
class HybridDefensePlaybook:
    query: str
    telemetry: Dict[str, Any]
    disruption_budget: float
    matched_techniques: List[HybridCandidateTechnique]
    pareto_mitigations: List[DefensePath]
    admitted_actions: List[Dict[str, Any]]
    rejected_actions: List[Dict[str, Any]]
    topological_proof_chains: List[str]


class SemanticGraphRAG:
    """Doctoral Hybrid Graph-RAG Engine with Dense Concept Projection and SMT Safety."""

    def __init__(
        self,
        knowledge_graph: Optional[ThreatDefenseKnowledgeGraph] = None,
        safety_verifier: Optional[FormalSafetyVerifier] = None,
        db_path: Optional[str] = None,
        latent_dimensions: int = 48,
    ):
        self.knowledge_graph = knowledge_graph or default_knowledge_graph
        self.safety_verifier = safety_verifier or default_safety_verifier
        self.db_path = db_path or str(DB_PATH)
        self.latent_dimensions = latent_dimensions

        self._lock = threading.Lock()
        self._initialized = False

        self._techniques: Dict[str, Dict[str, Any]] = {}
        self._technique_ids: List[str] = []
        self._corpus_texts: List[str] = []

        self._vectorizer: Optional[TfidfVectorizer] = None
        self._svd: Optional[TruncatedSVD] = None
        self._dense_embeddings: Optional[np.ndarray] = None
        self._token_index: Dict[str, Set[str]] = {}

    def _ensure_corpus(self) -> None:
        """Lazily load SQLite MITRE database or fall back to foundational seed."""
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return
            self._load_and_index()
            self._initialized = True

    def _load_and_index(self) -> None:
        loaded: Dict[str, Dict[str, Any]] = {}

        # 1. Attempt loading from SQLite
        resolved_db = self.db_path
        master_kb = Path("data/cyberguard.db")
        if not Path(resolved_db).exists() and master_kb.exists():
            resolved_db = str(master_kb)

        if Path(resolved_db).exists():
            try:
                with sqlite3.connect(resolved_db, timeout=10) as conn:
                    conn.row_factory = sqlite3.Row
                    cur = conn.cursor()
                    has_table = cur.execute(
                        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='techniques'"
                    ).fetchone()[0]
                    if has_table:
                        cur.execute(
                            "SELECT id, name, description, tactics, platforms FROM techniques"
                        )
                        for row in cur.fetchall():
                            tid = row["id"].upper().strip()
                            tactics = []
                            try:
                                tactics = json.loads(row["tactics"] or "[]")
                            except Exception:
                                pass
                            platforms = []
                            try:
                                platforms = json.loads(row["platforms"] or "[]")
                            except Exception:
                                pass
                            loaded[tid] = {
                                "id": tid,
                                "name": row["name"],
                                "description": row["description"] or "",
                                "tactics": tactics,
                                "platforms": platforms,
                            }
            except Exception as e:
                logger.warning("Failed loading techniques from SQLite: %s", e)

        # 2. Merge foundational seed to guarantee coverage of core threat vectors
        for tid, data in FOUNDATIONAL_TECHNIQUES.items():
            if tid not in loaded:
                loaded[tid] = data

        self._techniques = loaded
        self._technique_ids = sorted(loaded.keys())

        # 3. Assemble corpus documents for vectorization
        self._corpus_texts = []
        self._token_index.clear()

        for tid in self._technique_ids:
            tech = self._techniques[tid]
            tactics_str = " ".join(tech.get("tactics", []))
            platforms_str = " ".join(tech.get("platforms", []))
            text_doc = (
                f"{tid} {tech['name']} {tactics_str} {platforms_str} {tech['description']}"
            ).lower()
            self._corpus_texts.append(text_doc)

            # Inverted token index for sparse fast retrieval
            words = set(re.findall(r"\b[a-zA-Z0-9_\.-]{2,}\b", text_doc))
            for w in words:
                self._token_index.setdefault(w, set()).add(tid)

        # 4. Fit TF-IDF & TruncatedSVD Dense Semantic Concept Model
        if self._corpus_texts:
            n_samples = len(self._corpus_texts)
            n_components = min(self.latent_dimensions, max(2, n_samples - 1))

            self._vectorizer = TfidfVectorizer(
                max_features=4000,
                sublinear_tf=True,
                stop_words="english",
                ngram_range=(1, 2),
            )
            tfidf_matrix = self._vectorizer.fit_transform(self._corpus_texts)

            self._svd = TruncatedSVD(n_components=n_components, random_state=42)
            dense_repr = self._svd.fit_transform(tfidf_matrix)

            # L2-normalize dense rows for unit cosine similarities
            norms = np.linalg.norm(dense_repr, axis=1, keepdims=True)
            norms[norms == 0] = 1e-12
            self._dense_embeddings = dense_repr / norms

    def search_dense(self, query: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """Dense semantic search via Latent Semantic Concept Projection."""
        self._ensure_corpus()
        if not query.strip() or self._dense_embeddings is None or self._vectorizer is None or self._svd is None:
            return []

        try:
            q_tfidf = self._vectorizer.transform([query.lower()])
            q_dense = self._svd.transform(q_tfidf)
            norm = np.linalg.norm(q_dense)
            if norm > 0:
                q_dense = q_dense / norm

            sims = np.dot(self._dense_embeddings, q_dense.T).ravel()
            top_indices = np.argsort(-sims)[:top_k]

            results = []
            for idx in top_indices:
                score = float(sims[idx])
                if score > 0.05:
                    results.append((self._technique_ids[idx], score))
            return results
        except Exception as e:
            logger.error("Dense search failure: %s", e)
            return []

    def search_sparse(
        self, query: str, telemetry: Optional[Dict[str, Any]] = None, top_k: int = 10
    ) -> List[Tuple[str, float]]:
        """Sparse lexical & deterministic indicator matching."""
        self._ensure_corpus()
        telemetry = telemetry or {}
        scores: Dict[str, float] = {}

        clean_query = query.strip()

        # 1. Exact ATT&CK Technique ID matches
        for m in _ATTACK_ID_PATTERN.findall(clean_query):
            tid = m.upper()
            if tid in self._techniques:
                scores[tid] = scores.get(tid, 0.0) + 10.0

        # 2. Windows Event IDs
        found_eids = _EVENT_ID_PATTERN.findall(clean_query)
        if "winlog_event_id" in telemetry:
            found_eids.append(str(telemetry["winlog_event_id"]))
        for eid in found_eids:
            if eid in WIN_EVENT_ID_MAP:
                for tid in WIN_EVENT_ID_MAP[eid]:
                    if tid in self._techniques:
                        scores[tid] = scores.get(tid, 0.0) + 5.0

        # 3. Port mapping
        found_ports = _PORT_PATTERN.findall(clean_query)
        if "dest_port" in telemetry:
            found_ports.append(str(telemetry["dest_port"]))
        for port in found_ports:
            if port in WELL_KNOWN_PORTS_MAP:
                for tid in WELL_KNOWN_PORTS_MAP[port]:
                    if tid in self._techniques:
                        scores[tid] = scores.get(tid, 0.0) + 4.0

        # 4. Lexical inverted token overlap
        tokens = set(re.findall(r"\b[a-zA-Z0-9_\.-]{2,}\b", clean_query.lower()))
        for t in tokens:
            matching_tids = self._token_index.get(t, set())
            for tid in matching_tids:
                scores[tid] = scores.get(tid, 0.0) + 0.5

        # Normalize sparse scores
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
        if not ranked:
            return []

        max_s = max(kv[1] for kv in ranked) or 1.0
        return [(tid, score / max_s) for tid, score in ranked]

    def search_hybrid(
        self,
        query: str,
        telemetry: Optional[Dict[str, Any]] = None,
        alpha: float = 0.5,
        top_k: int = 5,
    ) -> List[HybridCandidateTechnique]:
        """Reciprocal Rank Fusion with Hypergraph Grounding Re-Ranking."""
        self._ensure_corpus()
        telemetry = telemetry or {}

        sparse_matches = self.search_sparse(query, telemetry=telemetry, top_k=20)
        dense_matches = self.search_dense(query, top_k=20)

        sparse_ranks = {tid: rank for rank, (tid, _) in enumerate(sparse_matches)}
        dense_ranks = {tid: rank for rank, (tid, _) in enumerate(dense_matches)}

        sparse_score_map = dict(sparse_matches)
        dense_score_map = dict(dense_matches)

        all_candidate_tids = set(sparse_ranks.keys()).union(dense_ranks.keys())
        if not all_candidate_tids and query.strip():
            # If no direct matches, return foundational fallbacks
            all_candidate_tids = set(FOUNDATIONAL_TECHNIQUES.keys())

        rrf_scores: Dict[str, float] = {}
        k_rrf = 30.0

        for tid in all_candidate_tids:
            r_sparse = sparse_ranks.get(tid, 100)
            r_dense = dense_ranks.get(tid, 100)

            # Standard RRF formula
            rrf = (alpha / (k_rrf + r_sparse)) + ((1.0 - alpha) / (k_rrf + r_dense))

            # Deterministic exact match boost
            if tid.upper() in query.upper():
                rrf += 0.5

            rrf_scores[tid] = rrf

        # Hypergraph Topological Grounding Re-Ranking
        ranked_tids = sorted(rrf_scores.keys(), key=lambda tid: rrf_scores[tid], reverse=True)
        candidates: List[HybridCandidateTechnique] = []

        for tid in ranked_tids:
            tech_data = self._techniques.get(tid)
            if not tech_data:
                continue

            # Check Knowledge Hypergraph topology
            defense_paths = self.knowledge_graph.find_defense_paths(tid)
            has_graph_defense = len(defense_paths) > 0
            targeted_art = defense_paths[0].artifact_name if defense_paths else None

            # Boost grounded techniques with topological proof paths
            base_score = rrf_scores[tid]
            grounded_score = base_score * (1.35 if has_graph_defense else 1.0)

            candidates.append(
                HybridCandidateTechnique(
                    technique_id=tid,
                    name=tech_data["name"],
                    tactics=tech_data.get("tactics", []),
                    platforms=tech_data.get("platforms", []),
                    description=tech_data.get("description", ""),
                    sparse_score=round(sparse_score_map.get(tid, 0.0), 4),
                    dense_score=round(dense_score_map.get(tid, 0.0), 4),
                    hybrid_score=round(grounded_score, 4),
                    grounded_in_graph=has_graph_defense,
                    targeted_artifact=targeted_art,
                    defense_paths_count=len(defense_paths),
                )
            )

        # Sort by final grounded hybrid score descending
        candidates.sort(key=lambda c: c.hybrid_score, reverse=True)
        return candidates[:top_k]

    def retrieve_pareto_playbook(
        self,
        query: str,
        telemetry: Optional[Dict[str, Any]] = None,
        max_disruption: float = 0.50,
        tradeoff_lambda: float = 0.5,
        top_k_techniques: int = 3,
        verify_safety: bool = True,
    ) -> HybridDefensePlaybook:
        """Computes Pareto-optimal D3FEND mitigations governed by Formal SMT Safety Invariants."""
        telemetry = telemetry or {}
        matched = self.search_hybrid(
            query=query, telemetry=telemetry, top_k=top_k_techniques
        )

        src_ip = (
            telemetry.get("src_ip")
            or telemetry.get("source_ip")
            or telemetry.get("remote_ip")
            or "203.0.113.42"
        )
        dest_port = telemetry.get("dest_port") or telemetry.get("destination_port")
        process_name = telemetry.get("process_name") or telemetry.get("image") or "malicious.exe"

        pareto_mitigations: List[DefensePath] = []
        admitted_actions: List[Dict[str, Any]] = []
        rejected_actions: List[Dict[str, Any]] = []
        proof_chains: List[str] = []

        seen_countermeasures: Set[str] = set()

        for cand in matched:
            best_path = self.knowledge_graph.pareto_optimal_defense(
                technique_id=cand.technique_id,
                max_disruption=max_disruption,
                tradeoff_lambda=tradeoff_lambda,
            )
            if not best_path:
                continue

            if best_path.countermeasure_id in seen_countermeasures:
                continue
            seen_countermeasures.add(best_path.countermeasure_id)

            pareto_mitigations.append(best_path)
            proof_chains.append(best_path.explanation_proof)

            # Determine concrete execution target
            action_type = best_path.actuator_action
            if action_type in {"block_ip", "rate_limit"}:
                target = src_ip
            elif action_type in {"kill_process"}:
                target = process_name
            elif action_type in {"isolate_port", "drop_port"}:
                target = str(dest_port or 80)
            elif action_type in {"drop_suricata_signature"}:
                target = str(telemetry.get("signature_id") or "2010999")
            else:
                target = src_ip

            action_params: Dict[str, Any] = {
                "d3fend_id": best_path.countermeasure_id,
                "countermeasure": best_path.countermeasure_name,
                "technique_id": best_path.technique_id,
                "disruption_cost": best_path.disruption_cost,
                "coverage_score": best_path.coverage_score,
            }
            if dest_port:
                action_params["port"] = dest_port

            if verify_safety:
                v_res: VerificationResult = self.safety_verifier.verify_and_sign(
                    action=action_type,
                    target=target,
                    severity=telemetry.get("severity", "high"),
                    confidence=float(telemetry.get("confidence", 0.90)),
                    parameters=action_params,
                )

                action_record = {
                    "action": action_type,
                    "target": target,
                    "parameters": action_params,
                    "d3fend_id": best_path.countermeasure_id,
                    "admitted": v_res.admitted,
                    "proof_trace": v_res.proof_trace,
                    "disruption_score": v_res.disruption_score,
                    "proportionality_bound": v_res.proportionality_bound,
                }

                if v_res.admitted and v_res.rollback_receipt:
                    action_record["rollback_receipt"] = {
                        "token": v_res.rollback_receipt.token,
                        "signature_hmac": v_res.rollback_receipt.signature_hmac,
                        "timestamp": v_res.rollback_receipt.timestamp,
                    }
                    admitted_actions.append(action_record)
                else:
                    action_record["violated_invariants"] = [
                        inv.value for inv in v_res.violated_invariants
                    ]
                    rejected_actions.append(action_record)
            else:
                admitted_actions.append({
                    "action": action_type,
                    "target": target,
                    "parameters": action_params,
                    "d3fend_id": best_path.countermeasure_id,
                    "admitted": True,
                })

        return HybridDefensePlaybook(
            query=query,
            telemetry=telemetry,
            disruption_budget=max_disruption,
            matched_techniques=matched,
            pareto_mitigations=pareto_mitigations,
            admitted_actions=admitted_actions,
            rejected_actions=rejected_actions,
            topological_proof_chains=proof_chains,
        )

    def format_grounded_prompt(self, playbook: HybridDefensePlaybook) -> str:
        """Synthesize an unhallucinated prompt context for LLM reasoning."""
        lines = [
            "================================================================================",
            "DOCTORAL HYBRID GRAPH-RAG: THREAT-INFORMED ACTIVE DEFENSE CONTEXT",
            "================================================================================",
            f"Observed Incident Query: {playbook.query}",
            f"Telemetry Attributes: {json.dumps(playbook.telemetry, default=str)}",
            f"Operational Disruption Constraint Budget: <= {playbook.disruption_budget:.2f}",
            "",
            "HYPERGRAPH-GROUNDED MITRE ATT&CK TECHNIQUES:",
        ]

        if not playbook.matched_techniques:
            lines.append("  (No direct MITRE technique grounded. Rely on baseline anomaly policy.)")
        else:
            for tech in playbook.matched_techniques:
                tactics = ", ".join(tech.tactics) if tech.tactics else "Unspecified"
                lines.append(
                    f"- [{tech.technique_id}] {tech.name} (Tactics: {tactics})"
                )
                lines.append(
                    f"  Relevance Scores: Hybrid={tech.hybrid_score:.3f} (Dense={tech.dense_score:.3f}, Sparse={tech.sparse_score:.3f})"
                )
                if tech.grounded_in_graph:
                    lines.append(
                        f"  Targeted Digital Artifact: {tech.targeted_artifact} (Active Paths: {tech.defense_paths_count})"
                    )
                lines.append(f"  Description Excerpt: {tech.description[:220]}...")
                lines.append("")

        lines.append("PARETO-OPTIMAL D3FEND MITIGATION PATHS:")
        for path in playbook.pareto_mitigations:
            lines.append(
                f"- D3FEND: [{path.countermeasure_id}] {path.countermeasure_name}"
            )
            lines.append(
                f"  Actuator Action: '{path.actuator_action}' | Coverage: {path.coverage_score:.2f} | Disruption Cost: {path.disruption_cost:.2f}"
            )
            lines.append(f"  Formal Topological Proof: {path.explanation_proof}")
            lines.append("")

        lines.append("FORMAL NEURO-SYMBOLIC SAFETY GATE DISPOSITION:")
        lines.append(f"- Admitted Autonomous Actions: {len(playbook.admitted_actions)}")
        for act in playbook.admitted_actions:
            receipt = act.get("rollback_receipt", {})
            lines.append(
                f"  * ACTION '{act['action']}' on target '{act['target']}' (CERTIFIED - Token: {receipt.get('token', 'N/A')[:16]}...)"
            )

        if playbook.rejected_actions:
            lines.append(f"- Rejected High-Disruption / Unsafe Actions: {len(playbook.rejected_actions)}")
            for act in playbook.rejected_actions:
                lines.append(
                    f"  * BLOCKED '{act['action']}' on target '{act['target']}' (Violations: {', '.join(act.get('violated_invariants', []))})"
                )

        lines.extend([
            "",
            "MANDATORY EXECUTION DIRECTIVE: Neural models MUST NOT recommend actions outside the admitted",
            "set above. Hallucinated shell commands or actions violating Invariants I_1 through I_4 are strictly forbidden.",
            "================================================================================",
        ])

        return "\n".join(lines)

    def retrieve_defense_playbook(
        self,
        query: str = "",
        label: Optional[str] = None,
        techniques: Optional[List[str]] = None,
        telemetry: Optional[Dict[str, Any]] = None,
        top_k_techniques: int = 4,
        max_disruption: float = 0.50,
    ) -> Dict[str, Any]:
        """Universal adapter providing full drop-in compatibility for defense_rag callers."""
        composite_parts = []
        if query:
            composite_parts.append(query)
        if label:
            composite_parts.append(f"Threat Label: {label}")
        if techniques:
            composite_parts.append(f"Observed Techniques: {' '.join(techniques)}")
        effective_query = ". ".join(composite_parts) if composite_parts else "generic security anomaly"

        playbook = self.retrieve_pareto_playbook(
            query=effective_query,
            telemetry=telemetry,
            max_disruption=max_disruption,
            top_k_techniques=top_k_techniques,
        )

        playbook_techniques = []
        all_countermeasures = []
        concrete_actions = []

        for cand in playbook.matched_techniques:
            d3fend_cms = []
            for path in playbook.pareto_mitigations:
                if path.technique_id == cand.technique_id or path.technique_id in cand.technique_id:
                    d3fend_cms.append({
                        "d3fend_id": path.countermeasure_id,
                        "name": path.countermeasure_name,
                        "actuator_action": path.actuator_action,
                        "disruption_cost": path.disruption_cost,
                        "coverage_score": path.coverage_score,
                    })
                    all_countermeasures.append(d3fend_cms[-1])

            playbook_techniques.append({
                "technique_id": cand.technique_id,
                "name": cand.name,
                "tactics": cand.tactics,
                "platforms": cand.platforms,
                "relevance_score": cand.hybrid_score,
                "description_excerpt": cand.description[:300] + "...",
                "d3fend_countermeasures": d3fend_cms,
            })

        for act in playbook.admitted_actions:
            concrete_actions.append({
                "action": act["action"],
                "target": act["target"],
                "actuator": "firewall" if "ip" in act["action"] else "process" if "process" in act["action"] else "ips",
                "d3fend_id": act.get("d3fend_id", "D3-SPV"),
                "countermeasure_name": act.get("parameters", {}).get("countermeasure", ""),
                "params": act.get("parameters", {}),
            })

        return {
            "query": effective_query,
            "total_techniques_matched": len(playbook_techniques),
            "techniques": playbook_techniques,
            "d3fend_countermeasures": all_countermeasures,
            "concrete_actions": concrete_actions,
            "telemetry": telemetry or {},
            "grounded_proofs": playbook.topological_proof_chains,
            "admitted_actions": playbook.admitted_actions,
            "rejected_actions": playbook.rejected_actions,
            "_raw_playbook": playbook,
        }

    def format_prompt_context(self, playbook: Any) -> str:
        """Format playbook (either HybridDefensePlaybook or legacy dict) into prompt context."""
        if isinstance(playbook, HybridDefensePlaybook):
            return self.format_grounded_prompt(playbook)
        if isinstance(playbook, dict) and "_raw_playbook" in playbook:
            return self.format_grounded_prompt(playbook["_raw_playbook"])
        lines = [
            "================================================================================",
            "DOCTORAL HYBRID GRAPH-RAG: THREAT-INFORMED ACTIVE DEFENSE CONTEXT",
            "================================================================================",
            f"Query: {playbook.get('query', '') if isinstance(playbook, dict) else ''}",
            f"Telemetry: {json.dumps(playbook.get('telemetry', {}) if isinstance(playbook, dict) else {}, default=str)}",
            "",
            "IDENTIFIED MITRE ATT&CK TECHNIQUES:",
        ]
        if isinstance(playbook, dict):
            for tech in playbook.get("techniques", []):
                lines.append(f"- [{tech.get('technique_id')}] {tech.get('name')} (Score: {tech.get('relevance_score', 0):.2f})")
                for cm in tech.get("d3fend_countermeasures", []):
                    lines.append(f"  * D3FEND: [{cm.get('d3fend_id')}] {cm.get('name')} -> Action: {cm.get('actuator_action')}")
        lines.append("================================================================================")
        return "\n".join(lines)


# Singleton instance
default_semantic_rag = SemanticGraphRAG()

