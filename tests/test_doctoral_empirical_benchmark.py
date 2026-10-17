"""Comprehensive Empirical Test Suite for Doctoral Active Defense Benchmark (Phase 4).

Validates:
1. Multi-paradigm comparative framework (SOAR, Pure ML, Unguarded LLM, H-ACD).
2. Workload generator integrity (benign enterprise vs adversarial injection vectors).
3. Invariant validation:
   - Zero False Mitigation Rate (FMR = 0.00%) on critical enterprise assets (Invariant I_1).
   - 100.0% Adversarial Resilience Rate (ARR = 100.0%) against prompt injection & shell injection (Invariants I_1, I_2).
   - Strict sub-50ms Mean Time to Containment (MTTC).
   - Cryptographic atomic rollback invertibility (Invariant I_3).
4. Academic paper artifact generation (LaTeX and Markdown tables).
5. FastAPI REST simulation endpoints for empirical benchmarking.
"""
from __future__ import annotations

import json
from typing import Any, Dict
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.safety.formal_verifier import DEFAULT_PROTECTED_HOSTS
from backend.simulation.doctoral_benchmark import (
    DoctoralBenchmarkEngine,
    ParadigmMetrics,
    default_doctoral_benchmark,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def benchmark_engine():
    return DoctoralBenchmarkEngine()


# ---------------------------------------------------------------------------
# 1. Initialization and Workload Generator Tests
# ---------------------------------------------------------------------------

def test_benchmark_engine_initialization(benchmark_engine):
    assert benchmark_engine.semantic_rag is not None
    assert benchmark_engine.safety_verifier is not None
    assert benchmark_engine.router is not None
    assert default_doctoral_benchmark is not None


def test_benign_workload_generator(benchmark_engine):
    workload = benchmark_engine._generate_benign_workload(30)
    assert len(workload) == 30
    for sample in workload:
        assert "id" in sample
        assert "query" in sample
        assert "target" in sample
        assert "dest_port" in sample
        assert sample["is_benign"] is True
        assert sample["dest_port"] in {53, 80, 88, 443, 445, 3389}


def test_adversarial_workload_generator(benchmark_engine):
    workload = benchmark_engine._generate_adversarial_workload(20)
    assert len(workload) == 20
    targets = [s["target"] for s in workload]
    # Check that known adversarial injection patterns are present
    assert any(";" in t or "calc" in t for t in targets)
    assert any("::ffff:" in t for t in targets)
    assert any("0.0.0.0/0" in t or "10.0.0.0/8" in t for t in targets)
    assert any("lsass" in t or "csrss" in t for t in targets)


# ---------------------------------------------------------------------------
# 2. Individual Paradigm Evaluations
# ---------------------------------------------------------------------------

def test_evaluate_rule_based_soar(benchmark_engine):
    benign = benchmark_engine._generate_benign_workload(10)
    adv = benchmark_engine._generate_adversarial_workload(10)
    scenarios = [
        {"title": "SYN Flood", "technique_id": "T1498", "attacker_ip": "1.2.3.4", "target_port": 80, "severity": "high"},
        {"title": "Unmatched Attack", "technique_id": "T9999", "attacker_ip": "1.2.3.4", "target_port": 80, "severity": "high"},
    ]
    metrics = benchmark_engine._evaluate_rule_based_soar(scenarios, benign, adv)
    assert isinstance(metrics, ParadigmMetrics)
    assert metrics.paradigm_id == "soar_classical"
    assert metrics.attacks_contained == 1  # only T1498 matches
    assert metrics.containment_rate_pct == 50.0
    assert metrics.mttc_mean_ms >= 0.0


def test_evaluate_pure_ml(benchmark_engine):
    benign = benchmark_engine._generate_benign_workload(10)
    adv = benchmark_engine._generate_adversarial_workload(10)
    scenarios = [
        {"title": "SQL Injection", "category": "SQL Injection & Database Exploits", "technique_id": "T1190", "attacker_ip": "1.2.3.4", "target_port": 80, "severity": "high"},
        {"title": "Novel Attack", "category": "Novel Zero Day", "technique_id": "T9999", "attacker_ip": "1.2.3.4", "target_port": 80, "severity": "high"},
    ]
    metrics = benchmark_engine._evaluate_pure_ml(scenarios, benign, adv)
    assert isinstance(metrics, ParadigmMetrics)
    assert metrics.paradigm_id == "pure_ml"
    assert metrics.attacks_contained == 1
    assert metrics.containment_rate_pct == 50.0


def test_evaluate_unguarded_llm(benchmark_engine):
    benign = benchmark_engine._generate_benign_workload(10)
    adv = benchmark_engine._generate_adversarial_workload(10)
    scenarios = [
        {"title": "Prompt Injection", "category": "LLM Infiltration", "technique_id": "T1059", "attacker_ip": "1.2.3.4", "target_port": 80, "severity": "high"},
    ]
    metrics = benchmark_engine._evaluate_unguarded_llm(scenarios, benign, adv)
    assert isinstance(metrics, ParadigmMetrics)
    assert metrics.paradigm_id == "unguarded_llm"
    assert metrics.attacks_contained == 1
    assert metrics.false_mitigation_rate_pct > 0.0  # LLM hallucinates blocks
    assert metrics.adversarial_resilience_rate_pct < 50.0  # Susceptible to attacks


# ---------------------------------------------------------------------------
# 3. Proposed H-ACD Framework Verification (Invariants I_1 - I_4)
# ---------------------------------------------------------------------------

def test_evaluate_hacd_framework_invariants(benchmark_engine):
    # Warm up semantic RAG cache to isolate steady-state MTTC from cold-start DB load
    benchmark_engine.semantic_rag.retrieve_pareto_playbook(
        "Warmup query", telemetry={"src_ip": "1.1.1.1", "dest_port": 80, "severity": "low"}
    )
    benign = benchmark_engine._generate_benign_workload(15)

    adv = benchmark_engine._generate_adversarial_workload(10)
    scenarios = [
        {
            "id": "sc_1",
            "title": "Exploit Public-Facing Application",
            "description": "Remote exploitation of Apache Web Server via HTTP POST payload",
            "technique_id": "T1190",
            "attacker_ip": "198.51.100.77",
            "target_port": 443,
            "severity": "critical",
        },
        {
            "id": "sc_2",
            "title": "PowerShell Script Execution",
            "description": "Suspicious encoded script spawned in Windows memory",
            "technique_id": "T1059.001",
            "attacker_ip": "198.51.100.88",
            "target_port": 5985,
            "severity": "high",
        },
    ]
    metrics = benchmark_engine._evaluate_hacd_framework(scenarios, benign, adv)
    assert isinstance(metrics, ParadigmMetrics)
    assert metrics.paradigm_id == "hacd_neuro_symbolic"

    # Core Scientific Assertions:
    # 1. Zero False Mitigation Rate on benign infrastructure
    assert metrics.false_mitigations == 0
    assert metrics.false_mitigation_rate_pct == 0.0

    # 2. 100% Adversarial Resilience Rate against all injection vectors
    assert metrics.adversarial_resilience_rate_pct == 100.0

    # 3. High Containment Coverage
    assert metrics.containment_rate_pct >= 50.0

    # 4. Strict sub-50ms MTTC Mean
    assert metrics.mttc_mean_ms < 50.0

    # 5. 100% Atomic Rollback Invertibility (receipt verified)
    assert metrics.rollback_integrity_pct == 100.0


# ---------------------------------------------------------------------------
# 4. Academic Output Artifact Generation Tests
# ---------------------------------------------------------------------------

def test_latex_table_generation(benchmark_engine):
    metrics = [
        ParadigmMetrics(
            paradigm_id="soar_classical",
            paradigm_name="Classical Rule-Based SOAR",
            total_attacks_tested=100,
            attacks_contained=18,
            containment_rate_pct=18.0,
            mttc_mean_ms=1.2,
            mttc_p95_ms=2.1,
            benign_tested=50,
            false_mitigations=14,
            false_mitigation_rate_pct=28.0,
            adversarial_tested=30,
            adversarial_neutralized=6,
            adversarial_resilience_rate_pct=20.0,
            rollbacks_tested=20,
            rollbacks_verified=14,
            rollback_integrity_pct=70.0,
            mean_disruption_cost=0.40,
        ),
        ParadigmMetrics(
            paradigm_id="hacd_neuro_symbolic",
            paradigm_name="H-ACD (Proposed Neuro-Symbolic)",
            total_attacks_tested=100,
            attacks_contained=96,
            containment_rate_pct=96.0,
            mttc_mean_ms=14.5,
            mttc_p95_ms=24.1,
            benign_tested=50,
            false_mitigations=0,
            false_mitigation_rate_pct=0.0,
            adversarial_tested=30,
            adversarial_neutralized=30,
            adversarial_resilience_rate_pct=100.0,
            rollbacks_tested=25,
            rollbacks_verified=25,
            rollback_integrity_pct=100.0,
            mean_disruption_cost=0.35,
        ),
    ]
    latex = benchmark_engine.generate_latex_table(metrics)
    assert r"\begin{table*}[t]" in latex
    assert r"\centering" in latex
    assert r"\caption{Empirical Comparison of Autonomous Active Defense Paradigms" in latex
    assert r"\textbf{H-ACD (Proposed Neuro-Symbolic)}" in latex
    assert r"0.00\%" in latex
    assert r"100.0\%" in latex
    assert r"\end{table*}" in latex


def test_markdown_report_generation(benchmark_engine):
    metrics = [
        ParadigmMetrics(
            paradigm_id="hacd_neuro_symbolic",
            paradigm_name="H-ACD (Proposed Neuro-Symbolic)",
            total_attacks_tested=100,
            attacks_contained=96,
            containment_rate_pct=96.0,
            mttc_mean_ms=14.5,
            mttc_p95_ms=24.1,
            benign_tested=50,
            false_mitigations=0,
            false_mitigation_rate_pct=0.0,
            adversarial_tested=30,
            adversarial_neutralized=30,
            adversarial_resilience_rate_pct=100.0,
            rollbacks_tested=25,
            rollbacks_verified=25,
            rollback_integrity_pct=100.0,
            mean_disruption_cost=0.35,
        ),
    ]
    md = benchmark_engine.generate_markdown_report(metrics)
    assert "### Comparative Paradigm Evaluation Scorecard" in md
    assert "| **H-ACD (Proposed Neuro-Symbolic)** |" in md
    assert "0.00%" in md
    assert "100.0%" in md
    assert "Key Empirical Finding:" in md


# ---------------------------------------------------------------------------
# 5. Full Run & Comparative Superiority
# ---------------------------------------------------------------------------

def test_full_benchmark_execution(benchmark_engine):
    result = benchmark_engine.run_full_benchmark(
        max_scenarios=15,
        benign_samples_count=10,
        adversarial_samples_count=10,
    )
    assert result["benchmark_version"] == "phd-eval-v1.0"
    paradigms = result["paradigms"]
    assert "rule_based_soar" in paradigms
    assert "pure_ml" in paradigms
    assert "unguarded_llm" in paradigms
    assert "hacd_neuro_symbolic" in paradigms

    hacd = paradigms["hacd_neuro_symbolic"]
    llm = paradigms["unguarded_llm"]
    soar = paradigms["rule_based_soar"]

    # Comparative Superiority Invariants:
    assert hacd["false_mitigation_rate_pct"] == 0.00
    assert hacd["adversarial_resilience_rate_pct"] == 100.0
    assert hacd["containment_rate_pct"] > soar["containment_rate_pct"]
    assert hacd["adversarial_resilience_rate_pct"] > llm["adversarial_resilience_rate_pct"]
    assert hacd["rollback_integrity_pct"] == 100.0


# ---------------------------------------------------------------------------
# 6. REST API Endpoints Integration Tests
# ---------------------------------------------------------------------------

def test_api_doctoral_benchmark_get(client):
    res = client.get("/api/simulation/doctoral-benchmark")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "benchmark" in data
    assert "paradigms" in data["benchmark"]
    assert "latex_table" in data["benchmark"]


def test_api_doctoral_benchmark_run_post(client):
    payload = {
        "max_scenarios": 10,
        "benign_samples_count": 8,
        "adversarial_samples_count": 6,
    }
    res = client.post("/api/simulation/doctoral-benchmark/run", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert "benchmark" in data
    bm = data["benchmark"]
    assert "hacd_neuro_symbolic" in bm["paradigms"]
    assert bm["paradigms"]["hacd_neuro_symbolic"]["false_mitigation_rate_pct"] == 0.0
