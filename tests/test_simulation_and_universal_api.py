"""Integration tests for Simulation API and Universal Document Ingestion API."""
from __future__ import annotations

import io
import json
import zipfile
import pytest
from starlette.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_simulation_scenarios_listing():
    """Verify that all 100+ cyber threat attack simulation scenarios are available."""
    response = client.get("/api/simulation/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["total_scenarios"] >= 100

    scenario_ids = [s["id"] for s in data["scenarios"]]
    assert "dos_syn_flood_volumetric" in scenario_ids
    assert "ad_kerberoasting_spn" in scenario_ids
    assert "rce_log4j_jndi" in scenario_ids
    assert "ransomware_esxi_volume_encryption" in scenario_ids
    assert "c2_dns_tunneling_txt" in scenario_ids

    # Validate that CLI commands are included
    for s in data["scenarios"][:10]:
        assert "curl_command" in s
        assert "powershell_command" in s
        assert "technique_id" in s


def test_simulation_launch_syn_flood():
    """Test launching SYN flood DDoS simulation end-to-end (testing alias resolution)."""
    payload = {
        "scenario_id": "syn_flood_ddos",
        "custom_ip": "198.51.100.88",
        "enforce_live": False,
    }
    response = client.post("/api/simulation/launch", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["scenario_id"] in ("syn_flood_ddos", "dos_syn_flood_volumetric")
    assert data["attacker_ip"] == "198.51.100.88"
    assert len(data["rag_grounding"]["matched_techniques"]) >= 1
    assert data["ai_decision"]["verdict"] in ("malicious", "suspicious")
    assert data["actuator_execution"]["success"] is True
    assert data["ai_decision"]["rollback_token"] is not None
    assert len(data["timeline"]) == 4


def test_universal_ingest_raw_log():
    """Test universal ingestion with raw incident text and auto-triage."""
    raw_log = """
    CRITICAL SIEM EVENT:
    Ransomware LockBit staged from source IP 203.0.113.55 targeting DC on SMB port 445.
    Executed certutil -urlcache to drop payload. CVE-2021-44228 observed.
    """
    response = client.post(
        "/api/detect/universal-ingest/raw",
        json={
            "raw_text": raw_log,
            "filename": "incident_sample.log",
            "auto_triage": True,
            "enforce_live": False,
        },
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert data["extracted_iocs"]["primary_ip"] == "203.0.113.55"
    assert "CVE-2021-44228" in data["extracted_iocs"]["cve_identifiers"]
    assert len(data["mitre_grounding"]["matched_techniques"]) >= 1
    assert data["ai_triage"]["verdict"] in ("malicious", "suspicious")
    assert data["actuator_execution"]["success"] is True
