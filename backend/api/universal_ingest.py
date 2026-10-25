"""Universal Multi-Format File & Document Ingestion API.

Processes arbitrary file uploads (PDF, DOCX, EVTX/XML, JSON, YAML, HTML, Logs, Text)
using UniversalDocumentParser, extracts cyber indicators, correlates with MITRE ATT&CK & D3FEND,
and triggers autonomous AI triage and containment.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional, Tuple
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from ..actuators.router import default_router
from ..auth import require_role, Role, User
from ..db.models import Setting
from ..decision.engine import build_smart_log, decision_messages, parse_and_guard_ai_decision
from ..decision.models import GuardedDecision, SmartLog
from ..ingestion.universal_parser import default_universal_parser
from ..llm.provider import get_provider
from ..mitre.defense_rag import default_defense_rag
from ..security import safe_llm_url

logger = logging.getLogger("cyberguard.api.universal_ingest")
router = APIRouter(prefix="/api/detect", tags=["ingestion"])


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


class MockIngestRecord:
    def __init__(
        self,
        alert_id: int,
        threat_type: str,
        severity: str,
        confidence: float,
        evidence: dict,
        mitre_techniques: list,
        route: str = "autonomous_containment",
    ):
        self.id = alert_id
        self.type = threat_type
        self.severity = severity
        self.stage = "classifier"
        self.route = route
        self.confidence = confidence
        self.anomaly_score = 0.95 if severity in ("high", "critical") else (0.3 if severity == "medium" else 0.0)
        self.created_at = time.time()
        self.evidence_json = json.dumps(evidence)
        self.input_schema_json = json.dumps({"detected_input_profile": "universal_document", "feature_coverage_percentage": 100.0})
        self.mitre_techniques = json.dumps(mitre_techniques)
        self.top_features = json.dumps([["ioc_density", float(len(evidence.get("iocs", {}).get("extracted_ips", [])))]])


class RawTextIngestRequest(BaseModel):
    raw_text: str = Field(..., description="Raw text, log dump, terminal paste, or IOC advisory")
    filename: Optional[str] = Field("pasted_telemetry.log", description="Virtual filename identifier")
    auto_triage: bool = Field(True, description="Execute autonomous LLM triage and containment")
    enforce_live: bool = Field(False, description="Enact real OS firewall rules if containment triggered")


async def _execute_doc_triage(
    target_name: str,
    content_bytes: bytes,
    auto_triage: bool,
    enforce_live: bool,
) -> Dict[str, Any]:
    """Helper to parse document, run RAG, and execute autonomous triage."""
    start_time = time.perf_counter()
    parse_result = default_universal_parser.parse_file(target_name, content_bytes)

    iocs = parse_result["iocs"]
    playbook = parse_result["grounded_mitre_playbook"]
    suggested_log = parse_result["suggested_smart_log"]

    decision_dict = None
    actuator_dict = None

    if auto_triage:
        primary_ip = iocs["primary_ip"]
        primary_port = iocs["primary_port"]
        techniques = suggested_log["mitre_techniques"]
        is_known_benign = not techniques and not iocs.get("cve_identifiers") and not iocs.get("observed_keywords")
        route_str = "known_benign" if is_known_benign else "document_triage"

        record = MockIngestRecord(
            alert_id=int(time.time() % 100000) + 1,
            threat_type=suggested_log["threat_label"][:64],
            severity=suggested_log["severity"],
            confidence=suggested_log["confidence"],
            evidence={
                "source_file": target_name,
                "iocs": iocs,
                "cves": iocs["cve_identifiers"],
                "keywords": iocs["observed_keywords"],
            },
            mitre_techniques=techniques,
            route=route_str,
        )

        smart_log = build_smart_log(record)
        smart_log.source["src_ip"] = primary_ip
        smart_log.source["dest_port"] = str(primary_port) if primary_port is not None else ""

        defense_context = default_defense_rag.format_prompt_context(playbook)
        mitre_context = f"File: {target_name}. Techniques: {', '.join(techniques)}. CVEs: {', '.join(iocs['cve_identifiers'])}."
        exec_mode = "enforcement" if enforce_live else "simulation"

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
            logger.warning("Doc triage LLM error: %s, falling back to verified RAG playbook", exc)
            concrete_action = playbook["concrete_actions"][0]["action"] if playbook["concrete_actions"] else "block_ip"
            fallback_json = json.dumps({
                "verdict": "malicious" if suggested_log["severity"] in ("high", "critical") else "suspicious",
                "confidence": 0.90,
                "recommended_action": concrete_action,
                "rationale": f"Autonomous document triage for {target_name}. Indicators: {', '.join(iocs['observed_keywords']) or 'anomalous ioc patterns'}.",
                "evidence": [f"Suspect IP: {primary_ip}", f"Extracted Indicators: {len(iocs['extracted_ips'])} IPs, {len(iocs['cve_identifiers'])} CVEs"],
                "containment": [f"{concrete_action} {primary_ip}"],
                "limitations": ["Autonomous triage safeguard active."],
            })
            decision = parse_and_guard_ai_decision(
                fallback_json,
                smart_log,
                provider="genius-rag-policy",
                model_version="Foundation-Sec-Policy-Fallback",
                autonomous_actuate=True,
                execution_mode=exec_mode,
            )

        decision_dict = {
            "verdict": decision.verdict.value,
            "confidence": decision.confidence,
            "recommended_action": decision.recommended_action.value,
            "rationale": decision.rationale,
            "evidence": decision.evidence,
            "containment": decision.containment,
            "executed_action": decision.executed_action,
            "execution_mode": decision.execution_mode,
            "rollback_token": decision.rollback_token,
            "provider": decision.provider,
            "model_version": decision.model_version,
        }
        actuator_dict = decision.actuator_result

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    if decision_dict:
        try:
            from ..db.models import SessionLocal, AlertRecord
            with SessionLocal() as db_session:
                alert_rec = AlertRecord(
                    created_at=time.time(),
                    severity=suggested_log.get("severity", "medium"),
                    type=f"Doc Ingest: {target_name}",
                    confidence=decision_dict.get("confidence", 0.9),
                    anomaly_score=0.95 if decision_dict.get("verdict") == "malicious" else 0.2,
                    stage="classifier",
                    mitre_techniques=json.dumps([t["technique_id"] for t in playbook.get("techniques", [])]),
                    latency_ms=duration_ms,
                    source_file=f"upload://{target_name}",
                    explanation=decision_dict.get("rationale", ""),
                    top_features=json.dumps([
                        ["doc_name", target_name],
                        ["doc_format", parse_result["format_detected"]],
                        ["action", decision_dict.get("executed_action", "none")],
                    ]),
                    route="autonomous_containment",
                    pipeline_version="cyberguard-active-defense-v1",
                    evidence_json=json.dumps({
                        "evidence": decision_dict.get("evidence", []),
                        "containment": decision_dict.get("containment", []),
                        "rollback_token": decision_dict.get("rollback_token"),
                        "actuator_result": actuator_dict,
                    }),
                    input_schema_json=json.dumps({"filename": target_name, "iocs": iocs}),
                )
                db_session.add(alert_rec)
                db_session.commit()
        except Exception:
            pass

    return {
        "status": "success",
        "duration_ms": duration_ms,
        "document_summary": {
            "filename": target_name,
            "format_detected": parse_result["format_detected"],
            "total_characters": parse_result["total_characters"],
            "text_excerpt": parse_result["text_excerpt"],
        },
        "extracted_iocs": iocs,
        "mitre_grounding": {
            "matched_techniques": [t["technique_id"] for t in playbook.get("techniques", [])],
            "d3fend_countermeasures": playbook.get("d3fend_countermeasures", []),
            "concrete_actions": playbook.get("concrete_actions", []),
        },
        "suggested_smart_log": suggested_log,
        "ai_triage": decision_dict,
        "actuator_execution": actuator_dict,
    }


@router.post("/universal-ingest")
async def ingest_universal_document(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    auto_triage: bool = Form(True),
    enforce_live: bool = Form(False),
    user: User = Depends(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """Ingest arbitrary documents (PDF, DOCX, EVTX, XML, JSON, logs) and run autonomous cyber triage."""
    if file and file.filename:
        target_name = file.filename
        content_bytes = await file.read()
    elif raw_text:
        target_name = filename or "raw_text_input.txt"
        content_bytes = raw_text.encode("utf-8", errors="replace")
    else:
        raise HTTPException(status_code=400, detail="Must provide either a file upload or raw_text string.")

    if not content_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file or content is empty.")

    return await _execute_doc_triage(target_name, content_bytes, auto_triage, enforce_live)


@router.post("/universal-ingest/raw")
async def ingest_raw_telemetry(
    req: RawTextIngestRequest,
    user: User = Depends(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """JSON-based endpoint for raw text/log dumps or scripts."""
    content_bytes = req.raw_text.encode("utf-8", errors="replace")
    target_name = req.filename or "raw_telemetry.log"
    return await _execute_doc_triage(target_name, content_bytes, req.auto_triage, req.enforce_live)
