"""Smart Log queue and guarded AI decision-support endpoints."""
from __future__ import annotations

import hashlib
import json
import re
import time
import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ValidationError

from ..db.models import (
    AlertRecord, AuditEvent, DecisionCase, ResponseSimulation, SessionLocal, Setting,
)
from ..decision.engine import (
    build_smart_log,
    decision_messages,
    parse_and_guard_ai_decision,
    policy_decision,
)
from ..decision.models import GuardedDecision, SmartLog
from ..decision.audit import append_audit_event, verify_audit_chain
from ..config import ANALYST_ID, SIMULATOR_ALLOWED_ASSETS
from ..limiter import limiter
from ..llm.provider import get_provider
from ..llm.mitre_index import get_mitre_rag
from ..security import safe_llm_url
from ..actuators.router import default_router
from ..mitre.defense_rag import default_defense_rag
from ..mitre.semantic_rag import default_semantic_rag


router = APIRouter(prefix="/api/decision", tags=["smart-decision"])
log = logging.getLogger("cyberguard.api.decision")


def _get_rag():
    return get_mitre_rag()


class EvaluateRequest(BaseModel):
    refresh: bool = False
    autonomous_actuate: bool = False
    execution_mode: str = "simulation"


class ActuateRequest(BaseModel):
    action: str = "block_ip"
    target: str = ""
    mode: str = "simulation"
    params: dict = {}


class RollbackRequest(BaseModel):
    rollback_token: str


class AnalystFeedback(BaseModel):
    verdict: Literal["malicious", "suspicious", "benign", "needs_human"]
    notes: str = ""


class ResponseSimulationRequest(BaseModel):
    action: Literal[
        "observe", "alert", "escalate", "quarantine_recommended", "block_recommended"
    ]
    asset_ref: str
    ttl_seconds: int = 300
    approvals: int = 0
    idempotency_key: str


def _save_case(
    smart_log: SmartLog,
    decision: GuardedDecision | None = None,
) -> None:
    with SessionLocal() as session:
        case = session.query(DecisionCase).filter_by(alert_id=smart_log.alert_id).first()
        if case is None:
            case = DecisionCase(alert_id=smart_log.alert_id)
        case.smart_log_json = smart_log.model_dump_json()
        if decision is not None:
            case.decision_json = decision.model_dump_json()
            case.provider = decision.provider
            case.prompt_version = decision.prompt_version
            case.policy_version = decision.policy_version
        session.add(case)
        if decision is not None:
            append_audit_event(
                session,
                actor="cyberguard-policy",
                action="decision_evaluated",
                entity_type="alert",
                entity_id=smart_log.alert_id,
                payload={
                    "verdict": decision.verdict.value,
                    "source": decision.source,
                    "provider": decision.provider,
                    "model_version": decision.model_version,
                    "policy_version": decision.policy_version,
                    "prompt_version": decision.prompt_version,
                    "degraded": decision.degraded,
                    "executed_action": decision.executed_action,
                    "execution_mode": decision.execution_mode,
                    "rollback_token": decision.rollback_token,
                },
            )
        session.commit()



def _smart_log_for(alert_id: int) -> SmartLog:
    with SessionLocal() as session:
        alert = session.get(AlertRecord, alert_id)
        if alert is None:
            raise HTTPException(404, "Alert not found")
        smart_log = build_smart_log(alert)
    _save_case(smart_log)
    return smart_log


def _provider_settings() -> dict:
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


@router.get("/smart-log/{alert_id}")
@limiter.limit("60/minute")
def smart_log(request: Request, alert_id: int) -> dict:
    return _smart_log_for(alert_id).model_dump(mode="json")


@router.get("/queue")
@limiter.limit("30/minute")
def review_queue(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict]:
    result = []
    offset = 0
    batch_size = min(500, max(100, limit))
    with SessionLocal() as session:
        while len(result) < limit:
            rows = (
                session.query(DecisionCase)
                .order_by(DecisionCase.created_at.desc())
                .offset(offset)
                .limit(batch_size)
                .all()
            )
            if not rows:
                break
            offset += len(rows)
            for row in rows:
                try:
                    smart = SmartLog.model_validate_json(row.smart_log_json)
                except ValidationError as exc:
                    log.warning(
                        "Skipping invalid persisted Smart Log for alert %s: %s",
                        row.alert_id, exc,
                    )
                    continue
                if smart.review_required:
                    result.append({
                        "alert_id": smart.alert_id,
                        "event_id": smart.event_id,
                        "created_at": smart.created_at,
                        "type": smart.detection.type,
                        "severity": smart.detection.severity,
                        "review_reason": smart.review_reason,
                        "decided": bool(row.decision_json),
                        "provider": row.provider,
                        "prompt_version": row.prompt_version,
                        "policy_version": row.policy_version,
                        "analyst_verdict": row.analyst_verdict,
                        "reviewed_at": row.reviewed_at,
                    })
                    if len(result) == limit:
                        break
            if len(rows) < batch_size:
                break
    return result


@router.get("/case/{alert_id}")
@limiter.limit("60/minute")
def case_detail(request: Request, alert_id: int) -> dict:
    """Return the review-safe case, latest decision, feedback, and audit trail."""
    with SessionLocal() as session:
        case = session.query(DecisionCase).filter_by(alert_id=alert_id).first()
        if case is None:
            raise HTTPException(404, "Decision case not found")
        try:
            smart = SmartLog.model_validate_json(case.smart_log_json)
            decision = (
                GuardedDecision.model_validate_json(case.decision_json)
                if case.decision_json else None
            )
        except ValidationError as exc:
            raise HTTPException(409, "Persisted decision case failed schema validation") from exc
        events = (
            session.query(AuditEvent)
            .filter_by(entity_type="alert", entity_id=str(alert_id))
            .order_by(AuditEvent.id.asc())
            .all()
        )
        return {
            "smart_log": smart.model_dump(mode="json"),
            "decision": decision.model_dump(mode="json") if decision else None,
            "feedback": {
                "verdict": case.analyst_verdict,
                "notes": case.analyst_notes,
                "reviewed_by": case.reviewed_by,
                "reviewed_at": case.reviewed_at,
            },
            "versions": {
                "policy": case.policy_version,
                "prompt": case.prompt_version,
            },
            "audit": [{
                "id": event.id,
                "created_at": event.created_at,
                "actor": event.actor,
                "action": event.action,
                "event_hash": event.event_hash,
            } for event in events],
        }


def _feedback_conflicts(smart: SmartLog, verdict: str) -> bool:
    known_malicious = (
        not smart.review_required
        and smart.detection.stage == "classifier"
        and smart.detection.severity in {"high", "critical"}
    )
    known_benign = (
        not smart.review_required and smart.detection.type.lower() == "benign"
    )
    return (known_malicious and verdict == "benign") or (
        known_benign and verdict == "malicious"
    )


@router.get("/export-reviewed")
@limiter.limit("10/minute")
def export_reviewed(
    request: Request,
    include_conflicts: bool = False,
    limit: int = Query(default=5000, ge=1, le=10000),
) -> dict:
    """Export reviewed Smart Logs only; raw flows and analyst notes are excluded."""
    rows_out = []
    excluded_conflicts = 0
    with SessionLocal() as session:
        rows = (
            session.query(DecisionCase)
            .filter(DecisionCase.reviewed_at.is_not(None))
            .order_by(DecisionCase.reviewed_at.asc())
            .limit(limit)
            .all()
        )
        for case in rows:
            try:
                smart = SmartLog.model_validate_json(case.smart_log_json)
            except ValidationError:
                continue
            conflict = _feedback_conflicts(smart, case.analyst_verdict)
            if conflict and not include_conflicts:
                excluded_conflicts += 1
                continue
            rows_out.append({
                "smart_log": smart.model_dump(mode="json"),
                "analyst_verdict": case.analyst_verdict,
                "reviewed_by": case.reviewed_by,
                "reviewed_at": case.reviewed_at,
                "conflict": conflict,
            })
    return {
        "schema_version": "reviewed-cases-export-v1",
        "rows": rows_out,
        "excluded_conflicts": excluded_conflicts,
        "training_effect": "none_shadow_candidate_only",
    }


@router.get("/audit/verify")
@limiter.limit("10/minute")
def audit_verify(request: Request) -> dict:
    with SessionLocal() as session:
        events = session.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
        return {"valid": verify_audit_chain(events), "events": len(events)}


@router.post("/simulate-response/{alert_id}")
@limiter.limit("20/minute")
def simulate_response(
    request: Request,
    alert_id: int,
    options: ResponseSimulationRequest,
) -> dict:
    """Create an allowlisted response *plan*. No firewall/EDR call exists here."""
    asset = re.sub(r"[^A-Za-z0-9_.:@/-]", "", options.asset_ref).strip()[:128]
    key = re.sub(r"[^A-Za-z0-9_.:-]", "", options.idempotency_key).strip()[:64]
    if not asset or asset not in SIMULATOR_ALLOWED_ASSETS:
        raise HTTPException(422, "asset is not in CG_SIM_ASSETS")
    if not key or key != options.idempotency_key or len(key) < 8:
        raise HTTPException(422, "invalid idempotency key")
    if not 60 <= options.ttl_seconds <= 3600:
        raise HTTPException(422, "ttl_seconds must be between 60 and 3600")
    if not 0 <= options.approvals <= 2:
        raise HTTPException(422, "approvals must be between 0 and 2")

    with SessionLocal() as session:
        existing = session.query(ResponseSimulation).filter_by(idempotency_key=key).first()
        if existing:
            if existing.alert_id != alert_id:
                raise HTTPException(409, "idempotency key belongs to another alert")
            return {**json.loads(existing.response_json), "cached": True}

        case = session.query(DecisionCase).filter_by(alert_id=alert_id).first()
        if case is None or not case.decision_json:
            raise HTTPException(409, "evaluate the guarded decision before simulation")
        try:
            decision = GuardedDecision.model_validate_json(case.decision_json)
        except ValidationError as exc:
            raise HTTPException(409, "stored decision failed validation") from exc

        action_rank = {
            "observe": 0, "alert": 1, "escalate": 2,
            "quarantine_recommended": 3, "block_recommended": 3,
        }
        allowed_rank = action_rank[decision.recommended_action.value]
        if action_rank[options.action] > allowed_rank:
            raise HTTPException(409, "simulation action exceeds guarded recommendation")
        disruptive = options.action in {"quarantine_recommended", "block_recommended"}
        approvals_required = 2 if disruptive else 0
        status = (
            "approval_required" if options.approvals < approvals_required
            else "simulation_ready"
        )
        plan = {
            "schema_version": "response-simulation-v1",
            "alert_id": alert_id,
            "asset_ref": asset,
            "requested_action": options.action,
            "status": status,
            "ttl_seconds": options.ttl_seconds,
            "approvals": options.approvals,
            "approvals_required": approvals_required,
            "dry_run": True,
            "executed": False,
            "executed_action": "none",
            "rollback": "not_applicable_no_state_changed",
            "idempotency_key": key,
            "limitations": [
                "Simulation only: no firewall, EDR, host, or network integration exists.",
                "Approval counts are simulated and are not authenticated signatures.",
                "A future actuator requires scoped credentials, health checks, and rollback.",
            ],
            "cached": False,
        }
        session.add(ResponseSimulation(
            idempotency_key=key,
            alert_id=alert_id,
            asset_ref=asset,
            requested_action=options.action,
            approvals=options.approvals,
            ttl_seconds=options.ttl_seconds,
            response_json=json.dumps(plan, sort_keys=True),
        ))
        append_audit_event(
            session,
            actor=ANALYST_ID,
            action="response_simulated",
            entity_type="alert",
            entity_id=alert_id,
            payload={
                "requested_action": options.action,
                "asset_ref": asset,
                "status": status,
                "executed": False,
                "idempotency_key": key,
            },
        )
        session.commit()
        return plan


@router.post("/feedback/{alert_id}")
@limiter.limit("30/minute")
def submit_feedback(
    request: Request,
    alert_id: int,
    feedback: AnalystFeedback,
) -> dict:
    """Record trusted analyst feedback for later offline evaluation/training.

    This endpoint deliberately does not retrain or promote a model. Automated
    online learning from attacker-influenced uploads would enable data poisoning.
    """
    notes = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", feedback.notes).strip()
    # Identity comes from server configuration. Remote use is already guarded
    # by CG_API_TOKEN; an untrusted body cannot claim another analyst identity.
    reviewer = re.sub(r"[^A-Za-z0-9_.@ -]", "", ANALYST_ID).strip() or "local-analyst"
    if len(notes) > 2000:
        raise HTTPException(422, "Feedback fields exceed allowed length")

    with SessionLocal() as session:
        alert = session.get(AlertRecord, alert_id)
        if alert is None:
            raise HTTPException(404, "Alert not found")
        case = session.query(DecisionCase).filter_by(alert_id=alert_id).first()
        if case is None:
            case = DecisionCase(
                alert_id=alert_id,
                smart_log_json=build_smart_log(alert).model_dump_json(),
            )
        case.analyst_verdict = feedback.verdict
        case.analyst_notes = notes
        case.reviewed_by = reviewer
        case.reviewed_at = time.time()
        session.add(case)
        append_audit_event(
            session,
            actor=reviewer,
            action="analyst_feedback_recorded",
            entity_type="alert",
            entity_id=alert_id,
            payload={
                "verdict": feedback.verdict,
                "notes_sha256": hashlib.sha256(notes.encode()).hexdigest(),
            },
        )
        session.commit()

    return {
        "alert_id": alert_id,
        "status": "feedback_recorded",
        "reviewed_by": reviewer,
        "training_effect": "none_until_offline_validation",
    }


@router.post("/evaluate/{alert_id}")
@limiter.limit("20/minute")
async def evaluate(
    request: Request,
    alert_id: int,
    options: EvaluateRequest | None = None,
) -> dict:
    refresh = bool(options and options.refresh)
    autonomous_actuate = bool(options and options.autonomous_actuate)
    execution_mode = str(options.execution_mode) if options else "simulation"
    smart = _smart_log_for(alert_id)

    if not refresh:
        with SessionLocal() as session:
            cached = session.query(DecisionCase).filter_by(alert_id=alert_id).first()
            if cached and cached.decision_json:
                try:
                    decision = GuardedDecision.model_validate_json(cached.decision_json)
                    return {
                        "smart_log": smart.model_dump(mode="json"),
                        "decision": decision.model_dump(mode="json"),
                        "cached": True,
                    }
                except ValidationError as exc:
                    log.warning("Ignoring invalid cached decision for alert %s: %s",
                                alert_id, exc)

    baseline = policy_decision(smart)
    if not smart.review_required:
        _save_case(smart, baseline)
        return {
            "smart_log": smart.model_dump(mode="json"),
            "decision": baseline.model_dump(mode="json"),
            "cached": False,
        }

    query = " ".join([
        smart.detection.type,
        *smart.detection.mitre_techniques,
        *(name for name, _ in smart.detection.top_features),
    ])
    docs = _get_rag().query(query, k=4)
    context = "\n\n".join(doc["document"] for doc in docs)

    # Ground decision with verified D3FEND defensive countermeasures via Hybrid Graph-RAG
    defense_playbook = default_semantic_rag.retrieve_defense_playbook(
        label=smart.detection.type,
        techniques=smart.detection.mitre_techniques,
        telemetry=smart.source,
    )
    defense_context = default_semantic_rag.format_prompt_context(defense_playbook)

    try:
        provider = get_provider(_provider_settings())
        raw = await provider.chat(
            decision_messages(smart, context, defense_context), max_tokens=900
        )
        decision = parse_and_guard_ai_decision(
            raw,
            smart,
            provider.name,
            getattr(provider, "model", "unknown"),
            autonomous_actuate=autonomous_actuate,
            execution_mode=execution_mode,
        )
    except Exception as exc:
        log.warning("AI decision fallback for alert %s after %s",
                    alert_id, type(exc).__name__)
        decision = policy_decision(smart, degraded=True)
        decision.limitations.append(
            "AI provider was unavailable or returned an invalid structured decision."
        )

    _save_case(smart, decision)
    return {
        "smart_log": smart.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
        "cached": False,
    }


@router.post("/actuate/{alert_id}")
@limiter.limit("20/minute")
def actuate_alert(
    request: Request,
    alert_id: int,
    options: ActuateRequest,
) -> dict:
    """Manually or autonomously trigger a defensive actuator against an alert's threat."""
    smart = _smart_log_for(alert_id)
    target = options.target or smart.source.get("src_ip") or smart.source.get("remote_ip") or "192.168.1.100"
    res = default_router.execute_action(
        action=options.action,
        target=target,
        params=options.params,
        mode=options.mode,
    )
    with SessionLocal() as session:
        append_audit_event(
            session,
            actor=ANALYST_ID,
            action="manual_actuation",
            entity_type="alert",
            entity_id=alert_id,
            payload={
                "action": options.action,
                "target": target,
                "mode": options.mode,
                "success": res.success,
                "rollback_token": res.rollback_token,
                "simulated": res.simulated,
                "error": res.error,
            },
        )
        session.commit()
    return res.model_dump(mode="json")


@router.post("/rollback")
@limiter.limit("20/minute")
def rollback_action(
    request: Request,
    options: RollbackRequest,
) -> dict:
    """Roll back a previously executed or simulated mitigation by token."""
    success = default_router.rollback_action(options.rollback_token)
    with SessionLocal() as session:
        append_audit_event(
            session,
            actor=ANALYST_ID,
            action="rollback_executed",
            entity_type="action",
            entity_id=options.rollback_token,
            payload={"success": success, "token": options.rollback_token},
        )
        session.commit()
    return {"success": success, "token": options.rollback_token}


@router.get("/active-blocks")
@limiter.limit("30/minute")
def list_active_blocks(request: Request) -> list[dict]:
    """List all currently active or simulated mitigations."""
    return default_router.list_active_blocks()

