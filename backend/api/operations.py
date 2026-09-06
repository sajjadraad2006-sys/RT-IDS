"""Polled Live Operations snapshot with source-separated evidence."""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc

from ..config import ANALYST_ID, DB_PATH
from ..db.models import AlertRecord, DecisionCase, SecurityEventRecord, SessionLocal
from ..intelligence.threat_feeds import IntelligenceStore
from ..mitre import attack_db
from ..mitre.d3fend import D3fendStore
from ..operational import current_artifact_context
from ..operations.incidents import IncidentCapacityError, IncidentStore
from ..operations.risk import calculate_risk
from ..operations.triage import triage_evidence
from ..limiter import limiter

router = APIRouter(prefix="/api/operations", tags=["operations"])


class OsvQuery(BaseModel):
    ecosystem: str = Field(default="", max_length=64)
    name: str = Field(default="", max_length=256)
    version: str = Field(default="", max_length=128)


class IncidentResolution(BaseModel):
    verdict: str = Field(min_length=1, max_length=32)
    notes: str = Field(default="", max_length=2000)


def _alert_payload(row: AlertRecord, operational: dict) -> dict:
    try:
        techniques = json.loads(row.mitre_techniques or "[]")
    except json.JSONDecodeError:
        techniques = []
    triage = triage_evidence({
        "route": row.route,
        "confidence": row.confidence,
        "artifact_approved": operational["production_approved"],
        "artifact_status": operational["artifact_approval_state"],
        "evidence_refs": [f"alert:{row.id}"],
        "source_provenance": ["uploaded_flow_record"],
        "attack_candidates": techniques if row.stage == "classifier" else [],
        "timestamp": row.created_at,
    })
    return {
        "event_ref": f"alert:{row.id}",
        "id": row.id,
        "timestamp": row.created_at,
        "source_kind": "uploaded_flow_record",
        "source_status": "uploaded_evaluation" if not operational["production_approved"] else "uploaded_scoped_production",
        "severity": row.severity,
        "type": row.type,
        "stage": row.stage,
        "route": row.route,
        "confidence": row.confidence,
        "anomaly_score": row.anomaly_score,
        "attack_candidates": techniques if row.stage == "classifier" else [],
        "attack_candidate": (
            techniques[0] if row.stage == "classifier" and techniques else None
        ),
        "mapping_semantics": "heuristic_classifier_label_hypothesis",
        "triage": triage,
        "executed_action": "none",
    }


def _suricata_payload(row: SecurityEventRecord) -> dict:
    try:
        techniques = json.loads(row.mitre_techniques_json or "[]")
    except json.JSONDecodeError:
        techniques = []
    technique_ids = sorted({
        str(item.get("technique_id"))
        for item in techniques
        if isinstance(item, dict) and item.get("technique_id")
    })
    return {
        "event_ref": row.event_ref,
        "id": row.id,
        "timestamp": row.timestamp,
        "source_kind": "suricata_eve",
        "source_status": "uploaded_sensor_evidence",
        "source_event_type": row.source_event_type,
        "sensor_id": row.sensor_id,
        "flow_id": row.flow_id,
        "community_id": row.community_id,
        "signature_id": row.alert_signature_id,
        "signature": row.alert_signature,
        "severity": row.alert_severity or "info",
        "attack_candidates": technique_ids,
        "attack_candidate": technique_ids[0] if technique_ids else None,
        "mapping_semantics": "evidence-supported candidate ATT&CK mapping",
        "executed_action": "none",
    }


def _operations_snapshot(
    limit: int,
    *,
    materialize: bool = False,
) -> dict:
    """Return one bounded, stably ordered incremental UI snapshot."""
    operational = current_artifact_context()
    with SessionLocal() as session:
        alert_rows = (
            session.query(AlertRecord)
            .order_by(desc(AlertRecord.created_at), desc(AlertRecord.id))
            .limit(limit).all()
        )
        event_rows = (
            session.query(SecurityEventRecord)
            .order_by(desc(SecurityEventRecord.timestamp), desc(SecurityEventRecord.id))
            .limit(limit).all()
        )
        pending_reviews = session.query(DecisionCase).filter(
            DecisionCase.reviewed_at.is_(None)
        ).count()

    alerts = [_alert_payload(row, operational) for row in alert_rows]
    suricata = [_suricata_payload(row) for row in event_rows]
    incident_store = IncidentStore(DB_PATH)
    correlation_errors: list[str] = []
    if materialize:
        for item in alerts:
            try:
                correlated = incident_store.ingest({
                    **item,
                    "sensor_id": "uploaded-flow",
                    "signature_id": f"model:{item['type']}",
                }, count_duplicate=False)
                incident_store.record_triage(correlated["incident_id"], item["triage"])
            except IncidentCapacityError as exc:
                correlation_errors.append(str(exc))
                break
        for item in suricata:
            try:
                correlated = incident_store.ingest(item, count_duplicate=False)
                sensor_triage = triage_evidence({
                    "route": "human_review" if item["source_event_type"] == "alert" else "",
                    "confidence": 0,
                    "artifact_approved": False,
                    "artifact_status": "sensor_evidence_requires_analyst_correlation",
                    "evidence_refs": [item["event_ref"]],
                    "source_provenance": ["suricata_eve"],
                    "attack_candidates": item["attack_candidates"],
                    "timestamp": item["timestamp"],
                })
                incident_store.record_triage(correlated["incident_id"], sensor_triage)
            except IncidentCapacityError as exc:
                correlation_errors.append(str(exc))
                break

    intelligence = IntelligenceStore(DB_PATH)
    kev_health = intelligence.health("cisa_kev")
    epss_health = intelligence.health("first_epss")
    d3fend_health = D3fendStore(DB_PATH).health()
    attack_health = attack_db.get_stats()
    freshness_values = [
        kev_health["freshness_status"], epss_health["freshness_status"]
    ]
    combined_freshness = (
        "fresh" if all(item == "fresh" for item in freshness_values)
        else "stale" if "stale" in freshness_values else "unavailable"
    )
    incidents = incident_store.list_incidents(limit=limit)
    for incident in incidents:
        linked_evidence = incident_store.evidence(incident["incident_id"])
        cves = sorted({
            str(item.get("cve", "")).upper()
            for item in linked_evidence if item.get("cve")
        })[:32]
        vulnerability_contexts = [
            intelligence.vulnerability_context(cve) for cve in cves
        ]
        applicable = [
            item for item in vulnerability_contexts if item.get("status") == "applicable"
        ]
        epss_scores = [
            float(item["epss"]["score"])
            for item in applicable if item.get("epss")
        ]
        attack_ids = sorted({
            str(item.get("attack_candidate", ""))
            for item in linked_evidence if item.get("attack_candidate")
        })
        attack_verified = any(
            attack_db.check_technique_status(technique_id)[0] == "active_validated"
            for technique_id in attack_ids
        )
        classifier_confidences = [
            float(item["confidence"])
            for item in linked_evidence if item.get("confidence") is not None
        ]
        incident["risk"] = calculate_risk({
            "sensor_severity": incident["severity"],
            "classifier_confidence": (
                max(classifier_confidences) if classifier_confidences else None
            ),
            "kev": any(item.get("kev") for item in applicable),
            "epss_score": max(epss_scores) if epss_scores else None,
            "attack_verified": attack_verified,
            "intelligence_freshness": combined_freshness,
            "uncertainty": 0.25,
        })
        incident["vulnerability_intelligence"] = vulnerability_contexts
        incident["attack_candidates"] = attack_ids

    latest_alert = max((row.created_at for row in alert_rows), default=None)
    latest_suricata = max((row.timestamp for row in event_rows), default=None)
    generated_at = time.time()
    return {
        "snapshot_version": "live-operations-v1",
        "sequence": {
            "uploaded_flow_records": max((row.id for row in alert_rows), default=0),
            "suricata_eve": max((row.id for row in event_rows), default=0),
        },
        "generated_at": generated_at,
        "refresh_mode": "bounded_polling",
        "poll_interval_seconds": 4,
        "operational_mode": operational["operational_mode"],
        "artifact": operational,
        "evidence_by_source": {
            "uploaded_flow_records": {
                "status": "uploaded_not_continuous_ingestion",
                "freshest_event_at": latest_alert,
                "records": alerts,
            },
            "suricata_eve": {
                "status": "uploaded_eve_not_sensor_stream",
                "freshest_event_at": latest_suricata,
                "records": suricata,
            },
            "demo_data": {"status": "separate_client_only", "records": []},
            "future_adapters": {"status": "not_configured", "records": []},
        },
        "incidents": incidents,
        "correlation_health": {
            "status": "degraded_capacity" if correlation_errors else "available",
            "last_error": correlation_errors[-1] if correlation_errors else None,
            "max_incidents": incident_store.max_incidents,
            "max_evidence_per_incident": incident_store.max_evidence,
        },
        "review_exceptions": pending_reviews,
        "source_health": {
            "correlation": {
                "status": "degraded_capacity" if correlation_errors else "available",
                "last_error": correlation_errors[-1] if correlation_errors else None,
            },
            "model_pipeline": {
                "status": operational["operational_mode"],
                "freshest_event_at": latest_alert,
            },
            "suricata": {
                "status": "available" if event_rows else "no_uploaded_evidence",
                "freshest_event_at": latest_suricata,
            },
            "attack": attack_health,
            "d3fend": d3fend_health,
            "cisa_kev": kev_health,
            "first_epss": epss_health,
            "osv": {
                "status": "on_demand_package_context_required",
                "freshness_status": "not_applicable_without_package_context",
            },
        },
        "limitations": [
            "This page polls persisted uploaded records; it is not packet capture.",
            "Model artifacts remain evaluation-only unless the artifact banner says otherwise.",
            "All containment and high-impact response remains human-authorized.",
        ],
        "executed_action": "none",
    }


@router.get("/snapshot")
def operations_snapshot(
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    """Read the current snapshot without changing correlation state."""
    return _operations_snapshot(limit, materialize=False)


@router.post("/refresh")
@limiter.limit("20/minute")
def refresh_operations(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    """Idempotently materialize unseen evidence, then return the snapshot."""
    return _operations_snapshot(limit, materialize=True)


@router.get("/vulnerabilities/{cve}")
def vulnerability_context(cve: str) -> dict:
    """Join KEV/EPSS only through a syntactically valid CVE identifier."""
    return IntelligenceStore(DB_PATH).vulnerability_context(cve)


@router.post("/osv/query")
@limiter.limit("10/minute")
def osv_query(request: Request, query: OsvQuery) -> dict:
    """Query/cache OSV only with explicit ecosystem, package, and version."""
    return IntelligenceStore(DB_PATH).query_osv(query.model_dump())


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: str) -> dict:
    store = IncidentStore(DB_PATH)
    incidents = {
        item["incident_id"]: item for item in store.list_incidents(limit=5000)
    }
    if incident_id not in incidents:
        raise HTTPException(404, "incident not found")
    return {
        "incident": incidents[incident_id],
        "evidence": store.evidence(incident_id),
        "analyst_audit": store.analyst_audit(incident_id),
        "executed_action": "none",
    }


@router.post("/incidents/{incident_id}/resolve")
@limiter.limit("10/minute")
def resolve_incident(
    request: Request, incident_id: str, resolution: IncidentResolution
) -> dict:
    try:
        return IncidentStore(DB_PATH).resolve_by_analyst(
            incident_id,
            actor=ANALYST_ID,
            verdict=resolution.verdict,
            notes=resolution.notes,
        )
    except ValueError as exc:
        message = str(exc)
        raise HTTPException(404 if "does not exist" in message else 422, message) from exc
