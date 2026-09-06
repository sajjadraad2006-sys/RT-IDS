"""API router for Suricata EVE security event ingestion and analyst review."""
from __future__ import annotations

import collections
import json
import logging
import re
import time
import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request, UploadFile
from sqlalchemy import desc, select

from ..config import (
    ANALYST_ID,
    MAX_UPLOAD_MB,
)
from ..db.models import (
    SecurityEventRecord,
    SecurityEventTechniqueMapping,
    SessionLocal,
    Setting,
    SuricataIngestionRecord,
)
from ..limiter import limiter
from ..security import safe_llm_url
from ..suricata.advisory import build_suricata_alert_prompt, deterministic_suricata_summary
from ..suricata.attack_extractor import get_active_attack_snapshot_info
from ..suricata.parser import (
    MAX_LINE_BYTES,
    SuricataParseError,
    iter_eve_stream,
)
from ..suricata.schema import (
    SECURITY_EVENT_SCHEMA_VERSION,
    SURICATA_ADAPTER_VERSION,
    SecurityEventV1,
    SuricataIngestionReport,
)

log = logging.getLogger("cyberguard.api.events")

router = APIRouter(prefix="/api/events/suricata", tags=["suricata_events"])


def _try_int(val):
    """Parse a string-stored value back to int if possible, else return as-is."""
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return val


BATCH_SIZE = 500
DEFAULT_MAX_PERSIST = 10000
DEFAULT_MAX_RETURN = 500
DEFAULT_MAX_LINES = 500000
MAX_DEDUP_WINDOW = 50000
MAX_DISTINCT_EVENT_TYPES = 50


@router.post("/upload")
@limiter.limit("10/minute")
async def upload_suricata_eve(
    request: Request,
    file: UploadFile,
    sensor_id: str | None = Query(default=None, max_length=64),
) -> dict:
    """Stream and ingest Suricata EVE JSON / JSONL / NDJSON logs with strict validation."""
    started = time.perf_counter()
    filename_raw = (file.filename or "eve.json").strip()
    filename = re.sub(r"[\x00-\x1f\x7f/\\]", "_", filename_raw)[:255] or "eve.json"
    effective_sensor_id = re.sub(r"[^\w\-\.]", "_", (sensor_id or "suricata-default").strip())[:64] or "suricata-default"

    ingestion_id = uuid.uuid4().hex
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    max_lines = DEFAULT_MAX_LINES
    max_persist = DEFAULT_MAX_PERSIST
    max_return = DEFAULT_MAX_RETURN

    counts_by_type: dict[str, int] = {}
    rejection_reasons: dict[str, int] = {}
    returned_events: list[dict] = []

    total_parsed = 0
    accepted = 0
    rejected_lines = 0
    ignored_unsupported = 0
    alert_events_accepted = 0
    eligible_for_persistence = 0
    persisted_count = 0
    omitted_due_to_cap = 0
    duplicates_in_upload = 0
    duplicates_already_persisted = 0

    # Bounded in-memory deduplication window (CG-SUR-002)
    seen_upload_refs: set[str] = set()
    seen_upload_queue: collections.deque[str] = collections.deque()

    def record_seen_upload_ref(ref: str) -> bool:
        if ref in seen_upload_refs:
            return True
        if len(seen_upload_queue) >= MAX_DEDUP_WINDOW:
            old = seen_upload_queue.popleft()
            seen_upload_refs.discard(old)
        seen_upload_queue.append(ref)
        seen_upload_refs.add(ref)
        return False

    def record_type_count(tname: str) -> None:
        if tname in counts_by_type:
            counts_by_type[tname] += 1
        elif len(counts_by_type) < MAX_DISTINCT_EVENT_TYPES:
            counts_by_type[tname] = 1
        else:
            counts_by_type["other_unsupported"] = counts_by_type.get("other_unsupported", 0) + 1

    snapshot_info = get_active_attack_snapshot_info()

    session = SessionLocal()
    try:
        # Create initial in-progress ingestion record inside the transaction
        ingestion_rec = SuricataIngestionRecord(
            ingestion_id=ingestion_id,
            source_file=filename,
            sensor_id=effective_sensor_id,
            status="in_progress",
        )
        session.add(ingestion_rec)
        session.flush()

        pending_events_for_batch: list[SecurityEventV1] = []
        persisted_id_map: dict[str, int] = {}

        def flush_batch() -> None:
            nonlocal pending_events_for_batch, persisted_count, duplicates_already_persisted, duplicates_in_upload, omitted_due_to_cap
            if not pending_events_for_batch:
                return

            candidate_refs = [e.event_ref for e in pending_events_for_batch]
            # Query existing refs and their ingestion_id (CG-RE-001: correct accounting across upload window)
            existing_rows = session.execute(
                select(SecurityEventRecord.event_ref, SecurityEventRecord.ingestion_id).where(
                    SecurityEventRecord.sensor_id == effective_sensor_id,
                    SecurityEventRecord.event_ref.in_(candidate_refs),
                )
            ).all()
            existing_in_db = {r[0]: r[1] for r in existing_rows}

            to_insert_records: list[SecurityEventRecord] = []
            to_insert_techniques: list[list] = []
            seen_in_this_batch: set[str] = set()

            for ev in pending_events_for_batch:
                if ev.event_ref in existing_in_db:
                    saved_ingestion = existing_in_db[ev.event_ref]
                    if saved_ingestion == ingestion_id:
                        duplicates_in_upload += 1
                    else:
                        duplicates_already_persisted += 1
                    continue

                if ev.event_ref in seen_in_this_batch:
                    duplicates_in_upload += 1
                    continue

                seen_in_this_batch.add(ev.event_ref)
                existing_in_db[ev.event_ref] = ingestion_id

                if persisted_count < max_persist:
                    persisted_count += 1
                    rec = SecurityEventRecord(
                        event_ref=ev.event_ref,
                        ingestion_id=ingestion_id,
                        schema_version=ev.schema_version,
                        adapter_version=ev.adapter_version,
                        source_kind=ev.source_kind,
                        source_event_type=ev.source_event_type,
                        sensor_id=ev.sensor_id,
                        source_line_number=ev.source_line_number,
                        timestamp=ev.timestamp,
                        timestamp_iso=ev.timestamp_iso,
                        flow_id=ev.flow_id,
                        community_id=ev.community_id,
                        proto=ev.proto,
                        app_proto=ev.app_proto,
                        src_ip=ev.src_ip,
                        src_port=ev.src_port,
                        dest_ip=ev.dest_ip,
                        dest_port=ev.dest_port,
                        alert_signature=ev.alert_signature,
                        alert_signature_id=ev.alert_signature_id,
                        alert_category=ev.alert_category,
                        alert_severity=ev.alert_severity,
                        source_sensor_severity_raw=str(ev.source_sensor_severity_raw) if ev.source_sensor_severity_raw is not None else None,
                        source_sensor_action=ev.source_sensor_action,
                        executed_action=ev.executed_action,
                        evidence_json=json.dumps(ev.evidence, sort_keys=True, allow_nan=False),
                        mitre_techniques_json=json.dumps(
                            [m.model_dump() for m in ev.mitre_techniques], sort_keys=True, allow_nan=False
                        ),
                        source_file=filename,
                    )
                    to_insert_records.append(rec)
                    to_insert_techniques.append(ev.mitre_techniques)
                else:
                    omitted_due_to_cap += 1

            if to_insert_records:
                session.add_all(to_insert_records)
                session.flush()

                technique_batch: list[SecurityEventTechniqueMapping] = []
                for rec, raw_techs in zip(to_insert_records, to_insert_techniques):
                    persisted_id_map[rec.event_ref] = rec.id
                    for tech in raw_techs:
                        technique_batch.append(
                            SecurityEventTechniqueMapping(
                                security_event_id=rec.id,
                                technique_id=tech.technique_id,
                                tactic_id=tech.tactic_id,
                                signature_id=tech.signature_id,
                                validation_status=tech.validation_status.value if hasattr(tech.validation_status, "value") else str(tech.validation_status),
                                rule_match_observed=tech.rule_match_observed,
                                mapping_evidence_present=tech.mapping_evidence_present,
                                technique_observed=tech.technique_observed,
                                evidence_kind=tech.evidence_kind,
                                mapping_semantics=tech.mapping_semantics,
                                mapping_version=tech.mapping_version,
                                metadata_extraction_confidence=tech.metadata_extraction_confidence,
                                technique_occurrence_confidence=tech.technique_occurrence_confidence,
                                evidence_ref=tech.evidence_ref,
                                snapshot_version=tech.snapshot_version,
                                snapshot_source=tech.snapshot_source,
                                snapshot_indexed_time=tech.snapshot_indexed_time,
                            )
                        )
                if technique_batch:
                    session.add_all(technique_batch)
                    session.flush()
                    for tm in technique_batch:
                        session.expunge(tm)
                    technique_batch.clear()

                # Expunge only inserted records from session to avoid unbounded memory without detaching ingestion_rec (CG-SUR-001)
                for rec in to_insert_records:
                    session.expunge(rec)

            pending_events_for_batch.clear()

        try:
            for item in iter_eve_stream(
                file.file,
                filename=filename,
                sensor_id=effective_sensor_id,
                max_bytes=max_bytes,
                max_lines=max_lines,
            ):
                total_parsed += 1

                if item.error_reason:
                    rejected_lines += 1
                    rejection_reasons[item.error_reason] = (
                        rejection_reasons.get(item.error_reason, 0) + 1
                    )
                    continue

                if item.is_ignored:
                    ignored_unsupported += 1
                    record_type_count(item.ignored_type)
                    continue

                event: SecurityEventV1 | None = item.event
                if event is None:
                    continue

                accepted += 1
                record_type_count(event.source_event_type)
                if event.source_event_type == "alert":
                    alert_events_accepted += 1

                ref = event.event_ref
                if record_seen_upload_ref(ref):
                    duplicates_in_upload += 1
                    continue

                eligible_for_persistence += 1
                pending_events_for_batch.append(event)

                if len(pending_events_for_batch) >= BATCH_SIZE:
                    flush_batch()

                if len(returned_events) < max_return:
                    payload = event.to_dict()
                    returned_events.append(payload)

            flush_batch()

            for payload in returned_events:
                ref = payload.get("event_ref")
                if ref in persisted_id_map:
                    payload["id"] = persisted_id_map[ref]

        except SuricataParseError as exc:
            session.rollback()
            reason = str(exc)
            if reason == "upload_byte_limit_exceeded":
                raise HTTPException(413, f"Upload exceeds {MAX_UPLOAD_MB} MB limit") from exc
            if reason == "upload_line_limit_exceeded":
                raise HTTPException(413, f"Upload exceeds {max_lines} line limit") from exc
            if reason == "unsupported_file_extension":
                raise HTTPException(422, "Supported EVE containers are .json, .jsonl, and .ndjson") from exc
            if reason == "empty_upload":
                raise HTTPException(400, "Empty upload") from exc
            if reason == "binary_content_not_supported":
                raise HTTPException(400, "Binary content is not supported") from exc
            raise HTTPException(400, f"Parse failure: {reason}") from exc

        if accepted == 0:
            session.rollback()
            raise HTTPException(
                422,
                detail={
                    "message": "No usable Suricata EVE events found in upload",
                    "total_parsed": total_parsed,
                    "rejected_lines": rejected_lines,
                    "ignored_unsupported": ignored_unsupported,
                    "rejection_reasons": rejection_reasons,
                },
            )

        elapsed = time.perf_counter() - started
        report = SuricataIngestionReport(
            ingestion_id=ingestion_id,
            source_file=filename,
            sensor_id=effective_sensor_id,
            adapter_version=SURICATA_ADAPTER_VERSION,
            schema_version=SECURITY_EVENT_SCHEMA_VERSION,
            status="completed",
            total_parsed=total_parsed,
            accepted=accepted,
            rejected_lines=rejected_lines,
            ignored_unsupported_types=ignored_unsupported,
            counts_by_event_type=counts_by_type,
            alert_events_accepted=alert_events_accepted,
            eligible_for_persistence=eligible_for_persistence,
            persisted=persisted_count,
            omitted_due_to_persistence_cap=omitted_due_to_cap,
            duplicates_in_upload=duplicates_in_upload,
            duplicates_already_persisted=duplicates_already_persisted,
            newly_persisted_events=persisted_count,
            returned_events_count=len(returned_events),
            caps={
                "max_upload_bytes": max_bytes,
                "max_lines": max_lines,
                "max_line_bytes": MAX_LINE_BYTES,
                "max_return_events": max_return,
                "max_persist_events": max_persist,
            },
            rejection_reasons=rejection_reasons,
            active_attack_snapshot=snapshot_info,
            events=returned_events,
            elapsed_seconds=round(elapsed, 3),
            executed_action="none",
        )

        # Update ingestion record and commit (CG-SUR-001, CG-RE-005)
        if ingestion_rec not in session:
            session.add(ingestion_rec)
        ingestion_rec.status = "completed"
        ingestion_rec.total_parsed = total_parsed
        ingestion_rec.accepted = accepted
        ingestion_rec.persisted = persisted_count
        ingestion_rec.rejected_lines = rejected_lines
        ingestion_rec.duplicates_count = duplicates_in_upload + duplicates_already_persisted
        ingestion_rec.report_json = json.dumps(report.to_dict(), sort_keys=True, allow_nan=False)
        ingestion_rec.completed_at = time.time()
        session.commit()

        log.info(
            "Suricata upload %s (id=%s): parsed=%d accepted=%d persisted=%d alerts=%d dups=%d",
            filename, ingestion_id, total_parsed, accepted, persisted_count,
            alert_events_accepted, duplicates_in_upload + duplicates_already_persisted,
        )
        return report.to_dict()

    except HTTPException:
        session.rollback()
        raise
    except Exception as exc:
        session.rollback()
        log.exception("Unexpected error during Suricata upload: %s", exc)
        raise HTTPException(500, "Internal error processing Suricata upload") from exc
    finally:
        session.close()


@router.get("/events")
def list_suricata_events(
    event_type: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=32),
    technique_id: str | None = Query(default=None, max_length=32),
    sensor_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """List ingested Suricata events with optional filtering and pagination."""
    with SessionLocal() as s:
        q = s.query(SecurityEventRecord)
        if event_type:
            q = q.filter(SecurityEventRecord.source_event_type == event_type.lower())
        if severity:
            q = q.filter(SecurityEventRecord.alert_severity == severity.lower())
        if sensor_id:
            q = q.filter(SecurityEventRecord.sensor_id == sensor_id)
        if technique_id:
            q = q.join(
                SecurityEventTechniqueMapping,
                SecurityEventTechniqueMapping.security_event_id == SecurityEventRecord.id
            ).filter(SecurityEventTechniqueMapping.technique_id == technique_id.upper())

        total = q.count()
        rows = q.order_by(SecurityEventRecord.timestamp.desc(), SecurityEventRecord.id.desc()).offset(offset).limit(limit).all()

        results = []
        for r in rows:
            results.append({
                "id": r.id,
                "event_ref": r.event_ref,
                "ingestion_id": r.ingestion_id,
                "schema_version": r.schema_version,
                "adapter_version": r.adapter_version,
                "source_kind": r.source_kind,
                "source_event_type": r.source_event_type,
                "sensor_id": r.sensor_id,
                "source_line_number": r.source_line_number,
                "timestamp": r.timestamp,
                "timestamp_iso": r.timestamp_iso,
                "flow_id": r.flow_id,
                "community_id": r.community_id,
                "proto": r.proto,
                "app_proto": r.app_proto,
                "src_ip": r.src_ip,
                "src_port": r.src_port,
                "dest_ip": r.dest_ip,
                "dest_port": r.dest_port,
                "alert_signature": r.alert_signature,
                "alert_signature_id": r.alert_signature_id,
                "alert_category": r.alert_category,
                "alert_severity": r.alert_severity,
                "source_sensor_severity_raw": _try_int(r.source_sensor_severity_raw),
                "source_sensor_action": r.source_sensor_action,
                "executed_action": r.executed_action,
                "evidence": json.loads(r.evidence_json or "{}"),
                "mitre_techniques": json.loads(r.mitre_techniques_json or "[]"),
                "source_file": r.source_file,
                "created_at": r.created_at,
            })

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": results,
            "executed_action": "none",
        }


@router.get("/events/{event_id}")
def get_suricata_event(event_id: int) -> dict:
    """Retrieve full details and validated technique provenance for a single security event."""
    with SessionLocal() as s:
        rec = s.get(SecurityEventRecord, event_id)
        if not rec:
            raise HTTPException(404, "Security event not found")

        tech_mappings = s.query(SecurityEventTechniqueMapping).filter_by(security_event_id=rec.id).all()
        techniques = [
            {
                "technique_id": m.technique_id,
                "tactic_id": m.tactic_id,
                "signature_id": m.signature_id,
                "validation_status": m.validation_status,
                "rule_match_observed": m.rule_match_observed,
                "mapping_evidence_present": m.mapping_evidence_present,
                "technique_observed": m.technique_observed,
                "evidence_kind": m.evidence_kind,
                "mapping_semantics": m.mapping_semantics,
                "mapping_version": m.mapping_version,
                "metadata_extraction_confidence": m.metadata_extraction_confidence,
                "technique_occurrence_confidence": m.technique_occurrence_confidence,
                "evidence_ref": m.evidence_ref,
                "snapshot_version": m.snapshot_version,
                "snapshot_source": m.snapshot_source,
                "snapshot_indexed_time": m.snapshot_indexed_time,
            }
            for m in tech_mappings
        ]

        return {
            "id": rec.id,
            "event_ref": rec.event_ref,
            "ingestion_id": rec.ingestion_id,
            "schema_version": rec.schema_version,
            "adapter_version": rec.adapter_version,
            "source_kind": rec.source_kind,
            "source_event_type": rec.source_event_type,
            "sensor_id": rec.sensor_id,
            "source_line_number": rec.source_line_number,
            "timestamp": rec.timestamp,
            "timestamp_iso": rec.timestamp_iso,
            "flow_id": rec.flow_id,
            "community_id": rec.community_id,
            "proto": rec.proto,
            "app_proto": rec.app_proto,
            "src_ip": rec.src_ip,
            "src_port": rec.src_port,
            "dest_ip": rec.dest_ip,
            "dest_port": rec.dest_port,
            "alert_signature": rec.alert_signature,
            "alert_signature_id": rec.alert_signature_id,
            "alert_category": rec.alert_category,
            "alert_severity": rec.alert_severity,
            "source_sensor_severity_raw": _try_int(rec.source_sensor_severity_raw),
            "source_sensor_action": rec.source_sensor_action,
            "executed_action": rec.executed_action,
            "evidence": json.loads(rec.evidence_json or "{}"),
            "mitre_techniques": techniques,
            "source_file": rec.source_file,
            "explanation": rec.explanation,
            "created_at": rec.created_at,
        }


@router.post("/explain/{event_id}")
@limiter.limit("20/minute")
async def explain_suricata_event(request: Request, event_id: int) -> dict:
    """Generate advisory LLM analysis for an imported Suricata alert with deterministic fallback."""
    with SessionLocal() as s:
        rec = s.get(SecurityEventRecord, event_id)
        if not rec:
            raise HTTPException(404, "Security event not found")
        if rec.explanation:
            return {
                "explanation": rec.explanation,
                "cached": True,
                "executed_action": "none",
                "provider": "cached",
            }

        event_dict = {
            "id": rec.id,
            "event_ref": rec.event_ref,
            "source_kind": rec.source_kind,
            "source_event_type": rec.source_event_type,
            "sensor_id": rec.sensor_id,
            "timestamp_iso": rec.timestamp_iso,
            "proto": rec.proto,
            "app_proto": rec.app_proto,
            "alert_signature": rec.alert_signature,
            "alert_signature_id": rec.alert_signature_id,
            "alert_category": rec.alert_category,
            "alert_severity": rec.alert_severity,
            "source_sensor_action": rec.source_sensor_action,
            "executed_action": "none",
            "evidence": json.loads(rec.evidence_json or "{}"),
            "mitre_techniques": json.loads(rec.mitre_techniques_json or "[]"),
        }

    snapshot_info = get_active_attack_snapshot_info()
    prompt_messages = build_suricata_alert_prompt(event_dict, snapshot_info)

    from ..llm.provider import get_provider
    settings = {
        "llm_provider": Setting.get("llm_provider", "local"),
        "llama_url": safe_llm_url(
            Setting.get("llama_url", "http://127.0.0.1:8080"),
            "http://127.0.0.1:8080", local=True,
        ),
        "api_base_url": safe_llm_url(
            Setting.get("api_base_url", "https://api.deepseek.com/v1"),
            "https://api.deepseek.com/v1", local=False,
        ),
        "api_model": Setting.get("api_model", ""),
        "api_key": Setting.get("api_key", ""),
    }
    provider = get_provider(settings)

    explanation = ""
    is_degraded = False
    provider_name = getattr(provider, "name", "unknown")

    try:
        explanation = await provider.chat(prompt_messages)
    except Exception as exc:
        log.warning("Advisory LLM chat failed for Suricata event %d: %s; using deterministic fallback", event_id, exc)
        explanation = deterministic_suricata_summary(event_dict)
        is_degraded = True
        provider_name = "deterministic_fallback"

    explanation = (explanation or "").strip()[:4000]

    with SessionLocal() as s:
        rec2 = s.get(SecurityEventRecord, event_id)
        if rec2 and explanation:
            rec2.explanation = explanation
            s.commit()

    return {
        "explanation": explanation,
        "cached": False,
        "degraded": is_degraded,
        "provider": provider_name,
        "executed_action": "none",
    }


@router.get("/stats")
def suricata_stats() -> dict:
    """Return aggregated event counts and snapshot verification state."""
    snapshot_info = get_active_attack_snapshot_info()
    with SessionLocal() as s:
        total_events = s.query(SecurityEventRecord).count()
        alert_count = s.query(SecurityEventRecord).filter_by(source_event_type="alert").count()
        flow_count = s.query(SecurityEventRecord).filter_by(source_event_type="flow").count()
        dns_count = s.query(SecurityEventRecord).filter_by(source_event_type="dns").count()
        tls_count = s.query(SecurityEventRecord).filter_by(source_event_type="tls").count()
        ingestion_count = s.query(SuricataIngestionRecord).count()
        mapped_techniques = s.query(SecurityEventTechniqueMapping.technique_id).distinct().count()

        return {
            "total_events": total_events,
            "counts_by_type": {
                "alert": alert_count,
                "flow": flow_count,
                "dns": dns_count,
                "tls": tls_count,
            },
            "total_ingestions": ingestion_count,
            "unique_techniques_mapped": mapped_techniques,
            "active_attack_snapshot": snapshot_info,
            "adapter_version": SURICATA_ADAPTER_VERSION,
            "schema_version": SECURITY_EVENT_SCHEMA_VERSION,
            "executed_action": "none",
        }


@router.get("/attack-status")
def suricata_attack_status() -> dict:
    """Report dynamic active ATT&CK snapshot honesty status."""
    return get_active_attack_snapshot_info()
