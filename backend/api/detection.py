"""Detection endpoints — upload CSV/JSON logs, run the 4-stage pipeline,
return alerts + stage stats + feature importances. No LLM involved here.
Also: alert explanation (LLM layer), CSV export, pipeline health.
"""
from __future__ import annotations
import json, csv, io, time, logging, re
from typing import Literal
from fastapi import APIRouter, UploadFile, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from ..db.models import AlertRecord, DecisionCase, SessionLocal
from ..limiter import limiter

log = logging.getLogger("cyberguard.api.detection")
router = APIRouter(prefix="/api/detect", tags=["detection"])
_pipeline = None  # lazily built from saved models
_pipeline_metadata = None
_pipeline_root = None

# ── Upload limits ─────────────────────────────────────────────────────────────
BATCH_SIZE = 5000          # rows per processing batch
MAX_RETURN_ALERTS = 500    # cap JSON response to avoid huge payloads


def _safe_csv_cell(value) -> str:
    """Prevent spreadsheet formula execution in exported CSV files."""
    text = str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def _get_pipeline():
    global _pipeline, _pipeline_metadata, _pipeline_root
    from ..detection.bundles import resolve_active_bundle_dir
    from ..detection.integrity import IntegrityError
    try:
        model_root = resolve_active_bundle_dir()
    except IntegrityError as exc:
        raise HTTPException(
            status_code=503, detail="Active model pointer failed integrity validation"
        ) from exc
    if _pipeline is not None and _pipeline_root == model_root:
        return _pipeline
    from ..detection.pipeline import DetectionPipeline
    from ..detection.normalizer import Normalizer
    from ..detection.statistical import StatisticalFilter
    from ..detection.classifier import AttackClassifier
    from ..detection.autoencoder import AutoencoderDetector
    from ..detection.features import FEATURE_NAMES
    from ..detection.integrity import validate_artifact_bundle
    try:
        metadata = validate_artifact_bundle(model_root)
        norm = Normalizer().load(model_root / "normalizer.pkl")
        stat = StatisticalFilter().load(model_root / "statistical.pkl")
        clf = AttackClassifier(
            confidence_threshold=metadata["classifier"]["abstention_threshold"]
        ).load(model_root / "classifier.pkl")
        # The signed-off bundle metadata owns the serving threshold, including
        # for legacy classifier files that embedded a different default.
        clf.confidence_threshold = float(
            metadata["classifier"]["abstention_threshold"]
        )
        ae = AutoencoderDetector(len(FEATURE_NAMES)).load(
            model_root / "autoencoder.pt", len(FEATURE_NAMES))
        expected_features = len(FEATURE_NAMES)
        if norm.n_features != expected_features:
            raise IntegrityError("normalizer feature count does not match running schema")
        if stat.mean_ is None or len(stat.mean_) != expected_features:
            raise IntegrityError("statistical artifact feature count does not match schema")
        if ae.n_features != expected_features:
            raise IntegrityError("autoencoder feature count does not match running schema")
        if list(clf.classes_) != list(metadata.get("classes", [])):
            raise IntegrityError("classifier classes do not match artifact manifest")
        _pipeline = DetectionPipeline(norm, stat, clf, ae)
        _pipeline_metadata = metadata
        _pipeline_root = model_root
        log.info(
            "Detection pipeline loaded after integrity verification (production_approved=%s)",
            metadata.get("production_approved", False),
        )
    except (IntegrityError, OSError, KeyError, ValueError, RuntimeError) as exc:
        log.error("Detection pipeline refused unverified artifacts: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Detection artifacts are unavailable or failed integrity validation",
        ) from exc
    return _pipeline


def _parse_upload_streaming(name: str, raw: bytes) -> list[dict]:
    """Parse uploaded file into flow dicts.

    For CSV files, uses streaming DictReader. For JSON, decodes in one shot.
    Handles CSV, TSV, semicolon-delimited, JSON arrays, and NDJSON.
    """
    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return []

    # Reject obviously binary content (contains null bytes or too many
    # replacement characters — signals a binary file, not a log)
    null_ratio = text.count('\x00') / max(len(text), 1)
    replace_ratio = text.count('\ufffd') / max(len(text), 1)
    if null_ratio > 0.01 or replace_ratio > 0.2:
        return []

    # 1. Try JSON / NDJSON first
    if name.lower().endswith(".json") or text.startswith(("{", "[")):
        try:
            # Handle line-delimited JSON (NDJSON)
            if "\n" in text and not text.startswith("["):
                rows = []
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("{") and line.endswith("}"):
                        try:
                            rows.append(json.loads(line))
                        except (json.JSONDecodeError, TypeError):
                            continue
                if rows:
                    return rows
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        except Exception as e:
            log.debug("JSON parse fallback: %s", e)

    # 2. Delimiter auto-detection: Tab, Semicolon, or Comma
    first_line = text.split("\n")[0]
    delimiter = "\t" if "\t" in first_line else ";" if ";" in first_line else ","

    stream = io.StringIO(text)
    reader = csv.DictReader(stream, delimiter=delimiter)
    rows = []
    for r in reader:
        clean_row = { (k.strip() if k else ""): (v.strip() if v else "") for k, v in r.items() if k }
        if any(clean_row.values()):
            rows.append(clean_row)

    # 3. Fallback for raw headerless log lines
    if not rows:
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        for line in lines:
            parts = [p.strip() for p in line.replace("\t", ",").split(",") if p.strip()]
            if parts:
                rows.append({f"col_{i}": p for i, p in enumerate(parts)})

    return rows


@router.post("/upload")
@limiter.limit("10/minute")
async def upload(request: Request, file: UploadFile) -> dict:
    """Upload a log file and run it through the 4-stage detection pipeline.

    Handles large files (1M+ rows) via:
    - Streaming read with size limit enforcement
    - Batch processing (5000 rows per batch)
    - Batch DB inserts instead of per-row commits
    - Capped alert response (max 500 in JSON payload)
    """
    from ..config import MAX_UPLOAD_MB

    filename = (file.filename or "upload.log").strip()
    filename = re.sub(r"[\x00-\x1f\x7f]", "_", filename)[:255] or "upload.log"

    # ── Read with size limit ──────────────────────────────────────────────
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    chunks = []
    total_read = 0
    while True:
        chunk = await file.read(8 * 1024 * 1024)  # 8 MB chunks
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > max_bytes:
            raise HTTPException(
                413,
                f"File exceeds {MAX_UPLOAD_MB} MB limit. "
                f"Split the file or increase CG_MAX_UPLOAD_MB."
            )
        chunks.append(chunk)

    raw_content = b"".join(chunks)
    del chunks  # free memory early

    if not raw_content or len(raw_content.strip()) == 0:
        raise HTTPException(400, "Uploaded file is empty (0 bytes)")

    # ── Parse all flows ───────────────────────────────────────────────────
    flows = _parse_upload_streaming(filename, raw_content)
    del raw_content  # free raw bytes

    if not flows:
        raise HTTPException(
            400,
            "Could not parse flow entries from uploaded file. "
            "Please ensure it contains CSV, JSON, TSV, or log rows."
        )

    from ..config import MAX_UPLOAD_ROWS
    flows = [row for row in flows if isinstance(row, dict)]
    if not flows:
        raise HTTPException(400, "Uploaded data must contain JSON objects or tabular rows")
    total_flows = len(flows)
    if total_flows > MAX_UPLOAD_ROWS:
        raise HTTPException(413, f"File exceeds {MAX_UPLOAD_ROWS} row limit")
    log.info("Parsed %d flows from %s (%d bytes)", total_flows, filename, total_read)

    pipe = _get_pipeline()

    # ── Process in batches ────────────────────────────────────────────────
    all_alerts = []
    stage_counts = {"statistical": 0, "classifier": 0, "autoencoder": 0, "none": 0}
    total_alert_count = 0
    db_records = []
    max_db_alerts = 5000  # cap DB inserts to avoid SQLite slowdown
    t0 = time.perf_counter()

    for batch_start in range(0, total_flows, BATCH_SIZE):
        batch_flows = flows[batch_start:batch_start + BATCH_SIZE]
        batch_alerts = pipe.detect_batch(batch_flows)

        for flow, a in zip(batch_flows, batch_alerts):
            stage_key = a.stage if a.stage in stage_counts else "none"
            stage_counts[stage_key] += 1

            if a.severity == "none":
                continue

            total_alert_count += 1

            # Only keep alerts for the response up to the cap
            if len(all_alerts) < MAX_RETURN_ALERTS:
                all_alerts.append(a.to_dict())

            # Cap DB inserts to avoid massive slowdown on large files
            if len(db_records) < max_db_alerts:
                db_records.append(AlertRecord(
                    severity=a.severity, type=a.type,
                    confidence=a.confidence,
                    anomaly_score=a.anomaly_score, stage=a.stage,
                    mitre_techniques=json.dumps(a.mitre_techniques),
                    latency_ms=a.latency_ms,
                    source_file=filename,
                    flow_json="" if total_flows > 10000 else json.dumps(flow)[:8000],
                    top_features=json.dumps(a.top_features)
                ))

        # Log progress for large files
        processed = min(batch_start + BATCH_SIZE, total_flows)
        if total_flows > BATCH_SIZE and processed % (BATCH_SIZE * 10) == 0:
            log.info("Progress: %d / %d flows (%.0f%%)",
                     processed, total_flows, processed / total_flows * 100)

    # ── Batch-insert all DB records at once ────────────────────────────────
    smart_logs_created = 0
    if db_records:
        from ..decision.engine import build_smart_log

        with SessionLocal() as s:
            s.add_all(db_records)
            s.flush()
            for record in db_records:
                smart = build_smart_log(record)
                s.add(DecisionCase(
                    alert_id=record.id,
                    smart_log_json=smart.model_dump_json(),
                ))
                smart_logs_created += 1
            s.commit()

        # Response alerts are the first records in the same detection order.
        # Attach stable DB ids so the UI can request Smart Log/AI decisions.
        for payload, record in zip(all_alerts, db_records):
            payload["id"] = record.id
            payload["smart_log_url"] = f"/api/decision/smart-log/{record.id}"
            payload["decision_url"] = f"/api/decision/evaluate/{record.id}"

        log.info("Saved %d alerts and Smart Logs to DB (capped from %d total)",
                 len(db_records), total_alert_count)

    elapsed = time.perf_counter() - t0
    throughput = round(total_flows / max(elapsed, 1e-6))

    log.info("Upload complete: %d flows, %d alerts, %d rec/s in %.1fs",
             total_flows, len(all_alerts), throughput, elapsed)

    return {
        "file": filename,
        "flows": total_flows,
        "alerts": all_alerts,
        "total_alerts": stage_counts["classifier"] + stage_counts["autoencoder"],
        "alerts_capped": len(all_alerts) >= MAX_RETURN_ALERTS,
        "stage_counts": stage_counts,
        "throughput_rps": throughput,
        "feature_importance": pipe.clf.feature_importance(10),
        "pipeline_stats": pipe.get_stats(),
        "elapsed_seconds": round(elapsed, 2),
        "smart_logs_created": smart_logs_created,
        "operational_mode": (
            "production" if _pipeline_metadata and _pipeline_metadata.get("production_approved")
            else "evaluation_only"
        ),
    }


@router.get("/alerts")
def list_alerts(
    limit: int = Query(default=200, ge=1, le=1000),
    severity: Literal["none", "low", "medium", "high", "critical"] | None = None,
) -> list[dict]:
    with SessionLocal() as s:
        q = s.query(AlertRecord).order_by(AlertRecord.created_at.desc())
        if severity:
            q = q.filter_by(severity=severity)
        return [{"id": r.id, "created_at": r.created_at, "severity": r.severity,
                 "type": r.type, "confidence": r.confidence,
                 "anomaly_score": r.anomaly_score, "stage": r.stage,
                 "mitre_techniques": json.loads(r.mitre_techniques),
                 "latency_ms": r.latency_ms, "source_file": r.source_file}
                for r in q.limit(limit).all()]


@router.get("/stats")
def pipeline_stats() -> dict:
    """Return pipeline statistics if loaded."""
    if _pipeline is None:
        return {"status": "not loaded"}
    return _pipeline.get_stats()


@router.get("/health")
def pipeline_health() -> dict:
    """Report integrity, evaluated coverage, and serving readiness."""
    from ..detection.bundles import resolve_active_bundle_dir
    from ..detection.integrity import ARTIFACT_FILENAMES, validate_artifact_bundle
    integrity_error = ""
    metadata = {}
    try:
        model_root = resolve_active_bundle_dir()
        metadata = validate_artifact_bundle(model_root)
    except Exception as exc:
        model_root = None
        integrity_error = str(exc)[:300]
    artifact_status = {
        name: bool(model_root and (model_root / name).is_file())
        for name in ARTIFACT_FILENAMES
    }
    trained_classes = metadata.get("classes", [])
    from ..config import CLASSES
    missing_classes = sorted(set(CLASSES) - set(trained_classes))
    integrity_ok = bool(metadata) and not integrity_error
    serving_ready = False
    if integrity_ok:
        try:
            _get_pipeline()
            serving_ready = True
        except HTTPException as exc:
            integrity_error = str(exc.detail)[:300]
    production_approved = bool(metadata.get("production_approved", False))
    latest_candidate = None
    from ..config import MODELS_DIR
    candidates_root = MODELS_DIR / "candidates"
    if candidates_root.is_dir():
        for candidate_dir in sorted(candidates_root.iterdir(), reverse=True):
            if not candidate_dir.is_dir() or candidate_dir.is_symlink():
                continue
            try:
                candidate_meta = validate_artifact_bundle(candidate_dir)
                latest_candidate = {
                    "id": candidate_dir.name,
                    "status": candidate_meta.get("candidate_status", "unknown"),
                    "production_approved": bool(
                        candidate_meta.get("production_approved", False)
                    ),
                    "classes": candidate_meta.get("classes", []),
                    "quality_gate_results": candidate_meta.get(
                        "metrics", {}
                    ).get("quality_gate_results", {}),
                }
            except Exception:
                latest_candidate = {
                    "id": candidate_dir.name,
                    "status": "integrity_failed",
                    "production_approved": False,
                }
            break
    return {
        "ready": serving_ready,
        "operational_mode": "production" if production_approved else "evaluation_only",
        "production_approved": production_approved,
        "integrity_verified": integrity_ok,
        "integrity_error": integrity_error,
        "coverage_complete": integrity_ok and not missing_classes,
        "trained_classes": trained_classes,
        "missing_classes": missing_classes,
        "classifier_abstention_threshold": metadata.get("classifier", {}).get("abstention_threshold"),
        "autoencoder_threshold": metadata.get("autoencoder", {}).get("threshold"),
        "autoencoder_k": metadata.get("autoencoder", {}).get("k"),
        "loaded": _pipeline is not None,
        "active_bundle": str(model_root) if model_root else None,
        "latest_candidate": latest_candidate,
        "stages": {
            "normalizer": artifact_status["normalizer.pkl"],
            "statistical_filter": artifact_status["statistical.pkl"],
            "classifier": artifact_status["classifier.pkl"],
            "autoencoder": artifact_status["autoencoder.pt"],
        },
        "note": (
            "Artifacts failed integrity validation; detection is fail-closed"
            if not serving_ready else
            "Verified fixture artifacts only; not approved for production"
            if not production_approved else
            "Production-approved artifacts have incomplete class coverage"
            if missing_classes else "Production-approved artifact bundle is ready"
        ),
    }


@router.post("/explain/{alert_id}")
@limiter.limit("20/minute")
async def explain_alert(request: Request, alert_id: int) -> dict:
    """Use the LLM (10%) to explain a pipeline verdict (ground truth).
    The pipeline detected it — the LLM only explains WHY."""
    with SessionLocal() as s:
        rec = s.get(AlertRecord, alert_id)
        if not rec:
            raise HTTPException(404, "Alert not found")
        if rec.explanation:
            return {"explanation": rec.explanation, "cached": True}

    # Build alert dict for the prompt
    alert_dict = {
        "type": rec.type, "severity": rec.severity,
        "confidence": rec.confidence, "anomaly_score": rec.anomaly_score,
        "stage": rec.stage,
        "mitre_techniques": json.loads(rec.mitre_techniques),
        "top_features": json.loads(rec.top_features),
    }

    from ..llm.provider import get_provider
    from ..llm.prompts import explain_alert as build_prompt
    from ..mitre.mapper import get_technique_context
    from ..db.models import Setting
    from ..security import safe_llm_url

    mitre_ctx = get_technique_context(rec.type)
    messages = build_prompt(alert_dict, mitre_ctx)

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

    try:
        explanation = await provider.chat(messages)
        # Cache for future requests
        with SessionLocal() as s:
            rec2 = s.get(AlertRecord, alert_id)
            if rec2:
                rec2.explanation = explanation
                s.commit()
        return {"explanation": explanation, "cached": False, "provider": provider.name}
    except Exception as exc:
        return {
            "explanation": f"LLM unavailable ({exc}). Alert details: {rec.type} "
                          f"({rec.severity}) caught by {rec.stage}. "
                          f"MITRE: {rec.mitre_techniques}",
            "cached": False, "degraded": True,
        }


@router.get("/export")
def export_alerts_csv(limit: int = Query(default=5000, ge=1, le=5000)) -> StreamingResponse:
    """Export alerts as CSV for external analysis or reporting."""
    with SessionLocal() as s:
        rows = (s.query(AlertRecord)
                .order_by(AlertRecord.created_at.desc())
                .limit(limit).all())

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "time", "severity", "type", "confidence",
                     "anomaly_score", "stage", "mitre_techniques",
                     "latency_ms", "source_file"])
    for r in rows:
        writer.writerow([
            r.id, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r.created_at)),
            _safe_csv_cell(r.severity), _safe_csv_cell(r.type), round(r.confidence, 4),
            round(r.anomaly_score, 4), _safe_csv_cell(r.stage),
            _safe_csv_cell(r.mitre_techniques), r.latency_ms,
            _safe_csv_cell(r.source_file),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cyberguard_alerts.csv"},
    )
