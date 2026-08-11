"""Detection endpoints — upload CSV/JSON logs, run the 4-stage pipeline,
return alerts + stage stats + feature importances. No LLM involved here.
Also: alert explanation (LLM layer), CSV export, pipeline health.
"""
from __future__ import annotations
import json, csv, io, time, logging
from fastapi import APIRouter, UploadFile, HTTPException, Request
from fastapi.responses import StreamingResponse
from ..db.models import AlertRecord, SessionLocal
from ..limiter import limiter

log = logging.getLogger("cyberguard.api.detection")
router = APIRouter(prefix="/api/detect", tags=["detection"])
_pipeline = None  # lazily built from saved models

# ── Upload limits ─────────────────────────────────────────────────────────────
BATCH_SIZE = 5000          # rows per processing batch
MAX_RETURN_ALERTS = 500    # cap JSON response to avoid huge payloads


def _get_pipeline():
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    from ..config import TRAINED_DIR
    from ..detection.pipeline import DetectionPipeline
    from ..detection.normalizer import Normalizer
    from ..detection.statistical import StatisticalFilter
    from ..detection.classifier import AttackClassifier
    from ..detection.autoencoder import AutoencoderDetector
    from ..detection.features import FEATURE_NAMES
    try:
        norm = Normalizer().load(TRAINED_DIR / "normalizer.pkl")
        stat = StatisticalFilter().load(TRAINED_DIR / "statistical.pkl")
        clf = AttackClassifier().load(TRAINED_DIR / "classifier.pkl")
        ae = AutoencoderDetector(len(FEATURE_NAMES)).load(
            TRAINED_DIR / "autoencoder.pt", len(FEATURE_NAMES))
        _pipeline = DetectionPipeline(norm, stat, clf, ae)
        log.info("Detection pipeline loaded from trained models")
    except Exception as e:
        log.info("Trained models not found (%s) — initializing baseline pipeline", e)
        import numpy as np
        n_feat = len(FEATURE_NAMES)
        rng = np.random.default_rng(42)
        X_benign = rng.normal(0, 1, size=(1000, n_feat))
        X_attack = rng.normal(3, 1, size=(200, n_feat))
        X_all = np.vstack([X_benign, X_attack])
        y_all = np.array(["Benign"] * 1000 + ["DDoS"] * 200)

        norm = Normalizer().fit(X_benign)
        stat = StatisticalFilter(threshold=3.0).fit(X_benign)
        clf = AttackClassifier().fit(X_all, y_all)
        ae = AutoencoderDetector(n_feat, k=3.0).fit(X_benign, X_benign[:200], epochs=2, batch=128)

        _pipeline = DetectionPipeline(norm, stat, clf, ae)
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
                        except Exception:
                            pass
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
@limiter.limit("60/minute")
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

    total_flows = len(flows)
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
    if db_records:
        with SessionLocal() as s:
            s.add_all(db_records)
            s.commit()
        log.info("Saved %d alerts to DB (capped from %d total)",
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
    }


@router.get("/alerts")
def list_alerts(limit: int = 200, severity: str | None = None) -> list[dict]:
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
    """Check pipeline readiness — are all 4 stages loaded?"""
    from ..config import TRAINED_DIR
    normalizer_ok = (TRAINED_DIR / "normalizer.pkl").exists()
    statistical_ok = (TRAINED_DIR / "statistical.pkl").exists()
    classifier_ok = (TRAINED_DIR / "classifier.pkl").exists()
    autoencoder_ok = (TRAINED_DIR / "autoencoder.pt").exists()
    all_ok = all([normalizer_ok, statistical_ok, classifier_ok, autoencoder_ok])
    return {
        "ready": all_ok,
        "loaded": _pipeline is not None,
        "stages": {
            "normalizer": normalizer_ok,
            "statistical_filter": statistical_ok,
            "classifier": classifier_ok,
            "autoencoder": autoencoder_ok,
        },
        "note": "Run trainer.py on CICIDS2017 to train all stages" if not all_ok else "All stages ready",
    }


@router.post("/explain/{alert_id}")
async def explain_alert(alert_id: int) -> dict:
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

    mitre_ctx = get_technique_context(rec.type)
    messages = build_prompt(alert_dict, mitre_ctx)

    settings = {
        "llm_provider": Setting.get("llm_provider", "local"),
        "llama_url": Setting.get("llama_url", "http://127.0.0.1:8080"),
        "api_base_url": Setting.get("api_base_url", ""),
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
def export_alerts_csv(limit: int = 5000) -> StreamingResponse:
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
            r.severity, r.type, round(r.confidence, 4),
            round(r.anomaly_score, 4), r.stage, r.mitre_techniques,
            r.latency_ms, r.source_file,
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cyberguard_alerts.csv"},
    )
