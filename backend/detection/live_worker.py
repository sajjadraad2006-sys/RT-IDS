"""Real-Time Live Flow Worker & Pipeline Bridge.

Consumes flushed flow feature records from LiveFlowSniffer via a bounded,
thread-safe queue, batches them, executes DetectionPipeline v2, persists
generated alerts into SQLite, and maintains an in-memory alert stream for
real-time dashboard consumption.
"""
from __future__ import annotations

import collections
import json
import logging
import math
import os
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from ..db.models import AlertRecord, SessionLocal
from ..detection.input_schema import FEATURE_SCHEMA_VERSION
from .pipeline import PIPELINE_VERSION, Alert, DetectionPipeline
from .scan_correlator import ScanCorrelator

logger = logging.getLogger("cyberguard.detection.live_worker")


class LiveFlowWorker:
    """Worker thread that consumes flow records from a bounded queue and runs Pipeline v2."""

    def __init__(
        self,
        max_queue_size: int = 10000,
        batch_size: int = 50,
        flush_interval_sec: float = 0.5,
        pipeline_getter: Optional[Callable[[], DetectionPipeline]] = None,
        max_alerts_history: int = 200,
        scan_correlator: Optional[ScanCorrelator] = None,
    ):
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.flush_interval_sec = flush_interval_sec
        self.pipeline_getter = pipeline_getter
        self.max_alerts_history = max_alerts_history
        self.scan_correlator = scan_correlator or ScanCorrelator()

        self.queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=max_queue_size)
        self.recent_alerts: collections.deque[Dict[str, Any]] = collections.deque(
            maxlen=max_alerts_history
        )
        self._lock = threading.Lock()

        # Telemetry & statistics
        self.total_enqueued = 0
        self.total_processed = 0
        self.total_alerts = 0
        self.total_dropped = 0
        self.last_processed_time: float = 0.0
        self._session_alert_cache: Dict[str, Tuple[str, float]] = {}

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def set_pipeline_getter(self, getter: Callable[[], DetectionPipeline]) -> None:
        """Set or update the pipeline resolver callable."""
        self.pipeline_getter = getter

    def enqueue_flow(self, flow_dict: Dict[str, float]) -> bool:
        """Enqueue a flushed flow record with backpressure dropping if full."""
        try:
            self.queue.put_nowait(flow_dict)
            with self._lock:
                self.total_enqueued += 1
            return True
        except queue.Full:
            with self._lock:
                self.total_dropped += 1
            if self.total_dropped % 100 == 1:
                logger.warning(
                    "Live flow queue full (%d items). Dropping flow to protect memory.",
                    self.queue.qsize(),
                )
            return False

    def start(self) -> None:
        """Start the background pipeline consumer thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._run_loop,
                daemon=True,
                name="CyberGuard-LiveFlowWorker",
            )
            self._thread.start()
        logger.info("Live flow pipeline worker started.")

    def stop(self, drain: bool = True) -> None:
        """Stop worker thread and optionally process remaining queued flows."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            thread = self._thread

        if thread and thread.is_alive():
            thread.join(timeout=3.0)

        if drain:
            self._drain_remaining()

        logger.info("Live flow pipeline worker stopped.")

    def _drain_remaining(self) -> None:
        """Process any flows still buffered in the queue upon shutdown."""
        remaining: List[Dict[str, float]] = []
        while not self.queue.empty():
            try:
                remaining.append(self.queue.get_nowait())
            except queue.Empty:
                break

        if remaining and self.pipeline_getter:
            logger.info("Draining %d remaining flows from live queue...", len(remaining))
            try:
                pipe = self.pipeline_getter()
                for i in range(0, len(remaining), self.batch_size):
                    batch = remaining[i : i + self.batch_size]
                    self._process_batch_with_pipeline(pipe, batch)
            except Exception as exc:
                logger.error("Error during final queue drain: %s", exc)

    def _run_loop(self) -> None:
        """Main batch consumer loop."""
        batch: List[Dict[str, float]] = []
        last_flush = time.time()

        while self._running:
            try:
                timeout = max(0.05, self.flush_interval_sec - (time.time() - last_flush))
                flow = self.queue.get(timeout=timeout)
                batch.append(flow)
            except queue.Empty:
                pass

            now = time.time()
            should_flush = (
                len(batch) >= self.batch_size
                or (batch and (now - last_flush >= self.flush_interval_sec))
            )

            if should_flush:
                self._dispatch_batch(batch)
                batch = []
                last_flush = now

    def _dispatch_batch(self, batch: List[Dict[str, float]]) -> None:
        if not batch:
            return

        pipe = None
        if self.pipeline_getter:
            try:
                pipe = self.pipeline_getter()
            except Exception as exc:
                logger.error("Failed to acquire detection pipeline in live worker: %s", exc)
                return

        if not pipe:
            logger.warning("No detection pipeline available for live worker batch.")
            return

        self._process_batch_with_pipeline(pipe, batch)

    def _process_batch_with_pipeline(
        self, pipe: DetectionPipeline, batch: List[Dict[str, float]]
    ) -> List[Dict[str, Any]]:
        """Run batch through DetectionPipeline and persist any generated alerts."""
        if not batch:
            return []

        try:
            batch_results = pipe.detect_batch(batch)
        except Exception as exc:
            logger.error("Pipeline inference failed on live flow batch: %s", exc)
            return []

        generated_alerts: List[Dict[str, Any]] = []
        persist_records: List[AlertRecord] = []
        now = time.time()

        for alert, flow_input in zip(batch_results, batch):
            alert = self.scan_correlator.correlate_alert(alert, flow_input, timestamp=now)
            if alert.route == "benign":
                continue

            session_id = str(flow_input.get("session_id", ""))
            is_interim = bool(flow_input.get("is_interim", 0.0))

            # Deduplication: suppress duplicate alerts of same type for the same session within 15 seconds
            if session_id:
                with self._lock:
                    last_alert = self._session_alert_cache.get(session_id)
                    if last_alert:
                        last_type, last_time = last_alert
                        if last_type == alert.type and (now - last_time) < 15.0:
                            logger.debug("Deduplicated repeated alert '%s' for session %s (is_interim=%s)", alert.type, session_id, is_interim)
                            continue
                    self._session_alert_cache[session_id] = (alert.type, now)
                    if len(self._session_alert_cache) > 10000:
                        oldest = list(self._session_alert_cache.keys())[:2000]
                        for k in oldest:
                            self._session_alert_cache.pop(k, None)

            alert_dict = alert.to_dict()
            alert_dict["source"] = "live_stream"
            alert_dict["is_interim"] = is_interim
            alert_dict["session_id"] = session_id
            generated_alerts.append(alert_dict)

            executed_action = "none"
            rollback_token = None
            explanation = ""
            src_ip = str(flow_input.get("src_ip", "")).strip()

            # Wire autonomous containment actuators ONLY to confirmed known attacks with high confidence
            should_auto_contain = (
                src_ip
                and src_ip not in ("127.0.0.1", "0.0.0.0", "localhost")
                and alert.route == "known_attack"
                and alert.severity in ("high", "critical")
                and float(alert.confidence or 0.0) >= 0.85
            )

            if should_auto_contain:
                try:
                    from ..actuators.router import default_router
                    exec_mode = os.getenv("CG_ACTIVE_DEFENSE_MODE", "simulation").lower()
                    act_res = default_router.execute_action(
                        action="block_ip",
                        target=src_ip,
                        params={
                            "reason": f"Real-time autonomous containment for {alert.type} ({alert.confidence * 100:.1f}%)",
                            "severity": alert.severity,
                            "confidence": float(alert.confidence or 0.90),
                            "initiator_id": "system:live_flow_worker",
                            "approver_id": "policy:autonomous_active_defense",
                        },
                        mode=exec_mode,
                    )
                    if act_res.success:
                        if act_res.simulated:
                            executed_action = f"simulated:{act_res.action}"
                            explanation = f"Autonomous Active Defense: simulated {act_res.action} against {src_ip} (Verified Token: {act_res.rollback_token})"
                        else:
                            executed_action = f"executed:{act_res.action}"
                            explanation = f"Autonomous Active Defense: executed live {act_res.action} against {src_ip} (Rollback Token: {act_res.rollback_token})"
                        rollback_token = act_res.rollback_token
                    else:
                        executed_action = f"blocked_by_policy:{act_res.action}"
                        rollback_token = None
                        explanation = f"Autonomous Active Defense: containment rejected by policy for {src_ip} ({act_res.error})"
                    logger.info("Autonomous containment disposition for %s: action=%s (success=%s, token=%s)", src_ip, executed_action, act_res.success, rollback_token)
                except Exception as act_exc:
                    logger.debug("Autonomous containment dispatch skipped: %s", act_exc)

            evidence_payload = {
                **alert.evidence,
                "feature_evidence": alert.feature_evidence,
                "artifact_version": alert.artifact_pipeline_version,
                "source": "live_flow_sniffer",
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "is_interim": is_interim,
                "session_id": session_id,
                "executed_action": executed_action,
                "rollback_token": rollback_token,
            }

            schema_payload = {
                "detected_input_profile": "live_flow_sniffer",
                "feature_coverage_percentage": 100.0,
            }

            raw_anomaly = float(alert.anomaly_score or 0.0)
            if math.isfinite(raw_anomaly) and raw_anomaly > 10.0:
                calibrated_anomaly = round(min(9.99, 1.0 + math.log10(max(1.0, raw_anomaly)) * 0.75), 3)
            else:
                calibrated_anomaly = round(max(0.0, raw_anomaly), 3)

            cleaned_top_features = []
            for item in (alert.top_features or []):
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    feat_name, feat_val = item
                    if isinstance(feat_val, (int, float)) and math.isfinite(feat_val):
                        cleaned_top_features.append([feat_name, min(15.0, max(0.0, float(feat_val)))])
                    else:
                        cleaned_top_features.append(list(item))
                else:
                    cleaned_top_features.append(item)

            record_kwargs: Dict[str, Any] = {
                "created_at": now,
                "severity": alert.severity,
                "type": alert.type,
                "confidence": alert.confidence,
                "anomaly_score": calibrated_anomaly,
                "stage": alert.stage,
                "mitre_techniques": json.dumps(alert.mitre_techniques),
                "latency_ms": alert.latency_ms,
                "source_file": "live://sniffer",
                "flow_json": "",
                "top_features": json.dumps(cleaned_top_features),
                "explanation": explanation,
            }

            for key, val in {
                "route": alert.route,
                "pipeline_version": PIPELINE_VERSION,
                "evidence_json": json.dumps(evidence_payload, sort_keys=True),
                "input_schema_json": json.dumps(schema_payload, sort_keys=True),
            }.items():
                if hasattr(AlertRecord, key):
                    record_kwargs[key] = val

            persist_records.append(AlertRecord(**record_kwargs))

        if persist_records:
            try:
                with SessionLocal() as db_session:
                    db_session.add_all(persist_records)
                    db_session.commit()
            except Exception as exc:
                logger.error("Failed to commit live alert records to database: %s", exc)

        with self._lock:
            self.total_processed += len(batch)
            self.total_alerts += len(generated_alerts)
            self.last_processed_time = now
            for alert_dict in generated_alerts:
                self.recent_alerts.append(alert_dict)

        return generated_alerts

    def get_status(self) -> Dict[str, Any]:
        """Return runtime queue and processing statistics."""
        with self._lock:
            return {
                "is_running": self._running,
                "queue_size": self.queue.qsize(),
                "max_queue_size": self.max_queue_size,
                "total_enqueued": self.total_enqueued,
                "total_processed": self.total_processed,
                "total_alerts": self.total_alerts,
                "total_dropped": self.total_dropped,
                "last_processed_time": self.last_processed_time,
            }

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent generated alerts in reverse chronological order."""
        with self._lock:
            alerts = list(self.recent_alerts)
        return alerts[-limit:][::-1]


# Default global instance
default_live_worker = LiveFlowWorker()
