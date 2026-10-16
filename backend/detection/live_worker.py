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
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from ..db.models import AlertRecord, SessionLocal
from ..detection.input_schema import FEATURE_SCHEMA_VERSION
from .pipeline import PIPELINE_VERSION, Alert, DetectionPipeline

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
    ):
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.flush_interval_sec = flush_interval_sec
        self.pipeline_getter = pipeline_getter
        self.max_alerts_history = max_alerts_history

        self.queue: queue.Queue[Dict[str, float]] = queue.Queue(maxsize=max_queue_size)
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

        for alert in batch_results:
            if alert.route == "benign":
                continue

            alert_dict = alert.to_dict()
            alert_dict["source"] = "live_stream"
            generated_alerts.append(alert_dict)

            evidence_payload = {
                **alert.evidence,
                "feature_evidence": alert.feature_evidence,
                "artifact_version": alert.artifact_pipeline_version,
                "source": "live_flow_sniffer",
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
            }

            schema_payload = {
                "detected_input_profile": "live_flow_sniffer",
                "feature_coverage_percentage": 100.0,
            }

            record_kwargs: Dict[str, Any] = {
                "created_at": now,
                "severity": alert.severity,
                "type": alert.type,
                "confidence": alert.confidence,
                "anomaly_score": alert.anomaly_score,
                "stage": alert.stage,
                "mitre_techniques": json.dumps(alert.mitre_techniques),
                "latency_ms": alert.latency_ms,
                "source_file": "live://sniffer",
                "flow_json": "",
                "top_features": json.dumps(alert.top_features),
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
