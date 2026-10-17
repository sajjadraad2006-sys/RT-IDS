"""Unit & Integration Tests for Real-Time Pipeline Worker & Live Flow Sniffer Bridge.

Tests verify:
1. Bounded queue buffering, flow enqueuing, and backpressure behavior.
2. Batch processing via DetectionPipeline and database persistence of generated alerts.
3. End-to-end integration: LiveFlowSniffer flushes -> LiveFlowWorker enqueues -> Pipeline detects -> Alerts stored.
4. Live API endpoints (/live/start, /live/stop, /live/status, /live/alerts) and schema contracts.
5. Concurrent multi-threaded packet ingestion without lock contention or deadlock.
"""
import threading
import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from backend.db.init_db import init_all
from backend.db.models import AlertRecord, SessionLocal
from backend.detection.features import FEATURE_NAMES
from backend.detection.live_sniffer import LiveFlowSniffer
from backend.detection.live_worker import LiveFlowWorker, default_live_worker
from backend.detection.pipeline import Alert
from backend.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_all()


def _make_dummy_flow(dst_port: int = 80, length: float = 500.0) -> dict:
    flow = {name: 10.0 for name in FEATURE_NAMES}
    flow["Destination Port"] = float(dst_port)
    flow["flow_duration"] = 50000.0
    flow["total_fwd_packets"] = 5.0
    flow["total_bwd_packets"] = 5.0
    flow["packet_length_mean"] = length
    return flow


def test_worker_queue_buffering_and_backpressure():
    """Verify queue accepts items up to maxsize and drops with counter when full."""
    worker = LiveFlowWorker(max_queue_size=5)

    for i in range(5):
        assert worker.enqueue_flow(_make_dummy_flow()) is True

    assert worker.queue.qsize() == 5
    assert worker.total_enqueued == 5
    assert worker.total_dropped == 0

    # 6th item exceeds capacity and must be dropped cleanly
    assert worker.enqueue_flow(_make_dummy_flow()) is False
    assert worker.total_dropped == 1
    assert worker.queue.qsize() == 5


def test_worker_batch_inference_and_persistence():
    """Verify batch processing routes non-benign alerts to database and memory deque."""
    worker = LiveFlowWorker(batch_size=2, flush_interval_sec=0.1)

    # Mock pipeline returning 1 malicious alert and 1 benign
    mock_pipe = MagicMock()
    mock_alert_malicious = Alert(
        severity="high",
        type="DDoS",
        confidence=0.95,
        anomaly_score=1.5,
        stage="classifier",
        route="known_attack",
        mitre_techniques=["T1498"],
        latency_ms=1.2,
        top_features=[("packets_per_sec", 50000.0)],
        evidence={"classifier": {"label": "DDoS", "confidence": 0.95}},
    )
    mock_alert_benign = Alert(
        severity="none",
        type="Benign",
        confidence=0.99,
        anomaly_score=0.1,
        stage="none",
        route="benign",
    )
    mock_pipe.detect_batch.return_value = [mock_alert_malicious, mock_alert_benign]

    worker.set_pipeline_getter(lambda: mock_pipe)

    # Process batch directly
    batch = [_make_dummy_flow(), _make_dummy_flow()]
    generated = worker._process_batch_with_pipeline(mock_pipe, batch)

    assert len(generated) == 1
    assert generated[0]["type"] == "DDoS"
    assert generated[0]["route"] == "known_attack"
    assert worker.total_alerts == 1
    assert worker.total_processed == 2

    # Verify persisted in database
    with SessionLocal() as session:
        latest = (
            session.query(AlertRecord)
            .filter_by(source_file="live://sniffer", type="DDoS")
            .order_by(AlertRecord.id.desc())
            .first()
        )
        assert latest is not None
        assert latest.confidence == 0.95
        assert latest.severity == "high"


def test_worker_background_lifecycle_and_drain():
    """Verify worker thread processes enqueued items asynchronously."""
    mock_pipe = MagicMock()
    mock_alert = Alert(
        severity="medium",
        type="PortScan",
        confidence=0.88,
        route="known_attack",
    )
    mock_pipe.detect_batch.return_value = [mock_alert]

    worker = LiveFlowWorker(batch_size=2, flush_interval_sec=0.1)
    worker.set_pipeline_getter(lambda: mock_pipe)
    worker.start()

    assert worker.get_status()["is_running"] is True

    # Enqueue 2 flows
    worker.enqueue_flow(_make_dummy_flow())
    worker.enqueue_flow(_make_dummy_flow())

    # Wait for flush interval
    time.sleep(0.3)

    worker.stop(drain=True)
    assert worker.get_status()["is_running"] is False
    assert worker.total_processed >= 2


def test_live_sniffer_wires_to_worker():
    """Verify sniffer on_flow_flushed pushes directly to worker and processes flow."""
    sniffer = LiveFlowSniffer(idle_timeout_sec=0.2)
    worker = LiveFlowWorker(batch_size=1, flush_interval_sec=0.05)

    mock_pipe = MagicMock()
    mock_alert = Alert(severity="high", type="Bot", confidence=0.91, route="known_attack")
    mock_pipe.detect_batch.return_value = [mock_alert]
    worker.set_pipeline_getter(lambda: mock_pipe)

    # Wire callback
    sniffer.on_flow_flushed = worker.enqueue_flow
    worker.start()

    t0 = time.time()
    sniffer.process_packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=1234,
        dst_port=80,
        proto=6,
        length=100,
        tcp_flags=0x01,  # FIN triggers flush
        timestamp=t0,
    )

    time.sleep(0.2)
    worker.stop(drain=True)

    assert worker.total_enqueued >= 1
    assert worker.total_processed >= 1
    assert len(worker.get_recent_alerts()) >= 1


def test_live_api_endpoints():
    """Verify /api/detect/live/start, /stop, /status, and /alerts endpoints."""
    # Test status endpoint
    res_status = client.get("/api/detect/live/status")
    assert res_status.status_code == 200
    st = res_status.json()
    assert "is_capturing" in st
    assert "active" in st
    assert "packets_captured" in st
    assert "flows_aggregated" in st
    assert "worker" in st
    assert "queue_size" in st["worker"]

    # Test start endpoint
    res_start = client.post("/api/detect/live/start")
    assert res_start.status_code == 200
    start_data = res_start.json()
    assert start_data["success"] is True
    assert start_data["status"]["active"] is True
    assert start_data["status"]["worker"]["is_running"] is True

    # Test alerts endpoint
    res_alerts = client.get("/api/detect/live/alerts")
    assert res_alerts.status_code == 200
    alerts_data = res_alerts.json()
    assert "alerts" in alerts_data
    assert "total_alerts" in alerts_data

    # Test stop endpoint
    res_stop = client.post("/api/detect/live/stop")
    assert res_stop.status_code == 200
    stop_data = res_stop.json()
    assert stop_data["status"]["active"] is False


def test_concurrent_packet_ingestion():
    """Verify sniffer handles concurrent packet processing from multiple threads safely."""
    sniffer = LiveFlowSniffer()
    flushed_records = []
    sniffer.on_flow_flushed = lambda rec: flushed_records.append(rec)

    def worker_thread(tid: int):
        for i in range(50):
            sniffer.process_packet(
                src_ip=f"10.0.{tid}.{i % 10}",
                dst_ip="192.168.1.1",
                src_port=5000 + i,
                dst_port=80,
                proto=6,
                length=64,
                tcp_flags=0x10,
                timestamp=time.time(),
            )

    threads = [threading.Thread(target=worker_thread, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    status = sniffer.get_status()
    assert status["total_packets_captured"] == 250
    assert status["active_flows"] > 0

    # Flush all
    flushed = sniffer.flush_expired_flows(now=time.time() + 300.0)
    assert len(flushed) > 0


def test_concurrent_pipeline_resolution_under_load():
    """Verify thread-safe atomic initialization of _get_pipeline under concurrent load."""
    import concurrent.futures
    from backend.api.detection import _get_pipeline, eager_load_pipeline

    # Test eager load hook
    eager_pipe = eager_load_pipeline()
    assert eager_pipe is not None

    results = []
    errors = []

    def load_task():
        try:
            pipe = _get_pipeline()
            results.append(pipe)
        except Exception as exc:
            errors.append(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(load_task) for _ in range(10)]
        concurrent.futures.wait(futures)

    assert len(errors) == 0, f"Concurrent pipeline loading had errors: {errors}"
    assert len(results) == 10
    # Every thread must receive the exact same singleton instance
    first_id = id(results[0])
    for pipe in results[1:]:
        assert id(pipe) == first_id


def test_lifespan_startup_and_graceful_drain():
    """Verify FastAPI lifespan starts worker wiring and drains buffered flows on shutdown."""
    import asyncio
    from backend.detection.live_worker import default_live_worker
    from backend.main import _lifespan, app

    # Reset worker queue and state
    while not default_live_worker.queue.empty():
        default_live_worker.queue.get_nowait()

    async def run_lifespan_cycle():
        async with _lifespan(app):
            # Worker is wired and callable
            assert default_live_worker.pipeline_getter is not None
            # Buffer dummy flows while running
            default_live_worker.enqueue_flow(_make_dummy_flow())
            default_live_worker.enqueue_flow(_make_dummy_flow())
            assert default_live_worker.queue.qsize() == 2

        # Upon exiting lifespan context, queue must be drained
        assert default_live_worker.queue.empty()

    asyncio.run(run_lifespan_cycle())

