"""Tests for Phase 6: Production Suricata Live Tailer, Protocol Bridge & Synthetic Replayer."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.detection.features import FEATURE_NAMES
from backend.main import app
from backend.suricata.tailer import (
    SuricataLiveTailer,
    SyntheticEveReplayer,
    eve_to_flow_features,
)


def test_eve_to_flow_features_extraction():
    """Verify that EVE flow records map cleanly into 32 valid numeric features and aliases."""
    doc = {
        "timestamp": "2026-10-17T06:00:00.000000+00:00",
        "proto": "TCP",
        "dest_port": 443,
        "src_ip": "10.0.0.5",
        "dest_ip": "104.244.42.1",
        "flow": {
            "pkts_toserver": 15,
            "pkts_toclient": 20,
            "bytes_toserver": 1200,
            "bytes_toclient": 15000,
            "age": 3.5,
        },
        "tcp": {
            "syn": True,
            "ack": True,
            "fin": True,
            "rst": False,
            "psh": True,
            "urg": False,
        },
    }

    feats = eve_to_flow_features(doc)
    # Check that all 32 canonical model features exist and are valid non-NaN floats
    for name in FEATURE_NAMES:
        assert name in feats, f"Missing feature: {name}"
        assert isinstance(feats[name], (int, float))
        assert not (feats[name] != feats[name])  # Not NaN

    # Check key domain mappings
    assert feats["Destination Port"] == 443.0
    assert feats["total_fwd_packets"] == 15.0
    assert feats["total_bwd_packets"] == 20.0
    assert feats["syn_flag_count"] == 1.0
    assert feats["fin_flag_count"] == 1.0
    assert feats["rst_flag_count"] == 0.0


def test_process_line_flow_and_alert(tmp_path: Path):
    """Verify processing single JSON lines into SecurityEventV1 and enqueuing into pipeline."""
    eve_file = tmp_path / "eve.json"
    tailer = SuricataLiveTailer(
        eve_path=eve_file,
        feed_pipeline_worker=False,  # don't trigger background pipeline inference in this unit test
        persist_events=False,
    )

    flow_line = SyntheticEveReplayer.generate_eve_flow_event(
        src_ip="192.168.1.50",
        dest_ip="10.0.0.1",
        dest_port=80,
    )
    event, feats = tailer.process_line(flow_line)
    assert event is not None
    assert event.source_event_type == "flow"
    assert event.src_ip == "192.168.1.50"
    assert feats is not None
    assert feats["Destination Port"] == 80.0

    alert_line = SyntheticEveReplayer.generate_eve_alert_event(
        sig="ET MALWARE Potential Cobalt Strike Beacon",
        sid=2030001,
        sev=1,
    )
    alert_event, alert_feats = tailer.process_line(alert_line)
    assert alert_event is not None
    assert alert_event.source_event_type == "alert"
    assert "Cobalt Strike" in (alert_event.alert_signature or "")


def test_live_file_tailing_and_rotation(tmp_path: Path):
    """Test dynamic live file tailing, real-time line digestion, and log rotation survival."""
    eve_file = tmp_path / "eve.json"
    eve_file.write_text("", encoding="utf-8")

    tailer = SuricataLiveTailer(
        eve_path=eve_file,
        poll_interval=0.05,
        feed_pipeline_worker=False,
        persist_events=False,
    )

    tailer.start(from_end=False)
    try:
        # 1. Append initial events
        line1 = SyntheticEveReplayer.generate_eve_flow_event(src_ip="10.1.1.1") + "\n"
        line2 = SyntheticEveReplayer.generate_eve_flow_event(src_ip="10.1.1.2") + "\n"
        with eve_file.open("a", encoding="utf-8") as f:
            f.write(line1)
            f.write(line2)
            f.flush()

        # Wait for tailer to read lines
        for _ in range(30):
            if tailer.total_lines_read >= 2:
                break
            time.sleep(0.05)

        assert tailer.total_lines_read == 2
        assert tailer.total_events_parsed == 2

        # 2. Simulate log rotation via file truncation/reset (copytruncate mode)
        line3 = SyntheticEveReplayer.generate_eve_flow_event(src_ip="10.1.1.3") + "\n"
        with eve_file.open("w", encoding="utf-8") as f:
            f.write(line3)
            f.flush()

        # Wait for tailer to detect rotation (st_size < tell) and consume line 3
        for _ in range(40):
            if tailer.total_lines_read >= 3:
                break
            time.sleep(0.05)

        assert tailer.total_lines_read >= 3
    finally:
        tailer.stop()


def test_api_suricata_stream_endpoints():
    """Verify Suricata stream replay and status endpoints on FastAPI app."""
    client = TestClient(app)

    # 1. Check status
    res = client.get("/api/events/suricata/stream/status")
    assert res.status_code == 200
    data = res.json()
    assert "tailer" in data
    assert "worker" in data
    assert "total_lines_read" in data["tailer"]

    # 2. Replay synthetic batch
    replay_res = client.post("/api/events/suricata/stream/replay?flows_count=4&alerts_count=2")
    assert replay_res.status_code == 200
    replay_data = replay_res.json()
    assert replay_data["success"] is True
    assert replay_data["injected_count"] == 6
    assert len(replay_data["events"]) == 6
