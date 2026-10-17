"""Suricata EVE Live Streaming Tailer, Protocol Bridge & Synthetic Replayer.

Provides:
1. Real-time streaming reader for Suricata EVE JSON file tailing / named pipe / Unix domain sockets.
2. Protocol bridge translating raw Suricata events into SecurityEventV1 domain models.
3. Feature extraction bridge mapping EVE network telemetry into 32-feature CICFlowMeter
   vectors to drive CyberGuard's 4-stage RT-IDS pipeline worker in real time.
4. Synthetic EVE replayer for automated regression testing and pipeline benchmarking.
"""
from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..config import BASE_DIR
from ..db.models import SecurityEventRecord, SessionLocal
from ..detection.features import FEATURE_NAMES
from ..detection.live_worker import default_live_worker
from .parser import _parse_single_eve_dict
from .schema import SecurityEventV1

logger = logging.getLogger("cyberguard.suricata.tailer")

DEFAULT_EVE_PATH = os.getenv(
    "CG_SURICATA_EVE_PATH",
    str(BASE_DIR / "data" / "eve.json"),
)


def eve_to_flow_features(doc: Dict[str, Any]) -> Dict[str, float]:
    """Extract standard 32 CICFlowMeter feature vector from a Suricata EVE record."""
    dest_port = float(doc.get("dest_port", 80) or 80)
    proto_str = str(doc.get("proto", "TCP")).upper()
    proto = 6 if proto_str == "TCP" else (17 if proto_str == "UDP" else 0)

    flow_data = doc.get("flow", {}) if isinstance(doc.get("flow"), dict) else {}
    tcp_data = doc.get("tcp", {}) if isinstance(doc.get("tcp"), dict) else {}

    # Packets and bytes
    fwd_pkts = float(flow_data.get("pkts_toserver", 1) or 1)
    bwd_pkts = float(flow_data.get("pkts_toclient", 0) or 0)
    fwd_bytes = float(flow_data.get("bytes_toserver", 64) or 64)
    bwd_bytes = float(flow_data.get("bytes_toclient", 0) or 0)
    total_pkts = max(1.0, fwd_pkts + bwd_pkts)
    total_bytes = max(1.0, fwd_bytes + bwd_bytes)

    # Duration
    age_sec = float(flow_data.get("age", 1.0) or 1.0)
    duration_us = max(100.0, age_sec * 1e6)
    duration_sec = max(0.001, duration_us / 1e6)

    # Rates
    pkts_per_sec = min(2_000_000.0, total_pkts / duration_sec)
    bytes_per_sec = min(50_000_000.0, total_bytes / duration_sec)

    # Packet length stats
    fwd_len_mean = fwd_bytes / max(1.0, fwd_pkts)
    bwd_len_mean = (bwd_bytes / max(1.0, bwd_pkts)) if bwd_pkts > 0 else 0.0
    pkt_len_mean = total_bytes / total_pkts
    pkt_len_max = max(fwd_len_mean, bwd_len_mean, 64.0)
    pkt_len_min = min(fwd_len_mean, bwd_len_mean if bwd_pkts > 0 else fwd_len_mean, 40.0)

    # TCP Flags
    syn = 1.0 if tcp_data.get("syn") else (1.0 if doc.get("event_type") == "flow" and fwd_pkts == 1 else 0.0)
    ack = 1.0 if tcp_data.get("ack") else (1.0 if total_pkts > 1 else 0.0)
    rst = 1.0 if tcp_data.get("rst") else 0.0
    fin = 1.0 if tcp_data.get("fin") else 0.0
    psh = 1.0 if tcp_data.get("psh") else 0.0
    urg = 1.0 if tcp_data.get("urg") else 0.0

    # Timing / window
    fwd_hdr_len = fwd_pkts * 20.0
    bwd_hdr_len = bwd_pkts * 20.0
    flow_iat_mean = (duration_sec / max(1.0, total_pkts - 1)) if total_pkts > 1 else 0.0
    fwd_iat_mean = (duration_sec / max(1.0, fwd_pkts - 1)) if fwd_pkts > 1 else 0.0

    down_up_ratio = bwd_pkts / max(1.0, fwd_pkts)
    flow_bytes_ratio = fwd_bytes / max(1.0, total_bytes)

    features: Dict[str, float] = {
        # Group 1: Flow traffic (7)
        "flow_duration": float(duration_us),
        "total_fwd_packets": float(fwd_pkts),
        "total_bwd_packets": float(bwd_pkts),
        "total_fwd_bytes": float(fwd_bytes),
        "total_bwd_bytes": float(bwd_bytes),
        "packets_per_sec": float(pkts_per_sec),
        "bytes_per_sec": float(bytes_per_sec),
        # Group 2: Packet size distribution (7)
        "fwd_packet_length_mean": float(fwd_len_mean),
        "bwd_packet_length_mean": float(bwd_len_mean),
        "packet_length_mean": float(pkt_len_mean),
        "packet_length_std": 0.0,
        "packet_length_max": float(pkt_len_max),
        "packet_length_min": float(pkt_len_min),
        "avg_pkt_size": float(pkt_len_mean),
        # Group 3: TCP flags (6)
        "syn_flag_count": float(syn),
        "ack_flag_count": float(ack),
        "rst_flag_count": float(rst),
        "fin_flag_count": float(fin),
        "psh_flag_count": float(psh),
        "urg_flag_count": float(urg),
        # Group 4: Window and timing (6)
        "init_win_bytes_fwd": 64240.0,
        "init_win_bytes_bwd": 29200.0 if bwd_pkts > 0 else 0.0,
        "flow_iat_mean": float(flow_iat_mean),
        "flow_iat_std": 0.0,
        "flow_iat_max": float(duration_sec),
        "fwd_iat_mean": float(fwd_iat_mean),
        # Group 5: Headers (2)
        "fwd_header_len": float(fwd_hdr_len),
        "bwd_header_len": float(bwd_hdr_len),
        # Group 6: Behavioral / derived (4)
        "down_up_ratio": float(down_up_ratio),
        "flow_bytes_ratio": float(flow_bytes_ratio),
        "active_mean": float(duration_us),
        "idle_mean": 0.0,
        # CICFlowMeter Aliases
        "Destination Port": float(dest_port),
        "Flow Duration": float(duration_us),
        "Total Fwd Packets": float(fwd_pkts),
        "Total Backward Packets": float(bwd_pkts),
        "Total Length of Fwd Packets": float(fwd_bytes),
        "Total Length of Bwd Packets": float(bwd_bytes),
        "Flow Packets/s": float(pkts_per_sec),
        "Flow Bytes/s": float(bytes_per_sec),
        "Init_Win_bytes_forward": 64240.0,
        "Init_Win_bytes_backward": 29200.0 if bwd_pkts > 0 else 0.0,
    }

    # Flow session tracking
    src_ip = str(doc.get("src_ip", "0.0.0.0"))
    src_port = int(doc.get("src_port", 0) or 0)
    dest_ip = str(doc.get("dest_ip", "0.0.0.0"))
    features["session_id"] = f"{src_ip}:{src_port}->{dest_ip}:{int(dest_port)}@{doc.get('timestamp')}"
    features["source"] = "suricata_eve"
    return features


class SuricataLiveTailer:
    """Live streaming tailer reading Suricata EVE records and feeding CyberGuard RT-IDS."""

    def __init__(
        self,
        eve_path: Optional[str | Path] = None,
        poll_interval: float = 0.25,
        feed_pipeline_worker: bool = True,
        persist_events: bool = True,
        sensor_id: str = "suricata-live",
    ):
        self.eve_path = Path(eve_path or DEFAULT_EVE_PATH).resolve()
        self.poll_interval = poll_interval
        self.feed_pipeline_worker = feed_pipeline_worker
        self.persist_events = persist_events
        self.sensor_id = sensor_id

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Telemetry
        self.total_lines_read = 0
        self.total_events_parsed = 0
        self.total_flows_enqueued = 0
        self.total_errors = 0
        self.last_event_time: float = 0.0

    def start(self, from_end: bool = False) -> None:
        """Start the background tailer thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._tail_loop,
                args=(from_end,),
                daemon=True,
                name="CyberGuard-SuricataTailer",
            )
            self._thread.start()
        logger.info("Suricata live tailer started on %s", self.eve_path)

    def stop(self) -> None:
        """Stop the background tailer thread."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            thread = self._thread

        if thread and thread.is_alive():
            thread.join(timeout=2.0)
        logger.info("Suricata live tailer stopped.")

    def process_line(self, line: str) -> Tuple[Optional[SecurityEventV1], Optional[Dict[str, float]]]:
        """Parse a single newline-delimited EVE JSON line and bridge into RT-IDS pipeline."""
        line_clean = line.strip()
        if not line_clean:
            return None, None

        try:
            doc = json.loads(line_clean)
        except json.JSONDecodeError as exc:
            with self._lock:
                self.total_errors += 1
            logger.debug("Failed to decode JSON from EVE stream: %s", exc)
            return None, None

        with self._lock:
            self.total_lines_read += 1

        # 1. Parse into SecurityEventV1
        line_res = _parse_single_eve_dict(
            doc,
            line_number=self.total_lines_read,
            sensor_id=self.sensor_id,
        )

        event = line_res.event
        flow_features = None

        if event:
            with self._lock:
                self.total_events_parsed += 1
                self.last_event_time = time.time()

            # 2. Extract 32-feature vector if event contains flow or network telemetry
            if doc.get("event_type") in ("flow", "alert", "tls", "dns"):
                flow_features = eve_to_flow_features(doc)

                # 3. Feed live pipeline worker
                if self.feed_pipeline_worker and flow_features:
                    enqueued = default_live_worker.enqueue_flow(flow_features)
                    if enqueued:
                        with self._lock:
                            self.total_flows_enqueued += 1

            # 4. Persist SecurityEventRecord if configured
            if self.persist_events and event:
                try:
                    with SessionLocal() as session:
                        rec = SecurityEventRecord(
                            event_ref=event.event_ref,
                            timestamp=event.timestamp,
                            timestamp_iso=event.timestamp_iso,
                            sensor_id=event.sensor_id,
                            source_event_type=event.source_event_type,
                            flow_id=event.flow_id,
                            community_id=event.community_id,
                            proto=event.proto,
                            app_proto=event.app_proto,
                            src_ip=event.src_ip,
                            src_port=event.src_port,
                            dest_ip=event.dest_ip,
                            dest_port=event.dest_port,
                            alert_signature=event.alert_signature,
                            alert_signature_id=event.alert_signature_id,
                            alert_category=event.alert_category,
                            alert_severity=event.alert_severity,
                            evidence_json=json.dumps(event.evidence, sort_keys=True),
                            raw_log=line_clean[:4096],
                            schema_version=event.schema_version,
                            adapter_version=event.adapter_version,
                        )
                        session.add(rec)
                        session.commit()
                except Exception as exc:
                    # Ignore duplicate event refs gracefully
                    logger.debug("Did not persist duplicate EVE event %s: %s", event.event_ref, exc)

        return event, flow_features

    def _tail_loop(self, from_end: bool) -> None:
        """Main file polling and rotation detection loop."""
        file_handle = None
        current_inode = None

        while self._running:
            try:
                if not self.eve_path.exists():
                    time.sleep(self.poll_interval)
                    continue

                if file_handle is None:
                    file_handle = self.eve_path.open("r", encoding="utf-8", errors="replace")
                    try:
                        current_inode = os.fstat(file_handle.fileno()).st_ino
                    except Exception:
                        current_inode = None
                    if from_end:
                        file_handle.seek(0, os.SEEK_END)

                # Read available lines
                while self._running:
                    line = file_handle.readline()
                    if line:
                        self.process_line(line)
                    else:
                        break

                # Rotation check
                if self.eve_path.exists():
                    try:
                        stat = self.eve_path.stat()
                        # If file shrunk or inode changed, file was rotated
                        if stat.st_size < file_handle.tell() or (current_inode and stat.st_ino != current_inode):
                            logger.info("Detected Suricata log rotation on %s. Reopening.", self.eve_path)
                            file_handle.close()
                            file_handle = None
                            current_inode = None
                    except Exception:
                        pass

                time.sleep(self.poll_interval)
            except Exception as exc:
                logger.error("Error in Suricata live tail loop: %s", exc)
                time.sleep(self.poll_interval)

        if file_handle:
            try:
                file_handle.close()
            except Exception:
                pass

    def get_status(self) -> Dict[str, Any]:
        """Return runtime status and metrics of Suricata tailer."""
        with self._lock:
            return {
                "is_running": self._running,
                "eve_path": str(self.eve_path),
                "path_exists": self.eve_path.exists(),
                "sensor_id": self.sensor_id,
                "total_lines_read": self.total_lines_read,
                "total_events_parsed": self.total_events_parsed,
                "total_flows_enqueued": self.total_flows_enqueued,
                "total_errors": self.total_errors,
                "last_event_time": self.last_event_time,
            }


class SyntheticEveReplayer:
    """Synthesizes or replays EVE JSON streams for automated testing and CI/CD."""

    @staticmethod
    def generate_eve_flow_event(
        src_ip: str = "192.168.1.100",
        dest_ip: str = "10.0.0.5",
        src_port: int = 50222,
        dest_port: int = 80,
        pkts_toserver: int = 25,
        pkts_toclient: int = 30,
        bytes_toserver: int = 1500,
        bytes_toclient: int = 12000,
        timestamp: Optional[str] = None,
    ) -> str:
        """Create a synthetic Suricata EVE flow JSON string."""
        ts = timestamp or "2026-10-17T06:30:00.000000+00:00"
        doc = {
            "timestamp": ts,
            "flow_id": int(time.time() * 1000) % 1_000_000_000,
            "event_type": "flow",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": "TCP",
            "app_proto": "http",
            "flow": {
                "pkts_toserver": pkts_toserver,
                "pkts_toclient": pkts_toclient,
                "bytes_toserver": bytes_toserver,
                "bytes_toclient": bytes_toclient,
                "start": ts,
                "end": ts,
                "age": 2,
                "state": "closed",
                "reason": "shutdown",
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
        return json.dumps(doc)

    @staticmethod
    def generate_eve_alert_event(
        sig: str = "ET EXPLOIT Apache Struts RCE Vulnerability",
        sid: int = 2024099,
        sev: int = 1,
        src_ip: str = "198.51.100.88",
        dest_ip: str = "10.0.0.1",
        src_port: int = 44444,
        dest_port: int = 8080,
        timestamp: Optional[str] = None,
    ) -> str:
        """Create a synthetic Suricata EVE alert JSON string."""
        ts = timestamp or "2026-10-17T06:30:00.000000+00:00"
        doc = {
            "timestamp": ts,
            "flow_id": int(time.time() * 1000) % 1_000_000_000,
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": sid,
                "rev": 1,
                "signature": sig,
                "category": "Attempted Administrator Privilege Gain",
                "severity": sev,
                "metadata": {
                    "mitre_technique_id": ["T1190"],
                    "mitre_tactic_id": ["TA0001"],
                },
            },
            "flow": {
                "pkts_toserver": 15,
                "pkts_toclient": 12,
                "bytes_toserver": 4500,
                "bytes_toclient": 2200,
                "age": 1,
            },
        }
        return json.dumps(doc)


# Default global tailer instance
default_suricata_tailer = SuricataLiveTailer()
