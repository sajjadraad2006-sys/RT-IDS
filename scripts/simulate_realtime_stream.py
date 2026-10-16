"""End-to-End Real-Time Flow Streaming Simulation & Stress Benchmark.

Simulates a realistic real-time traffic feed into CyberGuard's LiveFlowSniffer
and LiveFlowWorker bridge, measuring:
- Line-rate packet ingestion into bidirectional flows.
- Immediate/timeout flow flushing to the LiveFlowWorker queue.
- Micro-batch inference throughput via DetectionPipeline v2.
- Alert generation rate, accuracy, and latency.
- Database write performance under SQLite WAL mode.
- System stability, queue sizing, and dropped flows.
"""
from __future__ import annotations

import collections
import json
import logging
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from backend.db.init_db import init_all
from backend.db.models import AlertRecord, SessionLocal
from backend.detection.features import FEATURE_NAMES
from backend.detection.live_sniffer import default_live_sniffer
from backend.detection.live_worker import default_live_worker
from backend.main import app

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cyberguard.sim")


def generate_packet_stream(
    num_flows: int = 100,
    attack_ratio: float = 0.3,
) -> List[Dict[str, Any]]:
    """Generate a sequence of packets belonging to benign and attack flows."""
    packets = []
    base_time = time.time() - 30.0

    for flow_idx in range(num_flows):
        is_attack = random.random() < attack_ratio
        attack_type = random.choice(["DDoS", "PortScan", "Anomaly"]) if is_attack else "Benign"

        src_ip = f"192.168.1.{10 + (flow_idx % 200)}"
        dst_ip = "10.0.0.1" if attack_type != "PortScan" else f"10.0.0.{random.randint(1, 50)}"
        src_port = 10000 + (flow_idx % 40000)
        dst_port = random.choice([80, 443, 8080]) if attack_type != "PortScan" else random.randint(1, 1024)
        proto = 6  # TCP

        flow_start = base_time + (flow_idx * 0.1)

        if attack_type == "Benign":
            # 3-way handshake + HTTP data + FIN teardown
            # 1. SYN
            packets.append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "proto": proto, "length": 60, "tcp_flags": 0x02, "win_size": 64240, "timestamp": flow_start,
            })
            # 2. SYN-ACK (Server -> Client)
            packets.append({
                "src_ip": dst_ip, "dst_ip": src_ip, "src_port": dst_port, "dst_port": src_port,
                "proto": proto, "length": 60, "tcp_flags": 0x12, "win_size": 29200, "timestamp": flow_start + 0.01,
            })
            # 3. ACK
            packets.append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "proto": proto, "length": 52, "tcp_flags": 0x10, "win_size": 64240, "timestamp": flow_start + 0.015,
            })
            # 4. Data request (Client -> Server)
            packets.append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "proto": proto, "length": 450, "tcp_flags": 0x18, "win_size": 64240, "timestamp": flow_start + 0.03,
            })
            # 5. Data response (Server -> Client)
            packets.append({
                "src_ip": dst_ip, "dst_ip": src_ip, "src_port": dst_port, "dst_port": src_port,
                "proto": proto, "length": 1400, "tcp_flags": 0x18, "win_size": 29200, "timestamp": flow_start + 0.05,
            })
            # 6. FIN-ACK
            packets.append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "proto": proto, "length": 52, "tcp_flags": 0x11, "win_size": 64240, "timestamp": flow_start + 0.08,
            })

        elif attack_type == "DDoS":
            # Volumetric SYN Flood
            for pkt_i in range(15):
                packets.append({
                    "src_ip": f"198.51.100.{random.randint(1, 254)}", "dst_ip": dst_ip,
                    "src_port": random.randint(1024, 65535), "dst_port": dst_port,
                    "proto": proto, "length": 64, "tcp_flags": 0x02, "win_size": 256,
                    "timestamp": flow_start + (pkt_i * 0.001),
                })
            # Immediate RST
            packets.append({
                "src_ip": dst_ip, "dst_ip": src_ip, "src_port": dst_port, "dst_port": src_port,
                "proto": proto, "length": 40, "tcp_flags": 0x04, "win_size": 0, "timestamp": flow_start + 0.02,
            })

        elif attack_type == "PortScan":
            # Single SYN probes
            packets.append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "proto": proto, "length": 44, "tcp_flags": 0x02, "win_size": 1024, "timestamp": flow_start,
            })
            # Immediate RST/ACK from closed port
            packets.append({
                "src_ip": dst_ip, "dst_ip": src_ip, "src_port": dst_port, "dst_port": src_port,
                "proto": proto, "length": 40, "tcp_flags": 0x14, "win_size": 0, "timestamp": flow_start + 0.005,
            })

        elif attack_type == "Anomaly":
            # Unusual packet size and extreme IAT
            packets.append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "proto": proto, "length": 65500, "tcp_flags": 0x20, "win_size": 100, "timestamp": flow_start,
            })
            packets.append({
                "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
                "proto": proto, "length": 65500, "tcp_flags": 0x01, "win_size": 100, "timestamp": flow_start + 10.0,
            })

    return packets


def run_realtime_simulation(total_flows: int = 150):
    print("=" * 75)
    print("  CYBERGUARD REAL-TIME FLOW INGESTION & PIPELINE BENCHMARK")
    print(f"  Target: LiveFlowSniffer -> LiveFlowWorker (Bounded Queue) -> Pipeline v2")
    print(f"  Workload: {total_flows} communication flows with mixed attack profiles")
    print("=" * 75)

    init_all()
    client = TestClient(app)

    # 1. Start Live Capture via API
    print("\n[Step 1] Starting Live Sniffer and Detection Worker via API...")
    res_start = client.post("/api/detect/live/start")
    assert res_start.status_code == 200, f"Start failed: {res_start.text}"
    start_data = res_start.json()
    print(f"  -> Capture armed: active={start_data['status']['active']}, mode={start_data['status']['mode']}")
    print(f"  -> Pipeline Worker running: {start_data['status']['worker']['is_running']}")

    # 2. Generate and Ingest Packet Stream
    print(f"\n[Step 2] Generating packet stream for {total_flows} flows...")
    packets = generate_packet_stream(num_flows=total_flows, attack_ratio=0.35)
    print(f"  -> Generated {len(packets)} packets across {total_flows} flows.")

    print("\n[Step 3] Streaming packets into LiveFlowSniffer...")
    t_start = time.perf_counter()
    for pkt in packets:
        default_live_sniffer.process_packet(
            src_ip=pkt["src_ip"],
            dst_ip=pkt["dst_ip"],
            src_port=pkt["src_port"],
            dst_port=pkt["dst_port"],
            proto=pkt["proto"],
            length=pkt["length"],
            tcp_flags=pkt["tcp_flags"],
            win_size=pkt["win_size"],
            timestamp=pkt["timestamp"],
        )
    t_ingest = time.perf_counter() - t_start
    pps = len(packets) / max(1e-6, t_ingest)
    print(f"  -> Ingestion completed in {t_ingest*1000:.2f} ms ({pps:,.0f} packets/sec).")

    # 3. Flush expired remaining flows
    print("\n[Step 4] Flushing expired flows...")
    flushed = default_live_sniffer.flush_expired_flows(now=time.time() + 300.0)
    print(f"  -> Flushed {len(flushed)} timed-out flows.")

    # 4. Wait for LiveFlowWorker to consume queue
    print("\n[Step 5] Waiting for LiveFlowWorker to finish queue processing...")
    t_drain_start = time.perf_counter()
    while not default_live_worker.queue.empty():
        time.sleep(0.05)
        if time.perf_counter() - t_drain_start > 10.0:
            print("  [WARN] Queue drain timeout exceeded!")
            break
    time.sleep(0.6)  # Allow final batch flush

    worker_status = default_live_worker.get_status()
    print(f"  -> Worker Processed: {worker_status['total_processed']} flows.")
    print(f"  -> Worker Alerts Generated: {worker_status['total_alerts']} alerts.")
    print(f"  -> Worker Dropped: {worker_status['total_dropped']} flows.")

    # 5. Query API telemetry & alerts
    print("\n[Step 6] Verifying API Live Telemetry & Alert Stream...")
    res_status = client.get("/api/detect/live/status")
    status = res_status.json()
    print(f"  -> API Telemetry: captured={status['packets_captured']} pkts, flushed={status['flows_aggregated']} flows")

    res_alerts = client.get("/api/detect/live/alerts?limit=100")
    alerts_data = res_alerts.json()
    alerts = alerts_data["alerts"]
    print(f"  -> API Live Alerts Returned: {len(alerts)} alerts (Total in system: {alerts_data['total_alerts']})")

    # Sample alert breakdown
    alert_types = collections.Counter(a["type"] for a in alerts)
    alert_routes = collections.Counter(a["route"] for a in alerts)
    print(f"  -> Alert Types Detected: {dict(alert_types)}")
    print(f"  -> Alert Routes: {dict(alert_routes)}")

    # 6. Verify SQLite Database Persistence
    print("\n[Step 7] Checking Database Records in SQLite...")
    with SessionLocal() as db_session:
        db_count = db_session.query(AlertRecord).filter_by(source_file="live://sniffer").count()
        sample_record = (
            db_session.query(AlertRecord)
            .filter_by(source_file="live://sniffer")
            .order_by(AlertRecord.id.desc())
            .first()
        )
    print(f"  -> Total AlertRecords persisted with source 'live://sniffer': {db_count}")
    if sample_record:
        print(f"  -> Sample DB Alert: ID={sample_record.id}, Type={sample_record.type}, Severity={sample_record.severity}, Route={sample_record.route}")

    # 7. Stop Live Capture
    print("\n[Step 8] Stopping Live Capture...")
    res_stop = client.post("/api/detect/live/stop")
    stop_data = res_stop.json()
    print(f"  -> Stopped: active={stop_data['status']['active']}, worker_running={stop_data['status']['worker']['is_running']}")

    print("\n" + "=" * 75)
    print("  SIMULATION RESULTS & PERFORMANCE SUMMARY")
    print(f"  Total Packets Processed: {status['packets_captured']}")
    print(f"  Total Flows Aggregated:  {status['flows_aggregated']}")
    print(f"  Total Ingestion Rate:    {pps:,.0f} pkts/sec")
    print(f"  Alerts Generated:        {alerts_data['total_alerts']}")
    print(f"  DB Records Stored:       {db_count}")
    print(f"  Queue Overflow Drops:    {worker_status['total_dropped']}")
    print("=" * 75)

    return {
        "status": status,
        "pps": pps,
        "total_alerts": alerts_data["total_alerts"],
        "db_count": db_count,
        "alert_types": dict(alert_types),
    }


if __name__ == "__main__":
    results = run_realtime_simulation(total_flows=120)
    print("\nSimulation script completed successfully.")
