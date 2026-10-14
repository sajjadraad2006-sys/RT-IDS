#!/usr/bin/env python3
"""CyberGuard Real-Time Live Traffic Streamer & Demonstration Bridge.

Provides a live real-time stream of network flows to CyberGuard, demonstrating
real-time packet flow ingestion, feature extraction, AI classification,
and immediate SOC dashboard visualization without requiring Npcap kernel elevation.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.request

API_BASE = "http://127.0.0.1:8000"

# Normal benign web browsing baseline parameters
BENIGN_PROFILE = {
    "Flow Duration": (50000, 300000),
    "Total Fwd Packets": (5, 25),
    "Total Backward Packets": (4, 30),
    "Total Length of Fwd Packets": (500, 4000),
    "Total Length of Bwd Packets": (1500, 35000),
    "Flow Packets/s": (10, 80),
    "Flow Bytes/s": (1000, 20000),
    "Packet Length Mean": (100, 600),
    "Packet Length Std": (50, 400),
    "Packet Length Max": (1460, 1500),
    "Min Packet Length": (40, 54),
    "SYN Flag Count": (1, 2),
    "ACK Flag Count": (8, 50),
    "RST Flag Count": (0, 0),
    "FIN Flag Count": (1, 2),
    "PSH Flag Count": (2, 10),
    "URG Flag Count": (0, 0),
    "Init_Win_bytes_fwd": (8192, 65535),
    "Init_Win_bytes_bwd": (8192, 65535),
    "Flow IAT Mean": (1000, 15000),
    "Flow IAT Std": (500, 8000),
    "Flow IAT Max": (5000, 50000),
    "Fwd IAT Mean": (2000, 20000),
    "Fwd Header Length": (160, 500),
    "Bwd Header Length": (160, 600),
    "Down/Up Ratio": (1.0, 4.0),
    "Active Mean": (0, 10000),
    "Idle Mean": (0, 10000),
}

ATTACK_PROFILES = {
    "DDoS": {
        "Flow Duration": (100, 5000),
        "Total Fwd Packets": (500, 5000),
        "Total Backward Packets": (0, 5),
        "Total Length of Fwd Packets": (20000, 250000),
        "Total Length of Bwd Packets": (0, 200),
        "Flow Packets/s": (5000, 50000),
        "Flow Bytes/s": (200000, 2500000),
        "SYN Flag Count": (500, 5000),
        "ACK Flag Count": (0, 2),
        "RST Flag Count": (0, 1),
        "Init_Win_bytes_fwd": (1024, 4096),
        "Init_Win_bytes_bwd": (0, 0),
        "Down/Up Ratio": (0.0, 0.05),
    },
    "PortScan": {
        "Flow Duration": (50, 2000),
        "Total Fwd Packets": (1, 3),
        "Total Backward Packets": (0, 1),
        "Total Length of Fwd Packets": (40, 160),
        "Total Length of Bwd Packets": (0, 40),
        "Flow Packets/s": (50, 500),
        "Flow Bytes/s": (2000, 20000),
        "SYN Flag Count": (1, 3),
        "ACK Flag Count": (0, 1),
        "RST Flag Count": (0, 1),
        "Init_Win_bytes_fwd": (1024, 2048),
        "Init_Win_bytes_bwd": (0, 0),
        "Down/Up Ratio": (0.0, 0.0),
    },
}


def generate_flow_record(attack_type: str | None = None) -> dict:
    flow = {}
    for k, (low, high) in BENIGN_PROFILE.items():
        val = random.uniform(low, high)
        flow[k] = int(val) if isinstance(low, int) else round(val, 2)

    if attack_type and attack_type in ATTACK_PROFILES:
        overrides = ATTACK_PROFILES[attack_type]
        for k, (low, high) in overrides.items():
            val = random.uniform(low, high)
            flow[k] = int(val) if isinstance(low, int) else round(val, 2)

    return flow


def push_flow_to_cyberguard(flow: dict) -> dict:
    csv_header = ",".join(flow.keys())
    csv_row = ",".join(str(v) for v in flow.values())
    csv_content = f"{csv_header}\n{csv_row}\n".encode("utf-8")

    boundary = "----CyberGuardLiveStreamBoundary12345"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"live_telemetry.csv\"\r\n"
        f"Content-Type: text/csv\r\n\r\n"
        f"{csv_content.decode('utf-8')}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{API_BASE}/api/detect/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return {"error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Real-Time Live Traffic Streamer")
    parser.add_argument("--interval", type=float, default=1.0, help="Interval in seconds between flows")
    parser.add_argument("--count", type=int, default=10, help="Total flows to send (default: 10)")
    parser.add_argument("--attack", choices=["none", "DDoS", "PortScan", "random"], default="random", help="Inject attack")
    args = parser.parse_args()

    print("=" * 70)
    print("  CyberGuard Real-Time Live Traffic Streamer Bridge")
    print("  Target: http://127.0.0.1:8000/api/detect/upload")
    print(f"  Streaming {args.count} flows every {args.interval}s [Attack Mode: {args.attack}]")
    print("=" * 70)

    for i in range(1, args.count + 1):
        attack = None
        if args.attack == "random":
            if i % 3 == 0:
                attack = random.choice(["DDoS", "PortScan"])
        elif args.attack != "none":
            attack = args.attack

        flow = generate_flow_record(attack)
        t0 = time.perf_counter()
        res = push_flow_to_cyberguard(flow)
        dt = (time.perf_counter() - t0) * 1000

        alerts = res.get("alerts_generated", 0)
        route_summary = res.get("route_counts", {})
        status = "ALERT [MALICIOUS]" if alerts > 0 else "NORMAL [BENIGN]"
        print(f"[{i:02d}/{args.count:02d}] {status} | Target: {attack or 'Benign':<8} | Latency: {dt:6.2f}ms | Routes: {route_summary}")
        time.sleep(args.interval)

    print("\nStream completed. Check the SOC Dashboard at http://127.0.0.1:8000 to see real-time alerts!")


if __name__ == "__main__":
    main()
