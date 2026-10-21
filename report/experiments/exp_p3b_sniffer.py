"""Experiment P3.b: Live Sniffer Behavioral Verification and Throughput Benchmark.

Measures:
1. TCP Handshake + Teardown flow lifecycle
2. TCP RST immediate flush
3. Idle and active timeout flushes
4. TIME_WAIT trailing ACK absorption
5. Early interim anomaly evaluation micro-windows
6. UDP flow aggregation
7. IPv6 drop behavior
8. Host raw socket loopback capture capability
9. Packets/sec throughput of process_packet()
"""
import datetime
import hashlib
import json
import os
import platform
import socket
import struct
import sys
import time
from pathlib import Path

# Ensure root workspace is on sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir))

from backend.detection.live_sniffer import LiveFlowSniffer, FlowRecord, PacketParseResult


def get_environment_info():
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "cpu_count": os.cpu_count() or 1,
    }


def run_sniffer_suite():
    results = {
        "metadata": {
            "experiment": "P3.b_sniffer_verification",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "environment": get_environment_info(),
        },
        "tests": {},
        "throughput": {}
    }

    # Test 1: TCP Handshake + Teardown
    flushed_flows_1 = []
    sniffer1 = LiveFlowSniffer(on_flow_flushed=lambda f: flushed_flows_1.append(f))
    t0 = 1000.0
    # Client SYN
    sniffer1.process_packet("10.0.0.1", "10.0.0.2", 12345, 80, 6, 60, tcp_flags=0x02, win_size=65535, timestamp=t0)
    # Server SYN-ACK
    sniffer1.process_packet("10.0.0.2", "10.0.0.1", 80, 12345, 6, 60, tcp_flags=0x12, win_size=64240, timestamp=t0 + 0.01)
    # Client ACK
    sniffer1.process_packet("10.0.0.1", "10.0.0.2", 12345, 80, 6, 52, tcp_flags=0x10, win_size=65535, timestamp=t0 + 0.02)
    # Client Data PSH-ACK
    sniffer1.process_packet("10.0.0.1", "10.0.0.2", 12345, 80, 6, 250, tcp_flags=0x18, win_size=65535, timestamp=t0 + 0.05)
    # Server Data PSH-ACK
    sniffer1.process_packet("10.0.0.2", "10.0.0.1", 80, 12345, 6, 1024, tcp_flags=0x18, win_size=64240, timestamp=t0 + 0.08)
    # Client FIN-ACK
    sniffer1.process_packet("10.0.0.1", "10.0.0.2", 12345, 80, 6, 52, tcp_flags=0x11, win_size=65535, timestamp=t0 + 0.10)
    # Server FIN-ACK (bidirectional completion)
    sniffer1.process_packet("10.0.0.2", "10.0.0.1", 80, 12345, 6, 52, tcp_flags=0x11, win_size=64240, timestamp=t0 + 0.12)

    results["tests"]["tcp_handshake_teardown"] = {
        "status": "PASSED" if len(flushed_flows_1) == 1 else "FAILED",
        "flushed_count": len(flushed_flows_1),
        "flow_features": flushed_flows_1[0] if flushed_flows_1 else None,
        "fwd_packets": flushed_flows_1[0]["total_fwd_packets"] if flushed_flows_1 else 0,
        "bwd_packets": flushed_flows_1[0]["total_bwd_packets"] if flushed_flows_1 else 0,
        "active_mean": flushed_flows_1[0]["active_mean"] if flushed_flows_1 else None,
        "idle_mean": flushed_flows_1[0]["idle_mean"] if flushed_flows_1 else None,
    }

    # Test 2: TCP RST immediate flush
    flushed_flows_2 = []
    sniffer2 = LiveFlowSniffer(on_flow_flushed=lambda f: flushed_flows_2.append(f))
    sniffer2.process_packet("10.0.0.5", "10.0.0.6", 5001, 443, 6, 60, tcp_flags=0x02, timestamp=2000.0)
    sniffer2.process_packet("10.0.0.6", "10.0.0.5", 443, 5001, 6, 40, tcp_flags=0x04, timestamp=2000.01) # RST

    results["tests"]["tcp_rst_immediate_flush"] = {
        "status": "PASSED" if len(flushed_flows_2) == 1 else "FAILED",
        "rst_count": flushed_flows_2[0]["rst_flag_count"] if flushed_flows_2 else 0,
    }

    # Test 3: Idle timeout and Active timeout
    flushed_flows_3 = []
    sniffer3 = LiveFlowSniffer(idle_timeout_sec=5.0, active_timeout_sec=30.0, on_flow_flushed=lambda f: flushed_flows_3.append(f))
    sniffer3.process_packet("10.0.0.10", "10.0.0.20", 3000, 8080, 6, 100, timestamp=3000.0)
    sniffer3.flush_expired_flows(now=3004.0) # Within 5s idle -> should not flush
    count_before = len(flushed_flows_3)
    sniffer3.flush_expired_flows(now=3006.0) # > 5s idle -> should flush
    count_after = len(flushed_flows_3)

    results["tests"]["idle_timeout"] = {
        "status": "PASSED" if (count_before == 0 and count_after == 1) else "FAILED",
        "flushed_before_expiry": count_before,
        "flushed_after_expiry": count_after,
    }

    # Test 4: TIME_WAIT ACK absorption
    flushed_flows_4 = []
    sniffer4 = LiveFlowSniffer(on_flow_flushed=lambda f: flushed_flows_4.append(f))
    # Full close
    sniffer4.process_packet("10.0.0.1", "10.0.0.2", 9000, 80, 6, 60, tcp_flags=0x02, timestamp=4000.0)
    sniffer4.process_packet("10.0.0.2", "10.0.0.1", 80, 9000, 6, 60, tcp_flags=0x12, timestamp=4000.01)
    sniffer4.process_packet("10.0.0.1", "10.0.0.2", 9000, 80, 6, 52, tcp_flags=0x11, timestamp=4000.02)
    sniffer4.process_packet("10.0.0.2", "10.0.0.1", 80, 9000, 6, 52, tcp_flags=0x11, timestamp=4000.03) # Flushes flow
    # Stray trailing ACK within TIME_WAIT window (1.0s later)
    sniffer4.process_packet("10.0.0.1", "10.0.0.2", 9000, 80, 6, 52, tcp_flags=0x10, timestamp=4000.5)

    status_4 = sniffer4.get_status()
    results["tests"]["time_wait_ack_absorption"] = {
        "status": "PASSED" if (len(flushed_flows_4) == 1 and status_4["teardown_acks_absorbed"] == 1 and status_4["active_flows"] == 0) else "FAILED",
        "total_flows_flushed": len(flushed_flows_4),
        "teardown_acks_absorbed": status_4["teardown_acks_absorbed"],
        "active_flows_remaining": status_4["active_flows"],
    }

    # Test 5: Early Interim Anomaly Evaluation (Micro-Windows)
    interim_flows = []
    final_flows = []
    def dispatch_capture(feat):
        if feat.get("is_interim") == 1.0:
            interim_flows.append(feat)
        else:
            final_flows.append(feat)

    sniffer5 = LiveFlowSniffer(on_flow_flushed=dispatch_capture)
    sniffer5.early_packet_threshold = 5  # Lower threshold for deterministic test
    for i in range(12):
        sniffer5.process_packet("10.0.0.100", "10.0.0.200", 4444, 80, 6, 100, timestamp=5000.0 + i * 0.1)

    results["tests"]["early_interim_micro_windows"] = {
        "status": "PASSED" if len(interim_flows) >= 1 else "FAILED",
        "interim_flows_generated": len(interim_flows),
        "interim_features_sample": interim_flows[0] if interim_flows else None,
    }

    # Test 6: UDP Flow Aggregation
    flushed_udp = []
    sniffer6 = LiveFlowSniffer(idle_timeout_sec=2.0, on_flow_flushed=lambda f: flushed_udp.append(f))
    # DNS Query & Response
    sniffer6.process_packet("192.168.1.10", "8.8.8.8", 53535, 53, 17, 68, timestamp=6000.0)
    sniffer6.process_packet("8.8.8.8", "192.168.1.10", 53, 53535, 17, 142, timestamp=6000.02)
    sniffer6.flush_expired_flows(now=6005.0)

    results["tests"]["udp_flow_aggregation"] = {
        "status": "PASSED" if len(flushed_udp) == 1 else "FAILED",
        "protocol": flushed_udp[0].get("proto") if flushed_udp else 17,
        "fwd_pkts": flushed_udp[0]["total_fwd_packets"] if flushed_udp else 0,
        "bwd_pkts": flushed_udp[0]["total_bwd_packets"] if flushed_udp else 0,
    }

    # Test 7: IPv6 Drop in parse_ipv4_packet
    # Construct a raw synthetic IPv6 packet header (version 6 in top 4 bits: 0x60)
    raw_ipv6 = bytes([0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40]) + (b"\x00" * 32)
    parsed_v6 = sniffer1.parse_ipv4_packet(raw_ipv6)
    results["tests"]["ipv6_packet_handling"] = {
        "status": "PASSED" if parsed_v6 is None else "FAILED",
        "parsed_result": str(parsed_v6),
        "note": "IPv6 packets are dropped (parse_ipv4_packet requires version == 4)",
    }

    # Test 8: Loopback Live Capture attempt
    sniffer_live = LiveFlowSniffer()
    capture_success = sniffer_live.start_capture(host="127.0.0.1")
    live_status = sniffer_live.get_status()
    sniffer_live.stop_capture()
    results["tests"]["loopback_live_capture_attempt"] = {
        "start_capture_returned": capture_success,
        "mode_reported": live_status["mode"],
        "is_capturing": live_status["is_capturing"],
        "note": "When unprivileged, raw socket binding fails and falls back to synthetic_harness mode while returning True",
    }

    # Test 9: Throughput Benchmark (50,000 synthetic packets)
    sniffer_bench = LiveFlowSniffer()
    num_packets = 50000
    # Pre-generate synthetic packet arguments to avoid benchmark generator overhead
    packets = [
        ("192.168.1.50", "10.0.0.1", 10000 + (i % 500), 80, 6, 128, 0x18, 65535, 7000.0 + i * 0.0001, 40)
        for i in range(num_packets)
    ]

    t_start = time.perf_counter()
    for pkt in packets:
        sniffer_bench.process_packet(
            src_ip=pkt[0], dst_ip=pkt[1], src_port=pkt[2], dst_port=pkt[3],
            proto=pkt[4], length=pkt[5], tcp_flags=pkt[6], win_size=pkt[7],
            timestamp=pkt[8], header_len=pkt[9]
        )
    t_end = time.perf_counter()
    elapsed = t_end - t_start
    throughput_pps = num_packets / elapsed if elapsed > 0 else 0.0

    results["throughput"] = {
        "packet_count": num_packets,
        "elapsed_seconds": round(elapsed, 4),
        "packets_per_second": round(throughput_pps, 2),
        "average_latency_microseconds": round((elapsed / num_packets) * 1e6, 3),
    }

    # Output file
    out_dir = root_dir / "report" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "sniffer_experiments.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[*] Sniffer test suite complete. Results saved to {out_path}")
    print(f"[*] Measured Throughput: {results['throughput']['packets_per_second']} pkts/sec ({results['throughput']['average_latency_microseconds']} us/pkt)")
    for tname, tdata in results["tests"].items():
        print(f"  - {tname:32}: {tdata.get('status', 'DONE')}")


if __name__ == "__main__":
    run_sniffer_suite()
