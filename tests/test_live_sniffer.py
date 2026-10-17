"""Comprehensive Unit & Integration Test Suite for Live Network Flow Sniffer.

Validates:
1. Raw IPv4 TCP and UDP packet header parsing.
2. Bidirectional flow assembly (forward and reverse packet aggregation).
3. 32-feature CICFlowMeter dictionary conformity against FEATURE_NAMES.
4. Immediate flow flushing upon TCP connection termination (FIN / RST).
5. Timeout-driven expiration (idle timeout and active duration limits).
6. Sniffer daemon lifecycle (start, stop, status).
"""
import math
import struct
import time
import pytest

from backend.detection.features import FEATURE_NAMES
from backend.detection.live_sniffer import FlowRecord, LiveFlowSniffer


def build_synthetic_ipv4_tcp_packet(
    src_ip: str = "192.168.1.50",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 443,
    flags: int = 0x02,  # SYN
    payload: bytes = b"GET / HTTP/1.1\r\n",
) -> bytes:
    """Construct a synthetic valid IPv4 TCP packet."""
    import socket
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    # IPv4 Header (20 bytes)
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + 20 + len(payload)
    ident = 54321
    flags_frag = 0
    ttl = 64
    proto = 6  # TCP
    checksum = 0

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ident, flags_frag, ttl, proto, checksum, src_bytes, dst_bytes
    )

    # TCP Header (20 bytes)
    seq = 1000
    ack = 0
    data_offset = (5 << 4)
    win_size = 64240
    urg_ptr = 0

    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack, data_offset, flags, win_size, 0, urg_ptr
    )

    return ip_hdr + tcp_hdr + payload


def test_packet_parsing_valid_tcp():
    sniffer = LiveFlowSniffer()
    raw_pkt = build_synthetic_ipv4_tcp_packet()
    parsed = sniffer.parse_ipv4_packet(raw_pkt)
    assert parsed is not None
    src_ip, dst_ip, src_port, dst_port, proto, length, tcp_flags, win_size = parsed

    assert src_ip == "192.168.1.50"
    assert dst_ip == "10.0.0.1"
    assert src_port == 54321
    assert dst_port == 443
    assert proto == 6
    assert tcp_flags == 0x02  # SYN
    assert win_size == 64240


def test_flow_aggregation_bidirectional():
    sniffer = LiveFlowSniffer()
    t0 = 1000.0

    # 1. Forward packet (Client -> Server)
    sniffer.process_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=443,
        proto=6,
        length=60,
        tcp_flags=0x02,  # SYN
        win_size=64240,
        timestamp=t0,
    )

    # 2. Reverse packet (Server -> Client)
    sniffer.process_packet(
        src_ip="10.0.0.1",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=54321,
        proto=6,
        length=60,
        tcp_flags=0x12,  # SYN-ACK
        win_size=29200,
        timestamp=t0 + 0.015,
    )

    # Check that both packets mapped to a single active flow
    status = sniffer.get_status()
    assert status["active_flows"] == 1
    assert status["total_packets_captured"] == 2

    # Flush flow and check 32-feature coverage
    flushed = sniffer.flush_expired_flows(now=t0 + 20.0)
    assert len(flushed) == 1
    feat_dict = flushed[0]

    assert feat_dict["Total Fwd Packets"] == 1.0
    assert feat_dict["Total Backward Packets"] == 1.0
    assert feat_dict["Destination Port"] == 443.0
    assert feat_dict["Init_Win_bytes_forward"] == 64240.0
    assert feat_dict["Init_Win_bytes_backward"] == 29200.0


def test_feature_vector_matches_model_feature_names():
    flow = FlowRecord(key=("192.168.1.50", "10.0.0.1", 54321, 80, 6), is_forward=True, timestamp=100.0)
    flow.update(length=120, is_fwd=True, tcp_flags=0x02, win_size=32768, timestamp=100.0)
    flow.update(length=850, is_fwd=False, tcp_flags=0x18, win_size=16384, timestamp=100.05)

    feat_dict = flow.to_feature_dict()

    # Verify that all 32 model features are present and non-empty
    for name in FEATURE_NAMES:
        assert name in feat_dict, f"Missing required model feature: {name}"
        assert not math.isnan(feat_dict[name]), f"Feature {name} produced NaN"
        assert not math.isinf(feat_dict[name]), f"Feature {name} produced Inf"


def test_tcp_fin_triggers_immediate_flow_flush():
    flushed_records = []
    sniffer = LiveFlowSniffer(on_flow_flushed=lambda rec: flushed_records.append(rec))

    # Send data packet
    sniffer.process_packet(
        src_ip="10.10.10.2",
        dst_ip="203.0.113.5",
        src_port=4000,
        dst_port=80,
        proto=6,
        length=200,
        tcp_flags=0x10,
        timestamp=100.0,
    )
    assert len(flushed_records) == 0

    # Send FIN packet
    sniffer.process_packet(
        src_ip="10.10.10.2",
        dst_ip="203.0.113.5",
        src_port=4000,
        dst_port=80,
        proto=6,
        length=40,
        tcp_flags=0x01,  # FIN
        timestamp=100.1,
    )

    # Must be flushed immediately upon connection termination
    assert len(flushed_records) == 1
    assert sniffer.get_status()["active_flows"] == 0


def test_sniffer_lifecycle_and_status():
    sniffer = LiveFlowSniffer(idle_timeout_sec=5.0)
    assert sniffer.get_status()["is_capturing"] is False

    # Start capture (falls back gracefully to synthetic harness if non-admin)
    started = sniffer.start_capture()
    assert started is True
    assert sniffer.get_status()["is_capturing"] is True

    # Stop capture
    sniffer.stop_capture()
    assert sniffer.get_status()["is_capturing"] is False


def test_raw_packet_with_8_0_ip_not_mistaken_for_ethernet():
    sniffer = LiveFlowSniffer()
    raw_pkt = build_synthetic_ipv4_tcp_packet(src_ip="8.0.1.2", dst_ip="10.0.0.1")
    parsed = sniffer.parse_ipv4_packet(raw_pkt)
    assert parsed is not None
    src_ip, dst_ip, src_port, dst_port, proto, length, tcp_flags, win_size = parsed
    assert src_ip == "8.0.1.2"
    assert dst_ip == "10.0.0.1"
    assert parsed.header_len == 40  # 20 IP + 20 TCP


def test_ethernet_encapsulated_ipv4_packet():
    sniffer = LiveFlowSniffer()
    raw_ip_pkt = build_synthetic_ipv4_tcp_packet(src_ip="192.168.1.100", dst_ip="172.16.0.1")
    # 14-byte Ethernet header: Dst MAC (6) + Src MAC (6) + EtherType 0x0800 (2)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    eth_pkt = eth_hdr + raw_ip_pkt
    parsed = sniffer.parse_ipv4_packet(eth_pkt)
    assert parsed is not None
    src_ip, dst_ip, src_port, dst_port, proto, length, tcp_flags, win_size = parsed
    assert src_ip == "192.168.1.100"
    assert dst_ip == "172.16.0.1"


def test_tcp_bidirectional_stateful_teardown():
    flushed = []
    sniffer = LiveFlowSniffer(on_flow_flushed=lambda r: flushed.append(r))
    t0 = 200.0

    # 1. Forward SYN
    sniffer.process_packet("192.168.1.10", "10.0.0.1", 5000, 80, 6, length=60, tcp_flags=0x02, timestamp=t0)
    # 2. Backward SYN-ACK
    sniffer.process_packet("10.0.0.1", "192.168.1.10", 80, 5000, 6, length=60, tcp_flags=0x12, timestamp=t0 + 0.01)
    # 3. Client FIN-ACK (first FIN)
    sniffer.process_packet("192.168.1.10", "10.0.0.1", 5000, 80, 6, length=52, tcp_flags=0x11, timestamp=t0 + 0.05)

    # In stateful teardown, bidirectional flow remains active until reciprocal FIN or RST arrives
    assert len(flushed) == 0
    assert sniffer.get_status()["active_flows"] == 1

    # 4. Server FIN-ACK (reciprocal FIN)
    sniffer.process_packet("10.0.0.1", "192.168.1.10", 80, 5000, 6, length=52, tcp_flags=0x11, timestamp=t0 + 0.06)

    # Now connection is fully closed: exactly 1 unified flow flushed
    assert len(flushed) == 1
    assert sniffer.get_status()["active_flows"] == 0
    rec = flushed[0]
    assert rec["total_fwd_packets"] == 2.0
    assert rec["total_bwd_packets"] == 2.0
    assert rec["fin_flag_count"] == 2.0


def test_header_length_accumulation_and_microflow_rates():
    flow = FlowRecord(key=("192.168.1.1", "10.0.0.1", 1234, 80, 6), is_forward=True, timestamp=100.0)
    flow.update(length=100, is_fwd=True, tcp_flags=0x02, win_size=1000, timestamp=100.0, header_len=40)
    flow.update(length=200, is_fwd=False, tcp_flags=0x12, win_size=1000, timestamp=100.0001, header_len=32)

    features = flow.to_feature_dict()
    assert features["fwd_header_len"] == 40.0
    assert features["bwd_header_len"] == 32.0
    assert not math.isinf(features["packets_per_sec"])
    assert not math.isnan(features["packets_per_sec"])
    # Safe rate capping ensures packets_per_sec <= 2 / 0.001 = 2000 pkts/sec instead of 20,000,000 pkts/sec
    assert features["packets_per_sec"] <= 2000.0


@pytest.mark.parametrize("sequence_type", [
    "standard_4way",      # Client FIN -> Server ACK -> Server FIN -> Client final ACK
    "piggybacked_finack", # Client FIN-ACK -> Server FIN-ACK -> Client pure ACK
    "rst_with_stray_ack", # Data -> RST -> Stray ACK
])
def test_tcp_teardown_final_ack_absorption_no_ghost_flows(sequence_type):
    """Verify that completed flows absorb trailing teardown ACKs without creating orphan ghost flows."""
    flushed = []
    sniffer = LiveFlowSniffer(on_flow_flushed=lambda r: flushed.append(r))
    t0 = 500.0

    if sequence_type == "standard_4way":
        # 1. SYN
        sniffer.process_packet("192.168.1.5", "10.0.0.8", 12345, 80, 6, length=60, tcp_flags=0x02, timestamp=t0)
        # 2. SYN-ACK
        sniffer.process_packet("10.0.0.8", "192.168.1.5", 80, 12345, 6, length=60, tcp_flags=0x12, timestamp=t0 + 0.01)
        # 3. Client FIN
        sniffer.process_packet("192.168.1.5", "10.0.0.8", 12345, 80, 6, length=52, tcp_flags=0x01, timestamp=t0 + 0.02)
        assert len(flushed) == 0
        assert sniffer.get_status()["active_flows"] == 1
        # 4. Server ACK
        sniffer.process_packet("10.0.0.8", "192.168.1.5", 80, 12345, 6, length=52, tcp_flags=0x10, timestamp=t0 + 0.03)
        assert len(flushed) == 0
        # 5. Server FIN
        sniffer.process_packet("10.0.0.8", "192.168.1.5", 80, 12345, 6, length=52, tcp_flags=0x01, timestamp=t0 + 0.04)
        assert len(flushed) == 1
        assert sniffer.get_status()["active_flows"] == 0
        # 6. Trailing final pure ACK from Client
        sniffer.process_packet("192.168.1.5", "10.0.0.8", 12345, 80, 6, length=40, tcp_flags=0x10, timestamp=t0 + 0.05)
        # MUST NOT create a ghost flow!
        assert sniffer.get_status()["active_flows"] == 0
        assert len(flushed) == 1
        assert sniffer.get_status()["teardown_acks_absorbed"] == 1

    elif sequence_type == "piggybacked_finack":
        sniffer.process_packet("192.168.1.5", "10.0.0.8", 12345, 80, 6, length=60, tcp_flags=0x02, timestamp=t0)
        sniffer.process_packet("10.0.0.8", "192.168.1.5", 80, 12345, 6, length=60, tcp_flags=0x12, timestamp=t0 + 0.01)
        sniffer.process_packet("192.168.1.5", "10.0.0.8", 12345, 80, 6, length=52, tcp_flags=0x11, timestamp=t0 + 0.02)
        sniffer.process_packet("10.0.0.8", "192.168.1.5", 80, 12345, 6, length=52, tcp_flags=0x11, timestamp=t0 + 0.03)
        assert len(flushed) == 1
        assert sniffer.get_status()["active_flows"] == 0
        # Trailing pure ACK
        sniffer.process_packet("192.168.1.5", "10.0.0.8", 12345, 80, 6, length=40, tcp_flags=0x10, timestamp=t0 + 0.04)
        assert sniffer.get_status()["active_flows"] == 0
        assert len(flushed) == 1
        assert sniffer.get_status()["teardown_acks_absorbed"] == 1

    elif sequence_type == "rst_with_stray_ack":
        sniffer.process_packet("192.168.1.5", "10.0.0.8", 12345, 80, 6, length=60, tcp_flags=0x02, timestamp=t0)
        sniffer.process_packet("192.168.1.5", "10.0.0.8", 12345, 80, 6, length=40, tcp_flags=0x04, timestamp=t0 + 0.01)
        assert len(flushed) == 1
        assert sniffer.get_status()["active_flows"] == 0
        # Stray pure ACK
        sniffer.process_packet("10.0.0.8", "192.168.1.5", 80, 12345, 6, length=40, tcp_flags=0x10, timestamp=t0 + 0.02)
        assert sniffer.get_status()["active_flows"] == 0
        assert len(flushed) == 1
        assert sniffer.get_status()["teardown_acks_absorbed"] == 1


def test_early_flow_anomaly_interim_classification_and_micro_windows():
    """Verify that active long-running flows emit interim features early (after 10 packets) without waiting 120s."""
    dispatched = []
    sniffer = LiveFlowSniffer(
        idle_timeout_sec=15.0,
        active_timeout_sec=120.0,
        on_flow_flushed=lambda rec: dispatched.append(rec),
    )
    t0 = 1000.0

    # Stream 9 packets (below early threshold of 10)
    for i in range(9):
        sniffer.process_packet(
            "10.0.0.50", "192.168.1.1", 44444, 80, 6,
            length=100, tcp_flags=0x10, timestamp=t0 + (i * 0.01),
        )

    assert len(dispatched) == 0
    assert sniffer.get_status()["active_flows"] == 1

    # 10th packet triggers early-stage interim classification
    sniffer.process_packet(
        "10.0.0.50", "192.168.1.1", 44444, 80, 6,
        length=100, tcp_flags=0x10, timestamp=t0 + 0.10,
    )

    assert len(dispatched) == 1
    assert dispatched[0]["is_interim"] == 1.0
    assert dispatched[0]["Total Fwd Packets"] == 10.0
    # Flow MUST remain active in table (continuity maintained)
    assert sniffer.get_status()["active_flows"] == 1
    assert sniffer.get_status()["total_interim_evals"] == 1


def test_early_flow_throughput_and_latency_benchmark():
    """Benchmark interim classification throughput and latency."""
    sniffer = LiveFlowSniffer()
    t_start = time.perf_counter()
    n_packets = 2000

    for i in range(n_packets):
        sniffer.process_packet(
            f"10.0.{i % 10}.1", "192.168.1.1", 10000 + (i % 50), 80, 6,
            length=64, tcp_flags=0x10, timestamp=1000.0 + (i * 0.001),
        )

    elapsed = time.perf_counter() - t_start
    throughput = n_packets / elapsed
    # Must process at least 5,000 pkts/sec online
    assert throughput > 5000.0, f"Throughput was {throughput:.1f} pkts/sec"

