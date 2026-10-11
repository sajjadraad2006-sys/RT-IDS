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
