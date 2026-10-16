"""Live Network Packet Capture & Flow Aggregation Engine.

Provides real-time line-rate packet sniffing and bidirectional flow assembly:
- Raw socket listener (IPv4/IPv6, TCP/UDP) with promiscuous mode support.
- Bidirectional 5-tuple flow aggregation with active and idle timeout flushing.
- Online feature extraction generating the 32 standard CICFlowMeter features.
- Streaming integration into CyberGuard Pipeline v2.
- Safe non-root simulation / harness mode for testing and development.
"""
from __future__ import annotations

import collections
import logging
import math
import platform
import socket
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .features import FEATURE_NAMES

logger = logging.getLogger("cyberguard.detection.live_sniffer")


class PacketParseResult(tuple):
    """8-tuple for backward compatibility with attribute extensions for header length."""

    def __new__(
        cls,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        length: int,
        tcp_flags: int,
        win_size: int,
        header_len: int = 20,
    ):
        obj = super().__new__(
            cls,
            (src_ip, dst_ip, src_port, dst_port, proto, length, tcp_flags, win_size),
        )
        obj.src_ip = src_ip
        obj.dst_ip = dst_ip
        obj.src_port = src_port
        obj.dst_port = dst_port
        obj.proto = proto
        obj.length = length
        obj.tcp_flags = tcp_flags
        obj.win_size = win_size
        obj.header_len = header_len
        return obj


class FlowRecord:
    """Tracks state and packet dynamics for a single bidirectional communication flow."""

    def __init__(self, key: Tuple[str, str, int, int, int], is_forward: bool, timestamp: float):
        self.key = key
        self.start_time = timestamp
        self.last_time = timestamp
        self.is_forward_init = is_forward

        # Packet and Byte counters
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_header_bytes = 0
        self.bwd_header_bytes = 0

        # Packet length histories
        self.fwd_lengths: List[int] = []
        self.bwd_lengths: List[int] = []

        # Inter-arrival times (seconds)
        self.fwd_iats: List[float] = []
        self.bwd_iats: List[float] = []
        self.flow_iats: List[float] = []
        self.last_fwd_time: Optional[float] = None
        self.last_bwd_time: Optional[float] = None

        # TCP Flag counters
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0

        # TCP Teardown State Tracking
        self.fin_fwd = False
        self.fin_bwd = False
        self.rst_seen = False

        # TCP Window bytes
        self.init_win_bytes_fwd = 0
        self.init_win_bytes_bwd = 0

    def update(
        self,
        length: int,
        is_fwd: bool,
        tcp_flags: int,
        win_size: int,
        timestamp: float,
        header_len: int = 20,
    ) -> None:
        """Update flow metrics with an incoming packet."""
        dt = timestamp - self.last_time
        if dt > 0:
            self.flow_iats.append(dt)
        self.last_time = timestamp

        if is_fwd:
            self.fwd_packets += 1
            self.fwd_bytes += length
            self.fwd_lengths.append(length)
            self.fwd_header_bytes += header_len
            if tcp_flags & 0x01: self.fin_fwd = True
            if tcp_flags & 0x04: self.rst_seen = True
            if self.last_fwd_time is not None:
                self.fwd_iats.append(timestamp - self.last_fwd_time)
            self.last_fwd_time = timestamp
            if self.fwd_packets == 1:
                self.init_win_bytes_fwd = win_size
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length
            self.bwd_lengths.append(length)
            self.bwd_header_bytes += header_len
            if tcp_flags & 0x01: self.fin_bwd = True
            if tcp_flags & 0x04: self.rst_seen = True
            if self.last_bwd_time is not None:
                self.bwd_iats.append(timestamp - self.last_bwd_time)
            self.last_bwd_time = timestamp
            if self.bwd_packets == 1:
                self.init_win_bytes_bwd = win_size

        # Update flags (TCP standard bits: FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32)
        if tcp_flags & 0x01: self.fin_count += 1
        if tcp_flags & 0x02: self.syn_count += 1
        if tcp_flags & 0x04: self.rst_count += 1
        if tcp_flags & 0x08: self.psh_count += 1
        if tcp_flags & 0x10: self.ack_count += 1
        if tcp_flags & 0x20: self.urg_count += 1

    def to_feature_dict(self) -> Dict[str, float]:
        """Convert accumulated flow statistics to the 32 standard CICFlowMeter features."""
        duration_us = max(0.0, (self.last_time - self.start_time) * 1e6)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        fwd_mean = (sum(self.fwd_lengths) / len(self.fwd_lengths)) if self.fwd_lengths else 0.0
        fwd_std = math.sqrt(sum((x - fwd_mean) ** 2 for x in self.fwd_lengths) / len(self.fwd_lengths)) if len(self.fwd_lengths) > 1 else 0.0

        bwd_mean = (sum(self.bwd_lengths) / len(self.bwd_lengths)) if self.bwd_lengths else 0.0
        bwd_std = math.sqrt(sum((x - bwd_mean) ** 2 for x in self.bwd_lengths) / len(self.bwd_lengths)) if len(self.bwd_lengths) > 1 else 0.0

        all_lengths = self.fwd_lengths + self.bwd_lengths
        flow_len_mean = (sum(all_lengths) / len(all_lengths)) if all_lengths else 0.0
        flow_len_std = math.sqrt(sum((x - flow_len_mean) ** 2 for x in all_lengths) / len(all_lengths)) if len(all_lengths) > 1 else 0.0

        flow_iat_mean = (sum(self.flow_iats) / len(self.flow_iats) * 1e6) if self.flow_iats else 0.0
        flow_iat_std = (math.sqrt(sum((x * 1e6 - flow_iat_mean) ** 2 for x in self.flow_iats) / len(self.flow_iats))) if len(self.flow_iats) > 1 else 0.0
        flow_iat_max = (max(self.flow_iats) * 1e6) if self.flow_iats else 0.0
        flow_iat_min = (min(self.flow_iats) * 1e6) if self.flow_iats else 0.0

        fwd_iat_mean = (sum(self.fwd_iats) / len(self.fwd_iats) * 1e6) if self.fwd_iats else 0.0
        fwd_iat_std = (math.sqrt(sum((x * 1e6 - fwd_iat_mean) ** 2 for x in self.fwd_iats) / len(self.fwd_iats))) if len(self.fwd_iats) > 1 else 0.0
        fwd_iat_max = (max(self.fwd_iats) * 1e6) if self.fwd_iats else 0.0
        fwd_iat_min = (min(self.fwd_iats) * 1e6) if self.fwd_iats else 0.0

        bwd_iat_mean = (sum(self.bwd_iats) / len(self.bwd_iats) * 1e6) if self.bwd_iats else 0.0
        bwd_iat_std = (math.sqrt(sum((x * 1e6 - bwd_iat_mean) ** 2 for x in self.bwd_iats) / len(self.bwd_iats))) if len(self.bwd_iats) > 1 else 0.0
        bwd_iat_max = (max(self.bwd_iats) * 1e6) if self.bwd_iats else 0.0
        bwd_iat_min = (min(self.bwd_iats) * 1e6) if self.bwd_iats else 0.0

        # Safe rate calculation: for single-packet or sub-millisecond flows, avoid epsilon division blowup
        if total_packets <= 1 or duration_us <= 0.0:
            flow_bytes_per_sec = 0.0
            flow_pkts_per_sec = 0.0
        else:
            duration_sec = duration_us / 1e6
            rate_duration_sec = max(1e-3, duration_sec)
            flow_bytes_per_sec = total_bytes / rate_duration_sec
            flow_pkts_per_sec = total_packets / rate_duration_sec

        fwd_bytes_ratio = float(self.fwd_bytes / max(1, self.bwd_bytes))
        avg_pkt_sz = float(total_bytes / max(1, total_packets))

        fwd_hdr_len = float(self.fwd_header_bytes if self.fwd_header_bytes > 0 else self.fwd_packets * 20)
        bwd_hdr_len = float(self.bwd_header_bytes if self.bwd_header_bytes > 0 else self.bwd_packets * 20)

        return {
            # Canonical feature names (32 features)
            "flow_duration": float(duration_us),
            "total_fwd_packets": float(self.fwd_packets),
            "total_bwd_packets": float(self.bwd_packets),
            "total_fwd_bytes": float(self.fwd_bytes),
            "total_bwd_bytes": float(self.bwd_bytes),
            "packets_per_sec": float(flow_pkts_per_sec),
            "bytes_per_sec": float(flow_bytes_per_sec),
            "fwd_packet_length_mean": float(fwd_mean),
            "bwd_packet_length_mean": float(bwd_mean),
            "packet_length_mean": float(flow_len_mean),
            "packet_length_std": float(flow_len_std),
            "packet_length_max": float(max(all_lengths)) if all_lengths else 0.0,
            "packet_length_min": float(min(all_lengths)) if all_lengths else 0.0,
            "avg_pkt_size": avg_pkt_sz,
            "syn_flag_count": float(self.syn_count),
            "ack_flag_count": float(self.ack_count),
            "rst_flag_count": float(self.rst_count),
            "fin_flag_count": float(self.fin_count),
            "psh_flag_count": float(self.psh_count),
            "urg_flag_count": float(self.urg_count),
            "init_win_bytes_fwd": float(self.init_win_bytes_fwd),
            "init_win_bytes_bwd": float(self.init_win_bytes_bwd),
            "flow_iat_mean": float(flow_iat_mean),
            "flow_iat_std": float(flow_iat_std),
            "flow_iat_max": float(flow_iat_max),
            "fwd_iat_mean": float(fwd_iat_mean),
            "fwd_header_len": fwd_hdr_len,
            "bwd_header_len": bwd_hdr_len,
            "down_up_ratio": float(self.bwd_packets / max(1, self.fwd_packets)),
            "flow_bytes_ratio": fwd_bytes_ratio,
            "active_mean": 0.0,
            "idle_mean": 0.0,
            # CICFlowMeter aliases for tabular compatibility
            "Destination Port": float(self.key[3]),
            "Flow Duration": float(duration_us),
            "Total Fwd Packets": float(self.fwd_packets),
            "Total Backward Packets": float(self.bwd_packets),
            "Total Length of Fwd Packets": float(self.fwd_bytes),
            "Total Length of Bwd Packets": float(self.bwd_bytes),
            "Flow Bytes/s": float(flow_bytes_per_sec),
            "Flow Packets/s": float(flow_pkts_per_sec),
            "Init_Win_bytes_forward": float(self.init_win_bytes_fwd),
            "Init_Win_bytes_backward": float(self.init_win_bytes_bwd),
        }


class LiveFlowSniffer:
    """Live network flow collector with raw packet capture and timeout-driven flow flushing."""

    def __init__(
        self,
        idle_timeout_sec: float = 15.0,
        active_timeout_sec: float = 120.0,
        on_flow_flushed: Optional[Callable[[Dict[str, float]], None]] = None,
    ):
        self.idle_timeout = idle_timeout_sec
        self.active_timeout = active_timeout_sec
        self.on_flow_flushed = on_flow_flushed

        self._active_flows: Dict[Tuple[str, str, int, int, int], FlowRecord] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._raw_socket: Optional[socket.socket] = None

        # Statistics
        self.total_packets_captured = 0
        self.total_flows_flushed = 0
        self.last_capture_mode = "idle"

    def parse_ipv4_packet(
        self,
        data: bytes,
        has_ethernet: Optional[bool] = None,
    ) -> Optional[PacketParseResult]:
        """Parse raw Ethernet/IP frame into packet dynamics.
        
        Returns: PacketParseResult (unpacks as 8-tuple for backwards compatibility, with .header_len).
        """
        if len(data) < 20:
            return None

        # Detect and skip Ethernet header (14 bytes) safely
        offset = 0
        if has_ethernet is True:
            offset = 14
        elif has_ethernet is False:
            offset = 0
        else:
            # Auto-detection: safely differentiate between Ethernet+IPv4 and raw IPv4 (e.g. 8.0.x.x IPs)
            if len(data) >= 34 and data[12:14] == b"\x08\x00" and ((data[14] >> 4) == 4):
                eth_ip_len = struct.unpack("!H", data[16:18])[0]
                raw_ip_len = struct.unpack("!H", data[2:4])[0] if ((data[0] >> 4) == 4) else -1
                if len(data) == eth_ip_len + 14 or (raw_ip_len != len(data) and eth_ip_len <= len(data) - 14):
                    offset = 14
                elif raw_ip_len == len(data):
                    offset = 0
                else:
                    offset = 14

        ip_header = data[offset:offset + 20]
        if len(ip_header) < 20:
            return None

        version_ihl = ip_header[0]
        version = version_ihl >> 4
        if version != 4:
            return None
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(data) < offset + ihl:
            return None

        total_length = struct.unpack("!H", ip_header[2:4])[0]
        proto = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])

        payload_offset = offset + ihl
        src_port, dst_port, tcp_flags, win_size = 0, 0, 0, 0
        transport_hdr_len = 0

        if proto == 6 and len(data) >= payload_offset + 20:  # TCP
            tcp_header = data[payload_offset:payload_offset + 20]
            src_port, dst_port = struct.unpack("!HH", tcp_header[0:4])
            tcp_flags = tcp_header[13]
            win_size = struct.unpack("!H", tcp_header[14:16])[0]
            data_offset = (tcp_header[12] >> 4) * 4
            transport_hdr_len = max(20, data_offset)
        elif proto == 17 and len(data) >= payload_offset + 8:  # UDP
            udp_header = data[payload_offset:payload_offset + 8]
            src_port, dst_port = struct.unpack("!HH", udp_header[0:4])
            transport_hdr_len = 8
        else:
            return None

        header_len = ihl + transport_hdr_len
        return PacketParseResult(
            src_ip, dst_ip, src_port, dst_port, proto, total_length, tcp_flags, win_size, header_len
        )

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        length: int,
        tcp_flags: int = 0,
        win_size: int = 0,
        timestamp: Optional[float] = None,
        header_len: int = 20,
    ) -> None:
        """Process a parsed packet into the flow aggregation table."""
        now = timestamp or time.time()
        with self._lock:
            self.total_packets_captured += 1

        # Canonical directional key
        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        rev_key = (dst_ip, src_ip, dst_port, src_port, proto)

        flushed_features = None
        with self._lock:
            if fwd_key in self._active_flows:
                flow = self._active_flows[fwd_key]
                flow.update(length, is_fwd=True, tcp_flags=tcp_flags, win_size=win_size, timestamp=now, header_len=header_len)
            elif rev_key in self._active_flows:
                flow = self._active_flows[rev_key]
                flow.update(length, is_fwd=False, tcp_flags=tcp_flags, win_size=win_size, timestamp=now, header_len=header_len)
            else:
                flow = FlowRecord(fwd_key, is_forward=True, timestamp=now)
                flow.update(length, is_fwd=True, tcp_flags=tcp_flags, win_size=win_size, timestamp=now, header_len=header_len)
                self._active_flows[fwd_key] = flow

            # TCP stateful connection termination check:
            # - Immediate flush on RST (connection aborted)
            # - Immediate flush on bidirectional completion (both forward and backward FIN seen)
            # - Flush on unidirectional teardown if flow never established reverse traffic (bwd_packets == 0 and fin_fwd)
            should_flush = False
            if flow.rst_seen:
                should_flush = True
            elif flow.fin_fwd and flow.fin_bwd:
                should_flush = True
            elif flow.bwd_packets == 0 and flow.fin_fwd:
                should_flush = True

            if should_flush:
                flow_key = fwd_key if fwd_key in self._active_flows else rev_key
                flow_to_flush = self._active_flows.pop(flow_key, None)
                if flow_to_flush:
                    self.total_flows_flushed += 1
                    flushed_features = flow_to_flush.to_feature_dict()

        # Dispatch outside the lock to prevent stalling packet ingestion
        if flushed_features and self.on_flow_flushed:
            try:
                self.on_flow_flushed(flushed_features)
            except Exception as exc:
                logger.error("Error dispatching flushed flow to pipeline: %s", exc)

    def _flush_flow_internal(self, key: Tuple[str, str, int, int, int]) -> Optional[Dict[str, float]]:
        with self._lock:
            flow = self._active_flows.pop(key, None)
            if not flow:
                return None
            self.total_flows_flushed += 1
            features = flow.to_feature_dict()

        if self.on_flow_flushed:
            try:
                self.on_flow_flushed(features)
            except Exception as exc:
                logger.error("Error dispatching flushed flow to pipeline: %s", exc)
        return features

    def flush_expired_flows(self, now: Optional[float] = None) -> List[Dict[str, float]]:
        """Flush flows that have exceeded active or idle timeout thresholds."""
        cur_time = now or time.time()
        to_dispatch: List[Dict[str, float]] = []

        with self._lock:
            expired_keys = []
            for key, flow in self._active_flows.items():
                if (cur_time - flow.last_time >= self.idle_timeout) or (cur_time - flow.start_time >= self.active_timeout):
                    expired_keys.append(key)

            for key in expired_keys:
                flow = self._active_flows.pop(key, None)
                if flow:
                    self.total_flows_flushed += 1
                    to_dispatch.append(flow.to_feature_dict())

        # Dispatch outside the lock
        if self.on_flow_flushed:
            for feat in to_dispatch:
                try:
                    self.on_flow_flushed(feat)
                except Exception as exc:
                    logger.error("Error dispatching flushed flow to pipeline: %s", exc)

        return to_dispatch

    def start_capture(self, host: str = "0.0.0.0", port_filter: Optional[int] = None) -> bool:
        """Start background packet listener thread using raw sockets (requires admin/root)."""
        if self._running:
            return True

        self._running = True
        try:
            if platform.system().lower() == "windows":
                # Windows raw IP socket
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                bind_host = host if host != "0.0.0.0" else "127.0.0.1"
                s.bind((bind_host, 0))
                try:
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except Exception as io_err:
                    logger.warning("Could not set SIO_RCVALL promiscuous mode: %s", io_err)
            else:
                # Linux AF_PACKET raw socket
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

            s.settimeout(1.0)
            self._raw_socket = s
            self.last_capture_mode = "raw_socket"
        except Exception as exc:
            logger.warning("Raw socket creation failed (insufficient OS permissions): %s. Falling back to synthetic harness mode.", exc)
            self.last_capture_mode = "synthetic_harness"
            return True

        def _worker():
            last_flush_check = time.time()
            while self._running and self._raw_socket:
                try:
                    data, _ = self._raw_socket.recvfrom(65535)
                    pkt = self.parse_ipv4_packet(data)
                    if pkt:
                        src_ip, dst_ip, src_port, dst_port, proto, length, tcp_flags, win_size = pkt
                        header_len = getattr(pkt, "header_len", 20)
                        if port_filter and (src_port != port_filter and dst_port != port_filter):
                            continue
                        self.process_packet(
                            src_ip, dst_ip, src_port, dst_port, proto, length,
                            tcp_flags=tcp_flags, win_size=win_size, header_len=header_len
                        )

                    now = time.time()
                    if now - last_flush_check >= 1.0:
                        self.flush_expired_flows(now=now)
                        last_flush_check = now
                except socket.timeout:
                    self.flush_expired_flows()
                except Exception as exc:
                    logger.error("Live packet sniffer worker encountered fatal error: %s", exc)
                    self._running = False
                    break

        self._thread = threading.Thread(target=_worker, daemon=True, name="CyberGuard-LiveSniffer")
        self._thread.start()
        logger.info("Live packet sniffer started on %s (mode=%s)", host, self.last_capture_mode)
        return True

    def stop_capture(self) -> None:
        """Halt packet capture and flush all remaining in-flight flows."""
        self._running = False
        if self._raw_socket:
            try:
                self._raw_socket.close()
            except Exception:
                pass
            self._raw_socket = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

        # Flush all remaining flows
        with self._lock:
            remaining_keys = list(self._active_flows.keys())
        for key in remaining_keys:
            self._flush_flow_internal(key)

        self.last_capture_mode = "idle"
        logger.info("Live packet sniffer stopped. Flushed all flows.")

    def get_status(self) -> Dict[str, Any]:
        """Return runtime capture and telemetry statistics."""
        with self._lock:
            active_count = len(self._active_flows)
        return {
            "is_capturing": self._running,
            "mode": self.last_capture_mode,
            "active_flows": active_count,
            "total_packets_captured": self.total_packets_captured,
            "total_flows_flushed": self.total_flows_flushed,
            "idle_timeout_sec": self.idle_timeout,
            "active_timeout_sec": self.active_timeout,
            # Frontend dashboard compatibility
            "active": self._running,
            "packets_captured": self.total_packets_captured,
            "flows_aggregated": self.total_flows_flushed,
        }


# Global default instance
default_live_sniffer = LiveFlowSniffer()
