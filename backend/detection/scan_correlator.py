"""Multi-Flow Sliding-Window PortScan and Sweep Correlator.

Single-flow inspection has an intrinsic limitation: an isolated TCP connection or normal
multi-host browsing cannot be reliably distinguished from an adversarial port probe based
solely on isolated flow metrics without behavioral context across time.

Real-world port scans and network sweeps exhibit distinct temporal and spatial clustering:
- Vertical PortScan: A single source IP probes multiple distinct destination ports on a target
  using reconnaissance probes (SYN-only, RST-terminated, or rapid banner-grab probes).
- Horizontal Network Sweep: A single source IP probes the same port across multiple target IPs
  with non-interactive reconnaissance probes (differentiated from normal web browsing).
- Strobe Scan: Multiple ports across multiple hosts within a short time window.

This module provides thread-safe, bounded, zero-leak sliding-window correlation that:
1. Tracks per-source IP connection targets within a configurable time window (default 2.0s).
2. Distinguishes interactive established application flows (web browsing, admin sessions)
   from reconnaissance probes (SYN, RST, rapid banner grabs).
3. Computes calibrated heuristic confidence based on probe volume and probe-to-interactive ratio.
4. Downranks isolated single probes and normal web browsing into benign traffic.
"""
from __future__ import annotations

import collections
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .pipeline import Alert

WEB_PORTS: Set[int] = {80, 443, 53, 8080, 8443}


def is_flow_probe_like(flow_meta: Dict[str, Any]) -> bool:
    """Classify whether a flow behaves as a reconnaissance probe vs. established interactive application session.
    
    Probe characteristics:
    - SYN packets with zero response / filtered (bwd_pkts == 0)
    - RST-terminated / rejected connections with minimal packet counts (pkts <= 3)
    - Rapid banner grabbing (nmap -sV): small server response (< 350B), minimal client payload (< 100B), pkts <= 5
    
    Interactive application characteristics (browsing, SSH, database sessions):
    - Bidirectional data transfer (fwd_bytes >= 100 and bwd_bytes >= 350, or total_bytes >= 800)
    - Multiple packets in both directions (fwd_pkts >= 3, bwd_pkts >= 2)
    - Multiple ACK flags established
    """
    fwd_pkts = float(flow_meta.get("total_fwd_packets", 0.0) or flow_meta.get("Total Fwd Packets", 0.0) or 0.0)
    bwd_pkts = float(flow_meta.get("total_bwd_packets", 0.0) or flow_meta.get("Total Backward Packets", 0.0) or 0.0)
    fwd_bytes = float(flow_meta.get("total_fwd_bytes", 0.0) or flow_meta.get("Total Length of Fwd Packets", 0.0) or 0.0)
    bwd_bytes = float(flow_meta.get("total_bwd_bytes", 0.0) or flow_meta.get("Total Length of Bwd Packets", 0.0) or 0.0)
    ack_flags = float(flow_meta.get("ack_flag_count", 0.0) or flow_meta.get("ACK Flag Count", 0.0) or 0.0)

    # An established interactive application flow (HTTP/TLS, SSH, Postgres) has bidirectional data
    is_interactive = (
        ((bwd_bytes >= 350 and fwd_bytes >= 100) or (bwd_bytes + fwd_bytes >= 800))
        and fwd_pkts >= 3
        and bwd_pkts >= 2
        and ack_flags >= 1
    )
    return not is_interactive


class ProbeWindowMetrics(tuple):
    """Dual-access window metric object: unpacks as (max_ports, max_hosts) or dict-like indexing."""

    def __new__(
        cls,
        ports: int,
        hosts: int,
        probe_ports: int = 0,
        interactive_ports: int = 0,
        probe_hosts: int = 0,
        interactive_hosts: int = 0,
        is_web_browsing: bool = False,
    ):
        return super().__new__(cls, (ports, hosts))

    def __init__(
        self,
        ports: int,
        hosts: int,
        probe_ports: int = 0,
        interactive_ports: int = 0,
        probe_hosts: int = 0,
        interactive_hosts: int = 0,
        is_web_browsing: bool = False,
    ):
        self.ports = ports
        self.hosts = hosts
        self.max_ports_target = ports
        self.max_hosts_port = hosts
        self.probe_ports_target = probe_ports
        self.interactive_ports_target = interactive_ports
        self.probe_hosts_port = probe_hosts
        self.interactive_hosts_port = interactive_hosts
        self.is_web_browsing = is_web_browsing

    def __getitem__(self, item):
        if isinstance(item, str):
            return getattr(self, item)
        return super().__getitem__(item)


class ScanCorrelator:
    """Sliding-window behavioral probe and scan correlator."""

    def __init__(
        self,
        window_sec: float = 2.0,
        min_ports_for_vertical_scan: int = 3,
        min_hosts_for_horizontal_sweep: int = 3,
        max_tracked_sources: int = 10000,
    ):
        self.window_sec = float(window_sec)
        self.min_ports = int(min_ports_for_vertical_scan)
        self.min_hosts = int(min_hosts_for_horizontal_sweep)
        self.max_tracked_sources = int(max_tracked_sources)

        # src_ip -> collections.deque of (timestamp, dst_ip, dst_port, is_probe_like, is_web_port)
        self._history: Dict[str, collections.deque[Tuple[float, str, int, bool, bool]]] = {}
        self._lock = threading.Lock()

    def record_probe(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        is_probe: bool = True,
        timestamp: Optional[float] = None,
    ) -> ProbeWindowMetrics:
        """Record an observed probe and return detailed window metrics."""
        if not src_ip or not dst_ip:
            return ProbeWindowMetrics(1, 1, probe_ports=1 if is_probe else 0)

        now = timestamp if timestamp is not None else time.time()
        cutoff = now - self.window_sec
        is_web = dst_port in WEB_PORTS

        with self._lock:
            # Capacity guard: prune oldest if table exceeds bound
            if len(self._history) > self.max_tracked_sources and src_ip not in self._history:
                to_remove = list(self._history.keys())[: max(1, self.max_tracked_sources // 10)]
                for k in to_remove:
                    self._history.pop(k, None)

            if src_ip not in self._history:
                self._history[src_ip] = collections.deque()

            dq = self._history[src_ip]
            dq.append((now, dst_ip, int(dst_port), bool(is_probe), is_web))

            # Prune expired entries for this source
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            if not dq:
                self._history.pop(src_ip, None)
                return ProbeWindowMetrics(0, 0)

            # Per target IP metrics
            target_all_ports: Dict[str, Set[int]] = collections.defaultdict(set)
            target_probe_ports: Dict[str, Set[int]] = collections.defaultdict(set)
            target_interactive_ports: Dict[str, Set[int]] = collections.defaultdict(set)

            # Per port metrics
            port_all_hosts: Dict[int, Set[str]] = collections.defaultdict(set)
            port_probe_hosts: Dict[int, Set[str]] = collections.defaultdict(set)
            port_interactive_hosts: Dict[int, Set[str]] = collections.defaultdict(set)

            for _, h, p, p_probe, p_web in dq:
                target_all_ports[h].add(p)
                if p_probe:
                    target_probe_ports[h].add(p)
                else:
                    target_interactive_ports[h].add(p)

                port_all_hosts[p].add(h)
                if p_probe:
                    port_probe_hosts[p].add(h)
                else:
                    port_interactive_hosts[p].add(h)

            curr_target_probe_ports = len(target_probe_ports.get(dst_ip, set()))
            curr_target_interactive_ports = len(target_interactive_ports.get(dst_ip, set()))
            curr_target_all_ports = len(target_all_ports.get(dst_ip, set()))

            curr_port_probe_hosts = len(port_probe_hosts.get(dst_port, set()))
            curr_port_interactive_hosts = len(port_interactive_hosts.get(dst_port, set()))
            curr_port_all_hosts = len(port_all_hosts.get(dst_port, set()))

            # Normal web browsing: multiple hosts contacted on web ports (80/443), but with interactive application data
            is_web_browsing = is_web and (curr_port_interactive_hosts >= 2) and (curr_port_probe_hosts == 0)

            return ProbeWindowMetrics(
                ports=curr_target_all_ports,
                hosts=curr_port_all_hosts,
                probe_ports=curr_target_probe_ports,
                interactive_ports=curr_target_interactive_ports,
                probe_hosts=curr_port_probe_hosts,
                interactive_hosts=curr_port_interactive_hosts,
                is_web_browsing=is_web_browsing,
            )

    def correlate_alert(
        self,
        alert: Alert,
        flow_meta: Dict[str, Any],
        timestamp: Optional[float] = None,
    ) -> Alert:
        """Correlate a pipeline Alert with sliding-window scan evidence."""
        src_ip = str(flow_meta.get("src_ip", "") or flow_meta.get("Source IP", "")).strip()
        dst_ip = str(flow_meta.get("dst_ip", "") or flow_meta.get("Destination IP", "")).strip()
        raw_port = flow_meta.get("dst_port") or flow_meta.get("Destination Port") or 0
        try:
            dst_port = int(float(raw_port))
        except (ValueError, TypeError):
            dst_port = 0

        if not src_ip or not dst_ip:
            return alert

        # Exclude local loopback traffic originating on the host itself
        if src_ip in ("127.0.0.1", "::1", "localhost", "0.0.0.0") or src_ip == dst_ip:
            return alert

        is_probe = is_flow_probe_like(flow_meta)
        syn_count = float(flow_meta.get("syn_flag_count", 0.0) or 0.0)
        is_candidate_probe = (
            syn_count > 0.0
            or is_probe
            or alert.type in ("PortScan", "unknown-anomaly")
            or alert.route in ("known_attack", "unknown_anomaly_review")
        )

        if not is_candidate_probe:
            return alert

        metrics = self.record_probe(
            src_ip, dst_ip, dst_port, is_probe=is_probe, timestamp=timestamp
        )

        probe_ports = metrics.probe_ports_target
        interactive_ports = metrics.interactive_ports_target
        probe_hosts = metrics.probe_hosts_port
        is_web_browsing = metrics.is_web_browsing

        # Vertical scan requires distinct target ports hit with reconnaissance probes
        is_vertical_scan = probe_ports >= self.min_ports
        # Horizontal sweep requires distinct hosts probed with reconnaissance probes
        is_horizontal_sweep = (probe_hosts >= self.min_hosts) and not is_web_browsing

        # Calibrated heuristic confidence based on probe volume and probe-to-interactive ratio
        heuristic_conf = 0.0
        if is_vertical_scan or is_horizontal_sweep:
            probe_volume = max(probe_ports, probe_hosts)
            total_activity = max(metrics.max_ports_target, metrics.max_hosts_port)
            probe_ratio = probe_volume / max(1, total_activity)

            if probe_volume >= 10:
                heuristic_conf = 0.98
            elif probe_volume >= 5:
                heuristic_conf = 0.92
            elif probe_volume >= 3:
                heuristic_conf = 0.88 if probe_ratio >= 0.8 else 0.65
            else:
                heuristic_conf = 0.50

        # Case 1: Model classified flow as PortScan
        if alert.type == "PortScan":
            if not is_probe or is_web_browsing or (probe_ports == 0 and interactive_ports >= 2):
                # Legitimate web browsing or administrative multi-service session falsely flagged by classifier
                alert.type = "Benign"
                alert.severity = "low"
                alert.route = "benign"
                alert.confidence = 0.05
                alert.note = "Classifier PortScan false positive downgraded: verified established interactive session"
                alert.evidence["scan_correlation"] = {
                    "confirmed": False,
                    "downgraded_false_alarm_mitigation": True,
                    "is_web_browsing": is_web_browsing,
                    "heuristic_confidence": 0.05,
                }
            elif is_vertical_scan or is_horizontal_sweep:
                # Multi-flow correlation CONFIRMS the scan behavior on target
                alert.confidence = max(float(alert.confidence or 0.0), 0.99)
                alert.severity = "high"
                alert.stage = "behavioral_correlation"
                scan_type = "Vertical PortScan" if is_vertical_scan else "Horizontal Sweep"
                if is_vertical_scan and is_horizontal_sweep:
                    scan_type = "Strobe Network Scan"
                alert.note = (
                    f"Confirmed {scan_type}: {probe_ports} probe ports on target, "
                    f"{probe_hosts} probe hosts on port from {src_ip} within {self.window_sec}s window"
                )
                alert.evidence["scan_correlation"] = {
                    "confirmed": True,
                    "scan_type": scan_type,
                    "distinct_ports": probe_ports,
                    "distinct_hosts": probe_hosts,
                    "probe_ports": probe_ports,
                    "probe_hosts": probe_hosts,
                    "heuristic_confidence": heuristic_conf,
                    "window_sec": self.window_sec,
                }
            elif probe_ports <= 1 and probe_hosts <= 1 and float(alert.confidence or 0.0) < 0.90:
                # Isolated single probe without surrounding scan clustering on destination
                alert.severity = "low"
                alert.route = "unknown_anomaly_review"
                alert.note = f"Single isolated probe to port {dst_port}; no multi-port scan detected in {self.window_sec}s window"
                alert.evidence["scan_correlation"] = {
                    "confirmed": False,
                    "distinct_ports": 1,
                    "distinct_hosts": 1,
                    "window_sec": self.window_sec,
                    "downgraded_false_alarm_mitigation": True,
                    "heuristic_confidence": 0.35,
                }

        # Case 2: Classifier thought it was Benign or Unknown, BUT strong multi-target probe burst occurred
        elif (is_vertical_scan or is_horizontal_sweep) and alert.route != "known_attack":
            # Outbound browsing traffic on standard web ports across hosts is normal web browsing,
            # not a network sweep attack.
            if is_horizontal_sweep and not is_vertical_scan and dst_port in WEB_PORTS:
                return alert
            alert.type = "PortScan"
            alert.severity = "high"
            alert.route = "known_attack"
            alert.stage = "behavioral_correlation"
            alert.confidence = heuristic_conf
            scan_type = "Vertical PortScan" if is_vertical_scan else "Horizontal Sweep"
            if is_vertical_scan and is_horizontal_sweep:
                scan_type = "Strobe Network Scan"
            alert.note = (
                f"Stealth {scan_type} detected by behavioral correlation: "
                f"{probe_ports} probe ports / {probe_hosts} probe hosts from {src_ip} within {self.window_sec}s"
            )
            alert.mitre_techniques = ["T1046", "T1595.001"]
            alert.evidence["scan_correlation"] = {
                "confirmed": True,
                "stealth_scan_detected": True,
                "distinct_ports": probe_ports,
                "distinct_hosts": probe_hosts,
                "probe_ports": probe_ports,
                "probe_hosts": probe_hosts,
                "heuristic_confidence": heuristic_conf,
                "window_sec": self.window_sec,
            }

        # Case 3: Model flagged flow as unknown-anomaly, but classifier is confident Benign on normal interactive or web traffic
        if alert.type == "unknown-anomaly" or alert.route == "unknown_anomaly_review":
            clf_evidence = alert.evidence.get("classifier", {}) if isinstance(alert.evidence.get("classifier"), dict) else {}
            clf_label = str(clf_evidence.get("label", "")).lower()
            clf_conf = float(alert.confidence or clf_evidence.get("confidence", 0.0) or 0.0)
            if clf_label == "benign" and clf_conf >= 0.70:
                if dst_port in WEB_PORTS or not is_probe or is_web_browsing:
                    alert.type = "Benign"
                    alert.severity = "none"
                    alert.route = "benign"
                    alert.note = "Statistical/autoencoder unknown anomaly downgraded: verified benign interactive/web traffic"
                    alert.evidence["anomaly_correlation"] = {
                        "downgraded_false_alarm_mitigation": True,
                        "classifier_confidence": clf_conf,
                        "dst_port": dst_port,
                    }

        return alert

    def clear(self) -> None:
        """Clear all active window state."""
        with self._lock:
            self._history.clear()
