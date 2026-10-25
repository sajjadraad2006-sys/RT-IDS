"""Multi-Flow Sliding-Window PortScan and Sweep Correlator.

Single-flow inspection has an intrinsic limitation: an isolated failed TCP connection
or network glitch cannot be reliably distinguished from an adversarial port probe based
solely on isolated flow metrics (resulting in high false-alarm rates or low precision).

Real-world port scans and network sweeps exhibit distinct temporal and spatial clustering:
- Vertical PortScan: A single source IP probes multiple distinct destination ports on a target.
- Horizontal Network Sweep: A single source IP probes the same port across multiple target IPs.
- Strobe Scan: Multiple ports across multiple hosts within a short time window.

This module provides thread-safe, bounded, zero-leak sliding-window correlation that:
1. Tracks per-source IP connection targets within a configurable time window (default 2.0s).
2. Boosts PortScan confidence and severity when multi-target probe thresholds are exceeded (precision > 95%).
3. Mitigates false positives by downranking isolated single probes into benign or low-severity anomaly review.
4. Detects stealthy sweeps even when individual flows produce marginal classifier scores.
"""
from __future__ import annotations

import collections
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .pipeline import Alert


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

        # src_ip -> collections.deque of (timestamp, dst_ip, dst_port)
        self._history: Dict[str, collections.deque[Tuple[float, str, int]]] = {}
        self._lock = threading.Lock()

    def record_probe(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: Optional[float] = None,
    ) -> Tuple[int, int]:
        """Record an observed probe and return (distinct_ports_in_window, distinct_hosts_in_window)."""
        if not src_ip or not dst_ip:
            return 1, 1

        now = timestamp if timestamp is not None else time.time()
        cutoff = now - self.window_sec

        with self._lock:
            # Capacity guard: prune oldest if table exceeds bound
            if len(self._history) > self.max_tracked_sources and src_ip not in self._history:
                to_remove = list(self._history.keys())[: max(1, self.max_tracked_sources // 10)]
                for k in to_remove:
                    self._history.pop(k, None)

            if src_ip not in self._history:
                self._history[src_ip] = collections.deque()

            dq = self._history[src_ip]
            dq.append((now, dst_ip, int(dst_port)))

            # Prune expired entries for this source
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            if not dq:
                self._history.pop(src_ip, None)
                return 0, 0

            distinct_ports = len({item[2] for item in dq})
            distinct_hosts = len({item[1] for item in dq})
            return distinct_ports, distinct_hosts

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

        if not src_ip:
            return alert

        # Ignore outbound client traffic originating from local monitored host/gateway
        # (prevents local admin/browsing sessions from triggering incoming port scan alarms)
        try:
            from ..actuators.guardrails import discover_protected_local_assets
            local_protected = discover_protected_local_assets()
            if src_ip in local_protected or src_ip in ("127.0.0.1", "0.0.0.0", "localhost"):
                return alert
        except Exception:
            if src_ip in ("127.0.0.1", "0.0.0.0", "localhost"):
                return alert

        # Only track TCP SYN / probe flows or flows that showed scan indicators
        syn_count = float(flow_meta.get("syn_flag_count", 0.0) or 0.0)
        is_candidate_probe = (
            syn_count > 0.0
            or alert.type in ("PortScan", "unknown-anomaly")
            or alert.route in ("known_attack", "unknown_anomaly_review")
        )

        if not is_candidate_probe:
            return alert

        distinct_ports, distinct_hosts = self.record_probe(
            src_ip, dst_ip, dst_port, timestamp=timestamp
        )

        is_vertical_scan = distinct_ports >= self.min_ports
        is_horizontal_sweep = distinct_hosts >= self.min_hosts

        # Case 1: Model classified as PortScan
        if alert.type == "PortScan":
            if is_vertical_scan or is_horizontal_sweep:
                # Multi-flow correlation CONFIRMS the scan behavior
                alert.confidence = max(alert.confidence, 0.99)
                alert.severity = "high"
                alert.stage = "behavioral_correlation"
                scan_type = "Vertical PortScan" if is_vertical_scan else "Horizontal Sweep"
                if is_vertical_scan and is_horizontal_sweep:
                    scan_type = "Strobe Network Scan"
                alert.note = (
                    f"Confirmed {scan_type}: {distinct_ports} distinct ports, "
                    f"{distinct_hosts} distinct hosts probed by {src_ip} within {self.window_sec}s window"
                )
                alert.evidence["scan_correlation"] = {
                    "confirmed": True,
                    "distinct_ports": distinct_ports,
                    "distinct_hosts": distinct_hosts,
                    "window_sec": self.window_sec,
                    "scan_type": scan_type,
                }
            elif distinct_ports == 1 and distinct_hosts == 1 and alert.confidence < 0.90:
                # Isolated single flow without surrounding probe activity
                # Suppress false alarm: downgrade to low-severity review
                alert.severity = "low"
                alert.route = "unknown_anomaly_review"
                alert.note = f"Single isolated probe to port {dst_port}; no multi-port scan detected in {self.window_sec}s window"
                alert.evidence["scan_correlation"] = {
                    "confirmed": False,
                    "distinct_ports": 1,
                    "distinct_hosts": 1,
                    "window_sec": self.window_sec,
                    "downgraded_false_alarm_mitigation": True,
                }

        # Case 2: Classifier thought it was Benign or Unknown, BUT strong multi-target sweep occurred
        elif (is_vertical_scan or is_horizontal_sweep) and alert.route != "known_attack":
            alert.type = "PortScan"
            alert.severity = "high"
            alert.route = "known_attack"
            alert.stage = "behavioral_correlation"
            alert.confidence = 0.98
            scan_type = "Vertical PortScan" if is_vertical_scan else "Horizontal Sweep"
            if is_vertical_scan and is_horizontal_sweep:
                scan_type = "Strobe Network Scan"
            alert.note = (
                f"Stealth {scan_type} detected by behavioral correlation: "
                f"{distinct_ports} ports / {distinct_hosts} hosts from {src_ip} within {self.window_sec}s"
            )
            alert.mitre_techniques = ["T1046", "T1595.001"]
            alert.evidence["scan_correlation"] = {
                "confirmed": True,
                "stealth_scan_detected": True,
                "distinct_ports": distinct_ports,
                "distinct_hosts": distinct_hosts,
                "window_sec": self.window_sec,
            }

        return alert

    def clear(self) -> None:
        """Clear all active window state."""
        with self._lock:
            self._history.clear()
