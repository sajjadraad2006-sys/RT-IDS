"""Tests for Multi-Flow Sliding-Window PortScan and Sweep Correlator."""
import time
import pytest

from backend.detection.pipeline import Alert
from backend.detection.scan_correlator import ScanCorrelator


def test_isolated_probe_is_downgraded():
    """Single isolated port probe without multi-port activity is downgraded to mitigate false positives."""
    correlator = ScanCorrelator(window_sec=2.0, min_ports_for_vertical_scan=3)
    alert = Alert(
        severity="high",
        type="PortScan",
        confidence=0.75,
        route="known_attack",
    )
    flow_meta = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "syn_flag_count": 1.0,
    }

    result = correlator.correlate_alert(alert, flow_meta, timestamp=100.0)
    assert result.severity == "low"
    assert result.route == "unknown_anomaly_review"
    assert "no multi-port scan detected" in result.note


def test_multi_port_vertical_scan_confirmed():
    """Rapid probes to 3 distinct destination ports on a target confirm a vertical port scan."""
    correlator = ScanCorrelator(window_sec=2.0, min_ports_for_vertical_scan=3)
    src_ip = "192.168.1.50"
    dst_ip = "10.0.0.1"

    # First probe
    a1 = Alert(severity="medium", type="PortScan", confidence=0.80, route="known_attack")
    r1 = correlator.correlate_alert(a1, {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": 22, "syn_flag_count": 1.0}, timestamp=100.0)

    # Second probe
    a2 = Alert(severity="medium", type="PortScan", confidence=0.80, route="known_attack")
    r2 = correlator.correlate_alert(a2, {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": 80, "syn_flag_count": 1.0}, timestamp=100.5)

    # Third probe (triggers vertical scan threshold)
    a3 = Alert(severity="medium", type="PortScan", confidence=0.80, route="known_attack")
    r3 = correlator.correlate_alert(a3, {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": 443, "syn_flag_count": 1.0}, timestamp=101.0)

    assert r3.severity == "high"
    assert r3.confidence >= 0.99
    assert r3.stage == "behavioral_correlation"
    assert "Confirmed Vertical PortScan" in r3.note
    assert r3.evidence["scan_correlation"]["confirmed"] is True
    assert r3.evidence["scan_correlation"]["distinct_ports"] == 3


def test_multi_host_horizontal_sweep_confirmed():
    """Probes to multiple distinct hosts on the same port confirm a horizontal sweep."""
    correlator = ScanCorrelator(window_sec=2.0, min_hosts_for_horizontal_sweep=3)
    src_ip = "172.16.0.40"

    correlator.correlate_alert(
        Alert(severity="medium", type="PortScan", confidence=0.7),
        {"src_ip": src_ip, "dst_ip": "10.0.0.1", "dst_port": 445, "syn_flag_count": 1.0},
        timestamp=200.0,
    )
    correlator.correlate_alert(
        Alert(severity="medium", type="PortScan", confidence=0.7),
        {"src_ip": src_ip, "dst_ip": "10.0.0.2", "dst_port": 445, "syn_flag_count": 1.0},
        timestamp=200.3,
    )
    r3 = correlator.correlate_alert(
        Alert(severity="medium", type="PortScan", confidence=0.7),
        {"src_ip": src_ip, "dst_ip": "10.0.0.3", "dst_port": 445, "syn_flag_count": 1.0},
        timestamp=200.6,
    )

    assert r3.severity == "high"
    assert r3.confidence >= 0.99
    assert "Horizontal Sweep" in r3.note
    assert r3.evidence["scan_correlation"]["distinct_hosts"] == 3


def test_stealth_scan_detected_from_benign_flows():
    """Rapid port sweep generates a PortScan alert even if classifier labeled flows as benign."""
    correlator = ScanCorrelator(window_sec=2.0, min_ports_for_vertical_scan=3)
    src_ip = "10.99.99.1"
    dst_ip = "10.99.99.2"

    for port in (21, 22):
        correlator.correlate_alert(
            Alert(severity="none", type="Benign", confidence=0.99, route="benign"),
            {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": port, "syn_flag_count": 1.0},
            timestamp=300.0,
        )

    # 3rd port probe
    r3 = correlator.correlate_alert(
        Alert(severity="none", type="Benign", confidence=0.99, route="benign"),
        {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": 23, "syn_flag_count": 1.0},
        timestamp=300.2,
    )

    assert r3.type == "PortScan"
    assert r3.route == "known_attack"
    assert r3.severity == "high"
    assert "Stealth Vertical PortScan" in r3.note
    assert "T1046" in r3.mitre_techniques


def test_window_expiration_prunes_stale_probes():
    """Probes separated by more than window_sec do not cluster together."""
    correlator = ScanCorrelator(window_sec=2.0, min_ports_for_vertical_scan=3)
    src_ip = "192.168.1.15"
    dst_ip = "10.0.0.10"

    correlator.record_probe(src_ip, dst_ip, 80, timestamp=10.0)
    correlator.record_probe(src_ip, dst_ip, 81, timestamp=11.0)
    # At t=15.0, previous probes (10.0, 11.0) are older than 2.0s and must be pruned
    ports, hosts = correlator.record_probe(src_ip, dst_ip, 82, timestamp=15.0)

    assert ports == 1
    assert hosts == 1
