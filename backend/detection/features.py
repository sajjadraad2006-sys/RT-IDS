"""Stage 1 — Numeric feature extraction.

Converts one network flow / log entry (dict) into a fixed numeric vector.
This is what the thesis completely skipped: the LLM never sees raw text here.

Thesis fix #4: "No feature extraction — Logs are converted to text and fed
directly to the LLM. No numeric features are computed."

We extract 30 scientifically validated features from CICIDS2017:
- Flow statistics (duration, packet/byte rates)
- Packet size distribution (mean, std, min, max)
- TCP flag counts (SYN, ACK, RST, FIN, PSH, URG)
- Window and timing features (init_win_bytes, IAT stats)
- Behavioral features (down_up_ratio, active/idle times)
"""
from __future__ import annotations
import math
from typing import Any

# ── Canonical feature vector ──────────────────────────────────────────────────
FEATURE_NAMES: list[str] = [
    # Group 1: Flow traffic (7)
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes", "total_bwd_bytes", "packets_per_sec", "bytes_per_sec",
    # Group 2: Packet size distribution (7)
    "fwd_packet_length_mean", "bwd_packet_length_mean",
    "packet_length_mean", "packet_length_std", "packet_length_max",
    "packet_length_min", "avg_pkt_size",
    # Group 3: TCP flags (6)
    "syn_flag_count", "ack_flag_count", "rst_flag_count", "fin_flag_count",
    "psh_flag_count", "urg_flag_count",
    # Group 4: Window and timing (6)
    "init_win_bytes_fwd", "init_win_bytes_bwd",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "fwd_iat_mean",
    # Group 5: Headers (2)
    "fwd_header_len", "bwd_header_len",
    # Group 6: Behavioral / derived (4)
    "down_up_ratio", "flow_bytes_ratio", "active_mean", "idle_mean",
]

# ── CICIDS2017 column aliases → canonical names ──────────────────────────────
_ALIASES: dict[str, str] = {
    # Flow stats
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_fwd_bytes",
    "Total Length of Bwd Packets": "total_bwd_bytes",
    "Flow Packets/s": "packets_per_sec",
    "Flow Bytes/s": "bytes_per_sec",
    # Packet size
    "Fwd Packet Length Mean": "fwd_packet_length_mean",
    "Bwd Packet Length Mean": "bwd_packet_length_mean",
    "Packet Length Mean": "packet_length_mean",
    "Packet Length Std": "packet_length_std",
    "Packet Length Max": "packet_length_max",
    "Min Packet Length": "packet_length_min",
    "Packet Length Min": "packet_length_min",
    "Average Packet Size": "avg_pkt_size",
    # TCP flags
    "SYN Flag Count": "syn_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "RST Flag Count": "rst_flag_count",
    "FIN Flag Count": "fin_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "URG Flag Count": "urg_flag_count",
    # Window / timing
    "Init_Win_bytes_forward": "init_win_bytes_fwd",
    "Init_Win_bytes_backward": "init_win_bytes_bwd",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Fwd IAT Mean": "fwd_iat_mean",
    # Headers
    "Fwd Header Length": "fwd_header_len",
    "Fwd Header Length.1": "fwd_header_len",
    "Bwd Header Length": "bwd_header_len",
    # Behavioral
    "Down/Up Ratio": "down_up_ratio",
    "Active Mean": "active_mean",
    "Idle Mean": "idle_mean",
}


def _num(v: Any) -> float:
    """Safely convert any value to a finite float.
    Missing values, infinities, and garbage strings become 0.0.
    This is critical — the thesis crashed on dirty input."""
    try:
        f = float(v)
        return f if math.isfinite(f) else 0.0
    except (TypeError, ValueError):
        return 0.0


def extract_features(flow: dict) -> dict[str, float]:
    """Map one flow record to the fixed 30-feature vector.

    Missing values and infinities become 0.0 — RobustScaler in Stage 1b
    handles the rest. Never raises on dirty input.

    Args:
        flow: Raw network flow record (column name → value).

    Returns:
        Dictionary of canonical feature name → numeric value.
    """
    out: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}

    for raw_key, value in flow.items():
        canon = _ALIASES.get(raw_key.strip() if isinstance(raw_key, str) else raw_key, raw_key)
        if canon in out:
            out[canon] = _num(value)

    # ── Derived features (computed if not already present) ────────────────
    dur = out["flow_duration"]
    total_pkts = out["total_fwd_packets"] + out["total_bwd_packets"]
    total_bytes = out["total_fwd_bytes"] + out["total_bwd_bytes"]

    # Packets per second
    if dur > 0 and out["packets_per_sec"] == 0.0:
        out["packets_per_sec"] = total_pkts / max(dur / 1e6, 1e-9)

    # Bytes per second
    if dur > 0 and out["bytes_per_sec"] == 0.0:
        out["bytes_per_sec"] = total_bytes / max(dur / 1e6, 1e-9)

    # Down/Up ratio
    if out["down_up_ratio"] == 0.0 and out["total_fwd_bytes"] > 0:
        out["down_up_ratio"] = out["total_bwd_bytes"] / max(out["total_fwd_bytes"], 1e-9)

    # Average packet size
    if out["avg_pkt_size"] == 0.0 and total_pkts > 0:
        out["avg_pkt_size"] = total_bytes / total_pkts

    # Flow bytes ratio: fwd/total — asymmetry reveals exfiltration (thesis fix #4)
    if out["flow_bytes_ratio"] == 0.0 and total_bytes > 0:
        out["flow_bytes_ratio"] = out["total_fwd_bytes"] / total_bytes

    return out


def extract_features_batch(flows: list[dict]) -> list[dict[str, float]]:
    """Vectorized batch extraction — map multiple flows at once."""
    return [extract_features(f) for f in flows]
