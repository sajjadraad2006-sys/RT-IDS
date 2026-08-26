"""Stage 1 — Numeric feature extraction.

Converts one network flow / log entry (dict) into a fixed numeric vector.
This is what the thesis completely skipped: the LLM never sees raw text here.

Thesis fix #4: "No feature extraction — Logs are converted to text and fed
directly to the LLM. No numeric features are computed."

We extract 32 fixed numerical flow features compatible with the documented
CICFlowMeter adapters:
- Flow statistics (duration, packet/byte rates)
- Packet size distribution (mean, std, min, max)
- TCP flag counts (SYN, ACK, RST, FIN, PSH, URG)
- Window and timing features (init_win_bytes, IAT stats)
- Behavioral features (down_up_ratio, active/idle times)
"""
from __future__ import annotations
import math
from typing import Any
import numpy as np

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
FEATURE_ALIASES: dict[str, str] = {
    # Flow stats
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_bwd_packets",
    "Total Length of Fwd Packets": "total_fwd_bytes",
    "Total Length of Bwd Packets": "total_bwd_bytes",
    "Flow Packets/s": "packets_per_sec",
    "Flow Bytes/s": "bytes_per_sec",
    # CSE-CIC-IDS2018 CICFlowMeter-V3 spellings
    "Tot Fwd Pkts": "total_fwd_packets",
    "Tot Bwd Pkts": "total_bwd_packets",
    "TotLen Fwd Pkts": "total_fwd_bytes",
    "TotLen Bwd Pkts": "total_bwd_bytes",
    "Flow Pkts/s": "packets_per_sec",
    "Flow Byts/s": "bytes_per_sec",
    # Packet size
    "Fwd Packet Length Mean": "fwd_packet_length_mean",
    "Bwd Packet Length Mean": "bwd_packet_length_mean",
    "Packet Length Mean": "packet_length_mean",
    "Packet Length Std": "packet_length_std",
    "Packet Length Max": "packet_length_max",
    "Min Packet Length": "packet_length_min",
    "Packet Length Min": "packet_length_min",
    "Average Packet Size": "avg_pkt_size",
    "Fwd Pkt Len Mean": "fwd_packet_length_mean",
    "Bwd Pkt Len Mean": "bwd_packet_length_mean",
    "Pkt Len Mean": "packet_length_mean",
    "Pkt Len Std": "packet_length_std",
    "Pkt Len Max": "packet_length_max",
    "Pkt Len Min": "packet_length_min",
    "Pkt Size Avg": "avg_pkt_size",
    # TCP flags
    "SYN Flag Count": "syn_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "RST Flag Count": "rst_flag_count",
    "FIN Flag Count": "fin_flag_count",
    "PSH Flag Count": "psh_flag_count",
    "URG Flag Count": "urg_flag_count",
    "SYN Flag Cnt": "syn_flag_count",
    "ACK Flag Cnt": "ack_flag_count",
    "RST Flag Cnt": "rst_flag_count",
    "FIN Flag Cnt": "fin_flag_count",
    "PSH Flag Cnt": "psh_flag_count",
    "URG Flag Cnt": "urg_flag_count",
    # Window / timing
    "Init_Win_bytes_forward": "init_win_bytes_fwd",
    "Init_Win_bytes_backward": "init_win_bytes_bwd",
    # CICIDS2017 releases use both the ``forward`` spelling and the shorter
    # ``fwd`` spelling.  The latter was missing from the serving extractor and
    # silently became zero at inference time.
    "Init_Win_bytes_fwd": "init_win_bytes_fwd",
    "Init_Win_bytes_bwd": "init_win_bytes_bwd",
    "Init Win bytes forward": "init_win_bytes_fwd",
    "Init Win bytes backward": "init_win_bytes_bwd",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Init Fwd Win Byts": "init_win_bytes_fwd",
    "Init Bwd Win Byts": "init_win_bytes_bwd",
    # Headers
    "Fwd Header Length": "fwd_header_len",
    "Fwd Header Length.1": "fwd_header_len",
    "Bwd Header Length": "bwd_header_len",
    "Fwd Header Len": "fwd_header_len",
    "Bwd Header Len": "bwd_header_len",
    # Behavioral
    "Down/Up Ratio": "down_up_ratio",
    "Active Mean": "active_mean",
    "Idle Mean": "idle_mean",
}

# Backwards-compatible private name for older callers.  New schema-validation
# code imports the public constant so aliases and coverage cannot drift apart.
_ALIASES = FEATURE_ALIASES


def canonical_feature_name(raw_name: Any) -> str | None:
    """Return the canonical model feature represented by a column name.

    Recognition is deliberately schema-based: a present zero-valued column is
    still present.  Unknown columns return ``None`` instead of being confused
    with a missing model feature.
    """
    if not isinstance(raw_name, str):
        return None
    stripped = raw_name.strip().lstrip("\ufeff")
    canonical = FEATURE_ALIASES.get(stripped, stripped)
    return canonical if canonical in FEATURE_NAMES else None


def _num(v: Any) -> float:
    """Safely convert any value to a finite float.
    Missing values, infinities, and garbage strings become 0.0 for trusted
    offline transforms. Untrusted uploads must first pass input_schema.py,
    which rejects and reports invalid cells before this fallback is reachable.
    """
    try:
        f = float(v)
        if not math.isfinite(f) or f < 0:
            return 0.0
        return min(f, 1e15)
    except (TypeError, ValueError):
        return 0.0


def extract_features(flow: dict) -> dict[str, float]:
    """Map one flow record to the fixed 32-feature vector.

    Trusted callers retain a total transform. API uploads are validated
    fail-closed before reaching this function.

    Args:
        flow: Raw network flow record (column name → value).

    Returns:
        Dictionary of canonical feature name → numeric value.
    """
    out: dict[str, float] = {name: 0.0 for name in FEATURE_NAMES}
    provided: set[str] = set()

    for raw_key, value in flow.items():
        canon = canonical_feature_name(raw_key)
        if canon in out:
            out[canon] = _num(value)
            provided.add(canon)

    # ── Derived features (computed if not already present) ────────────────
    dur = out["flow_duration"]
    total_pkts = out["total_fwd_packets"] + out["total_bwd_packets"]
    total_bytes = out["total_fwd_bytes"] + out["total_bwd_bytes"]

    # Packets per second
    if dur > 0 and "packets_per_sec" not in provided:
        out["packets_per_sec"] = total_pkts / max(dur / 1e6, 1e-9)

    # Bytes per second
    if dur > 0 and "bytes_per_sec" not in provided:
        out["bytes_per_sec"] = total_bytes / max(dur / 1e6, 1e-9)

    # Down/Up ratio
    if "down_up_ratio" not in provided and out["total_fwd_bytes"] > 0:
        out["down_up_ratio"] = out["total_bwd_bytes"] / max(out["total_fwd_bytes"], 1e-9)

    # Average packet size
    if "avg_pkt_size" not in provided and total_pkts > 0:
        out["avg_pkt_size"] = total_bytes / total_pkts

    # Flow bytes ratio: fwd/total — asymmetry reveals exfiltration (thesis fix #4)
    if "flow_bytes_ratio" not in provided and total_bytes > 0:
        out["flow_bytes_ratio"] = out["total_fwd_bytes"] / total_bytes

    return out


def extract_features_batch(flows: list[dict]) -> list[dict[str, float]]:
    """Vectorized batch extraction — map multiple flows at once."""
    return [extract_features(f) for f in flows]


def extract_features_matrix(flows: list[dict]) -> np.ndarray:
    """Ultra-fast feature matrix extraction — converts list of flow dicts directly to N × 32 NumPy float32 matrix.
    
    Fast direct dictionary key lookup without Pandas overhead.
    """
    if not flows:
        return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32)

    n = len(flows)
    n_feats = len(FEATURE_NAMES)
    arr = np.zeros((n, n_feats), dtype=np.float32)
    provided = np.zeros((n, n_feats), dtype=bool)

    # Cache feature index mapping for O(1) assignments
    feat_to_idx = {name: i for i, name in enumerate(FEATURE_NAMES)}

    for row_idx, flow in enumerate(flows):
        for raw_key, val in flow.items():
            canon = canonical_feature_name(raw_key)
            col_idx = feat_to_idx.get(canon)
            if col_idx is not None:
                arr[row_idx, col_idx] = _num(val)
                provided[row_idx, col_idx] = True

    return _derive_matrix(arr, feat_to_idx, provided)


def _derive_matrix(
    arr: np.ndarray,
    feat_to_idx: dict[str, int],
    provided: np.ndarray | None = None,
) -> np.ndarray:
    """Apply the same derived-feature rules to an already populated matrix."""
    idx = feat_to_idx
    if provided is None:
        provided = arr != 0
    duration = arr[:, idx["flow_duration"]]
    total_packets = (
        arr[:, idx["total_fwd_packets"]] + arr[:, idx["total_bwd_packets"]]
    )
    total_bytes = arr[:, idx["total_fwd_bytes"]] + arr[:, idx["total_bwd_bytes"]]
    seconds = np.maximum(duration / 1e6, 1e-9)
    missing = (duration > 0) & ~provided[:, idx["packets_per_sec"]]
    arr[missing, idx["packets_per_sec"]] = total_packets[missing] / seconds[missing]
    missing = (duration > 0) & ~provided[:, idx["bytes_per_sec"]]
    arr[missing, idx["bytes_per_sec"]] = total_bytes[missing] / seconds[missing]
    missing = ~provided[:, idx["down_up_ratio"]] & (
        arr[:, idx["total_fwd_bytes"]] > 0
    )
    arr[missing, idx["down_up_ratio"]] = (
        arr[missing, idx["total_bwd_bytes"]]
        / np.maximum(arr[missing, idx["total_fwd_bytes"]], 1e-9)
    )
    missing = ~provided[:, idx["avg_pkt_size"]] & (total_packets > 0)
    arr[missing, idx["avg_pkt_size"]] = total_bytes[missing] / total_packets[missing]
    missing = ~provided[:, idx["flow_bytes_ratio"]] & (total_bytes > 0)
    arr[missing, idx["flow_bytes_ratio"]] = (
        arr[missing, idx["total_fwd_bytes"]] / total_bytes[missing]
    )

    np.nan_to_num(arr, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return arr


def extract_features_dataframe(frame) -> np.ndarray:
    """Vectorized Pandas-to-feature conversion for large training captures."""
    n = len(frame)
    arr = np.zeros((n, len(FEATURE_NAMES)), dtype=np.float32)
    provided = np.zeros((n, len(FEATURE_NAMES)), dtype=bool)
    feat_to_idx = {name: index for index, name in enumerate(FEATURE_NAMES)}
    for raw_name in frame.columns:
        canonical = canonical_feature_name(raw_name)
        index = feat_to_idx.get(canonical)
        if index is None:
            continue
        values = frame[raw_name]
        # pandas is intentionally imported by the caller/training workflow,
        # not by the latency-sensitive single-flow inference module.
        try:
            numeric_dtype = np.issubdtype(values.dtype, np.number)
        except TypeError:
            numeric_dtype = False
        numeric = values if numeric_dtype else values.apply(lambda value: _num(value))
        converted = np.asarray(numeric, dtype=np.float64).copy()
        converted[~np.isfinite(converted)] = 0.0
        converted[converted < 0] = 0.0
        arr[:, index] = np.minimum(converted, 1e15).astype(np.float32)
        provided[:, index] = True
    return _derive_matrix(arr, feat_to_idx, provided)
