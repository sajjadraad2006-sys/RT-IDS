"""Stage 1 tests: extraction is total (never raises), fixed width, clean.
Validates all 32 features including derived ones like flow_bytes_ratio."""
import numpy as np
from backend.detection.features import extract_features, extract_features_batch, FEATURE_NAMES


def test_extract_from_cicids2017_row():
    row = {"Flow Duration": "120000", "Total Fwd Packets": "6",
           "Flow Bytes/s": "1500.5", "SYN Flag Count": "2"}
    out = extract_features(row)
    assert set(out.keys()) == set(FEATURE_NAMES)
    assert out["flow_duration"] == 120000.0
    assert out["syn_flag_count"] == 2.0


def test_dirty_input_becomes_zero_not_crash():
    out = extract_features({"Flow Duration": "inf", "Total Fwd Packets": None,
                            "Weird Column": "abc"})
    assert all(np.isfinite(v) for v in out.values())
    assert out["flow_duration"] == 0.0


def test_empty_flow_yields_full_vector():
    out = extract_features({})
    assert len(out) == len(FEATURE_NAMES)
    assert len(out) == 32, f"Expected 32 features, got {len(out)}"


def test_derived_features_computed():
    row = {"Flow Duration": "1000000", "Total Fwd Packets": "10",
           "Total Backward Packets": "5", "Total Length of Fwd Packets": "5000",
           "Total Length of Bwd Packets": "2000"}
    out = extract_features(row)
    assert out["packets_per_sec"] > 0
    assert out["bytes_per_sec"] > 0
    assert out["down_up_ratio"] > 0
    assert out["avg_pkt_size"] > 0


def test_flow_bytes_ratio_computed():
    """flow_bytes_ratio = fwd_bytes / total_bytes — critical for exfiltration detection."""
    row = {"Total Length of Fwd Packets": "7000",
           "Total Length of Bwd Packets": "3000"}
    out = extract_features(row)
    assert abs(out["flow_bytes_ratio"] - 0.7) < 0.01


def test_flow_bytes_ratio_zero_when_no_traffic():
    out = extract_features({})
    assert out["flow_bytes_ratio"] == 0.0


def test_batch_extraction():
    flows = [
        {"Flow Duration": "100", "SYN Flag Count": "1"},
        {"Flow Duration": "200", "SYN Flag Count": "2"},
        {"Flow Duration": "300", "SYN Flag Count": "3"},
    ]
    results = extract_features_batch(flows)
    assert len(results) == 3
    assert results[0]["flow_duration"] == 100.0
    assert results[2]["syn_flag_count"] == 3.0


def test_alias_fwd_header_length_dot_1():
    """CICIDS2017 has 'Fwd Header Length.1' in some CSVs."""
    row = {"Fwd Header Length.1": "320"}
    out = extract_features(row)
    assert out["fwd_header_len"] == 320.0


def test_flow_iat_max_extracted():
    row = {"Flow IAT Max": "5000"}
    out = extract_features(row)
    assert out["flow_iat_max"] == 5000.0


def test_negative_values_handled():
    row = {"Flow Duration": "-100", "Total Fwd Packets": "-5"}
    out = extract_features(row)
    assert out["flow_duration"] == -100.0  # valid finite float, not sanitized
    assert all(np.isfinite(v) for v in out.values())
