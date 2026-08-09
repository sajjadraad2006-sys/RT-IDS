"""Stage 4 tests: trained on benign only, unseen distribution must score
higher reconstruction error than benign (zero-day signal).

Validates: threshold calibration, anomaly ratio, save/load, and score_batch."""
import numpy as np
from backend.detection.autoencoder import AutoencoderDetector
from backend.detection.features import FEATURE_NAMES

N_FEATURES = len(FEATURE_NAMES)


def test_autoencoder_flags_unseen_pattern():
    rng = np.random.default_rng(2)
    X_benign = rng.normal(0, 1, size=(3000, N_FEATURES))
    X_val = rng.normal(0, 1, size=(500, N_FEATURES))
    ae = AutoencoderDetector(n_features=N_FEATURES, k=3.0).fit(
        X_benign, X_val, epochs=3, batch=256)
    assert ae.threshold is not None and ae.threshold > 0
    unseen = rng.normal(6, 1, size=(1, N_FEATURES))[0]  # distribution shift = attack
    benign_err = ae.score(rng.normal(0, 1, size=(1, N_FEATURES))[0])
    assert ae.score(unseen) > benign_err
    flagged, err = ae.is_zero_day(unseen)
    assert flagged and err > ae.threshold


def test_benign_stays_below_threshold():
    rng = np.random.default_rng(2)
    X_benign = rng.normal(0, 1, size=(3000, N_FEATURES))
    X_val = rng.normal(0, 1, size=(500, N_FEATURES))
    ae = AutoencoderDetector(n_features=N_FEATURES, k=3.0).fit(
        X_benign, X_val, epochs=5, batch=256)
    # Most benign flows should NOT be flagged (some at boundary is OK)
    benign_test = rng.normal(0, 1, size=(100, N_FEATURES))
    errors = ae.score_batch(benign_test)
    flagged_count = np.sum(errors > ae.threshold)
    # With k=3, we expect <5% false positives on benign
    assert flagged_count < 10, f"Too many false positives: {flagged_count}/100"


def test_anomaly_ratio():
    rng = np.random.default_rng(2)
    X_benign = rng.normal(0, 1, size=(3000, N_FEATURES))
    X_val = rng.normal(0, 1, size=(500, N_FEATURES))
    ae = AutoencoderDetector(n_features=N_FEATURES, k=3.0).fit(
        X_benign, X_val, epochs=3, batch=256)
    unseen = rng.normal(6, 1, size=(1, N_FEATURES))[0]
    err = ae.score(unseen)
    ratio = ae.anomaly_ratio(err)
    assert ratio > 3.0, "Unseen pattern should be >3 std devs from mean"


def test_score_batch():
    rng = np.random.default_rng(2)
    X_benign = rng.normal(0, 1, size=(1000, N_FEATURES))
    X_val = rng.normal(0, 1, size=(200, N_FEATURES))
    ae = AutoencoderDetector(n_features=N_FEATURES, k=3.0).fit(
        X_benign, X_val, epochs=2, batch=256)
    scores = ae.score_batch(rng.normal(0, 1, size=(50, N_FEATURES)))
    assert len(scores) == 50
    assert all(s >= 0 for s in scores)


def test_save_and_load(tmp_path):
    rng = np.random.default_rng(2)
    X_benign = rng.normal(0, 1, size=(1000, N_FEATURES))
    X_val = rng.normal(0, 1, size=(200, N_FEATURES))
    ae = AutoencoderDetector(n_features=N_FEATURES, k=3.0).fit(
        X_benign, X_val, epochs=2, batch=256)
    path = tmp_path / "ae_test.pt"
    ae.save(path)

    ae2 = AutoencoderDetector(n_features=N_FEATURES).load(path, N_FEATURES)
    assert ae2.threshold is not None
    assert abs(ae2.threshold - ae.threshold) < 1e-4
