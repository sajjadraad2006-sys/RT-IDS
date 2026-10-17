"""Stage 4 tests: trained on benign only, unseen distribution must score
higher reconstruction error than benign (unknown-anomaly signal).

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
    flagged, err = ae.is_unknown_anomaly(unseen)
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


def test_autoencoder_empirical_quantile_calibration():
    """Verify that autoencoder thresholding uses empirical quantile / percentile calibration."""
    rng = np.random.default_rng(42)
    X_benign = rng.normal(0, 1, size=(500, N_FEATURES))
    X_val = rng.normal(0, 1, size=(200, N_FEATURES))

    ae = AutoencoderDetector(n_features=N_FEATURES, quantile=99.0).fit(
        X_benign, X_val, epochs=2, batch=256
    )
    val_errs = ae.errors(X_val)
    expected_p99 = float(np.percentile(val_errs, 99.0))
    assert abs(ae.threshold - expected_p99) < 1e-5
    assert ae.quantile == 99.0


def test_normalizer_volumetric_log1p():
    """Verify that Normalizer with log_transform_skewed handles heavy-tailed volumetric features."""
    from backend.detection.normalizer import Normalizer, apply_log1p_volumetric

    # Heavy-tailed values like bytes_per_sec = 10,000,000
    sample = np.zeros((5, N_FEATURES))
    sample[:, 6] = [100.0, 1000.0, 100000.0, 5000000.0, 10000000.0]  # bytes_per_sec column

    norm = Normalizer(log_transform_skewed=True)
    norm.fit(sample)
    trans = norm.transform(sample)

    assert trans.shape == (5, N_FEATURES)
    assert not np.isnan(trans).any()
    assert not np.isinf(trans).any()
    # Check that heavy tail was squashed logarithmically rather than linearly blowing up
    assert np.all(np.abs(trans) < 100.0)

