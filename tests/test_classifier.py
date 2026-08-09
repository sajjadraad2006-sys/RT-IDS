"""Stage 3 tests on synthetic separable data (real eval is trainer.py on
CICIDS2017 — never fewer than 10k test samples).

Tests verify: class imbalance handling, feature importance, batch prediction,
and the confidence-gated attack classification."""
import numpy as np
from backend.detection.classifier import AttackClassifier
from backend.detection.features import FEATURE_NAMES

N_FEATURES = len(FEATURE_NAMES)


def test_classifier_learns_separable_data():
    rng = np.random.default_rng(1)
    benign = rng.normal(0, 0.3, size=(800, N_FEATURES))
    ddos = rng.normal(4, 0.3, size=(200, N_FEATURES))  # imbalanced on purpose
    X = np.vstack([benign, ddos])
    y = np.array(["Benign"] * 800 + ["DDoS"] * 200)
    clf = AttackClassifier().fit(X, y)
    label, conf = clf.predict(rng.normal(4, 0.3, size=(1, N_FEATURES))[0])
    assert label == "DDoS" and conf > 0.9
    assert clf.is_confident_attack(label, conf)
    assert len(clf.feature_importance(5)) >= 1


def test_benign_classified_correctly():
    rng = np.random.default_rng(1)
    benign = rng.normal(0, 0.3, size=(800, N_FEATURES))
    ddos = rng.normal(4, 0.3, size=(200, N_FEATURES))
    X = np.vstack([benign, ddos])
    y = np.array(["Benign"] * 800 + ["DDoS"] * 200)
    clf = AttackClassifier().fit(X, y)
    label, conf = clf.predict(rng.normal(0, 0.3, size=(1, N_FEATURES))[0])
    assert label == "Benign"
    assert not clf.is_confident_attack(label, conf)


def test_batch_predict():
    rng = np.random.default_rng(1)
    benign = rng.normal(0, 0.3, size=(800, N_FEATURES))
    ddos = rng.normal(4, 0.3, size=(200, N_FEATURES))
    X = np.vstack([benign, ddos])
    y = np.array(["Benign"] * 800 + ["DDoS"] * 200)
    clf = AttackClassifier().fit(X, y)
    labels, confs = clf.predict_batch(rng.normal(4, 0.3, size=(10, N_FEATURES)))
    assert len(labels) == 10
    assert len(confs) == 10
    assert all(isinstance(l, str) for l in labels)


def test_multiclass_classification():
    rng = np.random.default_rng(1)
    benign = rng.normal(0, 0.3, size=(400, N_FEATURES))
    ddos = rng.normal(4, 0.3, size=(100, N_FEATURES))
    scan = rng.normal(-4, 0.3, size=(100, N_FEATURES))
    X = np.vstack([benign, ddos, scan])
    y = np.array(["Benign"] * 400 + ["DDoS"] * 100 + ["PortScan"] * 100)
    clf = AttackClassifier().fit(X, y)
    assert len(clf.classes_) == 3
    assert "DDoS" in clf.classes_ and "PortScan" in clf.classes_
