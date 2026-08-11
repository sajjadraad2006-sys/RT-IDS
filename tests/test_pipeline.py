"""End-to-end pipeline: normal traffic is quiet, injected attack alerts,
and every alert carries latency + stage attribution + MITRE mapping."""
import numpy as np
from backend.detection.normalizer import Normalizer
from backend.detection.statistical import StatisticalFilter
from backend.detection.pipeline import DetectionPipeline, Alert, PipelineStats
from backend.detection.features import FEATURE_NAMES

N_FEATURES = len(FEATURE_NAMES)  # 32


class _FakeClf:
    def predict(self, x): return ("DDoS", 0.995)
    def predict_batch(self, X):
        labels = np.array(["DDoS"] * len(X))
        confs = np.full(len(X), 0.995)
        return labels, confs
    def is_confident_attack(self, label, conf): return label != "Benign" and conf > 0.9
    def feature_importance(self, top=10): return [("packets_per_sec", 0.21)]


class _FakeClfLowConf:
    """Classifier that returns low-confidence attack."""
    def predict(self, x): return ("PortScan", 0.75)
    def predict_batch(self, X):
        labels = np.array(["PortScan"] * len(X))
        confs = np.full(len(X), 0.75)
        return labels, confs
    def is_confident_attack(self, label, conf): return label != "Benign" and conf > 0.9
    def feature_importance(self, top=10): return []


class _FakeAE:
    threshold = 1.0
    def is_zero_day(self, x): return (False, 0.01)
    def score_batch(self, X): return np.full(len(X), 0.01)


class _FakeAEZeroDay:
    """Autoencoder that flags everything as zero-day."""
    threshold = 0.5
    def is_zero_day(self, x): return (True, 1.42)
    def score_batch(self, X): return np.full(len(X), 1.42)


def _pipeline(stat_passes: bool, clf=None, ae=None) -> DetectionPipeline:
    rng = np.random.default_rng(0)
    Xb = rng.normal(0, 1, size=(2000, N_FEATURES))
    norm = Normalizer().fit(Xb)
    stat = StatisticalFilter(threshold=3.0).fit(Xb)
    if not stat_passes:
        stat.threshold = 1e9  # nothing is anomalous
    return DetectionPipeline(norm, stat, clf or _FakeClf(), ae or _FakeAE())


def test_benign_flow_is_filtered_out_early():
    pipe = _pipeline(stat_passes=False)
    alert = pipe.detect({"Flow Duration": "1000"})
    assert alert.severity == "none" and alert.stage == "none"


def test_anomalous_flow_reaches_classifier_and_alerts():
    pipe = _pipeline(stat_passes=True)
    alert = pipe.detect({"Flow Duration": "9999999", "SYN Flag Count": "500"})
    assert isinstance(alert, Alert)
    assert alert.type == "DDoS" and alert.stage == "classifier"
    assert alert.confidence > 0.9 and alert.latency_ms >= 0
    assert "T1498" in alert.mitre_techniques


def test_pipeline_stats_tracking():
    pipe = _pipeline(stat_passes=True)
    pipe.detect({"Flow Duration": "1000"})
    pipe.detect({"Flow Duration": "9999999", "SYN Flag Count": "500"})
    stats = pipe.get_stats()
    assert stats["total_flows"] == 2
    assert "mean_latency_ms" in stats
    assert "drop_rate_pct" in stats


def test_zero_day_detection_via_autoencoder():
    """When classifier is uncertain, autoencoder catches zero-day."""
    pipe = _pipeline(stat_passes=True, clf=_FakeClfLowConf(), ae=_FakeAEZeroDay())
    alert = pipe.detect({"Flow Duration": "9999999", "SYN Flag Count": "500"})
    assert alert.type == "zero-day"
    assert alert.stage == "autoencoder"
    assert alert.anomaly_score > 1.0
    assert "T1203" in alert.mitre_techniques


def test_low_confidence_attack_gets_medium_severity():
    """When classifier detects but isn't confident, severity=medium."""
    pipe = _pipeline(stat_passes=True, clf=_FakeClfLowConf(), ae=_FakeAE())
    alert = pipe.detect({"Flow Duration": "9999999", "SYN Flag Count": "500"})
    assert alert.severity == "medium"
    assert alert.type == "PortScan"
    assert alert.stage == "classifier"


def test_alert_to_dict_serializable():
    pipe = _pipeline(stat_passes=True)
    alert = pipe.detect({"Flow Duration": "9999999", "SYN Flag Count": "500"})
    d = alert.to_dict()
    assert isinstance(d, dict)
    assert "severity" in d and "type" in d and "mitre_techniques" in d


def test_batch_detection():
    pipe = _pipeline(stat_passes=True)
    flows = [
        {"Flow Duration": "9999999", "SYN Flag Count": "500"},
        {"Flow Duration": "100"},
        {"Flow Duration": "9999999", "SYN Flag Count": "999"},
    ]
    alerts = pipe.detect_batch(flows)
    assert len(alerts) == 3
    assert all(isinstance(a, Alert) for a in alerts)


def test_top_features_in_alert():
    """Alerts from classifier stage should include top anomalous features."""
    pipe = _pipeline(stat_passes=True)
    alert = pipe.detect({"Flow Duration": "9999999", "SYN Flag Count": "500"})
    assert isinstance(alert.top_features, list)
