"""Pipeline v2 routing invariants and bounded process statistics."""
import json

import numpy as np
import pytest

from backend.detection.features import FEATURE_NAMES
from backend.detection.normalizer import Normalizer
from backend.detection.pipeline import Alert, DetectionPipeline, PipelineStats
from backend.detection.statistical import StatisticalFilter


N_FEATURES = len(FEATURE_NAMES)


class _FakeClf:
    confidence_threshold = 0.9

    def __init__(self, labels="DDoS", confidences=0.995):
        self.labels = labels
        self.confidences = confidences
        self.rows_seen = 0

    def predict_batch(self, matrix):
        self.rows_seen += len(matrix)
        labels = self.labels
        confidences = self.confidences
        if isinstance(labels, str):
            labels = [labels] * len(matrix)
        if isinstance(confidences, (int, float)):
            confidences = [confidences] * len(matrix)
        return np.asarray(labels[: len(matrix)]), np.asarray(confidences[: len(matrix)])

    def feature_importance(self, top=10):
        return [("packets_per_sec", 0.21)]


class _FakeAE:
    def __init__(self, *, threshold=1.0, errors=0.01):
        self.threshold = threshold
        self.errors = errors

    def score_batch(self, matrix):
        errors = self.errors
        if isinstance(errors, (int, float)):
            errors = [errors] * len(matrix)
        return np.asarray(errors[: len(matrix)], dtype=float)


def _pipeline(*, clf=None, ae=None, stat_threshold=3.0) -> DetectionPipeline:
    rng = np.random.default_rng(0)
    benign_training = rng.normal(0, 1, size=(2000, N_FEATURES))
    normalizer = Normalizer().fit(benign_training)
    statistical = StatisticalFilter(threshold=stat_threshold).fit(benign_training)
    return DetectionPipeline(
        normalizer,
        statistical,
        clf or _FakeClf(),
        ae or _FakeAE(),
    )


def _flow(duration=1.0):
    return {
        name: (duration if name == "flow_duration" else 0.0)
        for name in FEATURE_NAMES
    }


def _without_latency(alert: Alert) -> dict:
    payload = alert.to_dict()
    payload.pop("latency_ms")
    return payload


def test_classifier_receives_every_row_even_when_statistical_signal_is_quiet():
    classifier = _FakeClf()
    pipe = _pipeline(clf=classifier, stat_threshold=1e12)
    alerts = pipe.detect_batch([_flow(0.0), _flow(1.0), _flow(2.0)])
    assert classifier.rows_seen == 3
    assert [alert.route for alert in alerts] == ["known_attack"] * 3


def test_no_statistical_fast_exit_can_hide_supported_known_attack():
    pipe = _pipeline(clf=_FakeClf("DDoS", 0.995), stat_threshold=1e12)
    alert = pipe.detect(_flow())
    assert alert.type == "DDoS"
    assert alert.route == "known_attack"
    assert alert.stage == "classifier"
    assert "T1498" in alert.mitre_techniques


def test_benign_requires_classifier_and_anomaly_signals_to_be_quiet():
    pipe = _pipeline(
        clf=_FakeClf("Benign", 0.99),
        ae=_FakeAE(threshold=10.0, errors=0.01),
        stat_threshold=1e12,
    )
    alert = pipe.detect(_flow())
    assert alert.type == "Benign"
    assert alert.severity == "none"
    assert alert.route == "benign"


def test_classifier_benign_plus_autoencoder_signal_routes_unknown_review():
    pipe = _pipeline(
        clf=_FakeClf("Benign", 0.99),
        ae=_FakeAE(threshold=0.5, errors=1.42),
        stat_threshold=1e12,
    )
    alert = pipe.detect(_flow())
    assert alert.type == "unknown-anomaly"
    assert alert.stage == "autoencoder"
    assert alert.route == "unknown_anomaly_review"
    assert alert.anomaly_score == 1.42
    assert alert.mitre_techniques == []


def test_uncertain_non_benign_classifier_always_routes_human_review():
    pipe = _pipeline(
        clf=_FakeClf("PortScan", 0.75),
        ae=_FakeAE(threshold=0.5, errors=1.42),
    )
    alert = pipe.detect(_flow(9_999_999))
    assert alert.type == "PortScan"
    assert alert.severity == "medium"
    assert alert.stage == "classifier"
    assert alert.route == "human_review"


def test_high_confidence_label_outside_declared_scope_requires_review():
    pipe = _pipeline(clf=_FakeClf("PortScan", 0.999), stat_threshold=1e12)
    pipe.artifact_metadata = {"classes": ["Benign", "DDoS"]}
    pipe.supported_labels = {"Benign", "DDoS"}
    alert = pipe.detect(_flow())
    assert alert.route == "human_review"
    assert alert.mitre_techniques == []
    assert alert.evidence["routing_reason"] == (
        "classifier_label_outside_declared_supported_scope"
    )


def test_batch_preserves_order_and_single_row_routing_parity():
    flows = [_flow(0.0), _flow(1.0), _flow(2.0)]
    batch_pipe = _pipeline(
        clf=_FakeClf(["Benign", "DDoS", "PortScan"], [0.99, 0.995, 0.5]),
        ae=_FakeAE(threshold=10.0, errors=[0.01, 0.01, 0.01]),
        stat_threshold=1e12,
    )
    batch = batch_pipe.detect_batch(flows)
    assert [item.route for item in batch] == [
        "benign", "known_attack", "human_review"
    ]

    singles = []
    for flow, label, confidence in zip(
        flows, ["Benign", "DDoS", "PortScan"], [0.99, 0.995, 0.5]
    ):
        singles.append(
            _pipeline(
                clf=_FakeClf(label, confidence),
                ae=_FakeAE(threshold=10.0, errors=0.01),
                stat_threshold=1e12,
            ).detect(flow)
        )
    assert [_without_latency(item) for item in batch] == [
        _without_latency(item) for item in singles
    ]


def test_alert_json_is_finite_and_contains_versioned_evidence():
    payload = _pipeline().detect(_flow(9_999_999)).to_dict()
    encoded = json.dumps(payload, allow_nan=False)
    assert "cyberguard-pipeline-v2" in encoded
    assert payload["feature_evidence"]


@pytest.mark.parametrize(
    ("component", "invalid"),
    [
        ("classifier", float("nan")),
        ("classifier", "0.9"),
        ("classifier", 1.01),
        ("statistical", float("inf")),
        ("statistical", -1.0),
        ("autoencoder", float("nan")),
        ("autoencoder", -1.0),
    ],
)
def test_pipeline_rejects_invalid_calibrated_thresholds(component, invalid):
    classifier = _FakeClf()
    autoencoder = _FakeAE()
    stat_threshold = 3.0
    if component == "classifier":
        classifier.confidence_threshold = invalid
    elif component == "statistical":
        stat_threshold = invalid
    else:
        autoencoder.threshold = invalid
    pipe = _pipeline(
        clf=classifier, ae=autoencoder, stat_threshold=stat_threshold
    )
    with pytest.raises(ValueError, match="threshold must be finite"):
        pipe.detect(_flow())


def test_pipeline_stats_are_constant_space():
    stats = PipelineStats()
    for _ in range(10_000):
        stats.record(Alert(severity="none", type="Benign", route="benign"))
    assert stats.total_flows == 10_000
    assert stats.mean_latency_ms == 0
    assert not hasattr(stats, "_latencies")

    pipe = _pipeline(clf=_FakeClf("Benign", 0.99), stat_threshold=1e12)
    alerts = pipe.detect_batch([_flow(), _flow()])
    assert pipe.get_stats()["total_flows"] == 0
    completed = PipelineStats()
    for alert in alerts:
        completed.record(alert)
    pipe.commit_stats(completed)
    reported = pipe.get_stats()
    assert reported["scope"] == "process_lifetime"
    assert reported["total_flows"] == 2
    assert reported["latency_samples_retained"] == 0
