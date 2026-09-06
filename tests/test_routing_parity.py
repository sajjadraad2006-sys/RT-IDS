"""One canonical router drives serving, candidate, and shadow decisions."""
from __future__ import annotations

import ast
import inspect

import numpy as np
import pytest

from backend.detection.candidate_workflow import _pipeline_v2_routes
from backend.detection.features import FEATURE_NAMES
from backend.detection.pipeline import DetectionPipeline
from backend.detection.router import (
    PIPELINE_VERSION,
    ROUTING_SCHEMA_VERSION,
    route_signals,
)
from backend.detection.shadow import _route as shadow_route
from tests.helpers import canonical_flow


LABELS = np.array(["DDoS", "DDoS", "PortScan", "Benign", "Benign"])
CONFIDENCES = np.array([0.99, 0.50, 0.999, 0.99, 0.99])
STATISTICAL_SCORES = np.array([0.0, 0.0, 0.0, 4.0, 0.0])
AUTOENCODER_SCORES = np.array([0.0, 0.0, 0.0, 0.0, 0.0])
SUPPORTED = ["Benign", "DDoS"]


class _IdentityNormalizer:
    def transform(self, matrix):
        return matrix


class _FixedStatistical:
    threshold = 3.0

    def z_scores_batch(self, matrix):
        result = np.zeros_like(matrix, dtype=float)
        result[:, 0] = STATISTICAL_SCORES[: len(matrix)]
        return result


class _FixedClassifier:
    confidence_threshold = 0.9
    classes_ = ["Benign", "DDoS", "PortScan"]

    def __init__(self):
        self.rows_seen = 0

    def predict_batch(self, matrix):
        self.rows_seen += len(matrix)
        return LABELS[: len(matrix)], CONFIDENCES[: len(matrix)]


class _FixedAutoencoder:
    threshold = 1.0

    def score_batch(self, matrix):
        return AUTOENCODER_SCORES[: len(matrix)]


def _metadata():
    return {
        "pipeline_version": PIPELINE_VERSION,
        "routing_schema_version": ROUTING_SCHEMA_VERSION,
        "production_approved": False,
        "coverage_contract": {"trained_supported_labels": SUPPORTED},
    }


def test_serving_candidate_and_shadow_have_identical_routes_and_verdicts():
    flows = [canonical_flow() for _ in LABELS]
    serving_classifier = _FixedClassifier()
    serving = DetectionPipeline(
        _IdentityNormalizer(),
        _FixedStatistical(),
        serving_classifier,
        _FixedAutoencoder(),
        artifact_metadata=_metadata(),
    ).detect_batch(flows)

    candidate = _pipeline_v2_routes(
        LABELS,
        CONFIDENCES,
        classifier_threshold=0.9,
        supported_labels=SUPPORTED,
        statistical_flags=STATISTICAL_SCORES > 3.0,
        statistical_scores=STATISTICAL_SCORES,
        autoencoder_available=np.ones(len(LABELS), dtype=bool),
        autoencoder_flags=AUTOENCODER_SCORES > 1.0,
        autoencoder_scores=AUTOENCODER_SCORES,
    )

    shadow_classifier = _FixedClassifier()
    shadow = shadow_route(
        (
            _metadata(),
            _IdentityNormalizer(),
            _FixedStatistical(),
            shadow_classifier,
            _FixedAutoencoder(),
        ),
        np.zeros((len(LABELS), len(FEATURE_NAMES)), dtype=float),
    )

    expected_routes = [
        "known_attack",
        "human_review",
        "human_review",
        "unknown_anomaly_review",
        "benign",
    ]
    expected_verdicts = [
        "DDoS", "DDoS", "PortScan", "unknown-anomaly", "Benign"
    ]
    assert serving_classifier.rows_seen == shadow_classifier.rows_seen == len(LABELS)
    assert [alert.route for alert in serving] == expected_routes
    assert [alert.type for alert in serving] == expected_verdicts
    assert candidate["routes"].tolist() == shadow["routes"].tolist() == expected_routes
    assert (
        candidate["verdicts"].tolist()
        == shadow["verdicts"].tolist()
        == expected_verdicts
    )
    assert serving[2].mitre_techniques == []
    assert serving[3].mitre_techniques == []


def test_router_single_row_and_batch_results_are_identical():
    kwargs = {
        "classifier_threshold": 0.9,
        "supported_labels": SUPPORTED,
        "statistical_flags": STATISTICAL_SCORES > 3.0,
        "statistical_scores": STATISTICAL_SCORES,
        "autoencoder_available": np.ones(len(LABELS), dtype=bool),
        "autoencoder_flags": AUTOENCODER_SCORES > 1.0,
        "autoencoder_scores": AUTOENCODER_SCORES,
        "pipeline_version": PIPELINE_VERSION,
        "routing_schema_version": ROUTING_SCHEMA_VERSION,
    }
    batch = route_signals(LABELS, CONFIDENCES, **kwargs)
    singles = []
    for index in range(len(LABELS)):
        single_kwargs = {
            key: value[index : index + 1]
            if isinstance(value, np.ndarray)
            else value
            for key, value in kwargs.items()
        }
        singles.append(
            route_signals(
                LABELS[index : index + 1],
                CONFIDENCES[index : index + 1],
                **single_kwargs,
            )
        )
    assert batch.routes.tolist() == [item.routes[0] for item in singles]
    assert batch.verdicts.tolist() == [item.verdicts[0] for item in singles]


def test_out_of_scope_benign_label_requires_human_review():
    routed = route_signals(
        ["Benign"],
        [0.999],
        classifier_threshold=0.9,
        supported_labels=["DDoS"],
        statistical_flags=[False],
        statistical_scores=[0.0],
        autoencoder_available=[False],
        autoencoder_flags=[False],
        autoencoder_scores=[0.0],
        pipeline_version=PIPELINE_VERSION,
        routing_schema_version=ROUTING_SCHEMA_VERSION,
    )
    assert routed.routes.tolist() == ["human_review"]


def test_router_module_has_only_pure_computation_dependencies():
    import backend.detection.router as router

    tree = ast.parse(inspect.getsource(router))
    imported_roots = {
        node.names[0].name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
    }
    imported_roots.update(
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert imported_roots <= {"__future__", "dataclasses", "typing", "numpy"}


@pytest.mark.parametrize(
    (
        "label", "confidence", "supported", "stat_score", "ae_threshold",
        "ae_score", "expected_route",
    ),
    [
        ("DDoS", np.nextafter(0.9, 0.0), ["Benign", "DDoS"], 0.0, None, 0.0, "human_review"),
        ("DDoS", 0.9, ["Benign", "DDoS"], 0.0, None, 0.0, "known_attack"),
        ("DDoS", np.nextafter(0.9, 1.0), ["Benign", "DDoS"], 4.0, 1.0, 2.0, "known_attack"),
        ("PortScan", 0.999, ["Benign", "DDoS"], 0.0, None, 0.0, "human_review"),
        ("Benign", 0.99, ["Benign", "DDoS"], 3.0, None, 0.0, "benign"),
        ("Benign", 0.99, ["Benign", "DDoS"], np.nextafter(3.0, 4.0), None, 0.0, "unknown_anomaly_review"),
        ("Benign", 0.99, ["Benign", "DDoS"], 0.0, 1.0, 1.0, "benign"),
        ("Benign", 0.99, ["Benign", "DDoS"], 0.0, 1.0, np.nextafter(1.0, 2.0), "unknown_anomaly_review"),
    ],
)
def test_threshold_boundaries_have_cross_path_route_and_verdict_parity(
    label, confidence, supported, stat_score, ae_threshold, ae_score,
    expected_route,
):
    class OneStatistical:
        threshold = 3.0

        def z_scores_batch(self, matrix):
            result = np.zeros_like(matrix, dtype=float)
            result[:, 0] = stat_score
            return result

    class OneClassifier:
        confidence_threshold = 0.9
        classes_ = ["Benign", "DDoS", "PortScan"]

        def predict_batch(self, matrix):
            return np.asarray([label] * len(matrix)), np.full(len(matrix), confidence)

    class OneAutoencoder:
        threshold = ae_threshold

        def score_batch(self, matrix):
            return np.full(len(matrix), ae_score)

    metadata = {
        "pipeline_version": PIPELINE_VERSION,
        "routing_schema_version": ROUTING_SCHEMA_VERSION,
        "coverage_contract": {"trained_supported_labels": supported},
    }
    bundle = (
        metadata,
        _IdentityNormalizer(),
        OneStatistical(),
        OneClassifier(),
        OneAutoencoder(),
    )
    raw = np.zeros((1, len(FEATURE_NAMES)), dtype=float)
    serving = DetectionPipeline(*bundle[1:], artifact_metadata=metadata).detect_batch(
        [canonical_flow()]
    )[0]
    candidate = _pipeline_v2_routes(
        np.asarray([label]),
        np.asarray([confidence]),
        classifier_threshold=0.9,
        supported_labels=supported,
        statistical_flags=np.asarray([stat_score > 3.0]),
        statistical_scores=np.asarray([stat_score]),
        autoencoder_available=np.asarray([ae_threshold is not None]),
        autoencoder_flags=np.asarray([
            ae_threshold is not None and ae_score > ae_threshold
        ]),
        autoencoder_scores=np.asarray([ae_score]),
    )
    shadow = shadow_route(bundle, raw)

    assert serving.route == expected_route
    assert candidate["routes"].tolist() == shadow["routes"].tolist() == [
        expected_route
    ]
    assert candidate["verdicts"].tolist() == shadow["verdicts"].tolist() == [
        serving.type
    ]


def _valid_router_arguments():
    return {
        "classifier_labels": ["Benign"],
        "classifier_confidences": [0.9],
        "classifier_threshold": 0.9,
        "supported_labels": ["Benign"],
        "statistical_flags": [False],
        "statistical_scores": [0.0],
        "autoencoder_available": [False],
        "autoencoder_flags": [False],
        "autoencoder_scores": [0.0],
        "pipeline_version": PIPELINE_VERSION,
        "routing_schema_version": ROUTING_SCHEMA_VERSION,
    }


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("classifier_labels", [""]),
        ("classifier_confidences", [float("nan")]),
        ("classifier_confidences", [float("inf")]),
        ("classifier_confidences", [-0.01]),
        ("classifier_confidences", [1.01]),
        ("classifier_threshold", float("nan")),
        ("classifier_threshold", "0.9"),
        ("classifier_threshold", -0.01),
        ("classifier_threshold", 1.01),
        ("statistical_flags", ["false"]),
        ("statistical_scores", [float("nan")]),
        ("statistical_scores", [-1.0]),
        ("autoencoder_available", [1]),
        ("autoencoder_flags", ["true"]),
        ("autoencoder_scores", [float("inf")]),
        ("pipeline_version", "cyberguard-pipeline-v1"),
        ("routing_schema_version", "cyberguard-routing-v1"),
    ],
)
def test_router_rejects_malformed_or_nonfinite_evidence(field, invalid):
    arguments = _valid_router_arguments()
    arguments[field] = invalid
    with pytest.raises(ValueError):
        route_signals(**arguments)


def test_router_rejects_inconsistent_autoencoder_availability_and_lengths():
    arguments = _valid_router_arguments()
    arguments["autoencoder_flags"] = [True]
    with pytest.raises(ValueError, match="unavailable"):
        route_signals(**arguments)

    arguments = _valid_router_arguments()
    arguments["statistical_scores"] = [0.0, 1.0]
    with pytest.raises(ValueError, match="identical lengths"):
        route_signals(**arguments)
