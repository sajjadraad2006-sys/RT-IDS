"""Pure canonical routing for serving, candidate, and shadow evaluation.

This module performs no I/O and imports no database, LLM, filesystem, or
network component. Callers must compute every classifier/anomaly signal first.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

import numpy as np


PIPELINE_VERSION = "cyberguard-pipeline-v2"
ROUTING_SCHEMA_VERSION = "cyberguard-routing-v2"
CANONICAL_ROUTES = (
    "known_attack",
    "human_review",
    "unknown_anomaly_review",
    "benign",
)


@dataclass(frozen=True)
class CanonicalRoutingBatch:
    routes: np.ndarray
    verdicts: np.ndarray
    severities: np.ndarray
    stages: np.ndarray
    reasons: np.ndarray
    supported_label: np.ndarray
    confident_known_attack: np.ndarray
    known_attack: np.ndarray
    human_review: np.ndarray
    unknown_anomaly_review: np.ndarray
    actionable: np.ndarray
    pipeline_version: str
    routing_schema_version: str

    def as_dict(self) -> dict[str, np.ndarray | str]:
        return {
            "routes": self.routes,
            "verdicts": self.verdicts,
            "severities": self.severities,
            "stages": self.stages,
            "reasons": self.reasons,
            "supported_label": self.supported_label,
            "confident_known_attack": self.confident_known_attack,
            "known_attack": self.known_attack,
            "human_review": self.human_review,
            "unknown_anomaly_review": self.unknown_anomaly_review,
            "actionable": self.actionable,
            "pipeline_version": self.pipeline_version,
            "routing_schema_version": self.routing_schema_version,
        }


def _materialize(values: Iterable[Any], name: str) -> np.ndarray:
    """Return one bounded signal vector without coercing invalid scalars."""
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{name} must be a one-dimensional signal array")
    try:
        materialized = values if isinstance(values, np.ndarray) else list(values)
        result = np.asarray(materialized)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a one-dimensional signal array") from exc
    if result.ndim != 1:
        raise ValueError(f"{name} must be a one-dimensional signal array")
    return result


def _finite_numeric(
    values: Iterable[float],
    name: str,
    *,
    lower: float,
    upper: float | None = None,
) -> np.ndarray:
    raw = _materialize(values, name)
    if raw.dtype.kind == "b" or any(
        isinstance(item, (bool, np.bool_)) for item in raw.tolist()
    ):
        raise ValueError(f"{name} must contain finite numeric values")
    try:
        result = raw.astype(float, copy=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain finite numeric values") from exc
    if not np.isfinite(result).all():
        raise ValueError(f"{name} must contain finite numeric values")
    if np.any(result < lower) or (upper is not None and np.any(result > upper)):
        bounds = f"[{lower}, {upper}]" if upper is not None else f">= {lower}"
        raise ValueError(f"{name} values must be {bounds}")
    return result


def _strict_booleans(values: Iterable[bool], name: str) -> np.ndarray:
    raw = _materialize(values, name)
    if raw.dtype.kind != "b":
        raise ValueError(f"{name} must contain booleans")
    return raw.astype(bool, copy=False)


def _strict_labels(values: Iterable[str], name: str) -> np.ndarray:
    raw = _materialize(values, name)
    labels = raw.tolist()
    if any(
        not isinstance(item, (str, np.str_))
        or not str(item).strip()
        or len(str(item)) > 128
        for item in labels
    ):
        raise ValueError(f"{name} must contain non-empty labels of at most 128 characters")
    return np.asarray([str(item) for item in labels], dtype="U128")


def route_signals(
    classifier_labels: Iterable[str],
    classifier_confidences: Iterable[float],
    *,
    classifier_threshold: float,
    supported_labels: Iterable[str] | None,
    statistical_flags: Iterable[bool],
    statistical_scores: Iterable[float],
    autoencoder_available: Iterable[bool],
    autoencoder_flags: Iterable[bool],
    autoencoder_scores: Iterable[float],
    pipeline_version: str,
    routing_schema_version: str,
) -> CanonicalRoutingBatch:
    """Return canonical decisions after all signals have been computed."""
    if pipeline_version != PIPELINE_VERSION:
        raise ValueError("canonical router requires cyberguard-pipeline-v2")
    if routing_schema_version != ROUTING_SCHEMA_VERSION:
        raise ValueError("canonical router requires cyberguard-routing-v2")

    labels = _strict_labels(classifier_labels, "classifier_labels")
    confidences = _finite_numeric(
        classifier_confidences,
        "classifier_confidences",
        lower=0.0,
        upper=1.0,
    )
    stat_flags = _strict_booleans(statistical_flags, "statistical_flags")
    stat_scores = _finite_numeric(
        statistical_scores, "statistical_scores", lower=0.0
    )
    ae_available = _strict_booleans(
        autoencoder_available, "autoencoder_available"
    )
    ae_flags = _strict_booleans(autoencoder_flags, "autoencoder_flags")
    ae_scores = _finite_numeric(
        autoencoder_scores, "autoencoder_scores", lower=0.0
    )
    lengths = {
        len(labels),
        len(confidences),
        len(stat_flags),
        len(stat_scores),
        len(ae_available),
        len(ae_flags),
        len(ae_scores),
    }
    if len(lengths) != 1:
        raise ValueError("routing signal arrays must have identical lengths")

    if isinstance(classifier_threshold, (bool, np.bool_)) or not isinstance(
        classifier_threshold, (int, float, np.integer, np.floating)
    ):
        raise ValueError("classifier_threshold must be finite and between 0 and 1")
    try:
        threshold = float(classifier_threshold)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "classifier_threshold must be finite and between 0 and 1"
        ) from exc
    if not np.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("classifier_threshold must be finite and between 0 and 1")

    if np.any(ae_flags & ~ae_available):
        raise ValueError(
            "autoencoder_flags cannot be true when autoencoder evidence is unavailable"
        )

    if supported_labels is None:
        supported = np.ones(len(labels), dtype=bool)
    else:
        declared_values = _strict_labels(supported_labels, "supported_labels")
        declared = np.asarray(sorted(set(declared_values.tolist())), dtype="U128")
        supported = np.isin(labels, declared)

    benign_label = np.char.lower(labels) == "benign"
    effective_ae_flag = ae_available & ae_flags
    anomaly = stat_flags | effective_ae_flag
    known_attack = (~benign_label) & supported & (confidences >= threshold)
    # Scope is absolute: even a classifier-produced Benign label is not trusted
    # as benign when it falls outside the artifact's declared label universe.
    human_review = (~supported) | ((~benign_label) & ~known_attack)
    unknown_review = supported & benign_label & anomaly
    benign = supported & benign_label & ~anomaly

    routes = np.full(len(labels), "benign", dtype="U32")
    routes[human_review] = "human_review"
    routes[unknown_review] = "unknown_anomaly_review"
    routes[known_attack] = "known_attack"
    if not np.all(known_attack | human_review | unknown_review | benign):
        raise RuntimeError("canonical router left an input row undecided")

    verdicts = labels.copy()
    verdicts[unknown_review] = "unknown-anomaly"
    verdicts[benign] = "Benign"
    severities = np.full(len(labels), "medium", dtype="U16")
    severities[benign] = "none"
    severities[known_attack] = "high"
    severities[known_attack & (confidences > 0.98)] = "critical"
    severities[unknown_review & stat_flags & effective_ae_flag] = "high"
    stages = np.full(len(labels), "classifier", dtype="U16")
    stages[benign] = "none"
    stages[unknown_review & ~effective_ae_flag] = "statistical"
    stages[unknown_review & effective_ae_flag] = "autoencoder"

    reasons = np.full(
        len(labels), "classifier_and_independent_signals_non_actionable", dtype="U64"
    )
    reasons[known_attack] = "supported_known_label_classifier_evidence"
    reasons[human_review & ~supported] = (
        "classifier_label_outside_declared_supported_scope"
    )
    reasons[human_review & supported & ~anomaly] = (
        "uncertain_non_benign_classifier"
    )
    reasons[human_review & supported & anomaly] = (
        "uncertain_classifier_with_anomaly_evidence"
    )
    reasons[unknown_review] = "classifier_benign_with_independent_anomaly"

    return CanonicalRoutingBatch(
        routes=routes,
        verdicts=verdicts,
        severities=severities,
        stages=stages,
        reasons=reasons,
        supported_label=supported,
        confident_known_attack=known_attack,
        known_attack=known_attack,
        human_review=human_review,
        unknown_anomaly_review=unknown_review,
        actionable=~benign,
        pipeline_version=str(pipeline_version),
        routing_schema_version=str(routing_schema_version),
    )
