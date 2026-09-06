"""CyberGuard Pipeline v2: classifier-first, evidence-fusion routing.

Every validated flow reaches the known-attack classifier. Statistical and
autoencoder scores are calculated independently and may add review evidence;
neither signal is a pre-classifier benign gate. The LLM is never used here.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import threading
import time
from typing import Any

import numpy as np

from .autoencoder import AutoencoderDetector
from .classifier import AttackClassifier
from .features import FEATURE_NAMES, extract_features_matrix
from .normalizer import Normalizer
from .router import (
    PIPELINE_VERSION,
    ROUTING_SCHEMA_VERSION,
    CanonicalRoutingBatch,
    route_signals,
)
from .statistical import StatisticalFilter
from ..mitre.mapper import map_alert_to_techniques


LEGACY_PIPELINE_VERSION = "cyberguard-pipeline-legacy-v1"


def _finite(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if np.isfinite(result) else default


def _routing_threshold(
    value: Any, name: str, *, upper: float | None = None
) -> float:
    if isinstance(value, (bool, np.bool_)) or not isinstance(
        value, (int, float, np.integer, np.floating)
    ):
        raise ValueError(f"{name} threshold must be finite calibration metadata")
    result = float(value)
    if not np.isfinite(result) or result < 0.0 or (
        upper is not None and result > upper
    ):
        raise ValueError(f"{name} threshold must be finite calibration metadata")
    return result


@dataclass
class Alert:
    """One deterministic Pipeline v2 routing result."""

    severity: str
    type: str
    confidence: float = 0.0
    anomaly_score: float = 0.0
    stage: str = "none"
    route: str = "benign"
    mitre_techniques: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    note: str = ""
    top_features: list[tuple[str, float]] = field(default_factory=list)
    feature_evidence: list[dict[str, float | str]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    pipeline_version: str = PIPELINE_VERSION
    routing_schema_version: str = ROUTING_SCHEMA_VERSION
    artifact_pipeline_version: str = LEGACY_PIPELINE_VERSION

    def to_dict(self) -> dict[str, Any]:
        def json_safe(value: Any) -> Any:
            if isinstance(value, (float, np.floating)):
                return float(value) if np.isfinite(value) else 0.0
            if isinstance(value, (int, np.integer)):
                return int(value)
            if isinstance(value, dict):
                return {str(key): json_safe(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [json_safe(item) for item in value]
            return value

        return json_safe(asdict(self))


@dataclass
class PipelineStats:
    """Bounded process-lifetime counters; memory is O(1), not O(flows)."""

    total_flows: int = 0
    benign_decisions: int = 0
    classifier_alerts: int = 0
    unknown_anomaly_reviews: int = 0
    human_reviews: int = 0
    total_latency_ms: float = 0.0
    mean_latency_ms: float = 0.0

    def record(self, alert: Alert) -> None:
        self.total_flows += 1
        self.total_latency_ms += max(0.0, _finite(alert.latency_ms))
        self.mean_latency_ms = self.total_latency_ms / self.total_flows
        if alert.route == "benign":
            self.benign_decisions += 1
        elif alert.route == "known_attack":
            self.classifier_alerts += 1
        elif alert.route == "unknown_anomaly_review":
            self.unknown_anomaly_reviews += 1
        elif alert.route == "human_review":
            self.human_reviews += 1

    def merge(self, other: "PipelineStats") -> None:
        """Merge one bounded, already-complete operation summary."""
        self.total_flows += other.total_flows
        self.benign_decisions += other.benign_decisions
        self.classifier_alerts += other.classifier_alerts
        self.unknown_anomaly_reviews += other.unknown_anomaly_reviews
        self.human_reviews += other.human_reviews
        self.total_latency_ms += other.total_latency_ms
        self.mean_latency_ms = (
            self.total_latency_ms / self.total_flows if self.total_flows else 0.0
        )


class DetectionPipeline:
    """Versioned classifier-first orchestrator for validated flow records."""

    def __init__(
        self,
        normalizer: Normalizer,
        stat: StatisticalFilter,
        clf: AttackClassifier,
        ae: AutoencoderDetector,
        *,
        artifact_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.normalizer = normalizer
        self.stat = stat
        self.clf = clf
        self.ae = ae
        self.artifact_metadata = dict(artifact_metadata or {})
        self.artifact_pipeline_version = str(
            self.artifact_metadata.get("pipeline_version", LEGACY_PIPELINE_VERSION)
        )
        self.artifact_routing_schema_version = str(
            self.artifact_metadata.get(
                "routing_schema_version", "cyberguard-routing-legacy-v1"
            )
        )
        self.production_approved = bool(
            self.artifact_metadata.get("production_approved", False)
        )
        coverage = self.artifact_metadata.get("coverage_contract")
        coverage = coverage if isinstance(coverage, dict) else {}
        declared_supported = coverage.get(
            "trained_supported_labels", self.artifact_metadata.get("classes", [])
        )
        self.supported_labels: set[str] | None = {
            str(item) for item in declared_supported
            if isinstance(item, str) and item.strip()
        }
        # Unit callers without artifact metadata use their fake classifier's
        # declared universe. Serving always receives integrity-checked classes.
        if not self.artifact_metadata:
            classifier_labels = {
                str(item) for item in getattr(self.clf, "classes_", [])
            }
            self.supported_labels = classifier_labels or None
        self.calibration_status = (
            "calibrated_pipeline_v2"
            if self.artifact_pipeline_version == PIPELINE_VERSION
            else "legacy_unvalidated_evaluation_only"
        )
        self.stats = PipelineStats()
        self._stats_lock = threading.Lock()

    def _feature_evidence(
        self, raw: np.ndarray, normalized: np.ndarray, z_values: np.ndarray,
        *, top: int = 5,
    ) -> tuple[list[tuple[str, float]], list[dict[str, float | str]]]:
        order = np.argsort(z_values)[::-1][:top]
        pairs: list[tuple[str, float]] = []
        detailed: list[dict[str, float | str]] = []
        for index in order:
            name = FEATURE_NAMES[int(index)]
            z_score = max(0.0, _finite(z_values[index]))
            observed = _finite(raw[index])
            normalized_value = _finite(normalized[index])
            pairs.append((name, z_score))
            detailed.append({
                "name": name,
                "observed_value": observed,
                "normalized_value": normalized_value,
                "z_score": z_score,
            })
        return pairs, detailed

    def _build_alert(
        self,
        *,
        routed: CanonicalRoutingBatch,
        index: int,
        label: str,
        confidence: float,
        max_z: float,
        stat_flag: bool,
        ae_error: float,
        ae_flag: bool,
        top_features: list[tuple[str, float]],
        feature_evidence: list[dict[str, float | str]],
    ) -> Alert:
        label = str(label)
        confidence = min(1.0, max(0.0, _finite(confidence)))
        max_z = max(0.0, _finite(max_z))
        ae_error = max(0.0, _finite(ae_error))
        classifier_threshold = _finite(
            getattr(self.clf, "confidence_threshold", 1.0), 1.0
        )
        stat_threshold = max(0.0, _finite(getattr(self.stat, "threshold", 0.0)))
        ae_threshold_value = getattr(self.ae, "threshold", None)
        ae_threshold = (
            max(0.0, _finite(ae_threshold_value))
            if ae_threshold_value is not None else None
        )
        evidence = {
            "classifier": {
                "label": label,
                "confidence": confidence,
                "known_attack_threshold": classifier_threshold,
                "supported_label": bool(routed.supported_label[index]),
                "is_confident_known_attack": bool(
                    routed.confident_known_attack[index]
                ),
                "calibration_status": self.calibration_status,
            },
            "statistical": {
                "max_z_score": max_z,
                "threshold": stat_threshold,
                "flagged": bool(stat_flag),
                "role": "independent_evidence_not_a_gate",
                "calibration_status": self.calibration_status,
            },
            "autoencoder": {
                "available": ae_threshold is not None,
                "reconstruction_error": ae_error,
                "threshold": ae_threshold,
                "flagged": bool(ae_flag),
                "role": "unknown_anomaly_signal_not_exploit_proof",
                "calibration_status": self.calibration_status,
            },
            "artifact": {
                "pipeline_version": self.artifact_pipeline_version,
                "routing_schema_version": self.artifact_routing_schema_version,
                "production_approved": self.production_approved,
            },
            "routing": {
                "pipeline_version": routed.pipeline_version,
                "routing_schema_version": routed.routing_schema_version,
            },
            "routing_reason": str(routed.reasons[index]),
        }
        route = str(routed.routes[index])
        verdict = str(routed.verdicts[index])
        supported_label = bool(routed.supported_label[index])
        techniques = (
            map_alert_to_techniques(label)
            if route == "known_attack"
            or (
                route == "human_review"
                and supported_label
                and label.lower() != "benign"
            )
            else []
        )
        notes = {
            "known_attack": "supported known-label classifier evidence",
            "human_review": "uncertain classifier evidence requires analyst review",
            "unknown_anomaly_review": (
                "unknown behavior signal; not proof of an exploit"
            ),
            "benign": (
                "classifier and calibrated anomaly signals found no actionable evidence"
            ),
        }
        return Alert(
            severity=str(routed.severities[index]),
            type=verdict,
            confidence=confidence,
            anomaly_score=ae_error,
            stage=str(routed.stages[index]),
            route=route,
            mitre_techniques=techniques,
            note=notes[route],
            top_features=top_features, feature_evidence=feature_evidence,
            evidence=evidence,
            pipeline_version=routed.pipeline_version,
            routing_schema_version=routed.routing_schema_version,
            artifact_pipeline_version=self.artifact_pipeline_version,
        )

    def _detect_rows(self, flows: list[dict]) -> list[Alert]:
        if not flows:
            return []
        started = time.perf_counter()
        raw = extract_features_matrix(flows)
        normalized = self.normalizer.transform(raw)

        # Pipeline v2 invariant: classification happens before routing for all
        # rows. Statistical evidence cannot short-circuit this call.
        labels, confidences = self.clf.predict_batch(normalized)
        z_matrix = self.stat.z_scores_batch(normalized)
        max_z_scores = z_matrix.max(axis=1)
        classifier_threshold = _routing_threshold(
            getattr(self.clf, "confidence_threshold", None),
            "classifier",
            upper=1.0,
        )
        statistical_threshold = _routing_threshold(
            getattr(self.stat, "threshold", None), "statistical"
        )
        stat_flags = max_z_scores > statistical_threshold
        if getattr(self.ae, "threshold", None) is None:
            ae_errors = np.zeros(len(normalized), dtype=float)
            ae_flags = np.zeros(len(normalized), dtype=bool)
        else:
            autoencoder_threshold = _routing_threshold(
                self.ae.threshold, "autoencoder"
            )
            ae_errors = self.ae.score_batch(normalized)
            ae_flags = ae_errors > autoencoder_threshold

        routed = route_signals(
            labels,
            confidences,
            classifier_threshold=classifier_threshold,
            supported_labels=self.supported_labels,
            statistical_flags=stat_flags,
            statistical_scores=max_z_scores,
            autoencoder_available=np.full(
                len(normalized), getattr(self.ae, "threshold", None) is not None,
                dtype=bool,
            ),
            autoencoder_flags=ae_flags,
            autoencoder_scores=ae_errors,
            pipeline_version=PIPELINE_VERSION,
            routing_schema_version=ROUTING_SCHEMA_VERSION,
        )

        elapsed_per_row_ms = (time.perf_counter() - started) * 1000 / len(flows)
        alerts: list[Alert] = []
        for index in range(len(flows)):
            top, detailed = self._feature_evidence(
                raw[index], normalized[index], z_matrix[index]
            )
            alert = self._build_alert(
                routed=routed, index=index,
                label=str(labels[index]), confidence=float(confidences[index]),
                max_z=float(max_z_scores[index]), stat_flag=bool(stat_flags[index]),
                ae_error=float(ae_errors[index]), ae_flag=bool(ae_flags[index]),
                top_features=top, feature_evidence=detailed,
            )
            alert.latency_ms = round(max(0.0, elapsed_per_row_ms), 4)
            alerts.append(alert)
        return alerts

    def detect(self, flow: dict) -> Alert:
        """Run one already-validated record with the same logic as a batch."""
        return self._detect_rows([flow])[0]

    def detect_batch(self, flows: list[dict]) -> list[Alert]:
        """Infer one ordered result per row without mutating global statistics."""
        return self._detect_rows(flows)

    def commit_stats(self, completed: PipelineStats) -> None:
        """Commit a completed request summary exactly at its safe boundary."""
        with self._stats_lock:
            self.stats.merge(completed)

    def get_stats(self) -> dict[str, Any]:
        """Return bounded process-lifetime statistics (not upload statistics)."""
        with self._stats_lock:
            s = self.stats
            benign_rate = s.benign_decisions / max(s.total_flows, 1) * 100
            review_count = s.human_reviews + s.unknown_anomaly_reviews
            return {
                "scope": "process_lifetime",
                "pipeline_version": PIPELINE_VERSION,
                "total_flows": s.total_flows,
                "benign_decisions": s.benign_decisions,
                "benign_filtered": s.benign_decisions,
                "classifier_alerts": s.classifier_alerts,
                "autoencoder_alerts": s.unknown_anomaly_reviews,
                "unknown_anomaly_reviews": s.unknown_anomaly_reviews,
                "human_reviews": s.human_reviews,
                "review_count": review_count,
                "mean_latency_ms": round(s.mean_latency_ms, 4),
                "benign_rate_pct": round(benign_rate, 2),
                "drop_rate_pct": 0.0,
                "latency_samples_retained": 0,
            }
