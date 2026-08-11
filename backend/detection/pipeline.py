"""The 4-stage detection pipeline. THE CORE of CyberGuard (90% of value).
Works with zero LLM. The LLM layer only explains alerts afterwards.

    flow → features → [Z-filter] → [XGBoost] → [Autoencoder] → Alert

Pipeline logic:
1. Stage 1: Extract 30 numeric features, normalize with RobustScaler
2. Stage 2: Z-Score filter — if max|z| < threshold, flow is benign (fast exit)
3. Stage 3: XGBoost classifies into 8 attack types with confidence
4. Stage 4: Autoencoder catches zero-day attacks via reconstruction error

Each stage is independently testable and replaceable.
"""
from __future__ import annotations
import time
import logging
from dataclasses import dataclass, field, asdict
import numpy as np
from .features import extract_features, FEATURE_NAMES
from .normalizer import Normalizer
from .statistical import StatisticalFilter
from .classifier import AttackClassifier
from .autoencoder import AutoencoderDetector
from ..mitre.mapper import map_alert_to_techniques

log = logging.getLogger("cyberguard.pipeline")


@dataclass
class Alert:
    """Detection result from the pipeline."""
    severity: str                     # none | low | medium | high | critical
    type: str                         # Benign | DDoS | ... | zero-day
    confidence: float = 0.0
    anomaly_score: float = 0.0
    stage: str = "none"               # statistical | classifier | autoencoder
    mitre_techniques: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    note: str = ""
    top_features: list[tuple[str, float]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PipelineStats:
    """Cumulative pipeline statistics."""
    total_flows: int = 0
    benign_filtered: int = 0         # dropped at Stage 2
    classifier_alerts: int = 0       # caught at Stage 3
    autoencoder_alerts: int = 0      # caught at Stage 4
    low_confidence: int = 0          # uncertain classifications
    mean_latency_ms: float = 0.0
    _latencies: list[float] = field(default_factory=list, repr=False)

    def record(self, alert: Alert) -> None:
        self.total_flows += 1
        self._latencies.append(alert.latency_ms)
        if alert.severity == "none":
            self.benign_filtered += 1
        elif alert.stage == "classifier":
            self.classifier_alerts += 1
        elif alert.stage == "autoencoder":
            self.autoencoder_alerts += 1
        if alert.severity == "medium":
            self.low_confidence += 1
        if self._latencies:
            self.mean_latency_ms = sum(self._latencies) / len(self._latencies)


class DetectionPipeline:
    """4-stage detection pipeline orchestrator."""

    def __init__(self, normalizer: Normalizer, stat: StatisticalFilter,
                 clf: AttackClassifier, ae: AutoencoderDetector) -> None:
        self.normalizer = normalizer
        self.stat = stat
        self.clf = clf
        self.ae = ae
        self.stats = PipelineStats()

    def detect(self, flow: dict) -> Alert:
        """Run one flow through all 4 stages.

        Args:
            flow: Raw flow record (column name → value).

        Returns:
            Alert with severity, type, confidence, and MITRE mapping.
        """
        t0 = time.perf_counter()

        # ── Stage 1: Feature extraction + normalization ──────────────────
        feats = extract_features(flow)
        x = self.normalizer.transform_one(feats)

        # ── Stage 2: Statistical filter ──────────────────────────────────
        if not self.stat.is_anomalous(x[0]):
            alert = Alert(severity="none", type="Benign",
                         note="passed statistical filter", stage="none")
            self._finish(alert, t0)
            self.stats.record(alert)
            return alert

        # Get top anomalous features for explainability
        top_feats = self.stat.top_anomalous_features(x[0], FEATURE_NAMES, top=5)

        # ── Stage 3: XGBoost classifier ──────────────────────────────────
        label, conf = self.clf.predict(x[0])
        if self.clf.is_confident_attack(label, conf):
            sev = "critical" if conf > 0.98 else "high"
            alert = Alert(
                severity=sev, type=label, confidence=conf,
                stage="classifier",
                mitre_techniques=map_alert_to_techniques(label),
                top_features=top_feats)
            self._finish(alert, t0)
            self.stats.record(alert)
            return alert

        # ── Stage 4: Autoencoder (zero-day) ──────────────────────────────
        is_zd, err = self.ae.is_zero_day(x[0])
        if is_zd:
            alert = Alert(
                severity="high", type="zero-day",
                anomaly_score=round(err, 4),
                stage="autoencoder",
                mitre_techniques=map_alert_to_techniques("zero-day"),
                top_features=top_feats)
            self._finish(alert, t0)
            self.stats.record(alert)
            return alert

        # ── Low-confidence known attack ──────────────────────────────────
        if label.lower() != "benign":
            alert = Alert(
                severity="medium", type=label, confidence=conf,
                stage="classifier",
                mitre_techniques=map_alert_to_techniques(label),
                top_features=top_feats)
            self._finish(alert, t0)
            self.stats.record(alert)
            return alert

        # ── Passed all stages ────────────────────────────────────────────
        alert = Alert(severity="low", type="Benign",
                     note="passed all stages", stage="none")
        self._finish(alert, t0)
        self.stats.record(alert)
        return alert

    def _create_classifier_alert(self, label: str, conf: float, orig_i: int, X_norm: np.ndarray, n: int, t0: float) -> Alert:
        sev = "critical" if conf > 0.98 else "high"
        top_feats = self.stat.top_anomalous_features(X_norm[orig_i], FEATURE_NAMES, top=5)
        a = Alert(
            severity=sev, type=label, confidence=float(conf),
            stage="classifier",
            mitre_techniques=map_alert_to_techniques(label),
            top_features=top_feats,
        )
        a.latency_ms = round(((time.perf_counter() - t0) / n) * 1000, 3)
        self.stats.record(a)
        return a

    def _process_autoencoder_batch(self, sub_orig_indices: list[int], stage4_sub_indices: list[int],
                                   labels: list[str], confs: list[float], X_norm: np.ndarray,
                                   alerts: list[Alert | None], n: int, t0: float) -> None:
        X_stage4 = X_norm[sub_orig_indices]
        ae_errors = self.ae.score_batch(X_stage4)

        for orig_i, err, sub_i in zip(sub_orig_indices, ae_errors, stage4_sub_indices):
            label, conf = labels[sub_i], confs[sub_i]
            top_feats = self.stat.top_anomalous_features(X_norm[orig_i], FEATURE_NAMES, top=5)
            is_zd = (self.ae.threshold is not None) and (err > self.ae.threshold)

            if is_zd:
                a = Alert(
                    severity="high", type="zero-day",
                    anomaly_score=round(float(err), 4),
                    stage="autoencoder",
                    mitre_techniques=map_alert_to_techniques("zero-day"),
                    top_features=top_feats,
                )
            elif label.lower() != "benign":
                a = Alert(
                    severity="medium", type=label, confidence=float(conf),
                    stage="classifier",
                    mitre_techniques=map_alert_to_techniques(label),
                    top_features=top_feats,
                )
            else:
                a = Alert(severity="low", type="Benign", note="passed all stages", stage="none")

            a.latency_ms = round(((time.perf_counter() - t0) / n) * 1000, 3)
            self.stats.record(a)
            alerts[orig_i] = a

    def detect_batch(self, flows: list[dict]) -> list[Alert]:
        """Run multiple flows through the pipeline in fully vectorized batches."""
        if not flows:
            return []

        t0 = time.perf_counter()
        n = len(flows)

        # 1. Matrix feature extraction & normalization
        from .features import extract_features_matrix
        X_raw = extract_features_matrix(flows)
        X_norm = self.normalizer.transform(X_raw)

        # 2. Stage 2 Z-score filter
        anom_mask = self.stat.filter_batch(X_norm)
        alerts: list[Alert | None] = [None] * n

        n_benign_passed = len(np.where(~anom_mask)[0])
        if n_benign_passed > 0:
            self.stats.total_flows += n_benign_passed
            self.stats.benign_filtered += n_benign_passed

        anom_indices = np.where(anom_mask)[0]
        if len(anom_indices) == 0:
            return [a for a in alerts if a is not None]

        X_anom = X_norm[anom_indices]

        # 3. Stage 3 XGBoost classification
        labels, confs = self.clf.predict_batch(X_anom)
        stage4_sub_indices = []

        for idx_in_anom, (orig_i, label, conf) in enumerate(zip(anom_indices, labels, confs)):
            if self.clf.is_confident_attack(label, conf):
                alerts[orig_i] = self._create_classifier_alert(label, conf, orig_i, X_norm, n, t0)
            else:
                stage4_sub_indices.append(idx_in_anom)

        if not stage4_sub_indices:
            for orig_i, label, conf in zip(anom_indices, labels, confs):
                if alerts[orig_i] is None:
                    top_feats = self.stat.top_anomalous_features(X_norm[orig_i], FEATURE_NAMES, top=5)
                    sev = "medium" if label.lower() != "benign" else "low"
                    a = Alert(
                        severity=sev, type=label, confidence=float(conf),
                        stage="classifier" if label.lower() != "benign" else "none",
                        mitre_techniques=map_alert_to_techniques(label) if label.lower() != "benign" else [],
                        top_features=top_feats,
                    )
                    a.latency_ms = round(((time.perf_counter() - t0) / n) * 1000, 3)
                    self.stats.record(a)
                    alerts[orig_i] = a
            return [a for a in alerts if a is not None]

        # 4. Stage 4 Autoencoder zero-day processing
        sub_orig_indices = [anom_indices[sub_i] for sub_i in stage4_sub_indices]
        self._process_autoencoder_batch(sub_orig_indices, stage4_sub_indices, labels, confs, X_norm, alerts, n, t0)

        return [a for a in alerts if a is not None]

    def get_stats(self) -> dict:
        """Return pipeline statistics as a dict."""
        s = self.stats
        drop_rate = (s.benign_filtered / max(s.total_flows, 1)) * 100
        return {
            "total_flows": s.total_flows,
            "benign_filtered": s.benign_filtered,
            "classifier_alerts": s.classifier_alerts,
            "autoencoder_alerts": s.autoencoder_alerts,
            "low_confidence": s.low_confidence,
            "mean_latency_ms": round(s.mean_latency_ms, 3),
            "drop_rate_pct": round(drop_rate, 1),
        }

    @staticmethod
    def _finish(alert: Alert, t0: float) -> Alert:
        alert.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return alert
