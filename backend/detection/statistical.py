"""Independent Z-score anomaly evidence for Pipeline v2.

CPU-only and vectorized. It learns a benign reference distribution and emits
per-feature/max scores. Routing consumes this evidence after every row has
already reached the classifier; it is no longer a benign fast-exit gate.

Throughput is workload- and hardware-dependent and must be measured at runtime.

Thesis fix #1: The thesis used an LLM to read each log (~2-5 sec/log).
This vectorized filter is designed for high-throughput CPU processing.
"""
from __future__ import annotations
import logging
import numpy as np
from pathlib import Path
import joblib

log = logging.getLogger("cyberguard.statistical")


class StatisticalFilter:
    """Fast, interpretable Z-score evidence scorer for every validated row."""

    def __init__(self, threshold: float = 3.0) -> None:
        self.threshold = threshold
        self.mean_: np.ndarray | None = None
        self.std_: np.ndarray | None = None
        self.fitted = False

    def fit(self, X_benign: np.ndarray) -> "StatisticalFilter":
        """Compute per-feature mean and std from clean baseline traffic.

        Args:
            X_benign: Feature matrix of BENIGN-only flows (normalized).
        """
        self.mean_ = X_benign.mean(axis=0)
        std = X_benign.std(axis=0)
        std[std == 0] = 1e-9  # avoid div-by-zero on constant features
        self.std_ = std
        self.fitted = True
        log.info("Statistical filter fitted on %d benign samples (threshold=%.1f)",
                 X_benign.shape[0], self.threshold)
        return self

    def _z(self, X: np.ndarray) -> np.ndarray:
        if self.mean_ is None or self.std_ is None:
            raise RuntimeError("statistical filter is not fitted")
        z = np.abs((X - self.mean_) / self.std_)
        return np.clip(np.nan_to_num(z, nan=0.0, posinf=1e12), 0.0, 1e12)

    def is_anomalous(self, x: np.ndarray) -> bool:
        """Single flow → whether statistical anomaly evidence is present.

        Args:
            x: 1D normalized feature vector.
        """
        return bool(self._z(x).max() > self.threshold)

    def z_scores(self, x: np.ndarray) -> np.ndarray:
        """Return per-feature Z-scores for explainability.

        The dashboard uses this to show which features triggered the alert.
        """
        return self._z(x)

    def top_anomalous_features(self, x: np.ndarray, feature_names: list[str],
                                top: int = 5) -> list[tuple[str, float]]:
        """Return the top-N most anomalous features for a given flow.

        Args:
            x: 1D normalized feature vector.
            feature_names: List of feature names matching the vector.
            top: Number of top features to return.
        """
        zs = self.z_scores(x)
        order = np.argsort(zs)[::-1][:top]
        return [(feature_names[i], float(zs[i])) for i in order]

    def filter_batch(self, X: np.ndarray) -> np.ndarray:
        """Vectorized boolean anomaly evidence (never a routing fast-exit).

        Args:
            X: 2D feature matrix (N × features).

        Returns:
            Boolean array of length N. True = statistical anomaly evidence.
        """
        return self._z(X).max(axis=1) > self.threshold

    def z_scores_batch(self, X: np.ndarray) -> np.ndarray:
        """Return the bounded per-feature evidence matrix for a batch."""
        return self._z(X)

    def max_z_scores(self, X: np.ndarray) -> np.ndarray:
        """Return max Z-score per sample (for scoring/ranking)."""
        return self._z(X).max(axis=1)

    def save(self, path: str | Path) -> None:
        """Persist filter parameters to disk."""
        joblib.dump({"mean": self.mean_, "std": self.std_,
                     "threshold": self.threshold}, path)
        log.info("Statistical filter saved to %s", path)

    def load(self, path: str | Path) -> "StatisticalFilter":
        """Load filter parameters from disk."""
        d = joblib.load(path)
        self.mean_, self.std_, self.threshold = d["mean"], d["std"], d["threshold"]
        self.fitted = True
        log.info("Statistical filter loaded from %s", path)
        return self
