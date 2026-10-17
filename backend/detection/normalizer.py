"""Stage 1b — RobustScaler normalization.

RobustScaler uses median/IQR, so outliers (attacks) are not squashed the way
StandardScaler would squash them — exactly what we want for anomaly detection.
This ensures the Z-score filter and autoencoder see meaningful distributions.

Thesis fix: the original thesis fed raw text to an LLM. We compute proper
numeric features and normalize them for statistical analysis.
"""
from __future__ import annotations
import logging
import joblib
from pathlib import Path
import numpy as np
from sklearn.preprocessing import RobustScaler
from .features import FEATURE_NAMES

log = logging.getLogger("cyberguard.normalizer")

VOLUMETRIC_FEATURE_NAMES = (
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "packets_per_sec",
    "bytes_per_sec",
    "fwd_header_len",
    "bwd_header_len",
)

VOLUMETRIC_INDICES = tuple(
    i for i, name in enumerate(FEATURE_NAMES) if name in VOLUMETRIC_FEATURE_NAMES
)


def apply_log1p_volumetric(X: np.ndarray, indices: tuple[int, ...] = VOLUMETRIC_INDICES) -> np.ndarray:
    """Apply safe signed log1p transform to heavy-tailed volumetric feature columns."""
    X_out = np.array(X, dtype=float, copy=True)
    if X_out.ndim == 1:
        X_out = X_out.reshape(1, -1)
    for idx in indices:
        if idx < X_out.shape[1]:
            col = X_out[:, idx]
            X_out[:, idx] = np.sign(col) * np.log1p(np.abs(col))
    return X_out


class Normalizer:
    """RobustScaler wrapper with save/load and safety checks."""

    def __init__(self, log_transform_skewed: bool = False) -> None:
        self.scaler = RobustScaler()
        self.fitted = False
        self.n_features = len(FEATURE_NAMES)
        self.log_transform_skewed = log_transform_skewed

    def _preprocess(self, X: np.ndarray) -> np.ndarray:
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        if self.log_transform_skewed:
            X = apply_log1p_volumetric(X)
        return X

    def fit(self, X: np.ndarray) -> "Normalizer":
        """Fit the scaler on training data (should be mostly benign)."""
        X_proc = self._preprocess(X)
        self.scaler.fit(X_proc)
        self.n_features = X.shape[1]
        self.fitted = True
        log.info(
            "Normalizer fitted on %d samples × %d features (log_transform_skewed=%s)",
            X.shape[0], X.shape[1], self.log_transform_skewed,
        )
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform feature matrix using fitted scaler."""
        if not self.fitted:
            raise RuntimeError("Normalizer not fitted — run trainer.py first")
        X_proc = self._preprocess(X)
        transformed = self.scaler.transform(X_proc)
        transformed = np.nan_to_num(
            transformed, nan=0.0, posinf=1e6, neginf=-1e6
        )
        return np.clip(transformed, -1e6, 1e6)

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit and transform in one step."""
        self.fit(X)
        return self.transform(X)

    def transform_one(self, features: dict[str, float]) -> np.ndarray:
        """Transform a single flow's feature dict into a normalized 1×N array."""
        row = np.array([[features.get(n, 0.0) for n in FEATURE_NAMES]], dtype=float)
        return self.transform(row)

    def save(self, path: str | Path) -> None:
        """Persist the fitted scaler to disk."""
        joblib.dump({
            "scaler": self.scaler,
            "n_features": self.n_features,
            "log_transform_skewed": self.log_transform_skewed,
        }, path)
        log.info("Normalizer saved to %s", path)

    def load(self, path: str | Path) -> "Normalizer":
        """Load a previously fitted scaler from disk."""
        data = joblib.load(path)
        if isinstance(data, dict):
            self.scaler = data["scaler"]
            self.n_features = data.get("n_features", len(FEATURE_NAMES))
            self.log_transform_skewed = data.get("log_transform_skewed", False)
        else:
            # backward compat: older saves might just be the scaler
            self.scaler = data
            self.n_features = len(FEATURE_NAMES)
            self.log_transform_skewed = False
        self.fitted = True
        log.info("Normalizer loaded from %s (log_transform_skewed=%s)", path, self.log_transform_skewed)
        return self

