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


class Normalizer:
    """RobustScaler wrapper with save/load and safety checks."""

    def __init__(self) -> None:
        self.scaler = RobustScaler()
        self.fitted = False
        self.n_features = len(FEATURE_NAMES)

    def fit(self, X: np.ndarray) -> "Normalizer":
        """Fit the scaler on training data (should be mostly benign)."""
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        self.scaler.fit(X)
        self.n_features = X.shape[1]
        self.fitted = True
        log.info("Normalizer fitted on %d samples × %d features", X.shape[0], X.shape[1])
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Transform feature matrix using fitted scaler."""
        if not self.fitted:
            raise RuntimeError("Normalizer not fitted — run trainer.py first")
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        return self.scaler.transform(X)

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
        joblib.dump({"scaler": self.scaler, "n_features": self.n_features}, path)
        log.info("Normalizer saved to %s", path)

    def load(self, path: str | Path) -> "Normalizer":
        """Load a previously fitted scaler from disk."""
        data = joblib.load(path)
        if isinstance(data, dict):
            self.scaler = data["scaler"]
            self.n_features = data.get("n_features", len(FEATURE_NAMES))
        else:
            # backward compat: older saves might just be the scaler
            self.scaler = data
            self.n_features = len(FEATURE_NAMES)
        self.fitted = True
        log.info("Normalizer loaded from %s", path)
        return self
