"""
Layer 4 / Stage 3-4: Isolation Forest Anomaly Detector
Unsupervised outlier scoring for network flow traffic.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Tuple

class IsolationForestDetector:
    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray):
        """Fit Isolation Forest model on feature matrix."""
        print(f"[+] Fitting Isolation Forest detector (contamination={self.contamination})...")
        self.model.fit(X)
        self.is_fitted = True
        print("[✓] Isolation Forest training complete.")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies using fitted Isolation Forest.
        Returns:
            is_anomaly: Boolean mask (True for anomaly, False for benign)
            scores: Raw anomaly scores (lower/more negative = more anomalous)
        """
        if not self.is_fitted:
            self.fit(X)
            
        preds = self.model.predict(X)
        is_anomaly = preds == -1
        
        # decision_function: lower means more anomalous
        raw_scores = self.model.decision_function(X)
        # Normalize score to 0..1 confidence (higher = more anomalous)
        anomaly_confidence = 1.0 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-8)
        
        return is_anomaly, anomaly_confidence
