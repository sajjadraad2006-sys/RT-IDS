"""
Layer 4 / Stage 2: Statistical Outlier Filter (Z-Score)
Fast CPU-based filtering of normal traffic before deep inspection.
"""

import numpy as np
from typing import Tuple

class StatisticalFilter:
    def __init__(self, z_threshold: float = 3.0):
        self.z_threshold = z_threshold
        self.mean: np.ndarray = None
        self.std: np.ndarray = None
        self.is_fitted = False

    def fit(self, X: np.ndarray):
        """Compute mean and std from clean baseline traffic."""
        self.mean = np.mean(X, axis=0)
        self.std = np.std(X, axis=0)
        # Avoid division by zero
        self.std[self.std == 0] = 1e-6
        self.is_fitted = True
        print(f"[✓] Statistical filter fitted on {X.shape[0]} baseline samples.")

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Calculate maximum Z-score per sample across all features.
        Returns:
            is_anomalous: Boolean mask array (True if maximum Z-score > threshold)
            max_z_scores: Maximum Z-score for each sample
        """
        if not self.is_fitted:
            # If not fitted yet, auto-fit on input
            self.fit(X)
            
        z_scores = np.abs((X - self.mean) / self.std)
        max_z_scores = np.max(z_scores, axis=1)
        is_anomalous = max_z_scores > self.z_threshold
        
        return is_anomalous, max_z_scores
