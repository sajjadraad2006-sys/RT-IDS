"""
Layer 4: Integrated Detection Pipeline Manager
Coordinates data ingestion, feature normalization, statistical filtering,
machine learning anomaly detection, and MITRE ATT&CK evidence mapping.
"""

import pandas as pd
from typing import Dict, List, Any
from cyberguard.layer2_normalize.feature_extractor import FeatureExtractor
from cyberguard.layer4_ml.statistical_filter import StatisticalFilter
from cyberguard.layer4_ml.isolation_forest import IsolationForestDetector

class CyberGuardPipeline:
    def __init__(self, z_threshold: float = 3.0, contamination: float = 0.05):
        self.extractor = FeatureExtractor(target_col="Label")
        self.stat_filter = StatisticalFilter(z_threshold=z_threshold)
        self.iso_detector = IsolationForestDetector(contamination=contamination)
        self.is_trained = False

    def train_baseline(self, baseline_df: pd.DataFrame):
        """Train pipeline models on baseline traffic data."""
        print("[+] Training CyberGuard multi-stage pipeline on baseline data...")
        X_scaled, _, _ = self.extractor.fit_transform(baseline_df)
        self.stat_filter.fit(X_scaled)
        self.iso_detector.fit(X_scaled)
        self.is_trained = True
        print("[✓] Pipeline baseline training completed successfully.")

    def analyze_dataframe(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Run multi-stage detection pipeline on input traffic dataframe."""
        if not self.is_trained:
            self.train_baseline(df)
            
        X_scaled, y_labels = self.extractor.transform(df)
        is_stat_anom, z_scores = self.stat_filter.predict(X_scaled)
        is_iso_anom, iso_conf = self.iso_detector.predict(X_scaled)
        
        alerts = []
        for i in range(len(df)):
            is_anomalous = is_stat_anom[i] or is_iso_anom[i]
            
            # Determine alert severity
            if is_stat_anom[i] and is_iso_anom[i]:
                severity = "HIGH"
            elif is_iso_anom[i]:
                severity = "MEDIUM"
            elif is_stat_anom[i]:
                severity = "LOW"
            else:
                severity = "BENIGN"
                
            alert_entry = {
                "record_id": i + 1,
                "label": y_labels[i] if y_labels is not None else "Unknown",
                "severity": severity,
                "is_anomalous": is_anomalous,
                "z_score": float(z_scores[i]),
                "anomaly_confidence": float(iso_conf[i]),
                "stat_flag": bool(is_stat_anom[i]),
                "ml_flag": bool(is_iso_anom[i])
            }
            alerts.append(alert_entry)
            
        return alerts
