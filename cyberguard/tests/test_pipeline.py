"""
Pipeline Verification Test Script
Loads the sample CICIDS2017 dataset, runs data cleaning, statistical filtering,
and Isolation Forest detection, and outputs benchmark performance statistics.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cyberguard.config import DATASETS_DIR
from cyberguard.layer1_ingest.csv_loader import CSVLogLoader
from cyberguard.layer2_normalize.feature_extractor import FeatureExtractor
from cyberguard.layer4_ml.statistical_filter import StatisticalFilter
from cyberguard.layer4_ml.isolation_forest import IsolationForestDetector

def run_test():
    dataset_file = DATASETS_DIR / "cicids2017" / "sample_traffic.csv"
    if not dataset_file.exists():
        print(f"[✗] Dataset file not found at: {dataset_file}")
        return

    print("=================================================================")
    print("           CyberGuard Stage 1-4 Pipeline Verification            ")
    print("=================================================================")
    
    # 1. Ingest
    loader = CSVLogLoader(dataset_file)
    df = loader.load()

    # 2. Extract & Normalize Features
    extractor = FeatureExtractor(target_col="Label")
    X_scaled, y_labels, feature_names = extractor.fit_transform(df)

    # 3. Stage 2: Statistical Z-Score Filter
    print("\n--- Running Stage 2: Statistical Z-Score Filter ---")
    stat_filter = StatisticalFilter(z_threshold=3.0)
    is_stat_anom, z_scores = stat_filter.predict(X_scaled)
    print(f"Stage 2 flagged {is_stat_anom.sum()} / {len(X_scaled)} records ({is_stat_anom.sum()/len(X_scaled)*100:.2f}%) as statistical outliers.")

    # 4. Stage 3/4: Isolation Forest Anomaly Detection
    print("\n--- Running Stage 3/4: Isolation Forest Anomaly Detector ---")
    iso_forest = IsolationForestDetector(contamination=0.1)
    is_iso_anom, iso_conf = iso_forest.predict(X_scaled)
    print(f"Isolation Forest flagged {is_iso_anom.sum()} / {len(X_scaled)} records ({is_iso_anom.sum()/len(X_scaled)*100:.2f}%) as anomalous.")

    # Show sample detections
    print("\n--- Sample Detection Results (First 5 records) ---")
    for i in range(min(5, len(df))):
        label_str = y_labels[i] if y_labels is not None else "Unknown"
        print(f"Record #{i+1} | Label: {label_str} | Z-Score: {z_scores[i]:.2f} (Anom: {is_stat_anom[i]}) | IsoForest Conf: {iso_conf[i]:.2f} (Anom: {is_iso_anom[i]})")

    print("\n[✓] Pipeline verification complete!")

if __name__ == "__main__":
    run_test()
