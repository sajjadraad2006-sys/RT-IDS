#!/usr/bin/env python3
"""Quick verification that all CyberGuard modules import correctly.
Run with:  python verify.py
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))

t_start = time.perf_counter()

print("=" * 60)
print("CyberGuard Module Verification")
print("=" * 60)

checks = []
N_FEATURES = 32  # Updated: 7+7+6+6+2+4 = 32 features

# 1. Features
try:
    from backend.detection.features import extract_features, FEATURE_NAMES
    out = extract_features({"Flow Duration": "120000", "SYN Flag Count": "2"})
    assert len(out) == len(FEATURE_NAMES) == N_FEATURES, f"Expected {N_FEATURES}, got {len(out)}"
    assert out["flow_duration"] == 120000.0
    assert "flow_bytes_ratio" in out, "Missing flow_bytes_ratio feature"
    assert "flow_iat_max" in out, "Missing flow_iat_max feature"
    checks.append((f"Stage 1: Features ({N_FEATURES} features)", "PASS"))
except Exception as e:
    checks.append(("Stage 1: Features", f"FAIL: {e}"))

# 2. Normalizer
try:
    import numpy as np
    from backend.detection.normalizer import Normalizer
    norm = Normalizer().fit(np.random.randn(100, N_FEATURES))
    assert norm.fitted
    checks.append(("Stage 1b: Normalizer", "PASS"))
except Exception as e:
    checks.append(("Stage 1b: Normalizer", f"FAIL: {e}"))

# 3. Statistical Filter
try:
    from backend.detection.statistical import StatisticalFilter
    sf = StatisticalFilter(threshold=3.0).fit(np.random.randn(100, N_FEATURES))
    assert sf.fitted
    checks.append(("Stage 2: Z-Score Filter", "PASS"))
except Exception as e:
    checks.append(("Stage 2: Z-Score Filter", f"FAIL: {e}"))

# 4. Classifier
try:
    from backend.detection.classifier import AttackClassifier
    rng = np.random.default_rng(42)
    X = np.vstack([rng.normal(0, 0.3, size=(80, N_FEATURES)), rng.normal(4, 0.3, size=(20, N_FEATURES))])
    y = np.array(["Benign"]*80 + ["DDoS"]*20)
    clf = AttackClassifier().fit(X, y)
    label, conf = clf.predict(rng.normal(4, 0.3, size=(N_FEATURES,)))
    assert label == "DDoS" and conf > 0.5
    imp = clf.feature_importance(5)
    assert len(imp) >= 1, "Feature importance should return results"
    checks.append(("Stage 3: XGBoost Classifier", "PASS"))
except Exception as e:
    checks.append(("Stage 3: XGBoost Classifier", f"FAIL: {e}"))

# 5. Autoencoder
try:
    from backend.detection.autoencoder import AutoencoderDetector
    ae = AutoencoderDetector(n_features=N_FEATURES, k=3.0)
    ae.fit(np.random.randn(500, N_FEATURES), np.random.randn(100, N_FEATURES), epochs=2, batch=64)
    assert ae.threshold is not None and ae.threshold > 0
    checks.append(("Stage 4: Deep Autoencoder", "PASS"))
except Exception as e:
    checks.append(("Stage 4: Deep Autoencoder", f"FAIL: {e}"))

# 6. Pipeline
try:
    from backend.detection.pipeline import DetectionPipeline, Alert, PipelineStats
    checks.append(("Pipeline import", "PASS"))
except Exception as e:
    checks.append(("Pipeline import", f"FAIL: {e}"))

# 7. MITRE mapper (bidirectional)
try:
    from backend.mitre.mapper import map_alert_to_techniques, map_technique_to_labels, get_all_mapped_techniques
    t = map_alert_to_techniques("DDoS")
    assert "T1498" in t
    labels = map_technique_to_labels("T1498")
    assert "DDoS" in labels
    all_techs = get_all_mapped_techniques()
    assert len(all_techs) >= 15, f"Expected ≥15 mapped techniques, got {len(all_techs)}"
    checks.append((f"MITRE Mapper ({len(all_techs)} techniques mapped)", "PASS"))
except Exception as e:
    checks.append(("MITRE Mapper", f"FAIL: {e}"))

# 8. MITRE attack_db
try:
    from backend.mitre.attack_db import init, get_stats
    init()
    stats = get_stats()
    checks.append((f"MITRE Attack DB (techniques={stats.get('techniques', 0)})", "PASS"))
except Exception as e:
    checks.append(("MITRE Attack DB", f"FAIL: {e}"))

# 9. LLM provider
try:
    from backend.llm.provider import get_provider
    from backend.llm.local_client import LocalClient
    from backend.llm.api_client import ApiClient
    p = get_provider({"llm_provider": "local"})
    assert isinstance(p, LocalClient)
    p2 = get_provider({"llm_provider": "api"})
    assert isinstance(p2, ApiClient)
    checks.append(("LLM Provider Switch", "PASS"))
except Exception as e:
    checks.append(("LLM Provider Switch", f"FAIL: {e}"))

# 10. LLM Prompts
try:
    from backend.llm.prompts import SYSTEM_ANALYST, explain_alert, threat_briefing, ioc_extraction
    msgs = explain_alert({"type": "DDoS", "severity": "critical"}, "T1498 context")
    assert len(msgs) == 2 and msgs[0]["role"] == "system"
    checks.append(("LLM Prompts", "PASS"))
except Exception as e:
    checks.append(("LLM Prompts", f"FAIL: {e}"))

# 11. Config
try:
    from backend.config import BASE_DIR, DATA_DIR, TRAINED_DIR, CLASSES
    assert BASE_DIR.exists()
    assert len(CLASSES) == 8, f"Expected 8 attack classes, got {len(CLASSES)}"
    checks.append(("Config + Paths", "PASS"))
except Exception as e:
    checks.append(("Config + Paths", f"FAIL: {e}"))

# 12. DB Models
try:
    from backend.db.models import AlertRecord, Setting, ChatMessage, DecisionCase
    from backend.decision.engine import build_smart_log, policy_decision
    checks.append(("DB Models + Smart Decision", "PASS"))
except Exception as e:
    checks.append(("DB Models + Smart Decision", f"FAIL: {e}"))

# 13. Frontend files
try:
    fe = BASE_DIR / "frontend"
    assert (fe / "index.html").exists()
    assert (fe / "css" / "style.css").exists()
    js_files = list((fe / "js").glob("*.js"))
    assert len(js_files) >= 7
    checks.append((f"Frontend ({len(js_files)} JS files)", "PASS"))
except Exception as e:
    checks.append(("Frontend files", f"FAIL: {e}"))

# 14. Trained model integrity and operational mode
try:
    from backend.detection.integrity import (
        validate_artifact_bundle, validate_dataset_manifest,
    )
    artifact_meta = validate_artifact_bundle(TRAINED_DIR)
    mode = "production" if artifact_meta.get("production_approved") else "evaluation-only"
    checks.append((f"Artifact integrity ({mode})", "PASS"))
    datasets = validate_dataset_manifest(
        BASE_DIR / "cyberguard/datasets/manifest.json", BASE_DIR
    )
    assert datasets and all(not item["training_approved"] for item in datasets)
    checks.append((f"Dataset manifest ({len(datasets)} fixtures, 0 production)", "PASS"))
except Exception as e:
    checks.append(("Data/model integrity", f"FAIL: {e}"))

elapsed = time.perf_counter() - t_start

print()
for name, status in checks:
    if status == "PASS":
        icon = "✓"
    elif status.startswith("SKIP"):
        icon = "○"
    else:
        icon = "✗"
    print(f"  [{icon}] {name}: {status}")

passed = sum(1 for _, s in checks if s == "PASS")
skipped = sum(1 for _, s in checks if s.startswith("SKIP"))
total = len(checks)
print(f"\n{'=' * 60}")
print(f"  {passed}/{total} passed ({skipped} skipped) in {elapsed:.1f}s")
print(f"{'=' * 60}")
