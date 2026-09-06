#!/usr/bin/env python3
"""Quick verification that all CyberGuard modules import correctly.
Run with:  python verify.py
"""
import os
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))

# Verification must prove a fresh database state. Keep all generated SQLite/key
# files outside the checkout and alive for the duration of this process only.
_verification_data = tempfile.TemporaryDirectory(prefix="cyberguard-verify-")
os.environ["CG_DB_PATH"] = str(
    Path(_verification_data.name) / "application-verification.sqlite"
)

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
    checks.append(("Independent statistical evidence", "PASS"))
except Exception as e:
    checks.append(("Independent statistical evidence", f"FAIL: {e}"))

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

# 6. Strict schema + Pipeline v2 classifier-first invariant
try:
    from backend.detection.input_schema import validate_records
    from backend.detection.pipeline import DetectionPipeline, PIPELINE_VERSION

    rejected, schema = validate_records([{"message": "failed login"}])
    assert rejected == [] and schema["supported"] is False

    class CountingClassifier:
        confidence_threshold = 0.9
        classes_ = ["Benign"]

        def __init__(self):
            self.rows = 0

        def predict_batch(self, matrix):
            self.rows += len(matrix)
            return np.array(["Benign"] * len(matrix)), np.full(len(matrix), 0.99)

    class QuietAutoencoder:
        threshold = 1e9

        def score_batch(self, matrix):
            return np.zeros(len(matrix))

    classifier = CountingClassifier()
    pipeline = DetectionPipeline(norm, sf, classifier, QuietAutoencoder())
    rows = [{name: 0.0 for name in FEATURE_NAMES} for _ in range(3)]
    assert len(pipeline.detect_batch(rows)) == classifier.rows == 3
    assert PIPELINE_VERSION == "cyberguard-pipeline-v2"
    checks.append(("Strict schema + Pipeline v2 classifier-first", "PASS"))
except Exception as e:
    checks.append(("Strict schema + Pipeline v2", f"FAIL: {e}"))

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

# 8. MITRE snapshot -> isolated SQLite -> local RAG
mitre_stage_names = {
    "snapshot_validation": "MITRE snapshot validation",
    "sqlite_indexing": "MITRE SQLite indexing",
    "technique_count": "MITRE technique count + T1498 retrieval",
    "rag_retrieval": "MITRE RAG indexing + T1498 retrieval",
}
try:
    from backend.mitre.verification import verify_snapshot_index

    mitre = verify_snapshot_index(
        Path(_verification_data.name) / "mitre-verification.sqlite"
    )
    checks.extend([
        (
            f"MITRE snapshot validation (objects={mitre['snapshot_objects']})",
            "PASS",
        ),
        (f"MITRE SQLite indexing (indexed={mitre['sqlite_indexed']})", "PASS"),
        (
            "MITRE technique count + T1498 retrieval "
            f"(techniques={mitre['technique_count']})",
            "PASS",
        ),
        (
            f"MITRE RAG indexing + T1498 retrieval (indexed={mitre['rag_indexed']})",
            "PASS",
        ),
    ])
except Exception as e:
    failed_stage = getattr(e, "stage", "snapshot_validation")
    partial = getattr(e, "partial", {})
    completed = {
        "snapshot_validation": "snapshot_objects" in partial,
        "sqlite_indexing": "sqlite_indexed" in partial,
        "technique_count": "technique_count" in partial,
        "rag_retrieval": "rag_indexed" in partial,
    }
    failed_seen = False
    for stage, label in mitre_stage_names.items():
        if completed[stage]:
            checks.append((label, "PASS"))
        elif stage == failed_stage and not failed_seen:
            checks.append((label, f"FAIL: {e}"))
            failed_seen = True
        else:
            checks.append((label, "SKIP: prerequisite MITRE stage failed"))

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

# 15. Suricata Evidence Bridge
try:
    import io
    from backend.suricata.schema import SECURITY_EVENT_SCHEMA_VERSION, SURICATA_ADAPTER_VERSION
    from backend.suricata.parser import iter_eve_stream
    from backend.suricata.attack_extractor import validate_and_map_attack_metadata
    from backend.db.models import SecurityEventRecord, SecurityEventTechniqueMapping, SuricataIngestionRecord

    sample_eve = io.BytesIO(
        b'{"timestamp":"2026-08-30T12:00:00.000000+0000","event_type":"alert","src_ip":"192.168.1.10","src_port":4444,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2000001,"rev":1,"signature":"ET MALWARE Suspicious C2","category":"A Network Trojan was detected","severity":1,"metadata":{"mitre_technique_id":["T1071.001"],"mitre_tactic_id":["TA0011"]}}}\n'
    )
    items = list(iter_eve_stream(sample_eve, "eve.json", "suricata-verify", 1024*1024, 1000))
    assert len(items) == 1 and items[0].event is not None
    assert items[0].event.schema_version == SECURITY_EVENT_SCHEMA_VERSION
    assert items[0].event.adapter_version == SURICATA_ADAPTER_VERSION
    assert items[0].event.alert_signature_id == 2000001
    assert items[0].event.mitre_techniques[0].technique_id == "T1071.001"
    assert items[0].event.mitre_techniques[0].technique_observed is False
    assert items[0].event.mitre_techniques[0].rule_match_observed is True
    checks.append(("Suricata Evidence Bridge", "PASS"))
except Exception as e:
    checks.append(("Suricata Evidence Bridge", f"FAIL: {e}"))


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
failed = total - passed - skipped
print(f"\n{'=' * 60}")
print(
    f"  {passed}/{total} passed ({skipped} skipped, {failed} failed) "
    f"in {elapsed:.1f}s"
)
print(f"{'=' * 60}")

# This script is a required startup/CI gate.  A displayed FAIL must therefore
# also be observable by callers as a non-zero process status.
raise SystemExit(1 if failed else 0)
