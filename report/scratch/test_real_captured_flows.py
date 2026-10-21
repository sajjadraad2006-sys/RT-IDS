"""Test candidate-real-v1 pipeline against REAL attacker flows extracted from CSE-CIC-IDS2018."""
import sys
from pathlib import Path
import numpy as np
import json

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from backend.detection.normalizer import Normalizer
from backend.detection.statistical import StatisticalFilter
from backend.detection.classifier import AttackClassifier
from backend.detection.autoencoder import AutoencoderDetector
from backend.detection.pipeline import DetectionPipeline
from backend.detection.features import FEATURE_NAMES
from backend.detection.integrity import validate_artifact_bundle
from backend.mitre.semantic_rag import default_semantic_rag
from backend.safety.formal_verifier import default_safety_verifier

CANDIDATE_DIR = BASE_DIR / "data" / "models" / "candidates" / "candidate-real-v1"
DERIVED_DIR = BASE_DIR / "data" / "datasets" / "cse-cic-ids2018" / "derived"

def load_pipe():
    metadata = validate_artifact_bundle(CANDIDATE_DIR)
    norm = Normalizer().load(CANDIDATE_DIR / "normalizer.pkl")
    stat = StatisticalFilter().load(CANDIDATE_DIR / "statistical.pkl")
    clf = AttackClassifier(confidence_threshold=metadata["classifier"]["abstention_threshold"]).load(
        CANDIDATE_DIR / "classifier.pkl"
    )
    ae = AutoencoderDetector(len(FEATURE_NAMES)).load(CANDIDATE_DIR / "autoencoder.pt")
    return DetectionPipeline(norm, stat, clf, ae, artifact_metadata=metadata)

def test_real_flows():
    pipe = load_pipe()
    print("=" * 80)
    print(" 🎯 TESTING PIPELINE ON 100% REAL TRAFFIC FLOWS EXTRACTED FROM CSE-CIC-IDS2018")
    print("=" * 80)

    # 1. Real WebAttacks (Friday-23-02-2018)
    f23 = np.load(DERIVED_DIR / "Friday-23-02-2018_TrafficForML_CICFlowMeter.npz")
    web_indices = np.where(f23["y"] == "WebAttack")[0]
    benign_indices = np.where(f23["y"] == "Benign")[0]
    
    # 2. Real DoS (Friday-16-02-2018)
    f16 = np.load(DERIVED_DIR / "Friday-16-02-2018_TrafficForML_CICFlowMeter.npz")
    dos_indices = np.where(f16["y"] == "DoS")[0]

    # 3. Real DDoS / OOD Zero-day (Wednesday-21-02-2018)
    f21 = np.load(DERIVED_DIR / "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.npz")
    ddos_indices = np.where(f21["y"] == "DDoS")[0]

    # Sample representative flows
    samples = [
        ("Real WebAttack #1 (SQL Injection / XSS)", f23["X"][web_indices[10]], "WebAttack", "198.51.100.25"),
        ("Real WebAttack #2 (Brute Force Web)", f23["X"][web_indices[50]], "WebAttack", "198.51.100.26"),
        ("Real WebAttack #3 (SQL Injection)", f23["X"][web_indices[100]], "WebAttack", "198.51.100.27"),
        ("Real DoS #1 (DoS-SlowHTTPTest / Hulk)", f16["X"][dos_indices[15]], "DoS", "203.0.113.11"),
        ("Real DoS #2 (DoS-Slowloris)", f16["X"][dos_indices[250]], "DoS", "203.0.113.12"),
        ("Real Benign User #1 (Normal Workstation)", f23["X"][benign_indices[500]], "Benign", "192.168.1.102"),
        ("Real Benign User #2 (Web Portal Browsing)", f23["X"][benign_indices[2500]], "Benign", "192.168.1.103"),
        ("Real Zero-Day OOD Attack (DDoS-LOIC Flood)", f21["X"][ddos_indices[100]], "DDoS (Zero-Day OOD)", "185.220.101.5"),
    ]

    for title, row_vec, truth, src_ip in samples:
        flow_dict = {name: float(val) for name, val in zip(FEATURE_NAMES, row_vec)}
        alert = pipe.detect(flow_dict)
        
        # Test D3FEND Countermeasures & MITRE ATT&CK
        playbook = default_semantic_rag.retrieve_defense_playbook(
            label=alert.type,
            techniques=alert.mitre_techniques,
            telemetry={"src_ip": src_ip}
        )
        
        # Formal Safety Verification
        rec_action = "block_ip" if alert.route == "known_attack" else "observe"
        safety_check = default_safety_verifier.verify_and_sign(
            action=rec_action,
            target=src_ip,
            severity=alert.severity,
            confidence=alert.confidence
        )

        print(f"\n▶ {title}")
        print(f"  • Ground Truth:       {truth}")
        print(f"  • ML Classification:  {alert.type} (Confidence: {alert.confidence*100:.2f}%)")
        print(f"  • Decision Route:     {alert.stage} -> [{alert.route}]")
        print(f"  • MITRE ATT&CK:       {alert.mitre_techniques or 'None (Benign)'}")
        print(f"  • D3FEND Measures:    {[c['id'] + ': ' + c['name'] for c in playbook.get('countermeasures', [])[:2]]}")
        print(f"  • Autonomous Defense: Action: {rec_action} | Formally Admitted: {safety_check.admitted}")
        print("  " + "-" * 76)

if __name__ == "__main__":
    test_real_flows()
