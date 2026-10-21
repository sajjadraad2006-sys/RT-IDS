"""Test diverse realistic attack scenarios against candidate-real-v1 pipeline."""
import sys
from pathlib import Path
import json
import numpy as np

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
from backend.detection.features import FEATURE_NAMES, extract_features
from backend.detection.integrity import validate_artifact_bundle
from backend.decision.engine import build_smart_log, policy_decision
from backend.db.models import AlertRecord
from backend.mitre.semantic_rag import default_semantic_rag
from backend.mitre.defense_rag import default_defense_rag
from backend.safety.formal_verifier import default_safety_verifier

CANDIDATE_DIR = BASE_DIR / "data" / "models" / "candidates" / "candidate-real-v1"

def load_candidate_pipeline():
    metadata = validate_artifact_bundle(CANDIDATE_DIR)
    norm = Normalizer().load(CANDIDATE_DIR / "normalizer.pkl")
    stat = StatisticalFilter().load(CANDIDATE_DIR / "statistical.pkl")
    clf = AttackClassifier(confidence_threshold=metadata["classifier"]["abstention_threshold"]).load(
        CANDIDATE_DIR / "classifier.pkl"
    )
    ae = AutoencoderDetector(len(FEATURE_NAMES)).load(CANDIDATE_DIR / "autoencoder.pt")
    pipe = DetectionPipeline(norm, stat, clf, ae, artifact_metadata=metadata)
    return pipe

def make_flow(duration_sec, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes,
              syn=0, ack=0, rst=0, fin=0, psh=0, urg=0,
              win_fwd=64240, win_bwd=29200,
              pkt_len_mean=0, pkt_len_std=0, pkt_len_max=0, pkt_len_min=0,
              flow_iat_mean=0, fwd_iat_mean=0):
    flow = {
        "flow_duration": duration_sec * 1e6,
        "total_fwd_packets": fwd_pkts,
        "total_bwd_packets": bwd_pkts,
        "total_fwd_bytes": fwd_bytes,
        "total_bwd_bytes": bwd_bytes,
        "packets_per_sec": (fwd_pkts + bwd_pkts) / max(duration_sec, 1e-6),
        "bytes_per_sec": (fwd_bytes + bwd_bytes) / max(duration_sec, 1e-6),
        "fwd_packet_length_mean": fwd_bytes / max(fwd_pkts, 1),
        "bwd_packet_length_mean": bwd_bytes / max(bwd_pkts, 1),
        "packet_length_mean": pkt_len_mean or (fwd_bytes + bwd_bytes) / max(fwd_pkts + bwd_pkts, 1),
        "packet_length_std": pkt_len_std,
        "packet_length_max": pkt_len_max or max(fwd_bytes / max(fwd_pkts, 1), bwd_bytes / max(bwd_pkts, 1)),
        "packet_length_min": pkt_len_min,
        "avg_pkt_size": (fwd_bytes + bwd_bytes) / max(fwd_pkts + bwd_pkts, 1),
        "syn_flag_count": syn,
        "ack_flag_count": ack,
        "rst_flag_count": rst,
        "fin_flag_count": fin,
        "psh_flag_count": psh,
        "urg_flag_count": urg,
        "init_win_bytes_fwd": win_fwd,
        "init_win_bytes_bwd": win_bwd,
        "flow_iat_mean": flow_iat_mean or ((duration_sec * 1e6) / max(fwd_pkts + bwd_pkts, 1)),
        "flow_iat_std": (flow_iat_mean or ((duration_sec * 1e6) / max(fwd_pkts + bwd_pkts, 1))) * 0.4,
        "flow_iat_max": (duration_sec * 1e6) * 0.8,
        "fwd_iat_mean": fwd_iat_mean or ((duration_sec * 1e6) / max(fwd_pkts, 1)),
        "fwd_header_len": fwd_pkts * 32,
        "bwd_header_len": bwd_pkts * 32,
        "down_up_ratio": bwd_pkts / max(fwd_pkts, 1),
        "flow_bytes_ratio": fwd_bytes / max(fwd_bytes + bwd_bytes, 1),
        "active_mean": (duration_sec * 1e6) * 0.9,
        "idle_mean": 0.0,
    }
    return flow

def run_tests():
    pipe = load_candidate_pipeline()
    print("================================================================================")
    print(" 🚀 REAL ATTACK SCENARIO STRESS TEST & VALIDATION (CANDIDATE-REAL-V1)")
    print("================================================================================")
    
    scenarios = [
        # 1. Normal Legitimate User
        {
            "name": "1. Normal Legitimate Web Browsing (Chrome / HTTPS)",
            "ground_truth": "Benign",
            "flow": make_flow(
                duration_sec=2.4, fwd_pkts=12, bwd_pkts=18, fwd_bytes=1420, bwd_bytes=42800,
                syn=1, ack=28, fin=2, psh=6, win_fwd=64240, win_bwd=29200,
                pkt_len_mean=1474, pkt_len_std=480, pkt_len_max=1514, pkt_len_min=54,
                flow_iat_mean=80000, fwd_iat_mean=190000
            ),
            "ip": "192.168.1.105",
        },
        # 2. Heavy User (4K Streaming / Large ISO Download)
        {
            "name": "2. Heavy Legitimate User (Large File Download / Video Stream)",
            "ground_truth": "Benign",
            "flow": make_flow(
                duration_sec=18.5, fwd_pkts=450, bwd_pkts=1800, fwd_bytes=32000, bwd_bytes=2480000,
                syn=1, ack=2200, fin=2, psh=85, win_fwd=64240, win_bwd=65535,
                pkt_len_mean=1116, pkt_len_std=610, pkt_len_max=1514, pkt_len_min=54,
                flow_iat_mean=8200, fwd_iat_mean=41000
            ),
            "ip": "192.168.1.150",
        },
        # 3. Web SQL Injection (Sqlmap / Automated Payload Injector)
        {
            "name": "3. Web Application Attack: SQL Injection & Admin Password Extraction",
            "ground_truth": "WebAttack",
            "flow": make_flow(
                duration_sec=0.45, fwd_pkts=48, bwd_pkts=22, fwd_bytes=18400, bwd_bytes=4600,
                syn=1, ack=68, rst=4, psh=42, win_fwd=512, win_bwd=29200,
                pkt_len_mean=328, pkt_len_std=210, pkt_len_max=1280, pkt_len_min=64,
                flow_iat_mean=6400, fwd_iat_mean=9300
            ),
            "ip": "198.51.100.18",
        },
        # 4. Web XSS & Brute Force Probing
        {
            "name": "4. Web Application Attack: XSS & Credential Stuffing / Brute Force",
            "ground_truth": "WebAttack",
            "flow": make_flow(
                duration_sec=0.82, fwd_pkts=64, bwd_pkts=30, fwd_bytes=24800, bwd_bytes=6200,
                syn=1, ack=90, rst=8, psh=58, win_fwd=1024, win_bwd=29200,
                pkt_len_mean=330, pkt_len_std=195, pkt_len_max=1150, pkt_len_min=64,
                flow_iat_mean=8700, fwd_iat_mean=12800
            ),
            "ip": "198.51.100.22",
        },
        # 5. Volumetric DoS / Hulk Attack
        {
            "name": "5. Volumetric DoS: HTTP Request Flooding (DoS-Hulk)",
            "ground_truth": "DoS",
            "flow": make_flow(
                duration_sec=0.08, fwd_pkts=850, bwd_pkts=12, fwd_bytes=380000, bwd_bytes=840,
                syn=1, ack=860, psh=800, win_fwd=256, win_bwd=0,
                pkt_len_mean=441, pkt_len_std=85, pkt_len_max=820, pkt_len_min=40,
                flow_iat_mean=92, fwd_iat_mean=94
            ),
            "ip": "203.0.113.45",
        },
        # 6. Low-and-Slow DoS (Slowloris)
        {
            "name": "6. Low-and-Slow DoS: Connection Exhaustion (DoS-Slowloris)",
            "ground_truth": "DoS",
            "flow": make_flow(
                duration_sec=75.0, fwd_pkts=12, bwd_pkts=2, fwd_bytes=520, bwd_bytes=110,
                syn=1, ack=12, psh=8, win_fwd=8192, win_bwd=29200,
                pkt_len_mean=45, pkt_len_std=15, pkt_len_max=85, pkt_len_min=32,
                flow_iat_mean=5350000, fwd_iat_mean=6250000
            ),
            "ip": "203.0.113.89",
        },
        # 7. Novel Zero-Day / Covert DNS Tunneling & C2 Exfiltration
        {
            "name": "7. Zero-Day / Novel Attack: Covert DNS Exfiltration & Jittered C2 (T1071.004)",
            "ground_truth": "Unknown-ZeroDay",
            "flow": make_flow(
                duration_sec=142.0, fwd_pkts=180, bwd_pkts=180, fwd_bytes=42500, bwd_bytes=44800,
                syn=0, ack=0, rst=0, psh=0, win_fwd=0, win_bwd=0,
                pkt_len_mean=242, pkt_len_std=18, pkt_len_max=280, pkt_len_min=210,
                flow_iat_mean=788000, fwd_iat_mean=789000
            ),
            "ip": "198.51.100.99",
        },
    ]

    for sc in scenarios:
        flow = sc["flow"]
        alert = pipe.detect_batch([flow])[0]
        
        # Test Decision Engine Grounding
        fake_rec = AlertRecord(
            id=101,
            type=alert.type,
            severity=alert.severity,
            confidence=alert.confidence,
            anomaly_score=alert.anomaly_score,
            stage=alert.stage,
            route=alert.route,
            mitre_techniques=json.dumps(alert.mitre_techniques),
            top_features=json.dumps(alert.top_features),
            source_file="simulation_stream.pcap",
        )
        smart_log = build_smart_log(fake_rec)
        smart_log.source["src_ip"] = sc["ip"]
        
        # Retrieve D3FEND Countermeasures & MITRE Knowledge
        playbook = default_semantic_rag.retrieve_defense_playbook(
            label=alert.type,
            techniques=alert.mitre_techniques,
            telemetry=smart_log.source
        )
        
        # Formal Safety Verification
        rec_action = "block_ip" if alert.route == "known_attack" else "observe"
        safety_check = default_safety_verifier.verify_and_sign(
            action=rec_action,
            target=sc["ip"],
            severity=alert.severity,
            confidence=alert.confidence
        )
        
        print(f"\n▶ Scenario: {sc['name']}")
        print(f"  • Ground Truth:      {sc['ground_truth']}")
        print(f"  • ML Pipeline Class: {alert.type} (Confidence: {alert.confidence*100:.1f}%)")
        print(f"  • Routing Stage:     {alert.stage} -> Route: {alert.route}")
        print(f"  • Anomaly / AE Err:  {alert.anomaly_score:.4f} (Flagged: {alert.evidence.get('autoencoder', {}).get('flagged', False)})")
        print(f"  • MITRE ATT&CK:      {alert.mitre_techniques or 'None (Benign)'}")
        print(f"  • D3FEND Measures:   {[c['id'] + ': ' + c['name'] for c in playbook.get('countermeasures', [])[:2]]}")
        print(f"  • Safety Verifier:   Admitted={safety_check.admitted} (Action: {rec_action})")
        print("  " + "-" * 76)

if __name__ == "__main__":
    run_tests()
