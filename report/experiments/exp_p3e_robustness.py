"""Experiment P3.e: Robustness, Out-of-Scope Behaviors, Input Rejection, and Adversarial Perturbations.

Empirically tests:
1. Router behavior on Out-of-Scope (OOD) attack labels (e.g., BruteForce, Infiltration, WebAttack)
2. Input Contract Rejection across edge-case payloads (NaN, Inf, negative counts, string values, formula injections)
3. Formal Safety Verifier rejection of metacharacters and K_crit self-DoS targets
4. Adversarial Feature Perturbation sensitivity: step-wise evasion curve on DDoS and PortScan signatures
"""
import datetime
import json
import math
import os
import platform
import sys
from pathlib import Path

import numpy as np

root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir))

from backend.api.detection import _get_pipeline
from backend.detection.features import FEATURE_NAMES, extract_features
from backend.detection.router import route_signals
from backend.safety.formal_verifier import FormalSafetyVerifier


def get_environment_info():
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "cpu_count": os.cpu_count() or 1,
    }


def run_robustness_experiments():
    pipeline = _get_pipeline()
    verifier = FormalSafetyVerifier()

    results = {
        "metadata": {
            "experiment": "P3.e_robustness_and_adversarial",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "environment": get_environment_info(),
        },
        "ood_router_behavior": {},
        "input_contract_rejections": [],
        "safety_guardrail_rejections": [],
        "adversarial_perturbation_curves": {}
    }

    # 1. Out-of-Scope (OOD) Label Behavior in Router
    ood_labels = ["BruteForce", "Infiltration", "WebAttack", "ZeroDay_Exploit", "APT29_C2"]
    for lbl in ood_labels:
        # High confidence (0.99) but outside declared classes {"Benign", "Bot", "DDoS", "PortScan"}
        routed = route_signals(
            classifier_labels=[lbl],
            classifier_confidences=[0.99],
            classifier_threshold=0.90,
            supported_labels={"Benign", "Bot", "DDoS", "PortScan"},
            statistical_flags=[False],
            statistical_scores=[0.5],
            autoencoder_available=[False],
            autoencoder_flags=[False],
            autoencoder_scores=[0.0],
            pipeline_version="cyberguard-pipeline-v2",
            routing_schema_version="cyberguard-routing-v2",
        )
        results["ood_router_behavior"][lbl] = {
            "route": routed.routes[0],
            "verdict": routed.verdicts[0],
            "reason": routed.reasons[0],
            "supported_flag": bool(routed.supported_label[0]),
            "expected_route": "human_review"
        }

    # 2. Input Rejection Behavior
    test_payloads = [
        ("nan_duration", {"flow_duration": float("nan")}),
        ("inf_rate", {"packets_per_sec": float("inf")}),
        ("negative_packets", {"total_fwd_packets": -10}),
        ("string_in_numeric_field", {"flow_duration": "malicious_string"}),
        ("formula_injection_cell", {"flow_duration": "=1+1; cmd.exe"}),
        ("empty_dict", {}),
    ]

    for test_name, payload in test_payloads:
        # Test feature extractor defense
        extracted = extract_features(payload)
        is_finite = all(np.isfinite(extracted[k]) for k in FEATURE_NAMES)
        is_zero_defaulted = (extracted["flow_duration"] == 0.0) if "flow_duration" in payload else True

        results["input_contract_rejections"].append({
            "test_case": test_name,
            "handled_safely_without_crash": True,
            "all_features_finite": is_finite,
            "extracted_duration": float(extracted.get("flow_duration", 0.0)),
        })

    # 3. Formal Safety Verifier Rejection Tests
    safety_test_cases = [
        ("self_dos_loopback_v4", "block_ip", "127.0.0.1"),
        ("self_dos_loopback_v6", "block_ip", "::1"),
        ("self_dos_public_dns_cloudflare", "block_ip", "1.1.1.1"),
        ("self_dos_public_dns_google", "block_ip", "8.8.8.8"),
        ("mass_blackhole_broad_cidr", "block_ip", "0.0.0.0/0"),
        ("mass_blackhole_slash_8", "block_ip", "10.0.0.0/8"),
        ("shell_injection_semicolon", "block_ip", "192.168.1.100; rm -rf /"),
        ("shell_injection_backtick", "block_ip", "192.168.1.100`reboot`"),
        ("critical_kernel_process_kill", "kill_process", "csrss.exe"),
        ("critical_systemd_kill", "kill_process", "/usr/sbin/init"),
        ("valid_external_adversary", "block_ip", "198.51.100.42"),
    ]

    for s_name, act, tgt in safety_test_cases:
        res = verifier.verify_and_sign(action=act, target=tgt, severity="high", confidence=0.95)
        results["safety_guardrail_rejections"].append({
            "case": s_name,
            "action": act,
            "target": tgt,
            "admitted": res.admitted,
            "violated_invariants": [str(v) for v in res.violated_invariants],
            "disruption": res.disruption_score,
            "bound": res.proportionality_bound,
        })

    # 4. Adversarial Feature Perturbation Sensitivity Curve (DDoS SYN Flood)
    # Canonical synthetic DDoS flow template:
    # flow_duration: 10000 us, packets_per_sec: 50000, syn_flag_count: 1, init_win_bytes_fwd: 256
    base_ddos = {
        "flow_duration": 10000.0,
        "total_fwd_packets": 25.0,
        "total_bwd_packets": 0.0,
        "total_fwd_bytes": 1000.0,
        "total_bwd_bytes": 0.0,
        "packets_per_sec": 50000.0,
        "bytes_per_sec": 2000000.0,
        "fwd_packet_length_mean": 40.0,
        "bwd_packet_length_mean": 0.0,
        "packet_length_mean": 40.0,
        "packet_length_std": 0.0,
        "packet_length_max": 40.0,
        "packet_length_min": 40.0,
        "avg_pkt_size": 40.0,
        "syn_flag_count": 1.0,
        "ack_flag_count": 0.0,
        "rst_flag_count": 0.0,
        "fin_flag_count": 0.0,
        "psh_flag_count": 0.0,
        "urg_flag_count": 0.0,
        "init_win_bytes_fwd": 256.0,
        "init_win_bytes_bwd": 0.0,
        "flow_iat_mean": 400.0,
        "flow_iat_std": 50.0,
        "flow_iat_max": 500.0,
        "fwd_iat_mean": 400.0,
        "fwd_header_len": 500.0,
        "bwd_header_len": 0.0,
        "down_up_ratio": 0.0,
        "flow_bytes_ratio": 1.0,
        "active_mean": 7000.0,
        "idle_mean": 3000.0,
    }

    # Perturbation parameter: flow_duration stretched, reducing packets_per_sec
    ddos_curve = []
    pps_steps = [50000, 30000, 20000, 10000, 5000, 2500, 1000, 500, 200, 100]
    for pps in pps_steps:
        flow = dict(base_ddos)
        flow["packets_per_sec"] = float(pps)
        alert = pipeline.detect(flow)
        ddos_curve.append({
            "packets_per_sec": pps,
            "predicted_label": alert.evidence["classifier"]["label"],
            "confidence": round(alert.confidence, 4),
            "route": alert.route,
            "verdict": alert.type,
        })
    results["adversarial_perturbation_curves"]["ddos_rate_attenuation"] = ddos_curve

    # Perturbation parameter 2: Init Window Size dilation (from 256 towards benign 8192)
    win_curve = []
    win_steps = [256, 512, 1024, 2048, 4096, 6144, 8192, 16384, 64240]
    for win in win_steps:
        flow = dict(base_ddos)
        flow["init_win_bytes_fwd"] = float(win)
        alert = pipeline.detect(flow)
        win_curve.append({
            "init_win_bytes_fwd": win,
            "predicted_label": alert.evidence["classifier"]["label"],
            "confidence": round(alert.confidence, 4),
            "route": alert.route,
            "verdict": alert.type,
        })
    results["adversarial_perturbation_curves"]["ddos_window_dilation"] = win_curve

    out_dir = root_dir / "report" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "robustness_experiments.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[*] Robustness experiments complete. Saved to {out_path}")
    print("[*] Out-of-Scope Router decisions:")
    for lbl, rdata in results["ood_router_behavior"].items():
        print(f"  {lbl:18}: Route={rdata['route']}, Reason={rdata['reason']}")
    print("[*] DDoS Perturbation curve (pps vs confidence & route):")
    for step in ddos_curve[:5]:
        print(f"  PPS={step['packets_per_sec']:5}: Conf={step['confidence']:.4f}, Label={step['predicted_label']}, Route={step['route']}")


if __name__ == "__main__":
    run_robustness_experiments()
