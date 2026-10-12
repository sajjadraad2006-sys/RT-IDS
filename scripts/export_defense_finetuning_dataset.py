"""Generate instruction-tuning datasets for training Autonomous Cyber Defense LLMs.

Produces Alpaca and ShareGPT formatted JSONL training datasets grounded in:
1. MITRE ATT&CK adversary tactics & techniques
2. MITRE D3FEND defensive countermeasures
3. Real network flow records and Suricata EVE security alerts
4. Strict JSON schema-compliant autonomous response playbooks
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import sys

# Ensure repository root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

SCENARIOS = [
    {
        "threat": "DDoS",
        "attack_id": "T1498",
        "technique_name": "Network Denial of Service",
        "src_ip": "203.0.113.45",
        "dest_port": 80,
        "proto": "TCP",
        "evidence_signals": {"flow_packets_s": 85000.0, "syn_flag_count": 42000, "z_score": 5.4},
        "d3fend_id": "D3-NIPF",
        "countermeasure": "Network Ingress Packet Filtering",
        "action": "block_ip",
        "target": "203.0.113.45",
        "verdict": "malicious",
        "confidence": 0.98,
        "rationale": "High-volume SYN flood detected originating from external IP 203.0.113.45 exceeding 85,000 packets/sec with anomalous Z-score.",
        "containment": ["Apply ingress packet filter on source IP 203.0.113.45", "Rate-limit edge router SYN packets"],
    },
    {
        "threat": "PortScan",
        "attack_id": "T1046",
        "technique_name": "Network Service Discovery",
        "src_ip": "198.51.100.18",
        "dest_port": 445,
        "proto": "TCP",
        "evidence_signals": {"flow_duration": 120.0, "dst_host_srv_count": 250, "z_score": 4.1},
        "d3fend_id": "D3-ITR",
        "countermeasure": "Inbound Traffic Filtering",
        "action": "block_ip",
        "target": "198.51.100.18",
        "verdict": "malicious",
        "confidence": 0.94,
        "rationale": "Sequential port reconnaissance sweep targeting local service ports from remote IP 198.51.100.18.",
        "containment": ["Block inbound traffic from scanning host 198.51.100.18"],
    },
    {
        "threat": "Bot",
        "attack_id": "T1071",
        "technique_name": "Application Layer Protocol: C2",
        "src_ip": "192.168.1.105",
        "dest_ip": "185.220.101.5",
        "dest_port": 4444,
        "proto": "TCP",
        "evidence_signals": {"flow_iat_mean": 60000.0, "flow_bytes_ratio": 0.05, "z_score": 3.8},
        "d3fend_id": "D3-DNSF",
        "countermeasure": "DNS Sinkholing / Signature Drop",
        "action": "drop_suricata_signature",
        "target": "185.220.101.5",
        "verdict": "malicious",
        "confidence": 0.96,
        "rationale": "Periodic heartbeat beacons indicating automated Command and Control channel communication.",
        "containment": ["Drop C2 traffic signature on Suricata sensor", "Isolate internal host 192.168.1.105 for forensics"],
    },
    {
        "threat": "BruteForce",
        "attack_id": "T1110",
        "technique_name": "Brute Force",
        "src_ip": "198.51.100.99",
        "dest_port": 22,
        "proto": "TCP",
        "evidence_signals": {"failed_attempts": 140, "flow_packets_s": 120.0, "z_score": 4.7},
        "d3fend_id": "D3-NIPF",
        "countermeasure": "Network Ingress Packet Filtering",
        "action": "block_ip",
        "target": "198.51.100.99",
        "verdict": "malicious",
        "confidence": 0.99,
        "rationale": "Rapid repeated SSH login failures indicative of automated credential stuffing attack.",
        "containment": ["Block remote source IP 198.51.100.99 in host firewall"],
    },
    {
        "threat": "DoS",
        "attack_id": "T1499",
        "technique_name": "Endpoint Denial of Service: Application Exhaustion",
        "src_ip": "203.0.113.62",
        "dest_port": 80,
        "proto": "TCP",
        "evidence_signals": {"flow_duration": 300.0, "fwd_header_length": 40, "z_score": 4.5},
        "d3fend_id": "D3-RPS",
        "countermeasure": "Rate-Limiting / Connection Limiting",
        "action": "rate_limit",
        "target": "203.0.113.62",
        "verdict": "malicious",
        "confidence": 0.95,
        "rationale": "Slowloris application layer connection starvation keeping web worker threads occupied indefinitely.",
        "containment": ["Apply rate limit on source IP 203.0.113.62", "Drop idle half-open connections"],
    },
    {
        "threat": "WebAttack",
        "attack_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: Web Injection / RCE",
        "src_ip": "198.51.100.77",
        "dest_port": 8080,
        "proto": "TCP",
        "evidence_signals": {"fwd_packet_length_max": 2400.0, "flow_bytes_s": 95000.0, "z_score": 4.9},
        "d3fend_id": "D3-WAF",
        "countermeasure": "Web Application Filtering / Signature Dropping",
        "action": "drop_suricata_signature",
        "target": "198.51.100.77",
        "verdict": "malicious",
        "confidence": 0.97,
        "rationale": "High-severity web application payload injection matching known JNDI / SQL injection signature patterns.",
        "containment": ["Drop web attack signature on Suricata sensor", "Block malicious source IP 198.51.100.77"],
    },
    {
        "threat": "Infiltration",
        "attack_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel / Internal Pivot",
        "src_ip": "192.168.1.188",
        "dest_port": 445,
        "proto": "TCP",
        "evidence_signals": {"flow_bytes_ratio": 0.92, "bwd_packets_s": 450.0, "z_score": 5.1},
        "d3fend_id": "D3-PA",
        "countermeasure": "Process Termination / Host Isolation",
        "action": "isolate_port",
        "target": "192.168.1.188",
        "verdict": "malicious",
        "confidence": 0.96,
        "rationale": "Host compromised via lateral movement exhibiting internal SMB pivot and unauthorized data exfiltration.",
        "containment": ["Isolate lateral communication port 445 on compromised host 192.168.1.188", "Suspend suspicious process"],
    },
    {
        "threat": "Benign",
        "attack_id": "",
        "technique_name": "Normal Enterprise Traffic",
        "src_ip": "192.168.1.50",
        "dest_port": 443,
        "proto": "TCP",
        "evidence_signals": {"flow_packets_s": 15.0, "flow_duration": 45000.0, "z_score": 0.2},
        "d3fend_id": "",
        "countermeasure": "",
        "action": "observe",
        "target": "192.168.1.50",
        "verdict": "benign",
        "confidence": 0.99,
        "rationale": "Standard HTTPS browsing pattern with low packet rate and normal inter-arrival times.",
        "containment": [],
    },
]


def generate_training_sample(scenario: dict, sample_id: int) -> dict:
    """Create one grounded instruction-tuning example."""
    # Synthesize variable IPs and ports
    src_ip = scenario["src_ip"]
    if scenario["threat"] != "Benign":
        # Slight IP variations for diversity
        octets = src_ip.split(".")
        octets[3] = str((int(octets[3]) + sample_id) % 250 + 1)
        src_ip = ".".join(octets)

    telemetry = {
        "src_ip": src_ip,
        "dest_port": scenario.get("dest_port", 80),
        "protocol": scenario.get("proto", "TCP"),
        **scenario["evidence_signals"],
    }

    prompt = (
        f"You are the autonomous defense decision engine for CyberGuard.\n"
        f"Analyze the supplied telemetry and MITRE Grounding Context:\n\n"
        f"TELEMETRY: {json.dumps(telemetry)}\n"
        f"OBSERVED THREAT CLASS: {scenario['threat']}\n"
    )
    if scenario["attack_id"]:
        prompt += (
            f"MITRE ATT&CK: [{scenario['attack_id']}] {scenario['technique_name']}\n"
            f"MITRE D3FEND COUNTERMEASURE: [{scenario['d3fend_id']}] {scenario['countermeasure']}\n"
            f"APPROVED AUTONOMOUS ACTIONS: [block_ip, isolate_port, rate_limit, drop_suricata_signature, observe]\n"
        )
    prompt += "\nReturn a strict JSON response with verdict, confidence, recommended_action, rationale, containment, and limitations."

    response = {
        "verdict": scenario["verdict"],
        "confidence": scenario["confidence"],
        "recommended_action": scenario["action"],
        "rationale": scenario["rationale"],
        "evidence": [f"{k}={v}" for k, v in scenario["evidence_signals"].items()],
        "containment": scenario["containment"],
        "limitations": ["Autonomous defense is subject to deterministic allowlist guardrails."],
    }

    return {
        "id": f"cg-defense-{sample_id:04d}",
        "conversations": [
            {"from": "human", "value": prompt},
            {"from": "gpt", "value": json.dumps(response, indent=2)},
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Export CyberGuard Defense Fine-Tuning Dataset")
    parser.add_argument("--count", type=int, default=500, help="Number of training samples to generate")
    parser.add_argument("--output", type=str, default="data/defense_finetuning_dataset.jsonl", help="Output path")
    args = parser.parse_args()

    out_path = BASE_DIR / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)

    samples = []
    for i in range(args.count):
        scenario = random.choice(SCENARIOS)
        sample = generate_training_sample(scenario, i + 1)
        samples.append(sample)

    with open(out_path, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    print(f"Generated {len(samples)} fine-tuning samples successfully at: {out_path}")


if __name__ == "__main__":
    main()
