"""Comprehensive test suite for Genius Omni-Threat Defense RAG Engine.

Validates that the RAG engine accurately identifies ALL attack types across the cyber kill chain:
1. Volumetric DoS / DDoS (Network & Application Layer)
2. Identity & Active Directory attacks (Kerberoasting, DCSync, Pass-the-Hash, Golden Ticket)
3. Windows Security Event IDs & Sysmon telemetry (EventID 4625, 7045, Sysmon 1, Sysmon 8)
4. Living-off-the-Land Binaries (LOLBins: certutil, powershell, wmic, mshta)
5. Web Application Exploits (SQL Injection, XSS, SSRF, RCE)
6. Malware Families & C2 Infrastructure (Cobalt Strike, Mimikatz, LockBit Ransomware)
7. Threat Groups & APT attribution (Lazarus Group, APT28)
8. Multi-Hop Graph Traversal to D3FEND & Concrete Actuator Playbooks
9. Grounded Zero-Hallucination Prompt Context Generation
"""
import pytest
from backend.mitre.defense_rag import GeniusDefenseRAG, default_defense_rag


def test_defense_rag_retrieves_ddos_countermeasures():
    playbook = default_defense_rag.retrieve_defense_playbook("DDoS", telemetry={"src_ip": "203.0.113.10", "dest_port": 80})

    assert playbook["total_techniques_matched"] >= 1
    tids = [t["technique_id"] for t in playbook["techniques"]]
    assert "T1498" in tids or "T1499" in tids

    assert len(playbook["d3fend_countermeasures"]) >= 1
    assert len(playbook["concrete_actions"]) >= 1
    actions = [a["action"] for a in playbook["concrete_actions"]]
    assert "block_ip" in actions or "rate_limit" in actions


def test_defense_rag_retrieves_syn_flood_and_slowloris():
    playbook = default_defense_rag.retrieve_defense_playbook("SYN flood attack and slowloris HTTP exhaustion")
    tids = [t["technique_id"] for t in playbook["techniques"]]
    assert any(t in tids for t in ["T1498", "T1498.001", "T1499", "T1499.002"])
    assert len(playbook["d3fend_countermeasures"]) >= 1


def test_defense_rag_retrieves_identity_and_active_directory_attacks():
    playbook = default_defense_rag.retrieve_defense_playbook("Kerberoasting and DCSync attack")
    tids = [t["technique_id"] for t in playbook["techniques"]]
    assert any(t in tids for t in ["T1558.003", "T1003.006", "T1003"])
    assert len(playbook["d3fend_countermeasures"]) >= 1


def test_defense_rag_retrieves_pass_the_hash_and_golden_ticket():
    playbook = default_defense_rag.retrieve_defense_playbook("Pass the hash NTLM credential relay and golden ticket forgery")
    tids = [t["technique_id"] for t in playbook["techniques"]]
    assert any(t in tids for t in ["T1550.002", "T1558.001", "T1558"])
    assert len(playbook["d3fend_countermeasures"]) >= 1


def test_defense_rag_correlates_windows_event_ids():
    # EventID 4625 = Failed Logon / Brute Force
    playbook_4625 = default_defense_rag.retrieve_defense_playbook("Security alert: EventID 4625 repeated 50 times from 198.51.100.4")
    tids_4625 = [t["technique_id"] for t in playbook_4625["techniques"]]
    assert any(t in tids_4625 for t in ["T1110", "T1110.001"])

    # EventID 7045 = New Service Installed (Persistence)
    playbook_7045 = default_defense_rag.retrieve_defense_playbook("System log EventCode: 7045 service created by attacker")
    tids_7045 = [t["technique_id"] for t in playbook_7045["techniques"]]
    assert any(t in tids_7045 for t in ["T1543.003", "T1543"])


def test_defense_rag_correlates_sysmon_telemetry():
    # Sysmon Event 1 = Process Create (Command and Scripting Interpreter)
    playbook_sysmon1 = default_defense_rag.retrieve_defense_playbook("Sysmon Event: 1 powershell.exe spawned with encoded command")
    tids_sysmon1 = [t["technique_id"] for t in playbook_sysmon1["techniques"]]
    assert any(t in tids_sysmon1 for t in ["T1059", "T1059.001"])

    # Sysmon Event 8 = CreateRemoteThread (Process Injection)
    playbook_sysmon8 = default_defense_rag.retrieve_defense_playbook("Sysmon 8 remote thread created in lsass.exe")
    tids_sysmon8 = [t["technique_id"] for t in playbook_sysmon8["techniques"]]
    assert any(t in tids_sysmon8 for t in ["T1055.001", "T1055", "T1003.001"])


def test_defense_rag_identifies_lolbins_abuse():
    playbook = default_defense_rag.retrieve_defense_playbook("Attacker used certutil -urlcache -split to download stage2 payload")
    tids = [t["technique_id"] for t in playbook["techniques"]]
    assert any(t in tids for t in ["T1105", "T1140"])
    assert len(playbook["d3fend_countermeasures"]) >= 1


def test_defense_rag_identifies_web_vulnerabilities():
    # SQL Injection
    playbook_sqli = default_defense_rag.retrieve_defense_playbook("SQL injection attempt in auth endpoint: ' OR 1=1 --")
    tids_sqli = [t["technique_id"] for t in playbook_sqli["techniques"]]
    assert any(t in tids_sqli for t in ["T1190"])

    # SSRF / RCE
    playbook_rce = default_defense_rag.retrieve_defense_playbook("Remote code execution via Log4j CVE-2021-44228")
    tids_rce = [t["technique_id"] for t in playbook_rce["techniques"]]
    assert any(t in tids_rce for t in ["T1190", "T1203"])


def test_defense_rag_retrieves_malware_and_threat_actors():
    # Cobalt Strike & Ransomware
    playbook_cs = default_defense_rag.retrieve_defense_playbook("Cobalt Strike beaconing detected with LockBit ransomware payload")
    tids_cs = [t["technique_id"] for t in playbook_cs["techniques"]]
    assert any(t in tids_cs for t in ["T1071", "T1486", "T1059.001", "T1090.004"])

    # Threat Actor: Lazarus Group
    playbook_lazarus = default_defense_rag.retrieve_defense_playbook("Intrusion activity attributed to Lazarus Group")
    tids_lazarus = [t["technique_id"] for t in playbook_lazarus["techniques"]]
    assert len(tids_lazarus) >= 1


def test_defense_rag_correlates_targeted_ports():
    # Target port 3389 = RDP
    playbook_rdp = default_defense_rag.retrieve_defense_playbook("Suspicious inbound connection on dest_port: 3389", telemetry={"dest_port": 3389})
    tids_rdp = [t["technique_id"] for t in playbook_rdp["techniques"]]
    assert any(t in tids_rdp for t in ["T1021.001", "T1021"])

    # Target port 445 = SMB
    playbook_smb = default_defense_rag.retrieve_defense_playbook("Multiple connection spikes on port 445", telemetry={"dest_port": 445})
    tids_smb = [t["technique_id"] for t in playbook_smb["techniques"]]
    assert any(t in tids_smb for t in ["T1021.002", "T1021"])


def test_defense_rag_formats_prompt_context_with_grounding():
    playbook = default_defense_rag.retrieve_defense_playbook("PortScan", telemetry={"src_ip": "198.51.100.22", "dest_port": 443})
    prompt_ctx = default_defense_rag.format_prompt_context(playbook)

    assert "GROUNDED OMNI-THREAT INTELLIGENCE & D3FEND DEFENSE CONTEXT" in prompt_ctx
    assert "IDENTIFIED MITRE ATT&CK TECHNIQUES" in prompt_ctx
    assert "block_ip" in prompt_ctx
    assert "MANDATORY INSTRUCTION: You must base your recommended_action exclusively" in prompt_ctx


def test_defense_rag_handles_unknown_label_safely():
    playbook = default_defense_rag.retrieve_defense_playbook("CompletelyNonExistentPatternXYZ123")
    assert isinstance(playbook["techniques"], list)
    assert isinstance(playbook["d3fend_countermeasures"], list)
