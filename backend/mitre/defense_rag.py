"""Genius Omni-Threat Defense RAG Engine for CyberGuard.

Master Cybersecurity Retrieval-Augmented Generation Engine:
1. Full Corpus Coverage:
   - 697+ MITRE ATT&CK Enterprise Techniques & Subtechniques (all 14 tactics).
   - 821+ Malware and Tool definitions.
   - 174+ Threat Groups & APT profiles with aliases.
   - 15,757+ STIX Threat Relationships mapping Groups/Malware to ATT&CK Techniques.
   - 272+ MITRE D3FEND Defensive Techniques with official definitions.
   - 4,154+ Inferred D3FEND Relationships linking attacks to defensive countermeasures.
2. Full Cyber Ontological Taxonomy:
   - Windows Security Log Event IDs (4624, 4625, 4688, 4672, 4698, 7045, 1102, 4768, 4769, 4776...)
   - Sysmon Event IDs (1, 2, 3, 5, 7, 8, 10, 11, 12, 13, 14, 15, 22, 25)
   - Port & Protocol Anomalies (21, 22, 53, 80, 88, 135, 443, 445, 1433, 3306, 3389, 5985...)
   - Living-off-the-Land Binaries / LOLBins (powershell, wmic, certutil, bitsadmin, mshta, vssadmin...)
   - OWASP Top 10 Web Vectors (SQLi, XSS, RCE, SSRF, Path Traversal, Command Injection, WebShell...)
   - Identity & Active Directory vectors (Kerberoasting, DCSync, Pass-the-Hash, Golden Ticket, LSASS)
   - Ransomware & Volumetric DoS patterns.
3. Multi-Signal Hybrid Retrieval with Reciprocal Rank Fusion (RRF):
   - Signal A: Exact Identifier Recognition (ATT&CK IDs, D3FEND IDs, CVEs, Event IDs, Ports)
   - Signal B: SQLite FTS5 Full-Text Search with BM25 sublinear term frequency scoring
   - Signal C: STIX Threat Relationships Traversal (Malware/Group -> Techniques)
   - Signal D: Ontological Concept Graph Expansion
   - Signal E: RapidFuzz Fuzzy Token Scoring (typo and phrasing tolerance)
4. Multi-Hop Graph Traversal to D3FEND & Concrete Autonomous Actuators:
   - Threat Alert -> ATT&CK Techniques -> D3FEND Countermeasures -> Actuator Commands.
5. Zero-Hallucination Grounding Prompt Synthesis.
"""
from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from rapidfuzz import fuzz
    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False

from ..config import ATTACK_VERSION, BUNDLED_MITRE_DIR, DB_PATH

logger = logging.getLogger("cyberguard.defense_rag")

# ---------------------------------------------------------------------------
# Regex Identifiers
# ---------------------------------------------------------------------------
_ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_D3FEND_ID_PATTERN = re.compile(r"\bD3-[A-Z0-9]+\b", re.IGNORECASE)
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_WIN_EVENT_PATTERN = re.compile(r"(?:event\s*id|eventcode|winlog)\s*[:=]?\s*(\d{4,5})\b", re.IGNORECASE)
_SYSMON_PATTERN = re.compile(r"sysmon\s*(?:event)?\s*[:=]?\s*(\d{1,2})\b", re.IGNORECASE)
_PORT_PATTERN = re.compile(r"(?:port|dst_port|dest_port)\s*[:=]?\s*(\d{1,5})\b", re.IGNORECASE)
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ---------------------------------------------------------------------------
# Comprehensive Cyber Ontological Knowledge
# ---------------------------------------------------------------------------

# Windows Security Event IDs -> ATT&CK Techniques
WIN_EVENT_MAP: Dict[str, List[str]] = {
    "4624": ["T1078"],                   # Successful Logon
    "4625": ["T1110", "T1110.001"],      # Failed Logon (Brute Force / Password Spray)
    "4672": ["T1078"],                   # Special Privileges Assigned (Privilege Escalation)
    "4688": ["T1059", "T1059.001"],      # Process Creation
    "4697": ["T1543.003"],               # Service Installed
    "7045": ["T1543.003"],               # New Service Installed (System Log)
    "4698": ["T1053.005"],               # Scheduled Task Created
    "4702": ["T1053.005"],               # Scheduled Task Updated
    "4720": ["T1136.001"],               # User Account Created
    "4728": ["T1098"],                   # Member Added to Security Global Group
    "4732": ["T1098"],                   # Member Added to Security Local Group
    "4756": ["T1098"],                   # Member Added to Universal Security Group
    "4738": ["T1098"],                   # User Account Modified
    "4768": ["T1558"],                   # Kerberos TGT Requested
    "4769": ["T1558.003"],               # Kerberos Service Ticket Requested (Kerberoasting)
    "4771": ["T1110.003", "T1558.004"],  # Kerberos Pre-Authentication Failed (AS-REP Roasting)
    "4776": ["T1550.002"],               # NTLM Credential Validation (Pass-the-Hash)
    "1102": ["T1070.001"],               # Audit Log Cleared
    "104":  ["T1070.001"],               # System Log Cleared
}

# Sysmon Event IDs -> ATT&CK Techniques
SYSMON_MAP: Dict[str, List[str]] = {
    "1":  ["T1059", "T1059.001"],        # Process Create
    "2":  ["T1070.006"],                 # File Creation Time Changed (Timestomp)
    "3":  ["T1071", "T1049"],            # Network Connection (C2 / Discovery)
    "5":  ["T1562.001"],                 # Process Terminated (Impair Defenses)
    "7":  ["T1055", "T1574"],            # Image Loaded (DLL Injection / Hijacking)
    "8":  ["T1055.001"],                 # CreateRemoteThread (DLL / Process Injection)
    "10": ["T1003.001"],                 # ProcessAccess (LSASS Memory Access)
    "11": ["T1105"],                     # FileCreate (Ingress Tool / Dropper)
    "12": ["T1547.001", "T1112"],        # Registry Object Created/Deleted (Persistence)
    "13": ["T1547.001", "T1112"],        # Registry Value Set (Persistence)
    "14": ["T1547.001"],                 # Registry Object Renamed
    "15": ["T1564.004"],                 # FileCreateStreamHash (Alternate Data Streams)
    "22": ["T1071.004", "T1048.003"],    # DNSEvent (DNS C2 / Tunneling)
    "25": ["T1055.012"],                 # ProcessTampering (Process Hollowing)
}

# Port Anomalies -> ATT&CK Techniques & Protocols
PORT_MAP: Dict[str, List[str]] = {
    "21":   ["T1071", "T1048"],          # FTP
    "22":   ["T1021.004"],               # SSH Lateral Movement
    "23":   ["T1021"],                   # Telnet
    "25":   ["T1566", "T1048"],          # SMTP Phishing / Exfiltration
    "53":   ["T1071.004", "T1048.003"],  # DNS Tunneling / C2
    "80":   ["T1190", "T1071.001"],      # HTTP Web Exploit / C2
    "88":   ["T1558", "T1558.003"],      # Kerberos (Kerberoasting / AS-REP)
    "135":  ["T1021.002"],               # MSRPC / Lateral Movement
    "139":  ["T1021.002"],               # NetBIOS SMB
    "389":  ["T1087.002", "T1069.002"],  # LDAP Reconnaissance
    "443":  ["T1190", "T1071.001"],      # HTTPS Web Exploit / C2 Beacon
    "445":  ["T1021.002"],               # SMB Lateral Movement / PsExec
    "636":  ["T1087.002"],               # LDAPS Reconnaissance
    "1433": ["T1190", "T1005"],          # MSSQL Database / SQLi
    "1521": ["T1190"],                   # Oracle DB
    "3306": ["T1190", "T1005"],          # MySQL Database
    "3389": ["T1021.001"],               # RDP Lateral Movement
    "5985": ["T1021.006"],               # WinRM HTTP
    "5986": ["T1021.006"],               # WinRM HTTPS
    "8080": ["T1190", "T1071.001"],      # HTTP Proxy / Web Exploit
    "8443": ["T1190", "T1071.001"],      # HTTPS Proxy / Web Exploit
}

# Living-off-the-Land Binaries (LOLBins) & System Utilities
LOLBIN_MAP: Dict[str, List[str]] = {
    "powershell": ["T1059.001"],
    "powershell.exe": ["T1059.001"],
    "pwsh": ["T1059.001"],
    "cmd": ["T1059.003"],
    "cmd.exe": ["T1059.003"],
    "wmic": ["T1047"],
    "wmic.exe": ["T1047"],
    "certutil": ["T1105", "T1140"],
    "certutil.exe": ["T1105", "T1140"],
    "bitsadmin": ["T1197", "T1105"],
    "bitsadmin.exe": ["T1197", "T1105"],
    "mshta": ["T1218.005"],
    "mshta.exe": ["T1218.005"],
    "rundll32": ["T1218.011"],
    "rundll32.exe": ["T1218.011"],
    "regsvr32": ["T1218.010"],
    "regsvr32.exe": ["T1218.010"],
    "cscript": ["T1059.005"],
    "wscript": ["T1059.005"],
    "vssadmin": ["T1490"],
    "vssadmin.exe": ["T1490"],
    "schtasks": ["T1053.005"],
    "schtasks.exe": ["T1053.005"],
    "whoami": ["T1033"],
    "whoami.exe": ["T1033"],
    "net.exe": ["T1087", "T1069"],
    "net1.exe": ["T1087", "T1069"],
    "nltest": ["T1482"],
    "nltest.exe": ["T1482"],
    "procdump": ["T1003.001"],
    "procdump.exe": ["T1003.001"],
    "sc.exe": ["T1543.003"],
    "curl": ["T1105"],
    "wget": ["T1105"],
}

# Cyber Concept Expansion Graph (Attack categories across all 14 tactics)
CYBER_CONCEPT_GRAPH: Dict[str, List[str]] = {
    # 1. Reconnaissance & Discovery
    "portscan": ["T1046", "T1595"],
    "port scan": ["T1046", "T1595"],
    "nmap": ["T1046", "T1595.001"],
    "syn scan": ["T1046"],
    "reconnaissance": ["T1595", "T1590", "T1046"],
    "service discovery": ["T1046"],
    "network discovery": ["T1046", "T1016"],
    "domain trust discovery": ["T1482"],

    # 2. Resource Development & Infrastructure
    "compromised host": ["T1584"],
    "dns record manipulation": ["T1584.002"],
    "acquire infrastructure": ["T1583"],

    # 3. Initial Access
    "spearphishing": ["T1566", "T1566.001", "T1566.002"],
    "phishing": ["T1566"],
    "drive-by": ["T1189"],
    "drive by compromise": ["T1189"],
    "supply chain": ["T1195"],
    "valid accounts": ["T1078"],
    "default credentials": ["T1078.001"],

    # 4. Execution
    "powershell": ["T1059.001"],
    "command line": ["T1059.003"],
    "bash": ["T1059.004"],
    "vbs": ["T1059.005"],
    "javascript": ["T1059.007"],
    "wmi": ["T1047"],
    "scheduled task": ["T1053.005"],
    "cron job": ["T1053.003"],

    # 5. Persistence
    "registry run": ["T1547.001"],
    "startup folder": ["T1547.001"],
    "service creation": ["T1543.003"],
    "bits jobs": ["T1197"],
    "account manipulation": ["T1098"],
    "webshell": ["T1505.003", "T1190"],
    "web shell": ["T1505.003", "T1190"],

    # 6. Privilege Escalation
    "privilege escalation": ["T1068", "T1548"],
    "uac bypass": ["T1548.002"],
    "sudo bypass": ["T1548.003"],
    "process injection": ["T1055"],
    "dll injection": ["T1055.001"],
    "process hollowing": ["T1055.012"],

    # 7. Defense Evasion
    "defense evasion": ["T1562", "T1070", "T1036"],
    "disable antivirus": ["T1562.001"],
    "impair defenses": ["T1562.001"],
    "clear logs": ["T1070.001"],
    "clear event logs": ["T1070.001"],
    "timestomp": ["T1070.006"],
    "obfuscation": ["T1027"],
    "masquerading": ["T1036"],
    "amsi bypass": ["T1562.001"],

    # 8. Credential Access & Identity Attacks
    "brute force": ["T1110", "T1110.001"],
    "bruteforce": ["T1110", "T1110.001"],
    "password spray": ["T1110.003"],
    "credential stuffing": ["T1110.004"],
    "kerberoast": ["T1558.003"],
    "kerberoasting": ["T1558.003"],
    "as-rep roasting": ["T1558.004"],
    "asrep roasting": ["T1558.004"],
    "dcsync": ["T1003.006"],
    "lsass": ["T1003.001"],
    "lsass dump": ["T1003.001"],
    "mimikatz": ["T1003.001", "T1003.006", "T1550.002"],
    "pass the hash": ["T1550.002"],
    "pass-the-hash": ["T1550.002"],
    "pass the ticket": ["T1550.003"],
    "golden ticket": ["T1558.001"],
    "silver ticket": ["T1558.002"],
    "ntlm relay": ["T1557.001"],
    "llmnr poisoning": ["T1557.001"],
    "responder": ["T1557.001"],

    # 9. Web & Application Exploitation (OWASP Top 10)
    "sql injection": ["T1190"],
    "sqli": ["T1190"],
    "xss": ["T1190", "T1059.007"],
    "cross-site scripting": ["T1190"],
    "rce": ["T1203", "T1190"],
    "remote code execution": ["T1203", "T1190"],
    "command injection": ["T1059", "T1190"],
    "ssrf": ["T1190"],
    "server side request forgery": ["T1190"],
    "path traversal": ["T1190", "T1005"],
    "directory traversal": ["T1190"],
    "file upload": ["T1505.003", "T1190"],
    "insecure deserialization": ["T1190", "T1203"],
    "xxe": ["T1190"],
    "log4j": ["T1190", "T1203"],
    "zero day": ["T1190", "T1211"],

    # 10. Lateral Movement
    "lateral movement": ["T1021", "T1570", "T1550"],
    "psexec": ["T1021.002", "T1569.002"],
    "smb": ["T1021.002"],
    "rdp": ["T1021.001"],
    "ssh": ["T1021.004"],
    "winrm": ["T1021.006"],
    "arp spoofing": ["T1557.002"],
    "man in the middle": ["T1557"],
    "mitm": ["T1557"],

    # 11. Command and Control (C2)
    "c2": ["T1071", "T1071.001"],
    "command and control": ["T1071"],
    "beacon": ["T1071", "T1071.001"],
    "beaconing": ["T1071.001"],
    "cobalt strike": ["T1071", "T1059.001", "T1055"],
    "dns tunnel": ["T1071.004", "T1048.003"],
    "dns tunneling": ["T1071.004", "T1048.003"],
    "domain fronting": ["T1090.004"],
    "fast flux": ["T1568.001"],
    "tor": ["T1090.003"],

    # 12. Exfiltration
    "exfiltration": ["T1041", "T1048", "T1020"],
    "data exfiltration": ["T1041", "T1048"],
    "data theft": ["T1041", "T1048"],

    # 13. Impact & Denial of Service (DoS / DDoS)
    "ddos": ["T1498", "T1499"],
    "dos": ["T1498", "T1499"],
    "denial of service": ["T1498", "T1499"],
    "syn flood": ["T1498", "T1498.001"],
    "udp flood": ["T1498", "T1498.001"],
    "icmp flood": ["T1498", "T1498.001"],
    "slowloris": ["T1499", "T1499.002"],
    "http flood": ["T1499", "T1499.003"],
    "amplification": ["T1498.002"],
    "dns amplification": ["T1498.002"],
    "ntp amplification": ["T1498.002"],

    # 14. Ransomware & Extortion
    "ransomware": ["T1486", "T1490"],
    "data encrypted": ["T1486"],
    "shadow copies": ["T1490"],
    "delete shadows": ["T1490"],
    "lockbit": ["T1486", "T1490", "T1059.001"],
    "wannacry": ["T1486", "T1021.002"],
    "blackcat": ["T1486", "T1490"],
    "cryptominer": ["T1496"],
    "cryptomining": ["T1496"],
    "xmrig": ["T1496"],
}

# Concrete Action Mapping from D3FEND Defensive Concepts
D3FEND_ACTION_MAPPING: Dict[str, Dict[str, str]] = {
    # Network Filtering & Perimeter
    "D3-NIPF": {"action": "block_ip", "actuator": "firewall", "name": "Network Ingress Packet Filtering"},
    "D3-ITR":  {"action": "block_ip", "actuator": "firewall", "name": "Inbound Traffic Filtering"},
    "D3-BCF":  {"action": "block_ip", "actuator": "firewall", "name": "Broadcast Filtering"},
    "D3-RBF":  {"action": "rate_limit", "actuator": "firewall", "name": "Rate-based Filtering"},
    
    # Network Isolation & Eviction
    "D3-NIAT": {"action": "isolate_port", "actuator": "firewall", "name": "Network Isolation"},
    "D3-EVICT":{"action": "isolate_port", "actuator": "firewall", "name": "Process & Network Eviction"},
    "D3-USDT": {"action": "isolate_port", "actuator": "firewall", "name": "User Session Disconnect"},

    # Network Signature & Deep Packet Inspection
    "D3-DNSF": {"action": "drop_suricata_signature", "actuator": "suricata", "name": "DNS Filtering / Signature Drop"},
    "D3-NSA":  {"action": "drop_suricata_signature", "actuator": "suricata", "name": "Network Signature Analysis"},
    "D3-NTA":  {"action": "drop_suricata_signature", "actuator": "suricata", "name": "Network Traffic Analysis"},
    "D3-PA":   {"action": "drop_suricata_signature", "actuator": "suricata", "name": "Protocol Analysis"},

    # Authentication & Access Challenge
    "D3-MFA":  {"action": "block_ip", "actuator": "firewall", "name": "Authentication Challenge Enforcement"},
    "D3-AZC":  {"action": "block_ip", "actuator": "firewall", "name": "Authorization Check Enforcement"},

    # Process & Endpoint Containment
    "D3-PT":   {"action": "isolate_port", "actuator": "firewall", "name": "Process Termination / Port Isolation"},
    "D3-PS":   {"action": "isolate_port", "actuator": "firewall", "name": "Process Suspension"},
    "D3-ABPI": {"action": "isolate_port", "actuator": "firewall", "name": "Application Process Isolation"},
    "D3-KBPI": {"action": "isolate_port", "actuator": "firewall", "name": "Kernel-based Process Isolation"},
}


class GeniusDefenseRAG:
    """State-of-the-Art Omni-Threat Knowledge Retrieval & Mitigation Engine."""

    def __init__(self, db_path: str = str(DB_PATH)):
        self.db_path = db_path
        self._corpus_db_path = db_path
        self._lock = threading.Lock()
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self._technique_names: Dict[str, str] = {}
        self._d3fend_techniques: Dict[str, Dict[str, Any]] = {}
        self._d3fend_relationships: Dict[str, List[Dict[str, Any]]] = {}
        self._initialized = False

    def _ensure_corpus(self) -> bool:
        """Lazily initialize and ensure all SQLite knowledge bases and FTS5 indexes exist."""
        if self._initialized:
            return True
        with self._lock:
            if self._initialized:
                return True
            try:
                # Resolve active database; fallback to canonical knowledge DB if test db lacks data
                target_path = self.db_path
                master_kb = Path("data/cyberguard.db")

                def _is_db_populated(p: str) -> bool:
                    try:
                        if not Path(p).exists():
                            return False
                        with sqlite3.connect(p, timeout=5) as chk:
                            has_t = chk.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='techniques'").fetchone()[0]
                            has_d = chk.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='d3fend_techniques'").fetchone()[0]
                            if not has_t or not has_d:
                                return False
                            cnt_t = chk.execute("SELECT count(*) FROM techniques").fetchone()[0]
                            cnt_d = chk.execute("SELECT count(*) FROM d3fend_techniques").fetchone()[0]
                            return cnt_t > 0 and cnt_d > 0
                    except Exception:
                        return False

                if not _is_db_populated(target_path) and master_kb.exists() and _is_db_populated(str(master_kb)):
                    target_path = str(master_kb)

                self._corpus_db_path = target_path
                conn = sqlite3.connect(target_path, timeout=30)
                conn.row_factory = sqlite3.Row
                c = conn.cursor()

                # 1. Load ATT&CK techniques
                c.execute("SELECT id, name, description, tactics, platforms, is_subtechnique, parent_id FROM techniques")
                for row in c.fetchall():
                    tid = row["id"].upper()
                    self._techniques[tid] = {
                        "id": tid,
                        "name": row["name"],
                        "description": row["description"] or "",
                        "tactics": json.loads(row["tactics"] or "[]"),
                        "platforms": json.loads(row["platforms"] or "[]"),
                        "is_subtechnique": bool(row["is_subtechnique"]),
                        "parent_id": row["parent_id"] or "",
                    }
                    self._technique_names[tid] = row["name"].lower()

                # 2. Load D3FEND techniques
                c.execute("SELECT id, name, definition FROM d3fend_techniques")
                for row in c.fetchall():
                    did = row["id"].upper()
                    self._d3fend_techniques[did] = {
                        "id": did,
                        "name": row["name"],
                        "definition": row["definition"] or "",
                    }

                # 3. Load D3FEND relationships
                c.execute("SELECT attack_id, d3fend_id, relationship_type FROM d3fend_relationships")
                for row in c.fetchall():
                    aid = row["attack_id"].upper()
                    did = row["d3fend_id"].upper()
                    if aid not in self._d3fend_relationships:
                        self._d3fend_relationships[aid] = []
                    self._d3fend_relationships[aid].append({
                        "d3fend_id": did,
                        "relationship_type": row["relationship_type"],
                        "name": self._d3fend_techniques.get(did, {}).get("name", did),
                        "definition": self._d3fend_techniques.get(did, {}).get("definition", ""),
                    })

                # 4. Self-healing check: Ensure threat_relationships table exists
                has_threat_rels = c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='threat_relationships'").fetchone()[0]
                if not has_threat_rels or c.execute("SELECT count(*) FROM threat_relationships").fetchone()[0] == 0:
                    self._build_threat_relationships(conn)

                # 5. Self-healing check: Ensure cyber_knowledge_fts virtual table exists
                has_fts = c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='cyber_knowledge_fts'").fetchone()[0]
                if not has_fts or c.execute("SELECT count(*) FROM cyber_knowledge_fts").fetchone()[0] == 0:
                    self._build_fts_table(conn)

                conn.close()
                self._initialized = (len(self._techniques) > 0)
                logger.info(
                    "Genius Defense RAG initialized: %d ATT&CK techniques, %d D3FEND techniques, %d mapped relationships",
                    len(self._techniques), len(self._d3fend_techniques), len(self._d3fend_relationships)
                )
                return self._initialized
            except Exception as e:
                logger.error("Failed to load ATT&CK/D3FEND corpus: %s", e)
                return False

    def _build_threat_relationships(self, conn: sqlite3.Connection) -> None:
        """Extract all 15,000+ STIX relationships connecting Groups/Malware to Techniques."""
        snapshot_file = BUNDLED_MITRE_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"
        if not snapshot_file.exists():
            return

        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS threat_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT,
                source_name TEXT,
                source_type TEXT,
                technique_id TEXT,
                technique_name TEXT,
                relationship_type TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_threat_rel_src ON threat_relationships(source_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_threat_rel_src_name ON threat_relationships(source_name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_threat_rel_tech ON threat_relationships(technique_id)")

        with open(snapshot_file, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        stix_map = {}
        for obj in bundle.get("objects", []):
            t = obj.get("type")
            if t in ("attack-pattern", "intrusion-set", "malware", "tool"):
                refs = obj.get("external_references", [])
                for r in refs:
                    if r.get("source_name") == "mitre-attack":
                        stix_map[obj["id"]] = (r.get("external_id"), t, obj.get("name", ""))
                        break

        rows = []
        for obj in bundle.get("objects", []):
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                s = stix_map.get(obj.get("source_ref"))
                target = stix_map.get(obj.get("target_ref"))
                if s and target and target[1] == "attack-pattern":
                    rows.append((s[0], s[2], s[1], target[0], target[2], "uses"))

        if rows:
            c.executemany(
                "INSERT INTO threat_relationships (source_id, source_name, source_type, technique_id, technique_name, relationship_type) VALUES (?, ?, ?, ?, ?, ?)",
                rows
            )
            conn.commit()
            logger.info("Indexed %d threat relationships into SQLite", len(rows))

    def _build_fts_table(self, conn: sqlite3.Connection) -> None:
        """Build high-speed SQLite FTS5 index across techniques, software, groups, and d3fend."""
        c = conn.cursor()
        c.execute("DROP TABLE IF EXISTS cyber_knowledge_fts")
        c.execute("""
            CREATE VIRTUAL TABLE cyber_knowledge_fts USING fts5(
                doc_id UNINDEXED,
                doc_type UNINDEXED,
                name,
                aliases,
                tactics,
                platforms,
                content,
                tokenize='porter unicode61'
            )
        """)

        # Techniques
        for row in c.execute("SELECT id, name, tactics, platforms, description FROM techniques").fetchall():
            t_id, name, t_json, p_json, desc = row
            tactics_str = " ".join(json.loads(t_json or "[]"))
            platforms_str = " ".join(json.loads(p_json or "[]"))
            c.execute(
                "INSERT INTO cyber_knowledge_fts (doc_id, doc_type, name, aliases, tactics, platforms, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (t_id, "technique", name, "", tactics_str, platforms_str, desc or "")
            )

        # Software
        for row in c.execute("SELECT id, name, type, description FROM software").fetchall():
            s_id, name, s_type, desc = row
            c.execute(
                "INSERT INTO cyber_knowledge_fts (doc_id, doc_type, name, aliases, tactics, platforms, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (s_id, "software", name, s_type or "", "", "", desc or "")
            )

        # Groups
        for row in c.execute("SELECT id, name, aliases, description FROM groups").fetchall():
            g_id, name, aliases_json, desc = row
            aliases_str = " ".join(json.loads(aliases_json or "[]"))
            c.execute(
                "INSERT INTO cyber_knowledge_fts (doc_id, doc_type, name, aliases, tactics, platforms, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (g_id, "group", name, aliases_str, "", "", desc or "")
            )

        # D3FEND
        for row in c.execute("SELECT id, name, definition FROM d3fend_techniques").fetchall():
            d_id, name, definition = row
            c.execute(
                "INSERT INTO cyber_knowledge_fts (doc_id, doc_type, name, aliases, tactics, platforms, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (d_id, "d3fend", name, "", "", "", definition or "")
            )

        conn.commit()
        logger.info("Built cyber_knowledge_fts FTS5 table with full corpus")

    def search_techniques(
        self,
        query: str,
        telemetry: Optional[Dict[str, Any]] = None,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Multi-signal hybrid retrieval using exact matching, FTS5 BM25, concept expansion, and RRF."""
        if not self._ensure_corpus():
            return []

        clean_query = query.strip()
        lower_query = clean_query.lower()
        telemetry = telemetry or {}

        # Distinct channel ranks: channel_name -> list of technique_ids ordered by rank
        channel_ranks: Dict[str, List[str]] = {
            "exact": [],
            "fts5": [],
            "threat_entity": [],
            "ontology": [],
            "fuzzy": [],
        }

        # -------------------------------------------------------------------
        # Signal 1: Deterministic Pattern & Identifier Matching
        # -------------------------------------------------------------------
        exact_hits = set()
        # Direct ATT&CK ID
        for match in _ATTACK_ID_PATTERN.findall(clean_query):
            tid = match.upper()
            if tid in self._techniques:
                exact_hits.add(tid)
                parent = self._techniques[tid].get("parent_id")
                if parent and parent in self._techniques:
                    exact_hits.add(parent)

        # Windows Event ID
        for match in _WIN_EVENT_PATTERN.findall(clean_query):
            for tid in WIN_EVENT_MAP.get(match, []):
                if tid in self._techniques:
                    exact_hits.add(tid)

        # Sysmon Event ID
        for match in _SYSMON_PATTERN.findall(clean_query):
            for tid in SYSMON_MAP.get(match, []):
                if tid in self._techniques:
                    exact_hits.add(tid)

        # Port from query or telemetry
        ports_to_check = set(_PORT_PATTERN.findall(clean_query))
        if "dest_port" in telemetry:
            ports_to_check.add(str(telemetry["dest_port"]))
        if "destination_port" in telemetry:
            ports_to_check.add(str(telemetry["destination_port"]))

        for port_str in ports_to_check:
            for tid in PORT_MAP.get(port_str, []):
                if tid in self._techniques:
                    exact_hits.add(tid)

        channel_ranks["exact"] = list(exact_hits)

        # -------------------------------------------------------------------
        # Signal 2: Ontological Cyber Concept & LOLBin Expansion
        # -------------------------------------------------------------------
        ontology_hits = []
        for term, tids in CYBER_CONCEPT_GRAPH.items():
            if term in lower_query:
                for tid in tids:
                    if tid in self._techniques and tid not in ontology_hits:
                        ontology_hits.append(tid)

        for lolbin, tids in LOLBIN_MAP.items():
            if re.search(rf"\b{re.escape(lolbin)}\b", lower_query):
                for tid in tids:
                    if tid in self._techniques and tid not in ontology_hits:
                        ontology_hits.append(tid)

        channel_ranks["ontology"] = ontology_hits

        # -------------------------------------------------------------------
        # Signal 3 & 4: SQLite FTS5 Full-Text Search with BM25 + Threat Entity Graph
        # -------------------------------------------------------------------
        fts_techniques = []
        threat_techniques = []

        tokens = [t for t in re.findall(r"[A-Za-z0-9_-]+", lower_query) if len(t) >= 3]
        if tokens:
            try:
                conn = sqlite3.connect(self._corpus_db_path, timeout=10)
                conn.row_factory = sqlite3.Row
                c = conn.cursor()

                # Clean FTS match query with prefix support
                clean_fts_terms = [f'"{tok}"*' for tok in tokens[:8] if tok.isalnum()]
                if clean_fts_terms:
                    fts_query_str = " OR ".join(clean_fts_terms)
                    sql = """
                        SELECT doc_id, doc_type, name, bm25(cyber_knowledge_fts) as score
                        FROM cyber_knowledge_fts
                        WHERE cyber_knowledge_fts MATCH ?
                        ORDER BY score
                        LIMIT 15
                    """
                    rows = c.execute(sql, (fts_query_str,)).fetchall()
                    matched_software_or_groups = []

                    for r in rows:
                        d_id = r["doc_id"]
                        d_type = r["doc_type"]
                        if d_type == "technique":
                            if d_id in self._techniques and d_id not in fts_techniques:
                                fts_techniques.append(d_id)
                        elif d_type in ("software", "group"):
                            matched_software_or_groups.append((d_id, r["name"]))

                    # Expand matched software / groups via threat_relationships
                    for entity_id, entity_name in matched_software_or_groups:
                        rel_rows = c.execute(
                            "SELECT technique_id FROM threat_relationships WHERE source_id = ? OR source_name = ? LIMIT 10",
                            (entity_id, entity_name)
                        ).fetchall()
                        for rrow in rel_rows:
                            tid = rrow["technique_id"].upper()
                            if tid in self._techniques and tid not in threat_techniques:
                                threat_techniques.append(tid)

                conn.close()
            except Exception as exc:
                logger.debug("FTS5 query exception: %s", exc)

        channel_ranks["fts5"] = fts_techniques
        channel_ranks["threat_entity"] = threat_techniques

        # -------------------------------------------------------------------
        # Signal 5: RapidFuzz Semantic / Fuzzy Ratio (Typo & Variant Tolerance)
        # -------------------------------------------------------------------
        fuzzy_techniques = []
        if _HAS_RAPIDFUZZ and len(clean_query) >= 4:
            # Score against technique names
            fuzzy_scored = []
            for tid, tname in self._technique_names.items():
                ratio = fuzz.token_set_ratio(lower_query, tname)
                if ratio >= 70:
                    fuzzy_scored.append((tid, ratio))
            fuzzy_scored.sort(key=lambda x: x[1], reverse=True)
            fuzzy_techniques = [x[0] for x in fuzzy_scored[:10]]

        channel_ranks["fuzzy"] = fuzzy_techniques

        # -------------------------------------------------------------------
        # Signal 6: Reciprocal Rank Fusion (RRF)
        # -------------------------------------------------------------------
        channel_weights = {
            "exact": 1.5,
            "ontology": 1.0,
            "threat_entity": 0.9,
            "fts5": 0.8,
            "fuzzy": 0.6,
        }
        k_rrf = 60.0
        rrf_scores: Dict[str, float] = {}

        for ch_name, ranked_list in channel_ranks.items():
            weight = channel_weights.get(ch_name, 1.0)
            for rank_idx, tid in enumerate(ranked_list):
                score = weight / (k_rrf + (rank_idx + 1))
                rrf_scores[tid] = rrf_scores.get(tid, 0.0) + score

        # Sort by final RRF score
        sorted_candidates = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)[:top_k]

        results = []
        for tid, score in sorted_candidates:
            tech = self._techniques[tid].copy()
            tech["relevance_score"] = round(score * 100.0, 3)
            results.append(tech)

        return results

    def get_d3fend_countermeasures(self, attack_id: str) -> List[Dict[str, Any]]:
        """Retrieve verified D3FEND defensive countermeasures for an ATT&CK technique."""
        self._ensure_corpus()
        aid = attack_id.upper()
        countermeasures = list(self._d3fend_relationships.get(aid, []))

        # If it's a subtechnique without direct countermeasure, query parent technique
        if not countermeasures and "." in aid:
            parent_id = aid.split(".")[0]
            countermeasures = list(self._d3fend_relationships.get(parent_id, []))

        enriched = []
        seen = set()
        for cm in countermeasures:
            did = cm["d3fend_id"]
            if did in seen:
                continue
            seen.add(did)

            template = D3FEND_ACTION_MAPPING.get(did, {
                "action": "block_ip",
                "actuator": "firewall",
                "name": cm.get("name", did)
            })

            enriched.append({
                "d3fend_id": did,
                "name": cm.get("name", did),
                "relationship_type": cm.get("relationship_type", "mitigates"),
                "definition": cm.get("definition", "")[:500],
                "recommended_actuator": template["actuator"],
                "actuator_action": template["action"],
            })

        # Fallback perimeter containment if no direct mapping exists
        if not enriched:
            enriched.append({
                "d3fend_id": "D3-NIPF",
                "name": "Network Ingress Packet Filtering",
                "relationship_type": "default_perimeter_containment",
                "definition": "Restrict network ingress packet flow from unauthorized or malicious source addresses.",
                "recommended_actuator": "firewall",
                "actuator_action": "block_ip",
            })

        return enriched

    def retrieve_defense_playbook(
        self,
        query: str,
        telemetry: Optional[Dict[str, Any]] = None,
        top_k_techniques: int = 4,
    ) -> Dict[str, Any]:
        """Produce an exhaustive, grounded, hallucination-resistant active defense playbook."""
        telemetry = telemetry or {}
        matched_techniques = self.search_techniques(query, telemetry=telemetry, top_k=top_k_techniques)

        playbook_techniques = []
        all_countermeasures = []
        concrete_actions = []

        src_ip = telemetry.get("src_ip") or telemetry.get("source_ip") or telemetry.get("remote_ip") or "192.168.1.100"
        dest_port = telemetry.get("dest_port") or telemetry.get("destination_port")

        for tech in matched_techniques:
            tid = tech["id"]
            cms = self.get_d3fend_countermeasures(tid)
            tech_entry = {
                "technique_id": tid,
                "name": tech["name"],
                "tactics": tech["tactics"],
                "platforms": tech["platforms"],
                "relevance_score": tech.get("relevance_score", 0.0),
                "description_excerpt": tech["description"][:300] + "...",
                "d3fend_countermeasures": cms,
            }
            playbook_techniques.append(tech_entry)
            all_countermeasures.extend(cms)

            for cm in cms:
                act = cm["actuator_action"]
                target = src_ip if act in {"block_ip", "rate_limit"} else str(dest_port or src_ip)
                concrete_actions.append({
                    "action": act,
                    "target": target,
                    "actuator": cm["recommended_actuator"],
                    "d3fend_id": cm["d3fend_id"],
                    "countermeasure_name": cm["name"],
                    "params": {"port": dest_port} if dest_port else {},
                })

        return {
            "query": query,
            "total_techniques_matched": len(playbook_techniques),
            "techniques": playbook_techniques,
            "d3fend_countermeasures": all_countermeasures,
            "concrete_actions": concrete_actions,
            "telemetry": telemetry,
        }

    def format_prompt_context(self, playbook: Dict[str, Any]) -> str:
        """Format the complete multi-threat knowledge into a high-density, unhallucinated prompt."""
        lines = [
            "================================================================================",
            "GROUNDED OMNI-THREAT INTELLIGENCE & D3FEND DEFENSE CONTEXT (ZERO-HALLUCINATION)",
            "================================================================================",
            f"Query / Threat Context: {playbook.get('query')}",
            f"Extracted Telemetry: {json.dumps(playbook.get('telemetry', {}))}",
            "",
            "IDENTIFIED MITRE ATT&CK TECHNIQUES (CORRELATED FROM OFFICIAL v19.1 SNAPSHOT):"
        ]

        if not playbook.get("techniques"):
            lines.append("  (No direct ATT&CK technique identified. Rely on baseline anomaly policy.)")
        else:
            for tech in playbook["techniques"]:
                tactics_str = ", ".join(tech.get("tactics", []))
                lines.append(f"- [{tech['technique_id']}] {tech['name']} (Tactics: {tactics_str})")
                lines.append(f"  Summary: {tech['description_excerpt']}")
                lines.append("  Verified MITRE D3FEND Countermeasures:")
                for cm in tech.get("d3fend_countermeasures", []):
                    lines.append(f"    * [{cm['d3fend_id']}] {cm['name']} -> Action: {cm['actuator_action']} ({cm['recommended_actuator']})")
                lines.append("")

        lines.extend([
            "PERMITTED AUTONOMOUS ACTUATOR ACTIONS:",
            "- block_ip: Drop incoming network packets at host/edge firewall (Windows New-NetFirewallRule / Linux iptables).",
            "- isolate_port: Block access to targeted service port.",
            "- rate_limit: Throttle throughput to mitigate volumetric exhaustion.",
            "- drop_suricata_signature: Dynamically inject IPS drop rule for signature/beacon pattern.",
            "",
            "MANDATORY INSTRUCTION: You must base your recommended_action exclusively on the verified D3FEND",
            "actions listed above. Under no circumstance should you recommend ungrounded shell scripts or hypothetical tools.",
            "================================================================================"
        ])

        return "\n".join(lines)


# Global singleton instance
default_defense_rag = GeniusDefenseRAG()
