"""
Layer 6: MITRE ATT&CK Synchronization Module
Fetches up-to-date STIX 2.1 objects from official MITRE TAXII 2.1 server or GitHub fallback.
"""

import json
import sqlite3
import requests
from pathlib import Path
from typing import Dict, List, Any
from cyberguard.config import BASE_DIR, MITRE_TAXII_URL

DB_PATH = BASE_DIR / "mitre" / "attack_knowledge.db"
DB_PATH.parent.mkdir(exist_ok=True)

class MITRESync:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database schema for storing MITRE ATT&CK techniques."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_techniques (
                technique_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                tactic TEXT,
                stix_id TEXT
            )
        """)
        conn.commit()
        conn.close()

    def fetch_from_github_fallback(self) -> int:
        """Fetch latest Enterprise ATT&CK STIX JSON from MITRE official GitHub repository."""
        print("[+] Syncing MITRE ATT&CK from official GitHub repository...")
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            stix_data = resp.json()
            
            techniques_count = 0
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for obj in stix_data.get("objects", []):
                if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                    stix_id = obj.get("id")
                    name = obj.get("name", "")
                    description = obj.get("description", "")
                    
                    # Extract Technique ID (e.g. T1059)
                    external_refs = obj.get("external_references", [])
                    tech_id = None
                    for ref in external_refs:
                        if ref.get("source_name") == "mitre-attack":
                            tech_id = ref.get("external_id")
                            break
                            
                    if tech_id:
                        # Extract primary tactic
                        tactics = [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])]
                        tactic_str = ", ".join(tactics) if tactics else "unknown"
                        
                        cursor.execute("""
                            INSERT OR REPLACE INTO attack_techniques (technique_id, name, description, tactic, stix_id)
                            VALUES (?, ?, ?, ?, ?)
                        """, (tech_id, name, description, tactic_str, stix_id))
                        techniques_count += 1
                        
            conn.commit()
            conn.close()
            print(f"[✓] Successfully ingested {techniques_count} MITRE ATT&CK techniques into database.")
            return techniques_count
        except Exception as e:
            print(f"[✗] Error syncing MITRE ATT&CK: {e}")
            return 0

    def query_technique(self, technique_id: str) -> Dict[str, Any]:
        """Query a stored technique by its ID (e.g., T1071)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT technique_id, name, description, tactic FROM attack_techniques WHERE technique_id = ?", (technique_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "technique_id": row[0],
                "name": row[1],
                "description": row[2],
                "tactic": row[3]
            }
        return {}
