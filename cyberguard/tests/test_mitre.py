"""
MITRE ATT&CK Sync Test Script
Tests syncing Enterprise ATT&CK techniques from official GitHub repository into SQLite.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from cyberguard.layer6_mitre.taxii_sync import MITRESync

def run_test():
    print("=================================================================")
    print("              CyberGuard Layer 6 MITRE Sync Test                 ")
    print("=================================================================")
    
    sync = MITRESync()
    count = sync.fetch_from_github_fallback()
    
    if count > 0:
        # Query sample technique (e.g. T1071 - Application Layer Protocol)
        sample_id = "T1071"
        tech_info = sync.query_technique(sample_id)
        print(f"\n--- Query Technique {sample_id} ---")
        print(f"Name: {tech_info.get('name')}")
        print(f"Tactic: {tech_info.get('tactic')}")
        print(f"Description: {tech_info.get('description', '')[:120]}...")
        print("\n[✓] MITRE ATT&CK Sync verification complete!")
    else:
        print("[✗] Failed to sync MITRE ATT&CK techniques.")

if __name__ == "__main__":
    run_test()
