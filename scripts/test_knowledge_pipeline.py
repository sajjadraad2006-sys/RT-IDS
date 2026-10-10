"""Verification script for the new Genius Defense RAG architecture."""
import sqlite3
import json
import time

def test_complete_knowledge_pipeline():
    conn = sqlite3.connect("data/cyberguard.db")
    c = conn.cursor()
    
    # 1. Check techniques count
    tech_count = c.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
    print(f"ATT&CK Techniques: {tech_count}")
    assert tech_count >= 690, "Expected at least 690 techniques"

    # 2. Check d3fend techniques & relationships
    d3_count = c.execute("SELECT COUNT(*) FROM d3fend_techniques").fetchone()[0]
    rel_count = c.execute("SELECT COUNT(*) FROM d3fend_relationships").fetchone()[0]
    print(f"D3FEND Techniques: {d3_count}, Relationships: {rel_count}")
    assert d3_count >= 200, "Expected at least 200 D3FEND techniques"
    assert rel_count >= 4000, "Expected at least 4000 D3FEND relationships"

    # 3. Check threat relationships
    threat_rel_count = c.execute("SELECT COUNT(*) FROM threat_relationships").fetchone()[0]
    print(f"Threat Relationships (Software/Groups -> Techniques): {threat_rel_count}")
    assert threat_rel_count >= 15000, "Expected at least 15000 threat relationships"

    # 4. Check FTS5
    fts_count = c.execute("SELECT COUNT(*) FROM cyber_knowledge_fts").fetchone()[0]
    print(f"Cyber Knowledge FTS5 Documents: {fts_count}")
    assert fts_count >= 1500, "Expected at least 1500 FTS documents"

    conn.close()
    print("ALL CORE KNOWLEDGE BASES ARE POPULATED AND READY!")

if __name__ == "__main__":
    test_complete_knowledge_pipeline()
