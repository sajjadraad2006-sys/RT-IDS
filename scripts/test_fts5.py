import sqlite3
import json
import time

conn = sqlite3.connect('data/cyberguard.db')
c = conn.cursor()
t0 = time.time()
c.execute('DROP TABLE IF EXISTS cyber_knowledge_fts')
c.execute('''
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
''')

# 1. Techniques
for row in c.execute('SELECT id, name, tactics, platforms, description FROM techniques').fetchall():
    t_id, name, t_json, p_json, desc = row
    tactics_str = ' '.join(json.loads(t_json or '[]'))
    platforms_str = ' '.join(json.loads(p_json or '[]'))
    c.execute(
        'INSERT INTO cyber_knowledge_fts (doc_id, doc_type, name, aliases, tactics, platforms, content) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (t_id, 'technique', name, '', tactics_str, platforms_str, desc or '')
    )

# 2. Software
for row in c.execute('SELECT id, name, type, description FROM software').fetchall():
    s_id, name, s_type, desc = row
    c.execute(
        'INSERT INTO cyber_knowledge_fts (doc_id, doc_type, name, aliases, tactics, platforms, content) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (s_id, 'software', name, s_type or '', '', '', desc or '')
    )

# 3. Groups
for row in c.execute('SELECT id, name, aliases, description FROM groups').fetchall():
    g_id, name, aliases_json, desc = row
    aliases_str = ' '.join(json.loads(aliases_json or '[]'))
    c.execute(
        'INSERT INTO cyber_knowledge_fts (doc_id, doc_type, name, aliases, tactics, platforms, content) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (g_id, 'group', name, aliases_str, '', '', desc or '')
    )

# 4. D3FEND techniques
for row in c.execute('SELECT id, name, definition FROM d3fend_techniques').fetchall():
    d_id, name, definition = row
    c.execute(
        'INSERT INTO cyber_knowledge_fts (doc_id, doc_type, name, aliases, tactics, platforms, content) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (d_id, 'd3fend', name, '', '', '', definition or '')
    )

conn.commit()
dt = time.time() - t0
print(f"FTS5 virtual table built successfully in {dt:.3f} seconds!")

# Sample queries
test_queries = [
    "ransomware",
    "cobalt strike beacon",
    "kerberoast",
    "mimikatz lsass",
    "sql injection",
    "ddos syn flood",
]

for q in test_queries:
    clean_q = " OR ".join([f'"{w}"' for w in q.split() if len(w) > 2])
    query_sql = """
        SELECT doc_id, doc_type, name, bm25(cyber_knowledge_fts) as score
        FROM cyber_knowledge_fts
        WHERE cyber_knowledge_fts MATCH ?
        ORDER BY score
        LIMIT 3
    """
    rows = c.execute(query_sql, (clean_q,)).fetchall()
    print(f"\nQuery: '{q}' (FTS MATCH: {clean_q})")
    for r in rows:
        print(f"  -> [{r[1]}] {r[0]}: {r[2]} (bm25 score: {r[3]:.3f})")

conn.close()
