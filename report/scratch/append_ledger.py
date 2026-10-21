new_claims = """| **CLM-051** | SQLite Concurrency Pragmas | SQLite configured with WAL journal mode, relaxed sync (NORMAL), foreign keys ON, and 30s timeout | [`backend/db/models.py:22-31`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/backend/db/models.py#L22-L31) [CE-36] | **Verified** |
| **CLM-052** | Machine Secret Symlink Hardening | Local Fernet key created with `O_CREAT | O_EXCL`, `O_NOFOLLOW`, and `0o600` permissions | [`backend/db/models.py:34-58`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/backend/db/models.py#L34-L58) [CE-37] | **Verified** |
| **CLM-053** | Hash-Chained Audit Trail | Audit events chained via SHA-256 over canonicalized JSON; verified sequentially on demand | [`backend/decision/audit.py:15-62`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/backend/decision/audit.py#L15-L62) [CE-38],[CE-39] | **Verified** |
| **CLM-054** | Non-Destructive Migrations | Schema evolution implemented via SQLAlchemy reflection without dropping existing alert records | [`backend/db/init_db.py:8-48`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/backend/db/init_db.py#L8-L48) [CE-40] | **Verified** |
| **CLM-055** | Propositional Safety Gate | Safety invariants reduce to a 2-term boolean formula over 4 propositions; 3/16 states blocked | [`backend/safety/formal_verifier.py:28-48`](file:///c:/Users/wwwsa/OneDrive/Desktop/sec/backend/safety/formal_verifier.py#L28-L48) [CE-18],[CE-42] | **Verified** |
"""

with open('report/CLAIMS_LEDGER.md', 'r', encoding='utf-8') as f:
    content = f.read()

if 'CLM-051' not in content:
    with open('report/CLAIMS_LEDGER.md', 'a', encoding='utf-8') as f:
        f.write(new_claims)
    print('Successfully added CLM-051 through CLM-055 to CLAIMS_LEDGER.md')
else:
    print('CLM-051 already exists.')
