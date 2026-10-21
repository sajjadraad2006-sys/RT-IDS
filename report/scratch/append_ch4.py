import os

# Append Sections 4.18 and 4.19 to Chapter 4
content_to_append = '''

## 4.18 Database Persistence, SQLite Concurrency, and Hash-Chained Audit Trail

### 4.18.1 Concurrency Model and SQLite Engine Configuration
CyberGuard implements its primary persistence tier using an embedded SQLite database managed through the SQLAlchemy Object-Relational Mapping (ORM) framework `[CE-36]`. While enterprise Security Operations Centers (SOCs) traditionally deploy distributed relational databases (e.g., PostgreSQL clusters), edge-deployed intrusion detection appliances operate under stringent resource envelopes, requiring zero-dependency embedded persistence that avoids inter-process network round-trips.

To overcome SQLite's default database-level lock contention during concurrent sniffer ingestion and REST API queries, the engine initialization routine in `backend/db/models.py` establishes three critical runtime pragmas via SQLAlchemy connect event listeners `[CE-36]`:

```python
# File: backend/db/models.py:22-31
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    future=True,
    connect_args={"check_same_thread": False, "timeout": 30}
)

@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.close()
```

1. **Write-Ahead Logging (`PRAGMA journal_mode=WAL;`):** WAL mode decouples concurrent read operations from write transactions. Writers append new database pages to a dedicated `-wal` auxiliary file without overwriting the primary `.db` database pages. Consequently, long-running telemetry analytics queries executed by SOC analysts proceed entirely concurrently without blocking real-time sniffer alert ingestion workers.
2. **Synchronous Relaxed I/O (`PRAGMA synchronous=NORMAL;`):** In standard `FULL` synchronous mode, SQLite issues physical filesystem synchronization barriers (e.g., `fsync()`) at every critical transaction phase. Setting `synchronous=NORMAL` restricts physical disk syncs to WAL checkpoint events, achieving an order-of-magnitude reduction in disk I/O wait latency while preserving ACID atomicity across application crashes.
3. **Foreign Key Integrity (`PRAGMA foreign_keys=ON;`):** By default, SQLite disables foreign key constraint enforcement for backwards compatibility. Enforcing foreign key constraints ensures relational integrity between `alerts` and their associated `mitre_techniques` mapping records.
4. **Thread Concurrency (`check_same_thread=False, timeout=30`):** Multi-threaded FastAPI worker threads are permitted to share the database connection pool, with a 30-second busy timeout allowing transient write locks to resolve without throwing immediate `sqlite3.OperationalError: database is locked` exceptions.

### 4.18.2 Machine-Local Credential Protection and Link-Traversal Hardening
Persistent storage of sensitive operational secrets (e.g., administrative API keys, external threat feed tokens) requires cryptographic protection against local filesystem compromise. CyberGuard utilizes symmetric Fernet encryption derived from a local machine secret `[CE-37]`. To prevent symbolic link traversal attacks (CWE-59) in multi-tenant environments, key initialization in `backend/db/models.py` strictly verifies file ownership and permissions:

```python
# File: backend/db/models.py:34-56
def _fernet():
    """Open the machine-local key without following attacker-created links."""
    from cryptography.fernet import Fernet

    key_file = DB_PATH.parent / ".secret_key"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(key_file, flags)
    except FileNotFoundError:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        create_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(key_file, create_flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(Fernet.generate_key())
        except FileExistsError:
            pass
        fd = os.open(key_file, flags)

    with os.fdopen(fd, "rb") as handle:
        mode = stat.S_IMODE(os.fstat(handle.fileno()).st_mode)
        if mode & 0o077:
            os.fchmod(handle.fileno(), 0o600)
        key = handle.read()
    return Fernet(key)
```

By specifying `os.O_NOFOLLOW`, the POSIX kernel immediately rejects opening `.secret_key` if an adversary has created a symbolic link pointing to sensitive system files. Furthermore, the file is created atomically with `O_CREAT | O_EXCL` and mode `0o600` (read/write by owner only), and runtime permissions are defensively sanitized via `os.fchmod()` to prevent group or world readability.

### 4.18.3 Cryptographic Hash-Chained Audit Trail
For containment decisions and administrative overrides, post-incident forensic integrity requires tamper-evident audit logging. CyberGuard implements an append-only, cryptographic hash-chained ledger in `backend/decision/audit.py` `[CE-38]`.

Let $E_i$ represent the $i$-th audit event record in table `audit_events`. The event is characterized by the tuple:
$$E_i = (t_i, a_i, \alpha_i, \tau_i, \text{id}_i, p_i, h_{i-1})$$
where $t_i$ is the Unix timestamp, $a_i$ is the initiating actor (e.g., analyst identity or autonomous daemon), $\alpha_i$ is the action verb, $\tau_i$ is the entity type, $\text{id}_i$ is the entity identifier, $p_i$ is the JSON payload containing execution parameters, and $h_{i-1}$ is the cryptographic digest of the immediately preceding event ($h_0 = \text{""}$ for the genesis event).

The event hash $h_i$ is computed via SHA-256 over a strictly canonicalized JSON byte stream:
$$m_i = \text{JSON}_{\text{canon}}\left(\{ \text{"created_at"}: t_i, \text{"actor"}: a_i[:64], \text{"action"}: \alpha_i[:64], \text{"entity_type"}: \tau_i[:32], \text{"entity_id"}: \text{id}_i[:64], \text{"payload_json"}: p_i, \text{"previous_hash"}: h_{i-1} \}\right)$$
$$h_i = \mathcal{H}_{\text{SHA-256}}(m_i) \tag{4.12}$$

Canonicalization enforces lexicographically sorted keys and minimal token delimiters (`separators=(",", ":")`), ensuring that serialization whitespace variations cannot invalidate the digest.

Verification of chain integrity is performed by `verify_audit_chain()` `[CE-39]`. If an attacker directly alters a historical database row $E_k$ ($k < N$) or truncates intermediate records, the recalculation of $h_k$ diverges from the stored digest ($h_k \neq \mathcal{H}_{\text{SHA-256}}(m_k)$), or the pointer equality breaks ($h_{k-1} \neq E_k.\text{previous_hash}$), resulting in immediate verification failure:

```python
# File: backend/decision/audit.py:44-62
def verify_audit_chain(events: list[AuditEvent]) -> bool:
    previous_hash = ""
    for event in events:
        material = json.dumps({
            "created_at": event.created_at,
            "actor": event.actor,
            "action": event.action,
            "entity_type": event.entity_type,
            "entity_id": event.entity_id,
            "payload_json": event.payload_json,
            "previous_hash": previous_hash,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if event.previous_hash != previous_hash:
            return False
        if event.event_hash != hashlib.sha256(material).hexdigest():
            return False
        previous_hash = event.event_hash
    return True
```

### 4.18.4 Zero-Downtime Forward-Only Schema Migration
To support progressive architectural enhancements without requiring destructive database drops, `backend/db/init_db.py` implements forward-only DDL migrations executed during application startup `[CE-40]`. Using SQLAlchemy runtime schema reflection (`inspect(target_engine).get_columns()`), the migration harness inspects existing table definitions and dynamically executes non-destructive `ALTER TABLE ADD COLUMN` statements:

1. `_migrate_decision_cases()`: Appends analyst feedback attributes (`analyst_verdict`, `analyst_notes`, `reviewed_by`, `reviewed_at`, `policy_version`) to persist human-in-the-loop triage.
2. `_migrate_alerts()`: Appends Pipeline v2 routing provenance (`route`, `pipeline_version`, `evidence_json`, `input_schema_json`) to ensure legacy v1 databases remain backward-compatible with v2 telemetry.
3. `_migrate_security_event_technique_mappings()`: Defensively reconciles legacy schema discrepancies (e.g., dropping obsolete `confidence` columns).

## 4.19 Frontend Telemetry and Operational Visualization

### 4.19.1 Architectural Paradigm and Operational State Machine
CyberGuard includes an administrative operations dashboard designed for deployment in Security Operations Centers. The frontend is built as a lightweight, reactive Single-Page Application (SPA) communicating over authenticated REST endpoints.

The operational UI state machine balances real-time situational awareness with browser memory bounding:
1. **Bounded Polling and Stream Emulation:** Rather than establishing unbounded persistent WebSocket channels that risk resource exhaustion under DDoS alert floods, the dashboard implements a bounded polling controller (`test_frontend_live_operations.py`) that queries `/api/events/alerts` with an adaptive jittered backoff interval ($1.0\text{ s} \le \Delta t_{\text{poll}} \le 5.0\text{ s}$).
2. **Circular Ring Buffer in DOM:** To prevent memory leaks in analyst workstations during sustained network attacks generating thousands of alerts per minute, the frontend client maintains a bounded FIFO ring buffer of 250 alert nodes. Older alert elements are pruned from the DOM tree, avoiding layout recalculation degradation.
3. **Dual-Authorization Modal Dialog:** When an analyst triggers an active containment action (such as process suspension or network port isolation), the UI blocks execution and displays a dual-credential modal requiring the secondary approver to supply their independent username, password, and MFA token before submitting the signed JSON payload to `/api/decisions/execute`.
4. **Offline Resilience:** If network connectivity to the FastAPI backend is interrupted, the UI enters a visual fail-safe degraded state, disabling all active containment actuators while preserving the local cached triage view.
'''

with open('report/chapters/04-implementation-analysis.md', 'r', encoding='utf-8') as f:
    text = f.read()

if '## 4.18 Database Persistence' not in text:
    with open('report/chapters/04-implementation-analysis.md', 'a', encoding='utf-8') as f:
        f.write(content_to_append)
    print('Successfully appended Sections 4.18 and 4.19 to 04-implementation-analysis.md')
else:
    print('Sections 4.18 already present.')
