# Security knowledge, correlation, and Live Operations

Measured state: 2026-08-31. This document describes the implemented local behavior; it is not a model-accuracy claim.

## ATT&CK lifecycle

CyberGuard retrieves a pinned Enterprise ATT&CK release JSON from MITRE's official `attack-stix-data` publication repository.[1] `backend.mitre.taxii_sync` bounds the response to 100 MiB, records the source URL, release, retrieval time, and SHA-256, and writes the exact downloaded bytes atomically. It does not write unversioned `master/enterprise-attack.json` into a versioned filename.

`backend.mitre.attack_db.activate_snapshot` validates the bundle size, provenance hash, collection release metadata, external reference format, revoked/deprecated state, and active technique set. It replaces techniques, inactive techniques, groups, software, and activation metadata in one SQLite transaction. Failed attempts are audit-recorded without replacing the last-known-good active snapshot.

`backend.mitre.lifecycle.activate_with_rag` builds an isolated SQLite candidate and an isolated TF-IDF RAG candidate before activating the operational database. The current verified local result is ATT&CK v19.1, 25,843 STIX objects, 697 active techniques, and matching 697-row RAG coverage. Static classifier mappings remain heuristic hypotheses. Suricata rule metadata remains an evidence-supported candidate mapping. Unknown anomalies create no ATT&CK mapping.

## D3FEND lifecycle

MITRE publishes versioned D3FEND ontology JSON and inferred relationship JSON resources.[2] `backend.mitre.d3fend_sync` retrieves the pinned versioned files with bounded retries, timeouts, and response size. `backend.mitre.d3fend.D3fendStore` joins inferred ATT&CK relationships only to active ontology techniques with official D3FEND IDs, replaces the active index transactionally, and retains the prior active index on failure.

The measured v1.5.0 index contains 272 active defensive techniques and 4,154 deduplicated inferred relationships. API and UI wording is "candidate defensive techniques." Every result includes source version/hash, mapping version, relationship type, evidence source, and `executed_action: false`. An unverified originating ATT&CK identifier returns no D3FEND candidate. Display never means deployment or execution.

## Vulnerability intelligence

CISA KEV parsing follows the official catalog JSON/schema fields and rejects count mismatches or invalid CVE identifiers.[3] FIRST EPSS parsing stores the model version, score, percentile, and score date; EPSS is displayed as probability context, not evidence that exploitation occurred.[4] OSV queries follow the package ecosystem/name/version request model and are performed only when all three fields exist.[5]

`backend.intelligence.sync` provides:

- 5/30-second connect/read timeouts;
- at most three attempts with bounded exponential or `Retry-After` delays;
- ETag conditional retrieval;
- 64 MiB compressed-download and 256 MiB decompression limits;
- atomic local cache replacement;
- independent KEV and EPSS failure handling;
- last-known-good active data when refresh fails.

Measured live synchronization on 2026-08-31 indexed 1,687 KEV records at catalog version `2026.08.31` and 366,526 EPSS records at model version `v2026.06.15`. These counts describe feed ingestion only. OSV remains on-demand and returns `insufficient_package_context` for raw network evidence.

## Correlation, triage, and risk

`backend.operations.incidents.IncidentStore` correlates immutable evidence references by bounded sensor/community-ID, sensor/flow-ID, or sensor/signature windows. It hashes correlation dimensions rather than persisting address tuples in the incident index. Defaults are a 300-second window, 500 unique references per incident, and 10,000 incidents. A full incident rotates at the cap so unique source-event links are preserved. Replayed UI polling does not inflate duplicate counts.

Triage policy `triage-policy-v1` persists explicit states and full evidence/provenance context. Unknown anomalies, conflicting evidence, missing telemetry, unapproved artifacts, and uncertain results remain human-review exceptions. Only a production-approved artifact and validated policy may analytically auto-close benign evidence. Analyst resolution is append-only, hash-chained, and records `executed_action: none`.

Risk formula `transparent-risk-v1` returns every contribution separately: sensor evidence, classifier, calibrated statistical/OOD evidence, asset criticality, KEV, EPSS, package vulnerability, ATT&CK context, uncertainty adjustment, and freshness penalty. Uncalibrated saturated statistical values contribute zero and carry a warning. Missing context is explicit. The score prioritizes review and never authorizes containment.

## Live Operations

The browser sends an idempotent `POST /api/operations/refresh` every four seconds; `GET /api/operations/snapshot` remains read-only. It pauses while the tab or Live Operations view is hidden, aborts any request that becomes hidden or is superseded, prevents overlapping requests, ignores stale responses, and deduplicates each source independently. Polling is bounded to 3-5 seconds and 500 records per source response.

The page separates:

- persisted results from uploaded precomputed flow records;
- imported Suricata EVE evidence;
- simulated demo data;
- unconfigured future adapters.

It shows connection/degraded state, last success, last error, manual refresh, pause/resume, source freshness, incidents, review exceptions, triage, and transparent risk. It does not describe uploaded records as sensor streaming or packet inspection. No containment, firewall, quarantine, isolation, or EDR action is implemented.

## Commands

```bash
# Start locally
./venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Deterministic flow fixture
./venv/bin/python -m cyberguard.datasets.generate_sample --output cyberguard/datasets/cicids2017/sample_traffic.csv --rows 2000
./venv/bin/python -m cyberguard.datasets.generate_sample --check

# Official security knowledge and feeds
./venv/bin/python -m backend.mitre.taxii_sync
./venv/bin/python -m backend.mitre.d3fend_sync --version 1.5.0
./venv/bin/python -m backend.intelligence.sync

# Verification
./venv/bin/python -m pytest -q
./venv/bin/python verify.py
./venv/bin/python -m compileall -q backend cyberguard tests
for file in frontend/js/*.js; do node --check "$file"; done
./venv/bin/python -m bandit -r backend cyberguard -x '*/tests/*' -f txt
./venv/bin/python -m pip_audit --local --progress-spinner off
```

## Sources

[1] https://github.com/mitre-attack/attack-stix-data

[2] https://d3fend.mitre.org/resources/ontology

[3] https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json

[4] https://api.first.org/epss

[5] https://google.github.io/osv.dev/api
