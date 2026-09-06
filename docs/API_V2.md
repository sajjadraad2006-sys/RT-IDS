# CyberGuard API v2 contract

The server binds to loopback by default. OpenAPI is available at `/docs`.
This API analyzes uploaded flow records; it does not accept raw packets or
provide a network capture endpoint.

## `POST /api/detect/upload`

Multipart field: `file`.

Accepted extensions are `.csv`, `.tsv`, `.json`, `.ndjson`, and `.jsonl`.
CSV/TSV must have a header. JSON must contain an object or homogeneous object
array; NDJSON/JSONL requires one object per line. The schema must cover the 32
canonical features directly or through safe derivations.

Status codes:

- `200`: at least one row passed schema/numeric validation and was analyzed.
- `400`: malformed UTF-8/container, binary content, empty upload, or parse error.
- `413`: byte or parsed-row limit exceeded.
- `422`: unsupported extension/schema, headerless/arbitrary content, or no
  usable row after numeric validation.
- `503`: active artifacts are unavailable, invalid, or inconsistent with v2
  calibration metadata.

Important response fields:

```json
{
  "pipeline_version": "cyberguard-pipeline-v2",
  "artifact_pipeline_version": "cyberguard-pipeline-legacy-v1",
  "operational_mode": "evaluation_only",
  "total_parsed": 10,
  "accepted": 9,
  "rejected": 1,
  "analyzed": 9,
  "alerts_generated": 2,
  "alerts_returned": 2,
  "alerts_persisted": 2,
  "caps": {},
  "schema_validation": {},
  "route_counts": {},
  "evidence_signal_counts": {},
  "component_execution_counts": {},
  "pipeline_stats": {"scope": "this_upload"},
  "process_lifetime_stats": {"scope": "process_lifetime"},
  "alerts": []
}
```

`alerts` contains at most 500 records; persistence is capped at 5,000 alerts
per upload. Counts always describe generated, returned, and persisted records
separately. Results retain accepted input order.

Each alert exposes `route`, `stage`, finite signal values, pipeline/artifact
versions and canonical feature evidence. `mitre_techniques` is a heuristic
classifier-label mapping. It is empty for unknown-anomaly routes.

Raw duplicate member names in JSON objects are never collapsed. Escaped
spellings that decode to the same member, Unicode-normalization-equivalent
members, and nested-object duplicates follow the same rule. A duplicate in a
top-level JSON object or array member is a fatal `400` parse error with stable
reason `duplicate_json_key`. In NDJSON/JSONL it is a recoverable rejected line
with that reason in `schema_validation.rejection_reasons`; different aliases
for one canonical feature continue through the existing per-row conflict check.

Inference batches do not mutate process-lifetime counters. The endpoint keeps a
constant-space upload aggregate and commits it only after the full container and
byte/row limits have passed and bounded persistence reaches its commit point.
Fatal malformed-container, byte/row-limit, schema, later-batch inference,
response-preparation, and final persistence failures therefore emit no
successful upload statistics and persist no alert, ATT&CK mapping, Smart Log,
or decision case. Parser wrappers are closed deterministically. Valid uploads
update process statistics once.

## `GET /api/detect/health`

Returns artifact integrity/readiness and explicit scope:

- `operational_mode`, `production_approved`, `evaluation_only`;
- `pipeline_version`, `routing_schema_version`;
- `coverage_contract_present`, supported/evaluated/OOD-only/unsupported labels;
- telemetry profile and actual loaded state;
- latest candidate status without activating it.

`loaded` means the verified detector bundle was actually loaded. Advisory LLM
selection is unrelated to detection readiness.

## ATT&CK mappings

`GET /api/mitre/techniques` and `/api/mitre/techniques/{id}` return
`candidate_mapping` and provenance counts. The semantic label is “possible
technique based on classifier label,” not observed attacker behavior. Mapping
rows contain the alert ID, classifier label, mapping version, confidence, and
`observed_evidence=false`.

## Advisory endpoints

`POST /api/chat` uses a validated session ID, a bounded recent history from
that session only, and ATT&CK context only above the retrieval relevance
threshold. Prompts include operational mode, approval state, supported scope,
pipeline version and limitations.

`POST /api/detect/explain/{alert_id}` and
`POST /api/decision/evaluate/{alert_id}` treat a detector result as bounded
model evidence. The LLM cannot clear an unknown/ambiguous case, modify the
detector, or execute a response. Provider failure returns deterministic policy
fallback/degradation rather than breaking inference.

## Suricata Evidence Bridge endpoints

Detailed in [`docs/SURICATA_EVIDENCE_BRIDGE.md`](SURICATA_EVIDENCE_BRIDGE.md).

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/events/suricata/upload` | Ingest `.json`, `.jsonl`, `.ndjson` Suricata EVE records; transactional storage and `SuricataIngestionReport` |
| `GET` | `/api/events/suricata/events` | List imported events with filters (`event_type`, `severity`, `technique_id`) |
| `GET` | `/api/events/suricata/events/{id}` | Full canonical event record (`cyberguard-security-event-v1`) and ATT&CK provenance |
| `POST` | `/api/events/suricata/explain/{id}` | Advisory explanation with untrusted data boundary and deterministic fallback |
| `GET` | `/api/events/suricata/stats` | Aggregated counts by event type, alert count, and active snapshot state |
| `GET` | `/api/events/suricata/attack-status` | Honest dynamic ATT&CK snapshot metadata |

## Live Operations and defensive knowledge endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/operations/snapshot?limit=100` | Read-only bounded source-separated snapshot with sequence IDs, incidents, review exceptions, risk decomposition, and source freshness |
| `POST` | `/api/operations/refresh?limit=100` | Idempotently correlate unseen persisted evidence, aggregate triage, and return the refreshed snapshot; used by the four-second UI poller |
| `GET` | `/api/operations/vulnerabilities/{cve}` | KEV/EPSS context; returns not applicable unless the path is a valid CVE identifier |
| `POST` | `/api/operations/osv/query` | On-demand OSV query/cache requiring ecosystem, package name, and version |
| `GET` | `/api/operations/incidents/{id}` | Incident, bounded evidence links, analyst audit, and no-action status |
| `POST` | `/api/operations/incidents/{id}/resolve` | Audited analyst resolution using server-assigned analyst identity; no response execution |
| `POST` | `/api/mitre/sync` | Download, validate, stage, RAG-index, and transactionally activate the pinned official ATT&CK release; retains last known good on failure |
| `GET` | `/api/mitre/status` | Active ATT&CK source URL/kind, release, hash, object count, retrieval/index times, verification, and latest error |
| `GET` | `/api/mitre/d3fend/status` | Active D3FEND version/hash, technique and relationship counts, and latest error |
| `GET` | `/api/mitre/techniques/{id}` | ATT&CK detail plus official-relationship D3FEND candidates; always reports that no action was executed |

The refresh response reports `refresh_mode=bounded_polling` and a
four-second client interval. Uploaded flow records and Suricata EVE are both
file-imported evidence sources, not continuous capture. Demo records are never
returned in backend source lists. OSV is not applied without package ecosystem,
name, and version context.

## Security limits

Remote API access requires `CG_API_TOKEN`; production deployments also need a
TLS reverse proxy and real identity/RBAC. Request, upload, query, history, and
rate limits are configured in `backend/config.py` and `.env.example`.
