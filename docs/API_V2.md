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

## Security limits

Remote API access requires `CG_API_TOKEN`; production deployments also need a
TLS reverse proxy and real identity/RBAC. Request, upload, query, history, and
rate limits are configured in `backend/config.py` and `.env.example`.
