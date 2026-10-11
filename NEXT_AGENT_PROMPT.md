# CyberGuard — handoff to the next agent

**Updated:** 2026-08-27

Resolve the repository root from the current working directory. Do not reuse a
hard-coded workstation path, reset the worktree, or delete local datasets and
artifacts.

## Authoritative current state

- Serving orchestration is `cyberguard-pipeline-v2` with
  `cyberguard-routing-v2` semantics.
- The active artifact bundle is legacy fixture-shaped data,
  `production_approved: false`, evaluation-only.
- Its classifier classes are only `Benign`, `Bot`, `DDoS`, `PortScan`; it has
  no independently valid production result.
- The old `cse-cic-ids2018-v1-seed42` candidate remains `failed_gates` and
  inactive. Never promote it.
- Its standalone classifier macro F1 was about `0.9067`, but the historical
  hard-gated pipeline caught only `1 / 94,845` attacks. Those v1 final captures
  have been examined and must not be used to tune or claim Pipeline v2.
- No new untouched final dataset was available during the v2 implementation,
  so no v2 accuracy or production claim exists and no v2 candidate was trained.
- The product analyzes uploaded, precomputed flow records. Live packet or
  sensor ingestion is not implemented.
- There is no firewall, EDR, quarantine, or response actuator. The LLM is
  advisory and all response simulations retain `executed_action=none`.

## What has been implemented

### Strict input contract

`backend/detection/input_schema.py` and `backend/api/upload_stream.py` provide
versioned, fail-closed validation and bounded parsing.

Accepted containers are headered `.csv`/`.tsv`, JSON objects or object arrays,
and `.ndjson`/`.jsonl`. Supported schemas must cover all 32 model features
directly or through documented safe derivations. CICIDS2017 and CSE-CIC-IDS2018
CICFlowMeter aliases are covered, including `Init_Win_bytes_fwd`.

Raw/headerless `.log`/`.txt`, primitives, arbitrary objects, partial schemas,
duplicate raw JSON keys, conflicting aliases, and invalid numeric rows are
rejected. Escaped/Unicode-equivalent and nested duplicates also fail closed;
NDJSON rejects only the affected malformed line. Equal aliases are accepted
only when their finite numeric values agree. Zero is a present, legitimate
value. Validation reports include
profiles, direct/alias/derived and
missing features, ignored columns, conflicts, invalid/sanitized cells, rejected
and usable rows, and schema coverage.

### Pipeline v2

Every accepted row is normalized and classified before routing. Z-score and
autoencoder reconstruction error are independent evidence signals:

- supported confident attack -> `known_attack`;
- uncertain or out-of-scope non-benign classifier -> `human_review`;
- classifier benign plus anomaly -> `unknown_anomaly_review`;
- otherwise -> `benign`.

Unknown anomaly is not exploit proof and creates no ATT&CK technique. Single,
batch, serving, candidate evaluation, and shadow call the same pure
`backend/detection/router.py` implementation. The router rejects malformed or
non-finite signals and invalid threshold/version metadata instead of coercing
them. Process latency statistics are
constant-space. Batch inference does not mutate them; a completed valid upload
commits one aggregate, while fatal parse/limit/schema/later-inference/response-
preparation/persistence failures close parser resources, discard it, roll back,
and persist nothing.

### Candidate/data/promotion safety

- Feature hashes exclude labels; exact/near same-label and conflicting-label
  groups are reported, and conflicts fail gates.
- Candidate metadata includes trained/supported, evaluated, OOD-only,
  unsupported labels and telemetry profile.
- A manifest claiming Pipeline v2 must carry calibration source, bound dataset
  hashes, and matching thresholds.
- Candidate evaluation now reports end-to-end binary/per-class/calibration,
  routing, OOD, throughput/memory and all requested baselines without a
  statistical front gate.
- `evaluation_intake.py` validates future immutable licensed-data manifests,
  roles, capture/time separation, files/hashes, label provenance, and streamed
  feature fingerprints. `evaluation_report.py` binds complete metrics to the
  validated dataset, splits, artifacts, calibration, source, command, and
  environment. Test fixtures always remain non-evaluation evidence.
- Promotion is dry-run by default and requires all gates plus a passing
  `cyberguard-shadow-report-v3` bound to the exact manifest/artifact hashes,
  calibration metadata, coverage contract, and routing versions, with zero LLM
  calls, DB mutations, or active-pointer mutations.
- Real promotion requires explicit `--apply --approved-by`; never automate it.

### MITRE, LLM, Smart Log and UI honesty

- Classifier-label ATT&CK mappings persist transactionally with provenance and
  are displayed as heuristic candidate mappings, not observed behavior.
- Unknown anomalies create no mapping.
- Snapshot verification starts with an isolated empty database, validates the
  bundled active STIX snapshot, requires a nonzero index and `T1498`, and proves
  local RAG retrieval. Runtime indexing selects the MITRE external reference,
  replaces revoked or removed objects, and updates `sync_log`.
- RAG has a minimum relevance threshold. Chat history is bounded and isolated
  to the requested session; stored content remains untrusted.
- Smart Log v2 includes feature values, normalized/Z evidence, schema profile
  and coverage, pipeline/artifact status and a broader canonical fingerprint.
- The UI separates Demo from backend records, shows operational/coverage state,
  upload validation/caps, provider-confirmed model identity, and labels resource
  values as estimates or unmeasured.

### Reproducibility

- The default manifest declares one committed deterministic fixture only; it
  is `training_approved: false` and reproducible with `--check`.
- Root/dev requirements and `requirements-constraints.txt` provide exact
  versions but no hashes. `pip` is the supported installer; safe-default `uv`
  multi-index compatibility is not claimed.
- `run.sh` does not kill a process on port 8080, does not reinstall on every
  launch, creates directories before redirection, and fails closed on required
  verification.
- CI starts clean and runs dependency consistency, fixture/artifact/ATT&CK
  initialization, tests, verification, all syntax checks, Bandit and audit.

## Do not regress these invariants

1. Every validated row reaches the classifier.
2. Invalid or unsupported input cannot become an all-zero benign vector.
3. Batch and single routing remain identical and ordered.
4. Old v1 final captures are frozen historical evidence, not v2 tuning data.
5. No candidate is promoted automatically.
6. Unknown anomaly is not called an exploit and gets no invented ATT&CK map.
7. Demo alerts never mix with persisted backend alerts.
8. No LLM, firewall, EDR, quarantine, or online-learning action enters the
   inference path.
9. Synthetic fixtures, calibration, shadow, and final evaluation remain
   explicitly distinguished; only a validated licensed final intake may permit
   an accuracy claim.

### Suricata Evidence Bridge v1

- Ingestion of uploaded Suricata EVE JSON/JSONL/NDJSON files at `POST /api/events/suricata/upload`.
- Versioned canonical security-event contract: `cyberguard-security-event-v1`.
- Line-by-line bounded streaming parser supporting `alert`, `flow`, `dns`, and `tls` event types.
- Explicit ATT&CK extraction from allowlisted rule metadata with granular validation states (`active_validated`, `unknown_to_snapshot`, `syntactically_invalid`, etc.).
- Provenance semantics: `rule_match_observed=true`, `technique_observed=false` under `suricata_rule_metadata` evidence kind.
- Transactional persistence (`security_events`, `security_event_technique_mappings`, `suricata_ingestions`) with guaranteed rollback on fatal parse errors.
- Separation of database integer PKs from deterministic event references (`event_ref`).
- Advisory LLM explanation with untrusted data isolation, privacy bounding for network identifiers, and deterministic fallback. Always `executed_action="none"`.
- Detailed in [`docs/SURICATA_EVIDENCE_BRIDGE.md`](docs/SURICATA_EVIDENCE_BRIDGE.md).

## Verification

Use the repository virtual environment when valid:

```bash
python -m pip check
python -m pytest -q
python verify.py
python -m compileall -q backend cyberguard tests verify.py
for file in frontend/js/*.js; do node --check "$file"; done
bash -n run.sh run.bash cyberguard/setup.sh
bandit -r backend cyberguard -x '*/tests/*' -f txt
pip-audit --local --progress-spinner off
python -m cyberguard.datasets.generate_sample --check
```

The latest closure run passes **495 tests** with **13 deprecation warnings** and
**19/19 verify.py gates**. Python compilation, 11 JavaScript syntax checks,
Bandit (0 findings), and dependency audit (0 known vulnerabilities among
auditable packages; local development `torchvision` has no matching PyPI
record) also pass.

## Live Operations and intelligence phase

- Live Operations polls every four seconds without full-page refresh, pauses
  in hidden tabs, prevents overlap, rejects stale responses, and separates
  uploaded flow, imported Suricata, demo, and future-adapter records.
- ATT&CK v19.1 is pinned to the official versioned JSON, SHA-256 checked,
  transactionally activated, and synchronized with a 697-technique local RAG.
- D3FEND v1.5.0 indexes 272 active defensive techniques and 4,154 official
  inferred relationships. Results are candidates and never executed actions.
- Live KEV/EPSS sync measured 1,687 KEV and 366,526 EPSS records on 2026-08-31.
  OSV remains package-context-only.
- Correlation, `triage-policy-v1`, immutable analyst audit, and
  `transparent-risk-v1` are implemented and bounded.
- Full lifecycle and commands: `docs/SECURITY_KNOWLEDGE_ARCHITECTURE.md`.

## Remaining blockers and safe next step

The ML production blocker remains licensed training data. Acquire licensed,
immutable captures that have not been opened as v1 final data. Freeze their
hashes and capture/time partitions with `evaluation_intake.py`.

For evidence ingestion, the next safe steps are:
1. Acquire a new licensed, untouched final dataset and independently calibrate
   Pipeline v2; do not reuse historical final captures or smoke fixtures.
2. Add real package/SBOM inventory before applying OSV beyond explicit package
   context.
3. Add a bounded Zeek or continuous Suricata adapter only with queue,
   backpressure, offset, reconnect, and drop accounting.
4. Add SSO/RBAC before multi-analyst deployment. Keep response actuation out of
   scope until a separately authorized two-person workflow exists.
