# CyberGuard — handoff to the next agent

**Updated:** 2026-08-26

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
conflicting aliases, and invalid numeric rows are rejected. Zero is a present,
legitimate value. Validation reports include profiles, direct/alias/derived and
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
batch, candidate evaluation, and shadow use matching rules. Process latency
statistics are constant-space.

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
- Promotion is dry-run by default and requires all gates plus a passing
  `cyberguard-shadow-report-v2` bound to the exact manifest/artifact hashes,
  with zero LLM calls, DB mutations, or active-pointer mutations.
- Real promotion requires explicit `--apply --approved-by`; never automate it.

### MITRE, LLM, Smart Log and UI honesty

- Classifier-label ATT&CK mappings persist transactionally with provenance and
  are displayed as heuristic candidate mappings, not observed behavior.
- Unknown anomalies create no mapping.
- Snapshot indexing selects the MITRE external reference, replaces revoked or
  removed objects, updates `sync_log`, and synchronizes the local RAG index.
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
- Root requirements, dev requirements and a constrained lock are present.
- `run.sh` does not kill a process on port 8080, does not reinstall on every
  launch, creates directories before redirection, and fails closed on required
  verification.
- CI runs tests, Python/JavaScript syntax, fixture/manifest checks, Bandit and
  dependency audit.

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

## Verification

Use the repository virtual environment when valid:

```bash
python -m pytest -q
python verify.py
python -m compileall -q backend cyberguard tests verify.py
for file in frontend/js/*.js; do node --check "$file"; done
bandit -r backend cyberguard -x '*/tests/*' -f txt
pip-audit --local --progress-spinner off
python -m cyberguard.datasets.generate_sample --check
```

## Remaining blockers and safe next step

The production blocker is data, not another routing rewrite. Acquire licensed,
immutable captures that have not been opened as v1 final data. Freeze their
hashes and capture/time partitions; use only training/calibration to fit and
calibrate a new candidate; run one untouched end-to-end final evaluation; then
run bound shadow evaluation. Report failure honestly if any gate fails.

A safe live direction after that is a local Zeek JSON or Suricata EVE adapter
without packet-capture privileges, with explicit conversion, bounded queue,
backpressure/dead-letter counts, offsets/reconnect health, and no silent loss.
Until implemented and tested, keep the product labeled an offline uploaded-flow
analyzer.
