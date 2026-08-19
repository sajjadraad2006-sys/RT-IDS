# CyberGuard — next AI agent execution prompt

You are the next senior ML/security engineering agent working in:

`/home/sajjad/Desktop/project`

Your primary mission is to acquire a legitimate network-intrusion dataset, build and evaluate a reproducible candidate detection bundle, and leave CyberGuard materially closer to production readiness without weakening its security boundaries or overstating its coverage.

Do not stop after writing a plan or scaffolding. Continue through safe data acquisition, validation, training, evaluation, tests, and documentation whenever the environment permits. If an official dataset requires credentials, a click-through license, or more disk than is safely available, exhaust legitimate alternatives first, then report the exact blocker and leave a verified resumable acquisition workflow. Never bypass licensing or fabricate a successful training result.

## 1. Mandatory first actions

Before editing or downloading anything:

1. Inspect the entire repository structure, `git status`, and current diff. The worktree is intentionally dirty and contains valuable user changes. Preserve them; do not reset, revert, overwrite, or clean unrelated work.
2. Read these files completely:
   - `README.md`
   - `SECURITY_TEST_REPORT_AR.md`
   - `docs/SMART_LOG_ARCHITECTURE_AR.md`
   - `cyberguard/datasets/manifest.json`
   - `data/models/trained/artifacts.json`
   - `backend/detection/integrity.py`
   - `backend/detection/features.py`
   - `backend/detection/trainer.py`
   - `backend/detection/pipeline.py`
   - `backend/detection/classifier.py`
   - `backend/detection/autoencoder.py`
   - `backend/api/detection.py`
   - `backend/decision/engine.py`
   - `backend/api/decision.py`
   - `tests/test_integrity.py`
   - `tests/test_smart_decision.py`
3. Run the existing baseline before changing code:

   ```bash
   venv/bin/pytest -q
   venv/bin/python verify.py
   bash cyberguard/download_data.sh
   venv/bin/bandit -r backend cyberguard -x '*/tests/*' -f txt
   venv/bin/pip-audit --local --progress-spinner off
   ```

4. Check free disk space, RAM, CPU and GPU availability before choosing dataset size or training parameters. Do not fill the disk or assume CUDA exists.
5. Write a concrete plan with checkpoints and acceptance gates before editing.

## 2. Current verified state — preserve these properties

The current implementation already includes:

- 32-feature numerical flow extraction, RobustScaler, statistical filter, XGBoost classifier, and PyTorch autoencoder.
- Manifest and SHA-256 validation for datasets and executable model artifacts before deserialization.
- Fail-closed model loading: there is no silent synthetic production fallback.
- `data/models/trained/artifacts.json`, explicitly marked `production_approved: false`.
- Two deterministic synthetic fixtures in `cyberguard/datasets/manifest.json`, both marked `training_approved: false`. They are for tests/demo only and must never generate production metrics.
- The active legacy classifier exposes only `Benign`, `Bot`, `DDoS`, and `PortScan`.
- `/api/detect/health` truthfully reports `operational_mode: evaluation_only`, artifact integrity, trained classes, and missing classes.
- Autoencoder output is named `unknown-anomaly`, not “confirmed zero-day”, and receives no automatic MITRE technique because reconstruction error cannot infer attacker behavior.
- Smart Log, guarded AI decisions, separate policy/prompt/model versions, analyst review queue, server-stamped analyst identity, hash-chained immutable audit events, reviewed-case export, and a simulation-only response planner.
- LLM output is advisory. It cannot clear an uncertain alert, execute an action, or invent telemetry. `executed_action` remains `none`.
- The last known baseline was 99 passing tests, 15/15 verification checks, zero Bandit findings, and no known auditable dependency vulnerabilities. Re-measure; do not copy these numbers blindly.

## 3. Non-negotiable truth and safety constraints

- Never call synthetic, generated, demo, sampled-from-a-generator, or fixture-shaped data “CICIDS2017” or production training data.
- Never invent accuracy, throughput, attack coverage, calibration quality, dataset hashes, row counts, licenses, or citations.
- Never use a random row split as the only evaluation. Split by capture/day/source and time, and prove that duplicates or near-duplicates cannot cross partitions.
- Never tune thresholds on the final test set. Training, calibration/validation, and final test data must be separate.
- Never train on API uploads or analyst feedback automatically. Reviewed feedback is offline candidate input only.
- Never overwrite `data/models/trained/` during training. Write candidates under a new versioned directory such as `data/models/candidates/<candidate-id>/`.
- Never mark a candidate `production_approved: true` automatically. Promotion requires explicit human approval after the quality, security, and shadow gates are reported.
- Never feed raw logs, packet payloads, secrets, API keys, analyst notes, or filenames to a cloud LLM.
- Do not add an LLM to the detection hot path.
- Do not connect to a real firewall, router, EDR, cloud control plane, or public target. The response engine remains simulation-only.
- Do not weaken SSRF protection, API authentication, CORS/host checks, rate limits, upload limits, output escaping, audit immutability, or checksum validation.

## 4. Dataset acquisition — execute this, do not merely document it

### Source priority

Use internet research to verify current sources and prefer, in order:

1. The official publisher/source for CICIDS2017 or a newer suitable CIC dataset from the Canadian Institute for Cybersecurity/UNB.
2. An official institutional mirror with explicit provenance and license/terms.
3. A reputable immutable mirror only when the official source is unavailable. Record why it was needed and whether its bytes can be matched to an official checksum.

Do not hard-code or trust a remembered URL. Verify the live publisher page, license/terms, file format, expected size, and whether a publisher checksum exists. Cite the authoritative source in documentation.

### Acquisition requirements

- Use HTTPS, bounded streaming, timeouts, redirect validation, atomic temporary files, resumable behavior where practical, and an explicit maximum download size.
- Reject HTML, XML error pages, authentication pages, 404 bodies, tiny files, archive bombs, path traversal inside archives, symlinks, unexpected file counts, and schema mismatches.
- Calculate SHA-256 after download. If the publisher provides a checksum, require an exact match. If it does not, record the locally observed hash and set provenance/checksum status honestly; do not call it publisher-verified.
- Do not commit multi-gigabyte raw data to Git. Keep raw/derived data under an ignored data directory while committing only manifests, download/validation code, small test fixtures, and reports.
- Preserve the original downloaded bytes read-only. Produce normalized derived files separately and record parent hashes plus transformation code/version.
- Add every training/evaluation input to a machine-readable manifest with at least:
  - stable dataset ID and schema version;
  - publisher and authoritative source URL;
  - license/terms and access date;
  - local relative path and byte size;
  - SHA-256 and checksum provenance;
  - capture/day/source identity and time range;
  - exact row count, columns, label column and label counts;
  - transformation lineage;
  - `training_approved` and allowed uses.

If official data cannot be acquired legally or safely, do not substitute generated flows. Improve the acquisition command and manifest validation, record the blocker, and keep the system evaluation-only.

## 5. Dataset validation and leakage prevention

Before training, generate a dataset audit report in JSON plus human-readable Markdown/Arabic summary. It must include:

- schema compatibility with the 32-feature extractor;
- missing, constant, non-finite, negative-impossible, and extreme-value fields;
- label normalization table and unknown labels;
- class and capture imbalance;
- exact duplicates and stable canonical row/flow hashes;
- near-duplicate strategy where practical;
- timestamp parsing quality and chronological ordering;
- capture/source overlap across splits;
- whether identifiers, filenames, timestamps, or post-event fields could leak the target;
- unsupported claims: for example, numerical flow features do not inspect SQL/XSS payload text.

Deduplicate before splitting. Derive transforms/scalers/statistical baselines only from the training partition. Fit benign baselines and the autoencoder only on training-benign flows. Do not allow validation/test statistics to influence preprocessing.

### Required evaluation partitions

Create and persist deterministic split manifests containing row hashes/capture IDs:

1. **Training:** candidate fitting only.
2. **Calibration/validation:** classifier calibration, abstention threshold, statistical threshold, and autoencoder threshold.
3. **Independent final test:** opened once after the candidate and thresholds are frozen.
4. **OOD test:** hold out at least one attack family/capture entirely from supervised classifier training when the data permits. Measure whether it routes to `unknown-anomaly`/human review rather than being confidently mislabeled.

Prefer a different capture/day/source for the final test. If every class cannot appear in a genuinely independent test capture, report per-class support as missing and do not claim coverage for that class. Do not weaken the split merely to make the metrics look complete.

## 6. Candidate modelling strategy

Start with measured baselines and add complexity only when an independent validation result justifies it.

### Required baselines

- statistical filter alone;
- current XGBoost approach;
- Isolation Forest or another simple unsupervised baseline trained on training-benign only;
- current autoencoder trained on training-benign only;
- current four-stage routing pipeline.

### Recommended improvements to evaluate

Implement the smallest defensible improvements that produce measurable benefit:

1. Calibrate classifier probabilities using validation-only isotonic, Platt, or temperature scaling as appropriate.
2. Derive the abstention threshold from a stated operational objective on validation data, such as a maximum benign false-positive budget, then freeze it before final testing.
3. Evaluate an OOD ensemble using independent signals such as autoencoder reconstruction error plus Isolation Forest/statistical distance. Do not add a layer unless ablation proves that it improves OOD routing or reduces false positives.
4. Add input-schema and feature-distribution drift detection. Report PSI/KS or another justified statistic per feature, but do not automatically retrain.
5. Consider class weighting, focal objectives, or resampling only on the training partition. Never duplicate samples across partitions.
6. If sequence/time information is genuinely available, benchmark a temporal model separately. Do not add LSTM/Transformer complexity to tabular rows without an appropriate sequence definition and a clear measured gain.

The desired architecture is not “more layers at any cost.” It is the simplest pipeline that wins on independent metrics, calibration, latency, memory, OOD routing, and operational explainability.

## 7. Metrics and acceptance gates

Report raw counts and confidence intervals where practical. At minimum compute:

- per-class precision, recall, F1 and support;
- macro, weighted and binary attack-vs-benign metrics;
- labeled confusion matrix;
- per-class and macro PR-AUC where valid;
- benign false-positive rate and false positives per 10,000 benign flows;
- probability calibration: reliability bins, ECE and Brier score;
- abstention/coverage curve and selective risk;
- routing precision/recall: known attacks bypass AI when correct, ambiguous/OOD enter review;
- OOD detection AUROC/PR-AUC only when ground truth supports the calculation;
- autoencoder error distributions for train-benign, validation-benign, test-benign, known attack, and held-out family;
- throughput and p50/p95/p99 latency for each stage and the complete pipeline on the current hardware;
- peak RAM/VRAM and artifact sizes.

Quality gates must be declared before looking at final-test results. At minimum, a candidate cannot be recommended for promotion when:

- the final test has fewer than 10,000 rows;
- a claimed class lacks adequate independent support;
- it fails to beat the relevant simple baseline on macro F1/PR-AUC;
- calibration worsens materially;
- benign FPR exceeds the validation-defined operational budget;
- OOD samples are frequently assigned high-confidence known labels;
- any dataset/artifact/schema hash fails;
- results contain NaN/Infinity or cannot be reproduced from the saved split manifest and seed.

Do not relax a failed gate after seeing test results. A failed candidate remains a documented candidate, not an active model.

## 8. Artifact safety and reproducibility

For every candidate, save:

- dataset and split hashes;
- exact 32-feature schema hash and order;
- code revision and dirty-tree patch identifier;
- Python/package versions, seed and hardware summary;
- trained classes and independent per-class support;
- calibrated thresholds and their derivation method;
- all metrics and benchmark results;
- model/config hashes and byte sizes;
- candidate status such as `failed_gates` or `shadow_only_not_promoted`;
- known limitations and rollback predecessor.

Prefer safer formats:

- XGBoost native JSON/UBJ instead of pickling the estimator when feasible;
- JSON/NPZ for simple scaler/statistical parameters;
- `safetensors` or weights-only PyTorch state where practical.

If compatibility still requires Joblib/Pickle, verify the private checksum manifest before deserialization and document that checksum-only protection does not resist an attacker able to replace both artifact and manifest. Do not silently load legacy artifacts.

Add a separate, explicit promotion command with `--dry-run` by default. It must verify all gates, atomically switch a version pointer, retain the previous bundle, and support rollback. Implement it if safe, but do not run a real promotion without explicit user approval.

## 9. Shadow evaluation and drift

Build a reproducible shadow comparison that runs active and candidate bundles on the same bounded offline flows without changing live decisions. It should report:

- verdict/routing disagreement;
- confidence and anomaly-score shifts;
- per-class regressions;
- new false positives/false negatives;
- latency/resource regression;
- drift statistics;
- whether any Smart Log schema or policy behavior changes.

The shadow runner must not call an LLM for every row and must not mutate the active model or analyst decisions.

## 10. Tests that must be added or retained

Keep all existing tests passing and add focused tests for:

- official download success and fail-closed HTML/404/tiny/checksum/archive traversal cases;
- manifest completeness, schema mismatch and undeclared files;
- deterministic split reproduction and zero capture/hash overlap;
- duplicate and near-duplicate leakage prevention;
- preprocessing fitted only on training data;
- missing/unknown labels and unsupported class claims;
- calibration and abstention derived without test leakage;
- known, benign, ambiguous, OOD and conflicting-evidence routing;
- artifact corruption, feature-order mismatch, class mismatch and rollback;
- shadow runner non-mutation;
- NaN/Infinity and extreme numerical inputs;
- fresh and existing database migrations;
- prompt injection, malformed/excessive AI JSON, provider failure and timeout;
- the invariant that no AI or simulator path executes a firewall/EDR action.

Use small deterministic fixtures for unit tests. Large real datasets belong in integration/training workflows, not the default fast test suite.

## 11. Documentation and final handoff

Update code, manifests, README, Arabic architecture/security documentation, and API health output so they agree exactly.

Your final response must include:

1. The dataset actually used: publisher, URL, license, bytes, SHA-256, rows, captures and labels.
2. The exact split strategy and leakage checks.
3. Candidate architecture and every added/removed layer, with ablation evidence.
4. Full independent metrics with class supports and calibration/OOD results.
5. Candidate directory and status; clearly state that it was not promoted unless the user explicitly approved promotion.
6. Commands run and exact results for tests, Bandit, dependency audit, dataset audit and live health.
7. Modified files and migration behavior.
8. Known gaps, failed gates, unaudited dependencies and unsupported attack claims.
9. The single safest next action.

If no legitimate dataset could be acquired, the final answer must say so plainly. Do not present fixture training, code completion, or a successful smoke test as completion of the model-training objective.
