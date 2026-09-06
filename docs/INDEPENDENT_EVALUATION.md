# Independent-data intake and evaluation provenance

CyberGuard has no new licensed, untouched final-evaluation dataset in this
repository. This workflow prepares the trust boundary for one; it does not
download data, train a model, approve an artifact, or create an accuracy claim.
Small files created by `tests/test_evaluation_intake.py` are explicitly
synthetic contract fixtures and are not model-evaluation data.

## Immutable intake manifest

Use schema `cyberguard-independent-data-manifest-v1`. Keep private captures
outside Git and record all of the following before fitting or calibration:

- a stable dataset identifier;
- source name/URI, acquisition date, license identifier, and license record;
- one supported telemetry profile;
- `role_overlap_prohibited: true` and an explicit
  `forward_time_evaluation` boolean;
- explicit `fixture_only` and `evaluation_approved` booleans;
- for every file: ID, relative path, byte size, SHA-256, capture ID, timezone-
  aware capture start/end, supported labels, label provenance, known
  preprocessing, and exactly one role: `training`, `calibration`, `shadow`, or
  `final_evaluation`;
- a size/hash-bound JSONL feature-fingerprint sidecar for every file.

Each sidecar line has exactly this shape:

```json
{"feature_sha256":"<sha256-of-versioned-canonical-feature-row>","label":"Benign"}
```

The feature digest must exclude the label. Sidecars declare
`cyberguard-feature-fingerprints-jsonl-v1` and
`label_included_in_feature_hash: false`. The preprocessing that creates these
digests must be versioned in the manifest; the intake validator deliberately
does not guess how private raw telemetry maps to the 32-feature schema.

Validate without copying feature matrices into memory:

```bash
python -m backend.detection.evaluation_intake \
  /secure/dataset/manifest.json \
  --dataset-root /secure/dataset
```

Validation recomputes every file and sidecar size/hash. It rejects missing or
changed files, paths/symlinks outside the dataset root, unsupported telemetry,
ambiguous roles, capture reuse across roles, forward-time leakage, exact
feature duplicates across roles, conflicting labels for one feature digest,
and calibration/final reuse. Cross-file fingerprint comparison uses an
ephemeral SQLite database in a temporary directory rather than retaining an
unbounded rollback list or adding a database to the repository.

## Split and measurement discipline

Freeze roles before training. Training may fit model parameters. Calibration
may select thresholds and calibration metadata. Shadow may compare immutable
artifacts without changing the active pointer. Final evaluation is opened once
after all choices are frozen. No capture, time range, file path, or exact
feature row may cross these roles.

Synthetic fixtures, calibration measurements, shadow measurements, and final
evaluation use distinct report roles. A fixture intake report always has
`accuracy_claim_allowed: false`; `evaluation_report.py` refuses to label it as
final evaluation. A real final report also requires an intake report explicitly
approved for evaluation. Approval of data intake is not artifact production
approval.

## Bound report contract

`backend.detection.candidate_workflow` calculates:

- TP, FP, FN, TN, precision, recall, F1, benign FPR, and false positives per
  10,000 benign flows;
- per-class precision, recall, F1, PR-AUC, support, macro/weighted metrics, and
  10-bin ECE;
- routing counts plus total, human, unknown-anomaly, and unsupported-label
  review rates;
- high-confidence OOD mislabel rate;
- throughput and peak process RSS;
- classifier, statistical, autoencoder, full Pipeline v2, and Isolation Forest
  comparisons when the corresponding artifact exists.

Candidate metrics alone are labeled as a legacy dataset-audit measurement and
have `accuracy_claim_allowed: false`. Before any future result is consumed,
`build_evaluation_report()` binds the complete metric object to:

- the validated dataset-manifest SHA-256;
- exact split-manifest SHA-256 values;
- model artifact SHA-256 values;
- pipeline and routing schema versions;
- canonical calibration-metadata SHA-256;
- source revision, exact command, and environment metadata.

`validate_evaluation_report_bindings()` recomputes these bindings and fails if
an artifact, split, calibration value, metric payload, or dataset manifest has
changed. This is checksum provenance, not a detached signature. A future
signature design must keep the private key outside the repository and serving
host.

## Promotion remains separate

An evaluation report does not promote anything. Promotion remains dry-run by
default and additionally requires an intact candidate, passing declared gates,
an independently evaluated coverage contract, and a passing
`cyberguard-shadow-report-v3` for the same manifest, artifact hashes,
calibration metadata, coverage contract, pipeline version, and routing schema.
Real promotion still requires an explicit human approver.
