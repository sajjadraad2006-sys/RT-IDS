# CyberGuard

CyberGuard is a local, evaluation-stage analyzer for uploaded, precomputed
network-flow records. It validates a fixed 32-feature contract, runs a
known-attack classifier on every accepted row, calculates statistical and
autoencoder evidence independently, and routes ambiguous results to analyst
review. The LLM is advisory and is never part of inference.

CyberGuard is not currently a live packet IDS, payload inspector, IPS,
firewall, EDR, or automated quarantine system.

## Current operational status

- Runtime orchestration: `cyberguard-pipeline-v2` / `cyberguard-routing-v2`.
- Active bundled artifact: legacy, synthetic fixture-shaped,
  `production_approved: false`, evaluation-only.
- Active classifier labels: `Benign`, `Bot`, `DDoS`, `PortScan`.
- Independently evaluated production coverage for the active artifact: none.
- Previous CSE-CIC-IDS2018 candidate: `failed_gates`, inactive, never promoted.
- Live ingestion: not implemented.
- Automated response: not implemented; recommendations always have
  `executed_action=none`.

The active legacy bundle remains usable for deterministic tests and UI
evaluation. Pipeline v2 labels its thresholds as legacy/unvalidated evidence;
it does not reinterpret them as production calibration. `/api/detect/health`
reports integrity, pipeline version, approval state, supported/evaluated/OOD
scope, unsupported labels, and telemetry profile.

## Pipeline v2

For every row that passes the input contract:

1. Extract and normalize the 32 canonical numerical features.
2. Run the known-attack classifier. Every accepted row reaches this step.
3. Calculate the maximum absolute Z-score independently.
4. Calculate autoencoder reconstruction error independently when supported by
   the bundle.
5. Apply deterministic routing:

| Condition | Route | Result |
|---|---|---|
| Supported non-benign label at/above calibrated confidence | `known_attack` | Known-label alert |
| Non-benign but uncertain or outside declared scope | `human_review` | Analyst review; never silently benign |
| Classifier says benign and either anomaly signal is strong | `unknown_anomaly_review` | Unknown Anomaly review, with no invented ATT&CK technique |
| Classifier benign and anomaly signals non-actionable | `benign` | No alert |

The statistical detector is evidence, not a pre-classifier gate. Single-row,
batch, serving, evaluation, and shadow code use the same routing semantics.
Pipeline manifests claiming v2 must include calibration source/dataset hashes
and matching classifier, statistical, and autoencoder thresholds; missing or
mismatched metadata fails closed.

## Input contract

Supported upload containers:

- Headered `.csv` and `.tsv`.
- `.json` containing one object or a top-level array of homogeneous objects.
- `.ndjson` and `.jsonl`, one object per line.

Supported schemas include the canonical 32 fields and tested CICFlowMeter
spellings from CICIDS2017 and CSE-CIC-IDS2018. This includes
`Init_Win_bytes_fwd`, `Init_Win_bytes_bwd`, `Init Fwd Win Byts`, and their
documented variants. A schema may omit only fields that are safely derivable
from present dependencies. Coverage is based on column presence, so an
explicit numeric zero remains a legitimate value.

The API rejects with HTTP 400/413/422 as appropriate:

- `.log`, `.txt`, binary data, headerless text, and unsupported extensions;
- arbitrary JSON such as `{"message":"failed login"}` or JSON primitives;
- incomplete schemas such as only `col_0,col_1`;
- duplicate headers or conflicting aliases for one canonical feature;
- rows with missing, negative, non-numeric, or non-finite feature cells.

The CICFlowMeter `-1` initial-window sentinel is explicitly converted to zero,
and finite values above `1e15` are clipped. Both operations are reported. An
invalid row never becomes an all-zero benign inference row.

Every successful upload returns a `schema_validation` object with:

- detected input profile;
- recognized direct features and aliases;
- safely derivable and missing features;
- ignored columns, duplicate/alias conflicts;
- invalid numeric and sanitization counts;
- total parsed, accepted, rejected, usable and analyzed counts;
- feature coverage percentage;
- generated, returned, and persisted alert counts and caps.

CSV/TSV and NDJSON are parsed incrementally. JSON objects/arrays are decoded
incrementally with a bounded per-value buffer. Inference and database writes
use fixed batches; alert responses are capped at 500 and persistence at 5,000
per upload. Byte and row limits are enforced while reading. Process statistics
use constant-space counters rather than retaining one latency per flow.

## Installation and reproducibility

Python 3.12 is the CI target. Direct dependencies are exact-pinned in
`requirements.txt`; `requirements.lock` constrains the transitive closure;
development and security tools are exact-pinned in `requirements-dev.txt`.
The lock selects CPU-oriented PyTorch/XGBoost distributions for clean Linux CI
instead of inheriting CUDA or `torchvision` packages from a workstation.

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip check
```

The default dataset manifest declares one small committed deterministic
fixture. It is generated with seed 42 and is explicitly
`training_approved: false`; unavailable official production datasets are not
declared in the default fixture manifest.

```bash
python -m cyberguard.datasets.generate_sample --check
python -c "from backend.config import BASE_DIR; from backend.detection.integrity import validate_dataset_manifest; validate_dataset_manifest(BASE_DIR/'cyberguard/datasets/manifest.json', BASE_DIR)"
```

## Run locally

The launcher creates required directories, verifies dependency pins, refuses a
busy application port without killing its owner, initializes local databases,
and treats `verify.py` as a required gate. It installs only for a new virtual
environment or when `--setup` is explicitly requested.

```bash
# Existing, correctly pinned venv
bash run.sh

# Explicit dependency setup/update
bash run.sh --setup

# Start without an advisory LLM or remote ATT&CK refresh
CG_SKIP_LLM=1 CG_SKIP_MITRE_SYNC=1 bash run.sh
```

Then open `http://127.0.0.1:8000`. If the LLM is absent, flow analysis remains
available and the launcher says that chat is unavailable; it does not call this
frontend demo mode.

Direct development launch:

```bash
source venv/bin/activate
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Configuration keys are documented in `.env.example`. The launcher does not
silently load it; source an operator-owned copy explicitly before launch.

## API summary

Interactive OpenAPI documentation is at `http://127.0.0.1:8000/docs`.
The stable upload/health/advisory contract is also summarized in
[`docs/API_V2.md`](docs/API_V2.md).

| Method | Endpoint | Contract |
|---|---|---|
| `POST` | `/api/detect/upload` | Strict, bounded flow upload; Pipeline v2 results and schema report |
| `GET` | `/api/detect/health` | Integrity, actual operational mode, versions, and coverage scope |
| `GET` | `/api/detect/alerts` | Persisted backend alerts only; demo alerts remain frontend-only |
| `POST` | `/api/detect/explain/{id}` | Advisory explanation of bounded model evidence |
| `POST` | `/api/chat` | Session-bounded chat with relevance-filtered ATT&CK context |
| `GET` | `/api/chat/history/{session}` | Only that validated session ID, with a bounded limit |
| `GET` | `/api/mitre/techniques` | Active ATT&CK snapshot plus heuristic candidate mappings |
| `POST` | `/api/mitre/sync` | Refresh, replace the active index, update sync log and RAG |
| `GET` | `/api/decision/smart-log/{id}` | Smart Log v2 evidence and fingerprint |
| `GET` | `/api/decision/queue` | Ambiguous/unknown analyst-review cases |
| `POST` | `/api/decision/evaluate/{id}` | Deterministic policy plus guarded AI only when needed |
| `POST` | `/api/decision/feedback/{id}` | Audited offline feedback; never online retraining |
| `POST` | `/api/decision/simulate-response/{id}` | Allowlisted dry-run recommendation; no actuator |

ATT&CK rows created from a classifier label are stored transactionally with
the alert and carry alert ID, classifier label, mapping version, confidence,
and `heuristic_hypothesis` provenance. They are displayed as “possible
techniques based on classifier label,” never observed behavior. Unknown
anomalies create no technique mapping without independent evidence.

## Candidate evaluation and promotion

The candidate workflow uses capture-disjoint training, calibration, final, and
OOD partitions. Exact and near feature hashes exclude labels; labels are
tracked separately so same-label duplicates and conflicting-label duplicates
are reported. Conflicts fail candidate gates.

Pipeline v2 evaluation reports TP/FP/FN/TN, precision/recall/F1, benign FPR and
false positives per 10,000 benign rows, per-class support/precision/recall/F1
and PR-AUC, ECE, routing/review counts, OOD high-confidence mislabel rate,
throughput and memory, plus classifier/statistical/autoencoder/Isolation Forest
baselines.

Do not rerun or tune v2 on the v1 final captures documented in
`docs/CANDIDATE_EVALUATION_AR.md`; they have already been examined. A new,
untouched final evaluation source is required before any production claim.

Promotion is dry-run by default:

```bash
python -m backend.detection.promote data/models/candidates/<candidate-id>
```

Eligibility requires intact artifacts, v2 calibration, an independently
evaluated coverage contract, all declared gates, and a passing
`shadow_report.json` bound to the exact manifest and artifact hashes. Shadow
must record zero LLM calls, database mutations, and active-pointer mutations.
Real promotion additionally requires explicit `--apply --approved-by ...`;
CyberGuard never promotes automatically.

The current checksum boundary detects accidental/tampered artifact changes
before executable joblib/PyTorch deserialization, but a co-located manifest is
not sufficient against an attacker who can replace both. A production signing
design should verify a detached signature using a trusted public key; the
private signing key must remain outside the repository and serving host.

## Measured results and limitations

No new Pipeline v2 production metric is reported because no new untouched
final source was available during this recovery. Unit fixtures verify routing
behavior, not detection accuracy.

Historical, measured v1 result (not reusable for v2 tuning): the standalone
CSE-CIC-IDS2018 classifier reached macro F1 approximately `0.9067`, while the
hard-gated complete pipeline detected `1 / 94,845` attacks (recall about
`0.0000105`). That candidate remains `failed_gates` and inactive. See
`docs/CANDIDATE_EVALUATION_AR.md` for the frozen historical report.

Autoencoder reconstruction error measures deviation from its reference
distribution. It is not proof of an exploit, attacker intent, or an ATT&CK
technique. Uploaded numerical flows do not contain packet payloads, login
outcomes, host process events, or application evidence.

## Verification

```bash
python -m pytest -q
python verify.py
python -m compileall -q backend cyberguard tests verify.py
for file in frontend/js/*.js; do node --check "$file"; done
bandit -r backend cyberguard -x '*/tests/*' -f txt
pip-audit --local --progress-spinner off
python -m cyberguard.datasets.generate_sample --check
```

CI runs the same unit/integration, syntax, fixture, Bandit, dependency-audit,
and manifest gates from `.github/workflows/ci.yml`.

## Safe live-ingestion direction

Live ingestion remains intentionally unimplemented until an independently
evaluated artifact exists. A safe next adapter is a local Zeek JSON or
Suricata EVE flow reader running without packet-capture privileges. It must
convert an explicit source schema into the same input validator, use a bounded
queue with backpressure/dead-letter accounting, expose source/queue/reconnect
health, persist offsets or report every dropped record, and keep telemetry
collection separate from inference. No public target testing is needed.
The fail-closed adapter contract and current schema blocker are detailed in
[`docs/LIVE_INGESTION_DESIGN.md`](docs/LIVE_INGESTION_DESIGN.md).

## Security deployment

CyberGuard binds to loopback by default. Remote access requires a TLS reverse
proxy, strong `CG_API_TOKEN`, restrictive `CG_ALLOWED_HOSTS` and
`CG_ALLOWED_ORIGINS`, and a real identity/RBAC layer for multiple analysts.
Outbound LLM endpoints are allowlisted. Do not expose Uvicorn directly to the
Internet.

The project is licensed under the [MIT License](LICENSE). Original project
developer: Sajjad Raad. Academic baseline: 2025 University of Basra research
by Zainab Salem Aziz.
