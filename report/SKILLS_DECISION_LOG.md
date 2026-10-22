# Antigravity Skills Decision Log

This log records the catalog exploration and skill installation decisions conducted during Phase P1 of the CyberGuard Master's Thesis Technical Report project, adhering to the Mandatory Skills Protocol.

- **Catalog Source**: `rmyndharis/antigravity-skills` (v0.1.11, 307 catalog skills)
- **Local Tool**: `ag-skills` CLI / `catalog.json`
- **Execution Date**: 2026-10-17
- **Max Skills Installed Policy**: <= 10 curated skills.

---

## 1. Catalog Query Matrix (26 Required Queries)

| # | Query | Matches Found | Key Skills Found | Action & Decision Rationale |
|---|-------|:-------------:|------------------|-----------------------------|
| 1 | `pdf` | 0 | None in catalog | **Rejected / Custom Tooling Built**: No dedicated PDF generation skill exists in the catalog. Built custom Node.js Playwright/Paged.js PDF compilation pipeline (`report/build.mjs`). |
| 2 | `report` | 2 | `data-storytelling`, `team-collaboration-issue` | **Installed `data-storytelling`**: Provides frameworks for structured analytical narratives, data visualization contrast, and executive summaries. `team-collaboration-issue` rejected (irrelevant to technical reports). |
| 3 | `technical writing` | 0 | None in catalog | **Rejected / Custom Tooling Built**: Relying on local skills (`docs-architect`, `reference-builder`) and established IEEE thesis standards. |
| 4 | `documentation` | 21 | `api-documenter`, `architecture-decision-records`, `c4-architecture-*` | **Evaluated & Rejected**: General C4/API doc skills are either redundant with existing local `docs-architect` / `reference-builder` or too broad. Architecture documented directly from code evidence. |
| 5 | `academic` | 0 | None in catalog | **Rejected**: Local `academic-research-curator` skill already available for academic standards. |
| 6 | `research` | 5 | `search-specialist`, `firmware-analyst`, `malware-analyst`, `reverse-engineer` | **Evaluated**: `search-specialist` is already installed locally. Binary reverse engineering skills rejected as out of scope for IDS pipeline audit. |
| 7 | `literature` | 0 | None in catalog | **Rejected / Direct Research**: Conducted direct literature verification using verified DOIs and authoritative academic databases. |
| 8 | `citation` | 0 | None in catalog | **Rejected / Custom Tooling Built**: No citation management skill exists. Built dedicated IEEE citation resolver and verification test suite in `report/build.mjs` and `report/tests/test_citations.py`. |
| 9 | `diagram` | 7 | `c4-component`, `c4-container`, `mermaid-expert` | **Installed `mermaid-expert`**: Provides verified syntax and formatting for architecture, sequence, and flow state machine diagrams. |
| 10 | `mermaid` | 1 | `mermaid-expert` | **Installed `mermaid-expert`**: Chosen to ensure crisp, standards-compliant architectural and state diagrams. |
| 11 | `chart` | 3 | `helm-chart-scaffolding`, `mermaid-expert`, `team-composition-analysis` | **Evaluated & Rejected**: Helm and team composition skills irrelevant. Chart rendering implemented via Chart.js / D3 scripts with real empirical data feeds. |
| 12 | `data visualization` | 2 | `data-storytelling`, `kpi-dashboard-design` | **Installed `data-storytelling`** (already covered under `report`). `kpi-dashboard-design` rejected as corporate BI specific. |
| 13 | `html` | 0 | None in catalog | **Rejected / Custom Tooling Built**: Custom responsive thesis HTML template with KaTeX, Chart.js, and Paged.js created directly. |
| 14 | `frontend` | 7 | `frontend-developer`, `frontend-mobile-security-xss-scan` | **Evaluated & Rejected**: CyberGuard's React/Vite dashboard is audited directly via static analysis and Playwright. General frontend scaffolding skills not required. |
| 15 | `playwright` | 1 | `e2e-testing-patterns` | **Installed `e2e-testing-patterns`**: Guides headless browser orchestration for automated HTML-to-PDF rendering and visual verification. |
| 16 | `puppeteer` | 0 | None in catalog | **Rejected**: Using Playwright via Node.js for browser automation. |
| 17 | `latex` | 0 | None in catalog | **Rejected / Custom KaTeX Engine**: Math equations rendered via locally vendored KaTeX in HTML/Paged.js rather than LaTeX compiler. |
| 18 | `markdown` | 0 | None in catalog | **Rejected**: Markdown parsing handled natively via `marked` in Node.js build script. |
| 19 | `security audit` | 6 | `security-auditor`, `codebase-cleanup-deps-audit`, `firmware-analyst` | **Installed `security-auditor`**: Comprehensive security auditing methodology, DevSecOps controls, vulnerability assessment, and threat modeling guidelines. |
| 20 | `threat modeling` | 3 | `threat-modeling-expert`, `stride-analysis-patterns`, `security-auditor` | **Installed `threat-modeling-expert` & `stride-analysis-patterns`**: Selected for Chapter 7 STRIDE threat analysis and actuator containment security review. |
| 21 | `network` | 8 | `hybrid-cloud-networking`, `k8s-security-policies`, `linkerd-patterns` | **Evaluated & Rejected**: Catalog networking skills focus on cloud/K8s/service-mesh infrastructure rather than packet sniffing and raw sockets. |
| 22 | `ids` | 0 | None in catalog | **Rejected / Direct Code Analysis**: Core IDS sniffer, feature extractor, and decision engine analyzed directly from workspace source files. |
| 23 | `machine learning` | 3 | `data-scientist`, `machine-learning-ops-ml-pipeline`, `godot-gdscript-patterns` | **Evaluated & Rejected**: ML pipeline skills focus on training infrastructure rather than adversarial evaluation and train/serve skew forensics. Evaluated using scikit-learn, joblib, and custom scripts. |
| 24 | `evaluation` | 1 | `llm-evaluation` | **Evaluated & Rejected**: CyberGuard's LLM component is a secondary advisory explainer (`backend/llm/`). LLM prompts audited using local `prompt-engineering-patterns` skill. |
| 25 | `benchmark` | 1 | `llm-evaluation` | **Evaluated & Rejected**: Benchmark script written specifically in Python/pytest to measure P50/P95/P99 latency, throughput, and memory. |
| 26 | `testing` | 44 | `bats-testing-patterns`, `api-testing-*`, `tdd-workflows-tdd-cycle` | **Evaluated**: Local `tdd-workflows-tdd-cycle` already available and utilized for report build test harness. Other testing skills rejected to keep skill footprint lean. |

---

## 2. Installed Skills Inventory (Phase P1)

The following 6 skills were installed from `rmyndharis/antigravity-skills`:

1. `mermaid-expert` (`workflow`) - Diagrams, architecture flows, state machine illustrations.
2. `security-auditor` (`security`) - Comprehensive security auditing, risk assessment, vulnerability taxonomies.
3. `threat-modeling-expert` (`security`) - Threat modeling, attack trees, security boundary definition.
4. `stride-analysis-patterns` (`security`) - Systematic STRIDE threat identification and control mapping.
5. `data-storytelling` (`data-ai`) - Empirical results presentation, contrast analysis, executive summary framing.
6. `e2e-testing-patterns` (`testing`) - Browser-driven automated rendering and quality gate validation.

All 6 skills were inspected for safety: none perform unauthorized network calls, credentials access, or destructive commands.
Tooling for functions not provided by skills (HTML-to-PDF export, IEEE citation resolution, and numerical claim verification) was developed test-first directly in `report/`.

---

## 3. Independent Audit Fix-Pass Decisions

During the independent auditor fix-pass, the following evaluation of catalog skills and tools was conducted:
1. **Citation & DOI Validation**: Evaluated whether to install an external catalog skill vs. writing a dedicated, transparent stdlib verification script. Decision: Built `report/scripts/verify_references.py` using standard library `urllib.request` querying authoritative REST APIs (Crossref `api.crossref.org` and DataCite `api.datacite.org`). No untrusted third-party packages or catalog skills were introduced, ensuring absolute reproducibility and zero supply-chain risk.
2. **Quality Gates & Broken Link Audit**: Built direct verification scripts (`report/scratch/measure_quality_gates.py`, `report/tests/test_citations.py`) validating HTML DOM integrity, internal anchor resolution, and KaTeX rendering.
3. **Skill Footprint Constraint**: Maintained strict discipline by installing 0 new skills during the fix-pass, keeping the total installed skills at 6.

---

## 4. Fix-Pass 2 Skills Discovery Matrix (18 Mandatory Queries)

Executed on 2026-10-22 against catalog `rmyndharis/antigravity-skills` (v0.1.11, 307 catalog skills) using `npx @rmyndharis/antigravity-skills search "<query>"`. Raw results captured in `report/results/catalog_search_pass2.json`.

| # | Query | Matches Found | Key Skills Found | Action & Decision Rationale |
|---|-------|:-------------:|------------------|-----------------------------|
| 1 | `model evaluation` | 20 | `llm-evaluation`, `threat-modeling-expert` | **Evaluated & Rejected**: Matches focus on LLMs and threat modeling. Evaluation of tabular and autoencoder models requires standard scikit-learn / PyTorch metrics; built custom evaluation script in `report/experiments/exp_candidate_reeval.py`. |
| 2 | `imbalanced classification` | 0 | None in catalog | **Custom Tooling Built**: No dedicated imbalanced classification skill in catalog. Implemented per-class metrics, macro vs. weighted F1 analysis, and stratified bootstrap sampling directly using scikit-learn. |
| 3 | `data leakage` | 20 | `data-engineer`, `data-engineering-*` | **Custom Tooling Built**: Catalog skills focus on ETL/data warehouses. Built dataset leakage forensics scripts checking exact/near hash collisions and time/day disjointness. |
| 4 | `cross-validation` | 20 | `deployment-validation-*`, `application-performance-*` | **Evaluated & Rejected**: Matches are deployment config validators, not statistical cross-validation. Used scikit-learn cross-validation routines directly. |
| 5 | `calibration` | 0 | None in catalog | **Custom Tooling Built**: No calibration skill in catalog. Implemented 10-bin Expected Calibration Error (ECE), Brier score, and reliability diagram generators directly. |
| 6 | `experiment tracking` | 6 | `mlops-engineer`, `data-engineering-*` | **Installed `mlops-engineer`**: Applied for experiment artifact versioning, metadata logging schema, and reproducibility tracking. |
| 7 | `reproducibility` | 0 | None in catalog | **Custom Tooling Built**: Built deterministic experiment runners enforcing seeds, recording environment details, git commit hashes, and raw output JSONs per Truth Rules. |
| 8 | `benchmark` | 1 | `llm-evaluation` | **Evaluated & Rejected**: LLM-specific. Benchmark suite already implemented in `report/experiments/`. |
| 9 | `statistics` | 1 | `seo-content-refresher` | **Evaluated & Rejected**: Irrelevant SEO skill matching keyword. Statistical tests and confidence intervals implemented via SciPy/NumPy. |
| 10 | `bootstrap` | 0 | None in catalog | **Custom Tooling Built**: Implemented non-parametric percentile bootstrap (1,000 resamples) for 95% confidence intervals on tiny classes (Infiltration, WebAttack, Bot). |
| 11 | `confidence interval` | 1 | `e2e-testing-patterns` | **Evaluated & Rejected**: E2E testing skill matched coincidentally. CI computation built directly into experiment scripts. |
| 12 | `data validation` | 20 | `data-quality-frameworks`, `data-engineer` | **Installed `data-quality-frameworks`**: Applied for schema integrity verification, manifest checksum audits, and missing/corrupt row assertions on CICIDS2017 CSVs. |
| 13 | `security audit` | 20 | `security-auditor`, `firmware-analyst` | **Already Installed (`security-auditor`)**: Continued use for threat surface and defensive posture analysis. |
| 14 | `scientific writing` | 11 | `postmortem-writing`, `angular-migration` | **Evaluated & Rejected**: Unrelated writing skills. Adhering to IEEE thesis guidelines and local `docs-architect` skill. |
| 15 | `pdf` | 0 | None in catalog | **Custom Tooling Built**: Custom Playwright/Paged.js build pipeline maintained in `report/build.mjs`. |
| 16 | `report QA` | 2 | `data-storytelling`, `team-collaboration-issue` | **Already Installed (`data-storytelling`)**: Narrative framing and tabular presentation. |
| 17 | `accessibility` | 7 | `accessibility-compliance-accessibility-audit` | **Installed `accessibility-compliance-accessibility-audit`**: Applied to audit PDF/HTML report contrast, heading hierarchies, table headers, and ARIA labels. |
| 18 | `link checker` | 4 | `linkerd-patterns`, `kubernetes-architect` | **Evaluated & Rejected**: Matches are service mesh tools. Internal anchor link checker built directly into test suite (`test_citations.py`). |

### Fix-Pass 2 Skills Usage Impact:
- **`data-quality-frameworks`**: Structured the manifest and CSV integrity verification pipeline in `report/experiments/audit_dataset_provenance.py` to validate types, ranges, non-finite values, and hash fidelity.
- **`mlops-engineer`**: Standardized experiment outputs (`report/results/*.json`) with explicit metadata schemas, git commit hashes, execution seeds, environment signatures, and execution timers.
- **`accessibility-compliance-accessibility-audit`**: Guided HTML/PDF structure compliance: ensuring table headers (`<th>`), SVG accessibility titles, color contrast ratios on heatmaps, and RTL directionality for Arabic text.
- **`data-scientist`** (pre-installed): Guided the design of the day-disjoint split protocol, duplicate-policy sensitivity analysis, train/serve feature skew ablation, and non-parametric bootstrap confidence intervals.
- **`machine-learning-ops-ml-pipeline`** (pre-installed): Guided the candidate model re-evaluation harness, isolation forest / z-score baseline comparisons, and train/serve skew identification across `live_sniffer.py` and `tailer.py`.

