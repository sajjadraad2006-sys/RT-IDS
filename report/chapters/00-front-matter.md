# FRONT MATTER

<div class="title-page">
  <div class="thesis-header">
    <h2>[UNIVERSITY / FACULTY / INSTITUTION - TO BE FILLED]</h2>
    <h3>[DEPARTMENT OF MECHATRONICS ENGINEERING / COMPUTER ENGINEERING - TO BE FILLED]</h3>
  </div>

  <div class="thesis-title-block">
    <h1 class="thesis-main-title">AN EMPIRICAL AUDIT, BENCHMARKING, AND ARCHITECTURAL ANALYSIS OF A HYBRID REAL-TIME INTRUSION DETECTION AND AUTONOMOUS CONTAINMENT SYSTEM (CYBERGUARD)</h1>
    <h3 class="thesis-subtitle">Forensic Code Inspection, Train/Serve Skew Analysis, Formal Verification Guarantees, and Mechatronic Industrial Network Adaptation</h3>
  </div>

  <div class="thesis-metadata-block">
<p>A Thesis Submitted in Partial Fulfillment of the Requirements for the Degree of<br>
    <strong>Master of Science in Mechatronics / Cybersecurity Engineering</strong></p>
<div class="authorship-grid">
<div class="author-col">
<p><strong>Candidate:</strong></p>
<p class="placeholder-text">[STUDENT NAME - TO BE FILLED]</p>
<p class="placeholder-sub">[STUDENT IDENTIFIER / REGISTRATION NUMBER]</p>
</div>
<div class="supervisor-col">
<p><strong>Principal Supervisor:</strong></p>
<p class="placeholder-text">[SUPERVISOR - TO BE FILLED]</p>
<p class="placeholder-sub">[ACADEMIC TITLE / AFFILIATION]</p>
</div>
</div>
<div class="submission-date">
<p>October 2026</p>
</div>
  </div>
</div>

<div class="page-break"></div>

## DECLARATION OF AUTHORSHIP

I, [STUDENT NAME - TO BE FILLED], declare that this thesis titled *"An Empirical Audit, Benchmarking, and Architectural Analysis of a Hybrid Real-Time Intrusion Detection and Autonomous Containment System (CyberGuard)"* and the work presented in it are my own. I confirm that:

1. This work was done wholly while in candidature for a Master of Science degree at [UNIVERSITY / INSTITUTION - TO BE FILLED].
2. Where any part of this thesis has previously been submitted for a degree or any other qualification at this University or any other institution, this has been clearly stated.
3. Where I have consulted the published work of others, the source is always clearly attributed in accordance with IEEE citation standards.
4. Where the thesis is based on work done by myself jointly with others, I have made clear exactly what was done by others and what I have contributed myself.
5. All empirical figures, benchmarks, line counts, and vulnerability analyses presented in this document were directly measured or audited against the target codebase and verified execution environments; no metrics or citations have been fabricated.

<br><br>
<div class="signature-line">
  <p>Candidate Signature: _____________________________________ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Date: ___________________</p>
</div>

<div class="page-break"></div>

## ACKNOWLEDGMENTS

[STUDENT ACKNOWLEDGMENTS - TO BE FILLED]

*The author wishes to express sincere gratitude to [SUPERVISOR], the faculty of [DEPARTMENT], and colleagues for their invaluable guidance, constructive criticism, and technical insights throughout the course of this research.*

<div class="page-break"></div>

## ABSTRACT

Modern enterprise and industrial cyber-physical networks face increasingly sophisticated, low-latency cyber threats, ranging from volumetric denial-of-service and lateral reconnaissance to supply-chain tampering and prompt-injection vectors targeting cognitive security systems. To counter these attacks, modern security operations centers increasingly explore hybrid Real-Time Network Intrusion Detection Systems (RT-IDS) coupled with autonomous Security Orchestration, Automation, and Response (SOAR) containment mechanisms. This thesis presents a comprehensive, master's-thesis-grade technical audit, empirical benchmark, and critical evaluation of **CyberGuard**, an open-source hybrid intrusion detection and guarded containment framework. 

Adhering strictly to empirical evidence rules, this investigation combines static byte-and-AST source code auditing (disaggregating the 113,107 total repository lines into 31,865 Python source lines [27,750 SLOC across 139 files], 9,682 Python test lines [7,756 SLOC across 44 files], 6,917 frontend JS/HTML/CSS lines [6,223 SLOC across 13 files], 12,606 documentation and configuration lines [11,816 SLOC across 31 files], 617 automation and operational script lines [513 SLOC across 8 files], and 51,420 dataset, raw fixture, and binary asset lines [49,053 SLOC across 64 files] across exactly 299 total files), dependency forensics, and an exhaustive experimental test battery. Crucially, the repository encompasses two distinct model architectures: (1) a bundled synthetic-trained model (`data/models/trained/`) serving as an evaluation fixture across 4 classes, and (2) a newly integrated candidate pipeline (`data/models/candidate_cicids2017/`) trained on 2.097 million real CICIDS2017 network flows across 8 classes, retained strictly in shadow evaluation mode (`shadow_only_not_promoted, production_approved=false`).

We test seven critical hypotheses ($H_1$ through $H_7$). First, we confirm ($H_1$) that the bundled detection model was trained on an artificial synthetic fixture (`sample_traffic.csv`, seed 42) with hand-set Gaussian/exponential distributions across only four classes (`Benign`, `Bot`, `DDoS`, `PortScan`), rendering claimed laboratory accuracies (96.25%) scientifically unrepresentative of real traffic. When evaluated on real CICIDS2017 traffic, the bundled model suffers catastrophic collapse down to 38.15% accuracy and 0.0757 Macro-F1, triggering false alarms on 55.07% of benign flows. Second, while the real-data candidate model achieves a high headline accuracy (98.49%) and Weighted-F1 (0.9855 [95% CI: 0.9852, 0.9860]), this metric is heavily dominated by Benign traffic (84.8% of the test partition). Macro-F1 (0.6852 [95% CI: 0.6447, 0.7133]) unmasks severe operational blind spots: complete detection collapse on `Bot` traffic (0.00% recall, 0.00 F1 across 113 samples), poor precision on `PortScan` (0.1862), and severe variance on `Infiltration` (support = 7, rendering its 0.80 F1 statistically uninterpretable). Third, we expose critical methodological decisions in the candidate workflow: silent resolution of 6,132 exact and 3,228 near conflicting duplicate rows by first-seen CSV order; an optimistic row-order `capture_group` split that conceals temporal drift; and an autoencoder trained only on the first 100,000 benign rows that exhibits higher reconstruction error on benign test traffic than on attack traffic. Fourth, we expose severe train/serve feature skew: forcing features to live sniffer values collapses candidate Macro-F1 to 0.3668, while Suricata approximations drop it to 0.2840. Fifth, under a strict day-disjoint split (Mon–Wed train vs. Thu–Fri test), unseen attack miss rates jump to 65.69% ± 16.65%. Finally, we formulate a mechatronic cyber-physical safety interlock framework reconciling network containment with ISO 13849 robotic safety requirements.

**Keywords:** Network Intrusion Detection Systems (NIDS), Machine Learning in Cybersecurity, Train/Serve Skew, Empirical Software Forensics, Autonomous Containment, Formal Verification, SMT Solvers, Mechatronics Security, IEC 62443, Cyber-Physical Systems.

<div class="page-break"></div>

<div class="arabic-section" dir="rtl" lang="ar">

## ملخص الأطروحة (ARABIC ABSTRACT)

تواجه الشبكات المؤسسية والأنظمة السيبرانية-الفيزيائية المعاصرة تهديدات أمنية متقدمة وفائقة السرعة، تتراوح بين هجمات الحرمان من الخدمة الحجمية (DDoS) والاستطلاع الشبكي الخفي، وصولاً إلى استهداف أدوات الذكاء الاصطناعي التوليدي عبر هجمات حقن الأوامر (Prompt Injection). ولمواجهة هذه المخاطر، اتجهت مراكز العمليات الأمنية نحو تبني أنظمة كشف التسلل الشبكي الهجينة في الوقت الحقيقي (RT-IDS) المدمجة بمحركات الاحتواء الدفاعي الذاتي والتحكم الآلي (SOAR). تقدم هذه الأطروحة دراسة أكاديمية نقدية وتدقيقاً جنائياً برمجياً شاملاً، مدعوماً بتقييم تجريبي معملي، لمنظومة **CyberGuard** مفتوحة المصدر للكشف عن التسلل والتحييد التلقائي للتهديدات.

انطلاقاً من قواعد الحقيقة الصارمة القائمة على الأدلة المباشرة، يجمع هذا البحث بين التدقيق البرمجي الثابت للشفرة المصدرية (مع تفصيل إجمالي أسطر المستودع البالغة 113,107 أسطر إلى: 31,865 سطراً لمصدر بايثون [27,750 سطر برمجي عبر 139 ملفاً]، و 9,682 سطراً لاختبارات بايثون [7,756 سطر برمجي عبر 44 ملفاً]، و 6,917 سطراً لواجهات الويب JS/HTML/CSS [6,223 سطر برمجي عبر 13 ملفاً]، و 12,606 أسطر لملفات التوثيق والإعدادات [11,816 سطر برمجي عبر 31 ملفاً]، و 617 سطراً لنصوص الأتمتة والتشغيل [513 سطر برمجي عبر 8 ملفات]، و 51,420 سطراً لملفات البيانات والعينات والأصول الثنائية [49,053 سطر برمجي عبر 64 ملفاً] ضمن 299 ملفاً إجمالياً للمستودع)، وفحص نماذج التعلم الآلي المحفوظة، وتشغيل بطارية اختبارات إجهاد وتجارب استنساخية كاملة. وتفحص الأطروحة بنية النموذجين في المستودع: (1) النموذج المدمج المدرب على بيانات اصطناعية كعينة فحص، و (2) نموذج المرشح المستقل المدرب على بيانات حقيقية من مجموعة CICIDS2017 عبر 2.097 مليون تدفق شبكي، والمحفوظ حصرياً في وضع التقييم الخفي دون ترقية تشغيلية (`shadow_only_not_promoted`).

اختبرت الأطروحة سبع فرضيات علمية أساسية ($H_1$ إلى $H_7$)؛ حيث تم إثبات أن النموذج المدمج ($H_1$) يعاني من انهيار كارثي عند اختباره على بيانات شبكية حقيقية، حيث تهبط دقته من 96.25% إلى 38.15% ومعدل Macro-F1 إلى 0.0757، مع إطلاق إنذارات زائفة على 55.07% من تدفقات البيانات البريئة. ورغم تحقيق نموذج المرشح المدرب على البيانات الحقيقية دقة ظاهرية بلغت 98.49% ومعدل Weighted-F1 قدره 0.9855، إلا أن هذا المقياس مضلل بسبب هيمنة التدفقات البريئة (84.8% من البيانات)، بينما كشف معدل Macro-F1 البالغ 0.6852 عن فشل كلي في كشف هجمات البوتنت (`Bot`) بمعدل استدعاء 0.00% ودقة ضعيفة في كشف هجمات مسح المنافذ `PortScan` (0.1862). كما كشف التدقيق عن قرارات منهجية حساسة: حل التعارض في 6,132 صفاً متطابقاً بحسب أسبقية الظهور، وتقسيم البيانات بناءً على ترتيب الصفوف مما يمنح نتائج مفرطة التفاؤل، وانحراف التدريب والتشغيل الذي يخفض مقياس Macro-F1 إلى 0.3668 عند تطبيق قيود ملتقط الحزم المباشر، وتخطي نسبة إفلات الهجمات غير المرئية حاجز 65.69% عند اختبار نموذج مقسم على أساس الأيام المستقلة. واختتمت الأطروحة بطرح منظور هندسة الميكاترونكس لحماية الشبكات الصناعية الروبوتية وفق معايير الأمان الوظيفي (IEC 62443 و ISO 13849).

**الكلمات المفتاحية:** كشف التسلل الشبكي (NIDS)، التعلم الآلي في الأمن السيبراني، انحراف التدريب والتشغيل، التدقيق الجنائي للبرمجيات، الاحتواء التلقائي، التحقق الصوري، محللات SMT، أمن الميكاترونكس، معيار IEC 62443، الأنظمة السيبرانية-الفيزيائية.

</div>

<div class="page-break"></div>

## LIST OF ABBREVIATIONS

| Abbreviation | Expanded Definition |
|:-------------|:--------------------|
| **ABAC** | Attribute-Based Access Control |
| **API** | Application Programming Interface |
| **AST** | Abstract Syntax Tree |
| **ATT&CK** | Adversarial Tactics, Techniques, and Common Knowledge (MITRE) |
| **AUC-PR** | Area Under the Precision-Recall Curve |
| **AUC-ROC** | Area Under the Receiver Operating Characteristic Curve |
| **BFF** | Backend-for-Frontend |
| **BPF** | Berkeley Packet Filter |
| **C2** | Command and Control |
| **CIC** | Canadian Institute for Cybersecurity |
| **CIDR** | Classless Inter-Domain Routing |
| **CPS** | Cyber-Physical Systems |
| **CPU** | Central Processing Unit |
| **CVE** | Common Vulnerabilities and Exposures |
| **D3FEND** | Detection, Denial, and Disruption Framework Empowering Network Defense (MITRE) |
| **DAST** | Dynamic Application Security Testing |
| **DDoS** | Distributed Denial of Service |
| **DLQ** | Dead Letter Queue |
| **DNS** | Domain Name System |
| **DoS** | Denial of Service |
| **EVE** | Extensible Event Format (Suricata JSON log) |
| **FIFO** | First-In, First-Out |
| **FN / FNR** | False Negative / False Negative Rate |
| **FP / FPR** | False Positive / False Positive Rate |
| **HMAC** | Hash-based Message Authentication Code |
| **H-ACD** | Hybrid Autonomous Cyber Defense |
| **HTTP / HTTPS** | Hypertext Transfer Protocol / Secure |
| **IAC** | Infrastructure as Code |
| **IACS** | Industrial Automation and Control Systems |
| **IAT** | Inter-Arrival Time |
| **ICMP** | Internet Control Message Protocol |
| **ICS** | Industrial Control Systems |
| **IDE** | Integrated Development Environment |
| **IDS / IPS** | Intrusion Detection System / Intrusion Prevention System |
| **IEEE** | Institute of Electrical and Electronics Engineers |
| **IOC** | Indicator of Compromise |
| **IP / IPv4 / IPv6** | Internet Protocol / Versions 4 and 6 |
| **JSON / NDJSON** | JavaScript Object Notation / Newline-Delimited JSON |
| **JWT** | JSON Web Token |
| **KDD** | Knowledge Discovery and Data Mining |
| **LLM** | Large Language Model |
| **LOC** | Lines of Code |
| **LRU** | Least Recently Used (cache) |
| **MAC** | Media Access Control |
| **ML / DL** | Machine Learning / Deep Learning |
| **MTBF** | Mean Time Between Failures |
| **MTTD / MTTR** | Mean Time to Detect / Mean Time to Respond |
| **NIC** | Network Interface Card |
| **NIDS** | Network Intrusion Detection System |
| **NIST** | National Institute of Standards and Technology |
| **OIR** | Operational Incident Response |
| **OOD** | Out-of-Distribution |
| **OPC UA** | Open Platform Communications Unified Architecture |
| **OS** | Operating System |
| **OSI** | Open Systems Interconnection |
| **PCAP** | Packet Capture |
| **PLC** | Programmable Logic Controller |
| **QF_LRA** | Quantifier-Free Linear Real Arithmetic (SMT-LIB2 logic) |
| **RAG** | Retrieval-Augmented Generation |
| **RBAC** | Role-Based Access Control |
| **RFC** | Request for Comments (IETF standard) |
| **RNG** | Random Number Generator |
| **ROC** | Receiver Operating Characteristic |
| **RST / SYN / ACK** | Reset / Synchronize / Acknowledgment (TCP flags) |
| **RT-IDS** | Real-Time Intrusion Detection System |
| **RTL** | Right-to-Left (text direction) |
| **SAST** | Static Application Security Testing |
| **SCADA** | Supervisory Control and Data Acquisition |
| **SHA / SHA-256** | Secure Hash Algorithm (256-bit) |
| **SIEM** | Security Information and Event Management |
| **SMT** | Satisfiability Modulo Theories |
| **SOAR** | Security Orchestration, Automation, and Response |
| **SPA** | Single Page Application |
| **SQL / SQLi** | Structured Query Language / SQL Injection |
| **SSRF** | Server-Side Request Forgery |
| **STRIDE** | Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege |
| **TCP / UDP** | Transmission Control Protocol / User Datagram Protocol |
| **TDD** | Test-Driven Development |
| **TLS** | Transport Layer Security |
| **TN / TNR** | True Negative / True Negative Rate |
| **TP / TPR** | True Positive / True Positive Rate |
| **URI / URL** | Uniform Resource Identifier / Uniform Resource Locator |
| **VCS** | Version Control System |
| **VLAN** | Virtual Local Area Network |
| **VM** | Virtual Machine |
| **VRAM** | Video Random Access Memory |
| **WAF** | Web Application Firewall |
| **XGBoost** | eXtreme Gradient Boosting |
| **XML** | Extensible Markup Language |
| **XSS** | Cross-Site Scripting |
| **Z3** | High-performance SMT Solver (Microsoft Research) |

<div class="page-break"></div>

## TABLE OF CONTENTS

<!-- The build script dynamically replaces this with page-referenced targets -->
<div id="table-of-contents-target">
  <ul class="toc-list">
    <li><span class="toc-title">Front Matter</span> <span class="toc-page">i</span></li>
    <li><span class="toc-title">Chapter 1: Introduction</span> <span class="toc-page">1</span></li>
    <li><span class="toc-title">Chapter 2: Background and Literature Review</span> <span class="toc-page">11</span></li>
    <li><span class="toc-title">Chapter 3: System Architecture as Built</span> <span class="toc-page">23</span></li>
    <li><span class="toc-title">Chapter 4: Implementation Analysis (Module by Module)</span> <span class="toc-page">37</span></li>
    <li><span class="toc-title">Chapter 5: Research Methodology and Verification Setup</span> <span class="toc-page">57</span></li>
    <li><span class="toc-title">Chapter 6: Experimental Results and Performance Benchmarks</span> <span class="toc-page">69</span></li>
    <li><span class="toc-title">Chapter 7: Security, Safety, and Threat Analysis</span> <span class="toc-page">83</span></li>
    <li><span class="toc-title">Chapter 8: Critical Evaluation and Threats to Validity</span> <span class="toc-page">95</span></li>
    <li><span class="toc-title">Chapter 9: Mechatronics Perspective: Cyber-Physical Network Defense</span> <span class="toc-page">109</span></li>
    <li><span class="toc-title">Chapter 10: Recommendations, Future Work, and Conclusion</span> <span class="toc-page">121</span></li>
    <li><span class="toc-title">References (IEEE Format)</span> <span class="toc-page">129</span></li>
    <li><span class="toc-title">Appendix A: Code Evidence Ledger</span> <span class="toc-page">135</span></li>
    <li><span class="toc-title">Appendix B: Test and Benchmark Execution Summaries</span> <span class="toc-page">141</span></li>
    <li><span class="toc-title">Appendix C: 32-Feature Flow Engineering Dictionary</span> <span class="toc-page">145</span></li>
    <li><span class="toc-title">Appendix D: Reproducibility Protocol and Runbook</span> <span class="toc-page">149</span></li>
    <li><span class="toc-title">Appendix E: Methodological Audit of Candidate Real-Data Model</span> <span class="toc-page">153</span></li>
    <li><span class="toc-title">Appendix F: Codebase Inventory and File Category Partition</span> <span class="toc-page">157</span></li>
  </ul>
</div>

<div class="page-break"></div>

## LIST OF FIGURES

- **Fig. 1.** Conceptual Overview of Modern Hybrid RT-IDS in Contemporary SOC Operations (Chapter 1).
- **Fig. 2.** Evolution of Network Intrusion Detection Systems from Packet Filtering to Neuro-Symbolic Ensembles (Chapter 2).
- **Fig. 3.** Methodological Pitfalls Across the Machine Learning Security Pipeline, based on Arp et al. (Chapter 2).
- **Fig. 4.** High-Level Layered System Architecture of CyberGuard as Built (Chapter 3).
- **Fig. 5.** End-to-End Data Flow Pipeline: From Raw Packets and EVE Logs to Actuation and Human Review (Chapter 3).
- **Fig. 6.** Concurrency and Thread Synchronization Model Across Sniffer, Worker Queue, and Pipeline (Chapter 3).
- **Fig. 7.** Sequence Diagram: Real-Time Packet Sniffing, Flow Assembly, and Pipeline Ingestion (Chapter 3).
- **Fig. 8.** Sequence Diagram: Automated Containment Actuation Under Two-Person Rule and Formal Safety Gate (Chapter 3).
- **Fig. 9.** State Machine of Bidirectional Flow Record Lifecycle with Teardown and TIME_WAIT Absorption (Chapter 4).
- **Fig. 10.** Canonical Decision Tree and Routing State Diagram in `backend/detection/router.py` (Chapter 4).
- **Fig. 11.** Architectural Topology of Suricata Live Tailer EVE Streaming Ingestion (Chapter 4).
- **Fig. 12.** Multi-Stage Neuro-Symbolic Defense Decision Engine and Contradiction Guard (Chapter 4).
- **Fig. 13.** Cryptographic Two-Person Rule and Atomic Rollback Receipt Generation Workflow (Chapter 4).
- **Fig. 14.** Dolev-Yao Threat Model Applied to Enterprise and Network Sensor Ingestion Boundaries (Chapter 5).
- **Fig. 15.** Experimental Setup and Hardware Testbed Topology (Chapter 5).
- **Fig. 16.** Empirical Latency Distribution ($P_{50}, P_{90}, P_{95}, P_{99}$) for Single-Row Pipeline Ingestion (Chapter 6).
- **Fig. 17.** Batch Processing Throughput Scaling and Flow Latency vs. Batch Size (Chapter 6).
- **Fig. 18.** Memory Footprint (Peak Traced KB) Across Evaluated Processing Batch Sizes (Chapter 6).
- **Fig. 19.** Confusion Matrix Heatmap for Bundled Classifier on the 2,000-Row Fixture (Chapter 6).
- **Fig. 20.** Autoencoder Reconstruction Error Distribution vs. Stored Anomaly Threshold (Chapter 6).
- **Fig. 21.** Adversarial Evasion Sensitivity Curves: DDoS Rate Attenuation and Window Size Dilation (Chapter 6).
- **Fig. 22.** Confusion Matrix Heatmap for Candidate Multi-Class XGBoost Model on Real CICIDS2017 Test Traffic (Chapter 6).
- **Fig. 23.** Precision-Recall Curves for Candidate Model Across Known Attack Classes on Real CICIDS2017 Traffic (Chapter 6).
- **Fig. 24.** Trust Boundaries and Decomposed Threat Surface of the CyberGuard Engine (Chapter 7).
- **Fig. 25.** Attack Tree for Unauthorized Network Blackholing via Actuator Manipulation (Chapter 7).
- **Fig. 26.** Comparison of Claimed vs. Audited Capabilities Across Core Functional Modules (Chapter 8).
- **Fig. 27.** Proposed Architecture for Deploying CyberGuard in an Industrial Robotic Manufacturing Cell (Chapter 9).
- **Fig. 28.** Cyber-Physical Safety Interlock: Ensuring Network Containment Cannot Disable Robot E-Stop (Chapter 9).

<div class="page-break"></div>

## LIST OF TABLES

- **TABLE I.** Comparison of Major Intrusion Detection Benchmarks and Documented Limitations (Chapter 2).
- **TABLE II.** Comprehensive Taxonomy of Intrusion Detection Approaches: Rule-Based, Anomaly, ML, and Hybrids (Chapter 2).
- **TABLE III.** Summary of the 32 Canonical CICFlowMeter Feature Schema Groupings (Chapter 4).
- **TABLE IV.** Canonical Router Decision Matrix and Precedence Rules in `router.py` (Chapter 4).
- **TABLE V.** Actuator Disruption Weights and Mitigation Classifications (Chapter 4).
- **TABLE VI.** Experimental Execution Environment and Hardware Baseline Specifications (Chapter 5).
- **TABLE VII.** Measured Execution Results for PyTest Automated Verification Suite (Chapter 6).
- **TABLE VIII.** Empirical Sniffer Behavioral Verification and Edge-Case Test Suite Results (Chapter 6).
- **TABLE IX.** Pipeline Latency Distribution Statistics for Single-Row Ingestion (Chapter 6).
- **TABLE X.** Pipeline Batch Scaling Benchmarks: Latency, Throughput, and Memory Utilization (Chapter 6).
- **TABLE XI.** Bundled Known-Attack Classifier Performance Metrics on the 2,000-Row Fixture (Chapter 6).
- **TABLE XI-B.** Candidate Model Real-Data Evaluation Performance Metrics ($N=406,661$) (Chapter 6).
- **TABLE XI-C.** Candidate Model Confusion Matrix Contingency on Real Test Partition (Chapter 6).
- **TABLE XI-D.** Detection Baselines Comparison on Real CICIDS2017 Test Partition (Chapter 6).
- **TABLE XI-E.** Synthetic-to-Real Generalization Gap (Chapter 6).
- **TABLE XI-F.** Stricter Temporal Day-Disjoint Split vs. Within-Session Split (Chapter 6).
- **TABLE XI-G.** Duplicate-Policy Sensitivity Analysis on Real CICIDS2017 Training Data (Chapter 6).
- **TABLE XI-H.** Train/Serve Feature Skew Ablation Study (Chapter 6).
- **TABLE XI-I.** Complete 32-Feature Train/Serve Equivalence Matrix (Chapter 6).
- **TABLE XII.** Contingency Table: Ground Truth Labels vs. Canonical Pipeline v2 Routing Outcomes (Chapter 6).
- **TABLE XIII.** Autoencoder Reconstruction Error Statistics Grouped by Class (Chapter 6).
- **TABLE XIV.** Statistical Filter Maximum Z-Score Anomaly Trigger Rates by Class (Chapter 6).
- **TABLE XV.** Adversarial Evasion Sensitivity Curve on Simulated DDoS Flow (Chapter 6).
- **TABLE XVI.** Comprehensive STRIDE Security and Threat Analysis Matrix (Chapter 7).
- **TABLE XVII.** Systematic Verification Matrix and Final Verdicts on Hypotheses $H_1$ Through $H_7$ (Chapter 8).
- **TABLE XVIII.** Repository Claims vs. Empirical Reality Audit Ledger (Chapter 8).
- **TABLE XIX.** Comparison of Industrial Automation Protocols (Modbus TCP, EtherNet/IP, OPC UA, PROFINET) (Chapter 9).
- **TABLE XX.** Recommended Engineering Roadmap for Hardening CyberGuard to Production Readiness (Chapter 10).
- **TABLE XXI.** Code Evidence Ledger (Appendix A).
- **TABLE XXII.** Complete 32-Feature Flow Engineering Dictionary (Appendix C).
- **TABLE XXVI.** Complete Peer-Reviewed Reference Verification and Provenance Ledger (Appendix E).
- **TABLE XXVII.** Exhaustive Repository File Inventory by Architectural Partition (Appendix F).

<div class="page-break"></div>
