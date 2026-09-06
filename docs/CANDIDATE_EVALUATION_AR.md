# تقييم المرشح CSE-CIC-IDS2018 v1

**التاريخ:** 18 أغسطس 2026  
**الحالة:** `failed_gates` — لم يُرقَّ ولم يتغير النموذج الفعّال  
**المسار:** `data/models/candidates/cse-cic-ids2018-v1-seed42/`

> هذا تقرير تاريخي مجمّد لمرشح v1. لا يجوز استخدام captures المسماة
> `final test` هنا لضبط أو ادعاء نتيجة Pipeline v2. في 26 أغسطس 2026 أصبح
> منطق v2 classifier-first منفذًا ومختبرًا بوحدات حتمية، لكن لم تتوفر مجموعة
> final جديدة غير مفتوحة؛ لذلك لا توجد نتيجة دقة v2 ولا مرشح إنتاجي جديد.

## المصدر والترخيص

استُخدمت ملفات CSV الأصلية المنشورة من Canadian Institute for Cybersecurity في
University of New Brunswick ضمن
[CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html). يسمح الناشر
بالاستخدام وإعادة التوزيع مع ذكر المجموعة والرابط. رابط CICIDS2017 الرسمي توقف
عند نموذج بيانات شخصية يعرض خطأ خادم، لذلك لم يُتجاوز النموذج واستُخدم البديل
الأحدث الرسمي من S3 العام.

الناشر لا ينشر SHA-256 لهذه الملفات. تحقق التنزيل من حجم S3 وETag متعدد الأجزاء،
ثم سُجل SHA-256 محلي الملاحظة بصدق، ولا يوصف بأنه publisher-verified.

| Capture | الاستخدام | Bytes | SHA-256 المحلي |
|---|---|---:|---|
| 2018-02-15 | training | 375,945,899 | `fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b` |
| 2018-02-22 | training | 382,636,202 | `da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544` |
| 2018-02-14 | calibration | 358,223,333 | `acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147` |
| 2018-02-16 | final test | 333,723,605 | `1a4919faa0c49c7af97230b0c2d076eba23ee6dd81103a3801d51ac316355d8b` |
| 2018-02-23 | final test | 382,840,456 | `d0a7f5059d9823b6e9b392b759e306481a3502d190dea7a1b5502ae079ea069b` |
| 2018-02-21 | OOD test | 328,893,673 | `a5f4a1c2689e0aa6566c03a58466de9c407c0be0cbd3cc69306544026611be04` |

الإجمالي: **2,162,263,168 bytes** و**6,291,450 صفًا خامًا**. جرد labels الخام:

- 15 فبراير: 996,077 Benign؛ 41,508 GoldenEye؛ 10,990 Slowloris.
- 22 فبراير: 1,048,213 Benign؛ 249 Web brute force؛ 79 XSS؛ 34 SQL injection.
- 14 فبراير: 667,626 Benign؛ 193,360 FTP brute force؛ 187,589 SSH brute force.
- 16 فبراير: 446,772 Benign؛ 461,912 Hulk؛ 139,890 SlowHTTPTest؛ وصف header مكرر واحد حُذف من derived data.
- 23 فبراير: 1,048,009 Benign؛ 362 Web brute force؛ 151 XSS؛ 53 SQL injection.
- 21 فبراير: 360,833 Benign؛ 686,012 HOIC؛ 1,730 LOIC-UDP.

## التدقيق ومنع التسرب

حُفظت bytes الأصلية read-only تحت `data/datasets/cse-cic-ids2018/raw/`.
توجد المصفوفات المشتقة منفصلة تحت `derived/` مع parent hash وtransform version.
التدقيق الكامل في `dataset_audit.json` وملخصه العربي في
`DATASET_AUDIT_AR.md`.

قُسمت البيانات حسب أيام التقاط منفصلة قبل التدريب. ثم أزيل التكرار exact
وnear-duplicate عالميًا بترتيب ثابت: training ثم calibration ثم final ثم OOD.
كان hash المرشح v1 يضم `label` مع الصف، وهو خلل لأنه يخفي تطابق الميزات ذات
labels المتعارضة. لا يُعاد تفسير تقرير v1 كإثبات خلوه من هذا التسرب. الإصدار
الحالي `cyberguard-feature-row-hash-v2` يحسب exact/near من الميزات فقط، ويتتبع
labels منفصلة، ويبلغ same-label/conflicting-label ويُفشل gate عند التعارض.

| القسم | Captures | الصفوف بعد إزالة التسرب | Labels canonical |
|---|---|---:|---|
| Training pool | 15 و22 فبراير | 1,279,390 | Benign 1,246,955؛ DoS 32,120؛ WebAttack 315 |
| Calibration | 14 فبراير | 456,018 | Benign 361,924؛ BruteForce 94,094 |
| Final test | 16 و23 فبراير | 1,063,406 | Benign 968,561؛ DoS 94,481؛ WebAttack 364 |
| OOD | 21 فبراير | 531,248 | Benign 358,033؛ DDoS 173,215 |

ملف `split_manifest.npz` يحفظ row hashes وnear hashes، ويحفظ
`split_manifest.json` captures والأعداد وhash لكل قائمة. استُخدمت عينة تدريب
حتمية: كل الهجمات بعد dedup وحد أقصى 300,000 Benign مرتبة بالـrow hash. لم
تدخل إحصاءات calibration/final/OOD في RobustScaler أو baseline benign.

## المعمارية والـablation

- RobustScaler: fitted على training-benign فقط.
- StatisticalFilter: fitted على training-benign، والعتبة `8.356655` هي p99
  من calibration-benign، بميزانية FPR مقدارها 1%.
- XGBoost: 200 شجرة، depth 7، أوزان فئات؛ الأصناف المدرّبة
  `Benign, DoS, WebAttack`.
- عتبة الامتناع `0.735`: اختيرت من capture المعايرة فقط بحد benign FPR
  0.5% وحد high-confidence mislabel للفئة المحجوزة 10%.
- Autoencoder 32→64→32→16→32→64→32: 20 epoch على training-benign فقط؛
  العتبة p99.5 من calibration-benign.
- Isolation Forest: baseline على training-benign فقط.
- لم تُضف طبقة probability calibrator لأن capture المعايرة لا يحتوي support
  مستقلًا للأصناف supervised؛ إضافة isotonic/Platt في هذه الحالة غير مبررة.
- لم يُحتفظ بـOOD ensemble: statistical AUROC **0.9665** أعلى من max-signal
  ensemble **0.9462**. Isolation Forest AUROC **0.8021** وAE AUROC **0.6405**.

## نتائج final test المستقلة

### المصنف منفردًا

| Class | Precision | Recall | F1 | PR-AUC | Brier | Support |
|---|---:|---:|---:|---:|---:|---:|
| Benign | 0.9943 | 0.9599 | 0.9768 | 0.9964 | 0.05061 | 968,561 |
| DoS | 0.6965 | 0.9435 | 0.8014 | 0.7056 | 0.05059 | 94,481 |
| WebAttack | 0.9736 | 0.9121 | 0.9418 | 0.9147 | 0.000037 | 364 |

- Macro precision/recall/F1: **0.8881 / 0.9385 / 0.9067**.
- Weighted precision/recall/F1: **0.9678 / 0.9584 / 0.9612**.
- Macro PR-AUC: **0.8722**؛ macro Brier: **0.03375**؛ ECE-10: **0.06535**.
- Confusion matrix، بترتيب Benign/DoS/WebAttack:
  `[[929710,38842,9],[5339,89142,0],[32,0,332]]`.
- عند confidence 0.90: coverage **72.04%** وselective risk **0.414%**.

### المسار الكامل والبسيط

| Detector | TP | FP | FN | TN | Precision | Recall | F1 | Benign FPR / 10k |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Full 4-stage | 1 | 106 | 94,844 | 968,455 | 0.00935 | 0.0000105 | 0.0000211 | 1.094 |
| Statistical only | 1,294 | 5,363 | 93,551 | 963,198 | 0.1944 | 0.01364 | 0.02550 | 55.37 |
| Isolation Forest | 2,237 | 77,895 | 92,608 | 890,666 | 0.02792 | 0.02359 | 0.02557 | 804.23 |
| Autoencoder only | 0 | 180 | 94,845 | 968,381 | 0 | 0 | 0 | 1.858 |

المصنف وحده جيد نسبيًا، لكن StatisticalFilter المحفوظ منع معظم الهجمات من
الوصول إليه. known-attack bypass الصحيح كان 1/94,845 فقط؛ لذلك لا يجوز عرض
نتائج المصنف كأنها نتائج pipeline.

### OOD والرصد

- DDoS محجوز بالكامل من supervised training.
- Statistical OOD AUROC/PR-AUC: **0.9665 / 0.9414**.
- Isolation Forest: **0.8021 / 0.6502**.
- Autoencoder: **0.6405 / 0.3936**.
- High-confidence known-label misroute: **0%**، لكن review route أيضًا **0%**؛
  هذه ليست نتيجة نجاح، بل دليل أن البوابة الإحصائية أخفت OOD قبل المراجعة.

## الأداء والموارد

Benchmark من 50,000 صف على Ryzen 5 240 وRTX 5050 8GB:

- full pipeline: **256,882 row/s**، mean **0.00389 ms/row**؛ batch-estimated
  p50/p95/p99 = **0.000755 / 0.01809 / 0.02911 ms/row**.
- statistical: **11,339,751 row/s**.
- classifier على 22,723 صفًا وصلته: **625,972 row/s**.
- autoencoder على 22,723 صفًا وصلته: **160,185 row/s**.
- peak process RSS: **4,450,872 KiB**؛ peak CUDA allocation: **816,836,608 bytes**.

الأرقام تخص هذه المصفوفة والـbatching ولا تمثل network line rate أو SLA.

## الـgates والقرار

نجحت gates الخاصة بالحجم، support، finite output، ECE، benign FPR، وhigh
confidence OOD mislabel. فشل المرشح في:

1. full-pipeline F1 لم يتفوق على StatisticalFilter.
2. full-pipeline F1 لم يتفوق على Isolation Forest.

لذلك الحالة **`failed_gates`** و`production_approved=false`. رفض
`python -m backend.detection.promote ...` الـdry-run بسبب هذين الفشلين.
شغّل v1 مقارنة shadow تاريخية على 100,000 صف دون LLM أو تغيير pointer، لكن
هذا التقرير القديم لا يحقق عقد `cyberguard-shadow-report-v3` ولا يجعل المرشح
قابلًا للترقية. الترقية الحالية تتطلب تقريرًا مطابقًا ومربوطًا تشفيريًا بكل
artifact hashes والـmanifest مع صفر DB/pointer mutations. لم يُنفذ promotion
أو firewall/EDR action.

## الحدود والخطوة التالية

- لا توجد تغطية supervised مستقلة لـBruteForce أو DDoS أو Bot أو PortScan أو
  Infiltration في هذا المرشح.
- numerical flow features لا تفحص payload؛ تسمية WebAttack لا تعني قراءة SQL/XSS.
- checksum-only لا يقاوم مهاجمًا يستطيع تبديل artifact والـmanifest معًا.
- المرشح لم يطبق probability calibration layer؛ ECE المعروض للمصنف الخام.

الخطوة الآمنة التالية: منطق v2 classifier-first جاهز في الكود والتقييم والـshadow؛
يجب تدريبه ومعايرته **على training/calibration جديدة فقط** ثم تقييمه مرة واحدة
على captures نهائية جديدة لم تُفتح. لا تُستخدم أرقام v1 لضبط thresholds.

## عقد Pipeline v2 المنفذ بلا ادعاء نتيجة

- كل صف validated يصل إلى المصنف قبل التوجيه.
- Z-score وautoencoder إشارتان مستقلتان ولا تعلنان benign مبكرًا.
- التقرير الجديد يضم classifier/statistical/autoencoder/Isolation Forest
  baselines، TP/FP/FN/TN، FPR لكل 10,000، per-class PR-AUC/support، ECE،
  routing counts، review rate، OOD mislabel، throughput والذاكرة.
- manifest v2 يتطلب calibration source وdataset hashes وthresholds المطابقة.
- coverage contract يصرح trained/evaluated/OOD-only/unsupported والـtelemetry.
- لم يُنشأ أو يُرقَّ أي candidate v2 في هذا التحديث لغياب final جديد مستقل.
- بوابة `evaluation_intake.py` الجديدة وتوثيق
  `INDEPENDENT_EVALUATION.md` يرفضان role/capture/time leakage والتكرار الدقيق
  بين الأقسام، بينما يربط `evaluation_report.py` التقرير بالـdataset/splits/
  artifacts/calibration/source/command/environment. Fixtures لا يمكن تسميتها
  final evaluation ولا تكوّن ادعاء دقة.
