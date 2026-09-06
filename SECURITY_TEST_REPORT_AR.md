# تقرير الاسترداد والتحقق الأمني — CyberGuard

**التاريخ:** 27 أغسطس 2026

**النطاق:** المستودع المحلي `/home/sajjad/Desktop/project` فقط

**الوضع النهائي:** محلّل تدفقات مرفوعة للاختبار والتقييم، وليس IDS حيًا أو IPS

## الخلاصة التنفيذية

أُصلحت المشكلات المؤكدة في عقد الإدخال ومسار الكشف والتسريب بين مجموعات البيانات والترقية والـshadow وربط MITRE وإدارة الذاكرة وصدق الواجهة والتشغيل القابل لإعادة الإنتاج. أصبح الإدخال غير المدعوم يفشل صراحةً، ويمر كل صف صالح إلى المصنف قبل اتخاذ قرار التوجيه، بينما تعمل الإشارة الإحصائية والـautoencoder كأدلة مستقلة لا كبوابة إسقاط مبكر.

بعد إغلاق مراجعة الـclean checkout نجح التحقق النهائي في **241 اختبارًا من
241** من نسخة مصدر جديدة بلا قاعدة SQLite مولدة، ونجحت بوابة `verify.py` في
**18 من 18**. لم يجد Bandit أي ملاحظة، ولم يجد `pip-audit` ثغرة معروفة في
الحزم القابلة للتدقيق؛ بقي wheel ‏PyTorch `+cpu` خارج مطابقة إصدار PyPI. لم
تُستخدم أنظمة عامة، ولم يُولّد مرور مؤذٍ، ولم تُنفذ استجابة آلية على مضيف أو
شبكة.

لا يوجد مع ذلك نموذج صالح لاعتماد إنتاجي. الحزمة النشطة القديمة ما زالت `production_approved: false` و`evaluation_only: true`، وتدعم بالتدريب أربعة أصناف فقط: `Benign`, `Bot`, `DDoS`, `PortScan`، ولا يوجد لها تقييم مستقل مسجل. بقي مرشح CSE-CIC-IDS2018 السابق فاشلًا وغير نشط، ولم تحدث أي ترقية آلية أو يدوية أثناء هذا العمل.

## الأسباب الجذرية المؤكدة

1. كان مسار الرفع يحوّل الأعمدة المفقودة إلى أصفار، لذلك كان بإمكان JSON عشوائي أو سجل نصي غير مدعوم أن يصبح متجهًا صفريًا ثم يُعرض كحميد.
2. كان خط الكشف القديم يستخدم Z-score كبوابة صلبة؛ الصف داخل العتبة يُعلن حميدًا قبل أن يراه المصنف أو الـautoencoder. يفسر ذلك كشف هجوم واحد فقط من 94,845 في التقييم التاريخي رغم أن المصنف المنفرد حقق macro F1 يقارب 0.9067.
3. كان hash إزالة التكرار يتضمن الملصق، ولذلك لم يكن يكشف صفوف الخصائص المتطابقة ذات الملصقات المتعارضة.
4. كانت الترقية تتحقق من المقاييس والسلامة الأساسية، لكنها لم تُلزم بتقرير shadow مطابق مشفّرًا لنفس ملفات المرشح.
5. كان endpoint الرفع يحتفظ بنسخ كاملة من bytes والنص والصفوف، وكانت إحصاءات الكمون تنمو عنصرًا لكل تدفق طوال عمر العملية.
6. كانت واجهة MITRE تعتمد على mapping ثابت للملصقات ولم تكن مرتبطة بمخرجات التنبيه المحفوظة مع provenance واضح.
7. احتوت الواجهة والـprompts على توصيفات أوسع من الدليل الفعلي، منها تسمية unknown anomaly كاستغلال جديد، وإيحاءات بوجود فحص packet payload أو live ingestion.
8. كان manifest يعلن fixtures غائبة، وكانت التبعيات غير مقيدة بالكامل، وكان `run.sh` يثبت الحزم كل مرة ويمكنه إنهاء عملية أخرى على المنفذ 8080.
9. أنشأت الجداول MITRE من دون فهرسة snapshot؛ لذلك اعتمد نجاح الاختبارات على
   قاعدة محلية سابقة، وكانت `verify.py` تعرض PASS حتى عند `techniques=0`.
10. كانت دفعات الرفع تعدّل إحصاءات عمر العملية قبل اكتشاف تلف متأخر أو تجاوز
    حد الصفوف، وكانت خدمة/evaluation/shadow تنفذ قواعد توجيه منفصلة.
11. كان decoder القياسي يطوي مفاتيح JSON الخام المكررة إلى آخر قيمة بلا رفض.
12. كان الموجّه النقي يحوّل `NaN/Inf` والقيم السالبة والعتبة غير الصالحة إلى
    قيم بديلة بدل رفض evidence/calibration غير الصالح.
13. كان حساب feature importance بعد database commit؛ لذلك كان فشله النظري
    يستطيع إرجاع 500 بعد حفظ state، ولم يكن parser wrapper يُغلق صراحةً عند
    فشل inference في دفعة لاحقة.
14. لم توجد بوابة موحدة لبيانات التقييم المستقلة تربط الترخيص والأدوار والأزمنة
    والملفات والتكرار، كما لم يكن تقرير القياس مربوطًا بكل inputs والمعايرة.

## عقد الإدخال المغلق افتراضيًا

أضيف المخطط `cyberguard-flow-input-v1`. يقيس التقرير التغطية من أسماء الأعمدة لا من كون القيمة غير صفرية، ويعيد:

- profile المكتشف؛
- الخصائص المباشرة والـaliases والخصائص القابلة للاشتقاق بأمان؛
- الخصائص المطلوبة المفقودة والأعمدة المتجاهلة؛
- تعارضات aliases؛
- الخلايا الرقمية غير الصالحة وعمليات التعقيم؛
- الصفوف المرفوضة والصفوف القابلة للاستخدام ونسبة التغطية.

الصيغ المدعومة هي CSV وTSV ذوا header، وJSON array من objects، وNDJSON/JSONL. يلزم أن تغطي الأعمدة الخصائص الـ32 مباشرة أو عبر alias/اشتقاق معتمد. من aliases الموثقة `Init_Win_bytes_fwd` و`Init_Win_bytes_bwd`. القيمة الصفرية قيمة صحيحة وليست مؤشرًا إلى غياب الخاصية.

تُرفض صراحةً ملفات `.log` و`.txt`، والنصوص headerless، وJSON غير الكائني،
والمفاتيح الخام المكررة، والكائنات العشوائية مثل
`{"message":"failed login"}`، والأعمدة العامة مثل `col_0`, `col_1`، والصفوف
غير القابلة للتحويل إلى متجه finite. تكرار المفتاح داخل JSON container خطأ
fatal ثابت السبب `duplicate_json_key`، بينما يبقى سطر NDJSON المكرر رفضًا
recoverable مسجلًا. يشمل الكشف المفاتيح المكافئة بعد JSON escape أو Unicode
NFC والتكرار داخل nested objects. يقبل تعارض aliases الاسمي فقط عندما تتساوى
كل القيم finite؛ zero مقابل missing أو قيم مختلفة يفشل مغلقًا. لا توجد حاليًا
محولات Zeek أو Suricata مختبرة.

## Pipeline v2

الإصدار البرمجي هو `cyberguard-pipeline-v2` مع `cyberguard-routing-v2`:

1. يُتحقق من المخطط وتُستخرج الخصائص وتُطبّع.
2. يعمل مصنف الهجمات المعروفة على **كل صف صالح** بلا fast-exit إحصائي.
3. يُحسب Z-score بشكل مستقل لكل صف.
4. يُحسب reconstruction/OOD signal بشكل مستقل عندما تدعم الحزمة ذلك.
5. يوجه القرار حتميًا إلى:
   - `known_attack` لهجوم مدعوم عالي الثقة؛
   - `human_review` لتنبؤ هجومي غير مؤكد أو خارج النطاق؛
   - `unknown_anomaly_review` عندما يقول المصنف حميد لكن يوجد دليل anomaly قوي؛
   - `benign` فقط عند غياب دليل قابل للتصرف من المصنف والإشارات المعايرة.

لا يشارك LLM في مسار القرار. ولا تُعد reconstruction error دليلًا على استغلال
جديد. تستخدم الخدمة وتقييم المرشح والـshadow المكوّن النقي نفسه
`backend/detection/router.py`، وتحافظ الدوال الفردية والدفعات على verdict
وroute متطابقين وبترتيب الإدخال نفسه. يرفض router evidence غير finite أو
سالبًا، وأنواع boolean/labels غير الصحيحة، وعدم تساوي الأطوال، ونسخ pipeline/
routing أو classifier threshold غير الصالحة. السجلات التاريخية التي لا تحمل
route لا تعيد Smart Log توجيهها؛ تفشل إلى `legacy_route_requires_review`.

الحزم القديمة موسومة صراحةً `cyberguard-pipeline-legacy-v1` وعتباتها `legacy_unvalidated`. إذا ادعى manifest أنه v2 من دون calibration metadata أو hash مطابق فإنه يفشل مغلقًا بدل إعادة تفسير عتبات قديمة.

## البيانات والتقييم

- أصبح hash الدقيق مبنيًا على الخصائص فقط، والملصق محفوظًا ومقارنًا بصورة مستقلة.
- يميز التدقيق بين exact/near duplicates ذات الملصق نفسه وذات الملصقات المتعارضة.
- تمنع تعارضات الملصق نجاح بوابات الجودة، مع إبقاء split منفصلًا حسب capture أو الزمن.
- أضيف coverage contract بإصدار مستقل يبين الملصقات المدربة/المدعومة والمقيمة وOOD-only وغير المدعومة وtelemetry profile.
- لا تكفي جودة الأصناف الموجودة إذا كانت الأصناف المعلنة غائبة عن التقييم.

لم يُعَد استخدام captures الاختبار النهائي السابق لضبط v2. لم تتوفر في المستودع مجموعة نهائية جديدة مستقلة، ولذلك لم تُنتج مقاييس دقة أو recall أو FPR جديدة ولم يُعتمد أي مرشح. يدعم workflow الآن TP/FP/FN/TN والدقة والاستدعاء وF1 وFPR وFP/10k ومقاييس كل صنف وPR-AUC وECE والتوجيه ومعدل المراجعة وOOD mislabel والذاكرة والـthroughput، ومقارنات classifier/statistical/autoencoder/Isolation Forest عندما تتوفر بيانات مشروعة.

أضيف `evaluation_intake.py` لعقد manifest مستقل يربط source/license/acquisition
والـtelemetry والـcaptures والأزمنة والحجوم وSHA-256 والـlabels/provenance/
preprocessing ودورًا وحيدًا لكل ملف. يستخدم sidecars متدفقة وقاعدة SQLite
مؤقتة لكشف exact cross-role duplicates وconflicting labels، ويرفض capture/time
leakage وإعادة final للمعايرة. ويربط `evaluation_report.py` المقاييس بالـdataset
والـsplits والـartifacts والمعايرة وإصدارات pipeline/routing والمصدر والأمر
والبيئة. Fixtures موسومة non-evaluation ولا يمكن تسميتها final أو إسناد accuracy
claim إليها. التفاصيل في `docs/INDEPENDENT_EVALUATION.md`.

## shadow والترقية

الوضع الافتراضي للترقية dry-run. تتطلب الترقية الفعلية `--apply` وهوية موافق بشري، إضافة إلى:

- سلامة artifacts وmanifest؛
- حالة مرشح قابلة للترقية ونجاح كل البوابات المعلنة؛
- coverage contract وPipeline v2 metadata صالحين؛
- `cyberguard-shadow-report-v3` ناجح يطابق hashes الحالية للـartifacts
  والـmanifest والتدقيق والمعايرة وcoverage contract وإصدارات التوجيه؛
- عدم تغير artifacts بعد shadow؛
- صفر تغيير في active pointer أو قاعدة البيانات أثناء shadow؛
- صفر LLM call أثناء shadow.

توجد اختبارات للتقرير المفقود والقديم وغير المطابق والفاشل والصحيح، وتغير
artifact أو calibration/pipeline/coverage بعد shadow، وغياب الموافقة البشرية.
لم يُرقَّ مرشح CSE-CIC-IDS2018 الفاشل.

## MITRE وLLM وSmart Log

- تُحفظ candidate ATT&CK mappings مع alert ID وclassifier label وmapping version وconfidence وكونها heuristic hypothesis وليست observed evidence.
- يُربط العرض بتلك mappings الحية، وتتم الكتابة والتنظيف ضمن lifecycle قاعدة البيانات.
- لا يحصل unknown anomaly على technique من المصنف من دون دليل مستقل.
- يختار مزامِن ATT&CK المرجع الخارجي الصحيح ولا يفترض أن أول `external_references` هو MITRE، ويزيل/يعلّم العناصر الملغاة والمتقادمة ويحدث `sync_log` ثم يفهرس snapshot النشط.
- تبدأ اختبارات MITRE و`verify.py` من SQLite مؤقتة فارغة، وتتحقق من snapshot
  المضمنة، ومن count غير صفري ووجود `T1498`، ثم من استرجاع RAG. تعرض البوابة
  snapshot/SQLite/count/RAG كأربع نتائج مستقلة ولا يمكن أن تعرض PASS للعدد صفر.
- تشتمل prompts على operational mode وحالة الاعتماد ونطاق الأصناف وإصدار pipeline والقيود، وتصف artifact التقييمي كدليل غير متحقق يحتاج مراجعة.
- تاريخ المحادثة محدود بآخر رسائل الجلسة نفسها وبحدود أطوال، ويُعامل المحتوى المخزن كمدخل غير موثوق.
- يعيد RAG لا سياقًا عندما لا يتجاوز أي تطابق حد الصلة الأدنى.
- يغطي Smart Log canonical evidence أوسع: أهم خاصية وقيمتها finite وقيمتها المطبعة وZ/anomaly score وإصدار schema وprofile والتغطية وإصدار artifact/pipeline. يغطي fingerprint هذا الدليل، ولا تُخزن identifiers شبكية غير لازمة في prompt.

## الرفع والذاكرة

يقرأ الرفع CSV/TSV وNDJSON وJSON array تدريجيًا من spool المملوك للطلب من دون
إنشاء نسخة upload كاملة ثانية، ويفرض حدود bytes والصفوف أثناء المعالجة. حجم
دفعة inference الافتراضي 5,000 صف، وحد النتائج المعادة 500 alert، وحد الحفظ
5,000 alert. تعيد الاستجابة الأعداد المنفصلة: parsed وaccepted وrejected
وanalyzed وgenerated وreturned وpersisted، وتعرض caps.

استبدلت قائمة الكمونات غير المحدودة بمتوسط online ثابت الذاكرة. inference
للدفعة لا يغير الإحصاءات العامة؛ يجمع الرفع aggregate ثابت الحجم ولا يدمجه إلا
مرة بعد اكتمال container وحدود bytes/rows ونقطة الحفظ الآمنة. أثبتت regressions
أن 5,000 صف صالح يتبعها JSON تالف، وكذلك تجاوز حد الصفوف بعد دفعات معالجة،
يعيدان 400/413 بلا تغيير في الإحصاءات وبلا alerts أو mappings أو Smart Logs أو
decision cases. تشمل regressions أيضًا حد bytes، schema fatal، فشل inference
في دفعة لاحقة، فشل تجهيز response، وفشل database commit. أُغلق parser wrapper
حتميًا، وحُسب feature importance قبل commit، وبقي نجاح NDJSON الجزئي مرتبًا
ومحاسبًا بصورة صحيحة.

قياس محلي بوحدة fixture رقمية صفرية، وليس تقييم كشف أو قياس network line-rate:

| القياس | النتيجة |
|---|---:|
| Pipeline v2 مباشر، 50,000 صف، batch=5,000 | 3.8467 ث، 12,998 صف/ث |
| زيادة peak RSS في القياس المباشر | 41,036 KiB |
| رفع CSV كامل، 50,000 صف، 3,250,509 bytes | HTTP 200، تغطية 100% |
| وقت endpoint المرصود من العميل | 7.3114 ث، 6,839 صف/ث |
| throughput الداخلي المبلغ | 11,906 صف/ث |
| نتائج التنبيه في fixture الصفرية | 0 |

زيادة RSS في قياس TestClient كانت 1,155,620 KiB لأنها تضم تحميل النموذج ونسخة payload داخل عميل الاختبار والطلب؛ ليست قياس steady-state للخادم. لا تدعم هذه الأرقام ادعاء دقة أو قدرة سلكية.

## التشغيل القابل لإعادة الإنتاج

- `requirements.txt` و`requirements-dev.txt` مقيدان مباشرة، و
  `requirements-constraints.txt` يقيد closure كاملة بإصدارات دقيقة لكنه لا
  يحتوي hashes ولا يسمى hash lock. الـinstaller المدعوم هو `pip` مع PyPI وفهرس
  PyTorch CPU الرسمي؛ لا يُدّعى دعم `uv` الآمن الافتراضي ولا تُستخدم خيارات
  index غير آمنة.
- يفصل manifest fixture الاختبار الحتمية ذات 2,000 صف عن أي بيانات إنتاجية غير متاحة، وتبقى `training_approved: false`.
- يستطيع `generate_sample --check` إعادة توليد fixture والتحقق من checksum.
- ينشئ `run.sh` المجلدات قبل logs، ولا يعيد التثبيت إلا في setup صريح/بيئة جديدة، ولا يقتل منفذًا مشغولًا، ويوقف التشغيل عند فشل التحقق المطلوب، ويميز عدم توفر LLM عن demo mode.
- أضيف CI للاختبارات وverify وcompile وJavaScript syntax وBandit وpip-audit
  وmanifest/fixture validation، واختبار صريح لعقد intake/report، وفحص أن شجرة
  checkout لا تحتوي SQLite قبل/بعد الاختبارات.

## نتائج التحقق النهائية

| الفحص | النتيجة |
|---|---:|
| `pytest -q` | 241 ناجح، 0 فاشل، 13 تحذير deprecation |
| نسخة مصدر مؤقتة بلا SQLite، جولتان | 241 ناجح في كل جولة، 0 فاشل؛ بقي عدد ملفات قواعد البيانات صفرًا قبل وبعد الاختبار |
| `verify.py` | 18/18 ناجح، 0 متجاوز، 0 فاشل |
| `compileall` | ناجح |
| `node --check` | 8 ملفات ناجحة، 0 فاشل |
| `bash -n` | ملفان ناجحان، 0 فاشل |
| Bandit | 0 Low، 0 Medium، 0 High؛ 9,192 سطرًا |
| `pip-audit --local` | لا ثغرات معروفة للحزم القابلة للمطابقة؛ تعذر تدقيق PyTorch `2.13.0+cpu` عبر PyPI |
| fixture reproducibility | ناجح، 2,000 صف وchecksum مطابق |
| `pip install -r requirements-dev.txt` ثم `pip check` في Python 3.12 نظيف | ناجح؛ لا متطلبات مكسورة |
| حل `pip --dry-run --ignore-installed` من virtualenv جديدة | ناجح؛ استخدم PyPI وPyTorch CPU الرسمي واختار `torch 2.13.0+cpu` |
| `git diff --check` | ناجح |

لم تُستخدم بيئتا المستخدم القائمتان كنتيجة موثوقة: إحداهما بلا pytest
والأخرى تحمل تعارض torchvision سابقًا. أُنشئت بيئة Python 3.12 مؤقتة جديدة،
نجح فيها `pip install -r requirements-dev.txt` ثم `pip check`. لم تُحذف أو
تُعدّل حزم المستخدم.

## أوامر التحقق المستخدمة

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
git diff --check
```

## جسر أدلة Suricata EVE (الإصدار الأول)

أضيف مسار استيراد ملفات سجلات Suricata EVE (`.json`, `.jsonl`, `.ndjson`) في `POST /api/events/suricata/upload` بعقد أحداث أمنية قياسي `cyberguard-security-event-v1`:

1. **عقد الأحداث والتحليل المحدود**: قراءة تدفقية سطرية بحدود ذاكرة ثابتة وحجم رفع أقصى 100 ميغابايت وحدود 500,000 سطر، مع دعم أحداث `alert` و`flow` و`dns` و`tls` وتجاهل الأنواع غير المدعومة بأمان.
2. **استخراج دلالات ATT&CK بدقة وأمانة**: استخراج تقنيات MITRE فقط من حقول metadata المصرح بها، وتوثيق provenance صريح (`rule_match_observed=true`, `mapping_evidence_present=true`, `technique_observed=false`) وعرضها كـ "Evidence-supported candidate ATT&CK mapping".
3. **الذرية وقاعدة البيانات**: حفظ المعاملات ذريًا (`security_events`, `security_event_technique_mappings`, `suricata_ingestions`) مع التراجع الكامل عند أي فشل حرج، وفصل المفتاح الرئيسي للجدول عن المعرف الحتمي للحدث `event_ref`، واحتساب دقيق للتكرارات.
4. **الواجهة والاستشارة**: واجهة مستخدم مستقلة بممارسات DOM الآمنة، وعرض حالة snapshot الحية من قاعدة البيانات، وتقديم استشارة LLM مع إبقاء المعرفات الشبكية مفصولة ودون تنفيذ أي إجراء (`executed_action="none"`).

## الحدود المتبقية

1. يلزم مصدر final evaluation جديد مستقل ومرخص يمر بعقد
   `evaluation_intake.py`، منفصل حسب capture والزمن والميزات، قبل معايرة v2 أو
   أي اعتماد إنتاجي.
2. لا توجد live packet capture أو استجابة آلية (firewall/IPS/quarantine)؛ تم ربط أدلة Suricata EVE كملفات مرفوعة واستشارية فقط.
3. سلامة artifacts تعتمد حاليًا على hashes محلية وربط shadow. التصميم الأقوى هو توقيع manifest بمفتاح خاص خارج المستودع والتحقق بمفتاح عام مثبت، لكنه لم يُنفذ بلا بنية أسرار مناسبة.
4. بيئة `venv/` القديمة تحمل تعارض torchvision محليًا؛ بيئة التحقق المؤقتة
   نظيفة، ولا ينبغي استخدام البيئة القديمة كدليل reproducibility.

## إغلاق مرحلة Live Operations والمعلومات الأمنية — 2026-08-31

أُعيد تشغيل المجموعة الكاملة بعد إضافة دورة ATT&CK/D3FEND ومصادر KEV/EPSS/OSV
والربط والفرز والمخاطر والواجهة المتجددة:

| الفحص | النتيجة المقاسة |
|---|---:|
| `pytest -q` | 335 ناجح، 0 فاشل، 0 متجاوز، 13 تحذير deprecation |
| `verify.py` | 19/19 ناجح، 0 متجاوز، 0 فاشل |
| `compileall` | ناجح، 0 خطأ |
| `node --check` | 10/10 ملفات ناجحة |
| Bandit | 0 Low، 0 Medium، 0 High؛ 13,041 سطرًا |
| `pip-audit --local` | 0 ثغرات معروفة للحزم القابلة للتدقيق؛ `torchvision 0.29.0.dev20260810+cu126` غير موجود في PyPI ولذلك لم يُدقق |
| `pip check` في `venv/` المحلية | فشل موجود مسبقًا: torchvision dev يتطلب torch 2.14.0.dev بينما المثبت torch 2.13.0؛ لم تُعدّل بيئة المستخدم |
| fixture `generate_sample --check` | ناجح؛ 2,000 صف حتمي وعقد 32 ميزة |
| benchmark الربط | 10,000 حدث خلال 11.508 ثانية (869.0 حدث/ثانية)، 100 حادث، 10,000 رابط محفوظ، 0.147 MiB ذروة Python و2.789 MiB SQLite |

تمت مزامنة ATT&CK v19.1 من الملف الرسمي المثبت: 25,843 كائن STIX، 697
تقنية فعالة، و697 وثيقة RAG متطابقة. فهرس D3FEND v1.5.0 يحتوي 272 تقنية
دفاعية فعالة و4,154 علاقة inferred رسمية. المزامنة الحية لـCISA KEV وFIRST
EPSS فهرست 1,687 و366,526 سجلًا على الترتيب. هذه أعداد ingestion وليست
مقاييس دقة أو إثبات استغلال.

تبقى artifact الفعالة `production_approved=false` وevaluation-only. لم تتم
ترقية أي candidate، ولم يُضبط threshold من smoke fixture، ولم يُنفذ firewall
أو quarantine أو isolation أو EDR أو containment. واجهة Live Operations تستطلع
السجلات المحفوظة كل أربع ثوانٍ وتفصل المصادر؛ ليست packet capture ولا اتصال
sensor مستمر.

التفاصيل والأوامر والمصادر الرسمية موثقة في
`docs/SECURITY_KNOWLEDGE_ARCHITECTURE.md`.
