# تقرير الاختبار الأمني الشامل — CyberGuard

**التاريخ:** 18 أغسطس 2026  
**النطاق:** مشروع `/home/sajjad/Desktop/project` والخادم المحلي `127.0.0.1` فقط  
**نوع الاختبار:** مراجعة كود، فحص تبعيات، اختبارات API هجومية غير مدمرة، فحص HTTP حي، اختبارات إدخال/ضغط محدودة، وتقييم واقعي لنموذج الكشف

## الخلاصة التنفيذية

تم تقوية تطبيق الويب والـAPI وإغلاق الثغرات المؤكدة التي أمكن إصلاحها داخل المشروع. بعد إضافة اكتساب البيانات والتدقيق والـshadow والترقية المحكومة أصبحت النتيجة: **112/112 اختبارًا ناجحًا، صفر ملاحظات Bandit، وصفر ثغرات معروفة في التبعيات القابلة للتدقيق**. تم تحديث MITRE ATT&CK Enterprise إلى **v19.1** وفهرسة **709 تقنيات** في RAG المحلي الآمن.

لكن لا يجوز اعتبار النظام حاليًا "يصد جميع الهجمات": هو **IDS للكشف والتنبيه** وليس IPS/Firewall للحظر، والمصنف المدرّب فعليًا يعرف أربعة أصناف فقط: `Benign`, `Bot`, `DDoS`, `PortScan`. جرى جرد ملفي البيانات المحليين وإثبات أنهما synthetic fixtures وليسا CICIDS2017 رسميًا؛ يسجل manifest ذلك عبر `training_approved: false`. لذلك `/api/detect/health` يعرض `evaluation_only` ولا توجد metrics إنتاجية حتى يعاد التدريب والتقييم على بيانات حقيقية ممثلة.

## منهجية وحدود الاختبار

لم تُنفذ هجمات DDoS مدمرة، ولم يُستهدف أي موقع عام أو نظام غير مصرح به. استُخدمت محاكاة محلية، TestClient، وخادم Uvicorn مؤقت على loopback. هذا يختبر منطق الدفاع من دون الإضرار بالأجهزة أو الشبكات. لا يمكن لأي اختبار واحد إثبات غياب جميع الثغرات، ولا يمكن لأي نموذج ضمان كشف كل zero-day.

## النتائج النهائية بالأرقام

| الفحص | النتيجة |
|---|---:|
| Pytest | 112 ناجح / 0 فاشل |
| Bandit | 0 Low / 0 Medium / 0 High |
| pip-audit | 0 ثغرات معروفة |
| ملاحظة pip-audit | `torchvision` إصدار dev غير موجود في PyPI، لذلك لم يُدقق |
| MITRE STIX | 26,086 كائنًا |
| MITRE techniques | 709 |
| MITRE groups | 191 |
| RAG local index | 709 / 709 |
| اختبار الضغط | 50,000 Flow في 8.307 ثانية، نحو 6,019 Flow/s |
| نتائج الضغط المفقودة | 0 |
| نتائج NaN/Infinity بعد الإصلاح | 0 |

رقم 6,019 Flow/s يخص خليطًا هجوميًا ثقيلًا يصل إلى classifier/autoencoder؛ لا يدعم ادعاء أن **المسار الكامل** يحقق 100,000 Flow/s. قد يكون المرشح الإحصائي وحده أسرع، ويجب قياس كل مرحلة منفردة على جهاز الإنتاج.

## الهجمات على تطبيق الويب والـAPI

| الهجوم/المحاولة | رد الخادم النهائي | الحالة | ما تم عمله |
|---|---|---|---|
| SSRF إلى `169.254.169.254` | 422 | تم الصد | llama محصور في loopback والمنفذ المسموح |
| SSRF إلى Private IP | 422 | تم الصد | رفض كل عنوان محلي غير loopback |
| تمويه loopback كعدد `2130706433` | 422 | تم الصد | تحقق IP صارم |
| Domain suffix مثل `api.deepseek.com.evil` | 422 | تم الصد | مطابقة hostname كاملة بقائمة سماح |
| Cloud API عبر HTTP | 422 | تم الصد | HTTPS فقط |
| منفذ Cloud غير 443 | 422 | تم الصد | تقييد المنفذ |
| Credentials داخل URL | 422 | تم الصد | رفض userinfo/query/fragment |
| إعداد SSRF قديم مخزّن في DB | عاد إلى `127.0.0.1:8080` | تم التعطيل | تعقيم القيم القديمة عند القراءة + تحقق عند التنفيذ |
| عميل بعيد بلا API token | 403 | تم الصد | remote API يتطلب `CG_API_TOKEN` |
| Token مفقود/خاطئ عند تفعيله | 401 | تم الصد | مقارنة ثابتة الزمن |
| Origin خبيث / CSRF | 403 | تم الصد | allowlist للـOrigin قبل API |
| Host header خبيث | 400 | تم الصد | TrustedHost allowlist |
| TRACE/PUT غير مسموح | 405 | تم الصد | طرق CORS/API محددة |
| Path traversal مشفر وخام | 404 | تم الصد | لا وصول خارج static mounts |
| طلب `data/.secret_key` | 404 | تم الصد | مجلد البيانات غير معروض |
| SQLi في بحث MITRE | 200 مع قائمة فارغة/محدودة | آمن | استعلامات SQLite parameterized |
| XSS في query | 200 مع `[]` | آمن | لا انعكاس HTML، والواجهة تهرّب النص |
| HTML/JS من LLM | يعرض كنص | آمن بالمراجعة | Markdown يهرب HTML قبل التنسيق + CSP |
| JSON primitives بدل Flow objects | 400 | تم الصد | قبول صفوف object/tabular فقط |
| Binary upload/null bytes | 400 | تم الصد | كشف المحتوى الثنائي |
| تجاوز حجم الرفع | 413 | تم الصد | حد bytes وصفوف |
| Flood على upload | 429 | تم الصد | rate limit = 10/minute |
| Chat/query resource abuse | 422 | تم الصد | حدود طول وعدد صارمة |
| Header بحجم 20KB | 431 | تم الصد | حد افتراضي 16KB |
| URL بطول 5KB | 414 | تم الصد | حد افتراضي 4KB |
| JSON body أكبر من 1MB | 413 | تم الصد | حد Body عام منفصل عن Upload |
| CSV formula injection | أضيفت `'` قبل `= + - @` | تم الصد | تعقيم export |
| Numeric overflow/NaN/Infinity | 200 وJSON finite | تم الصد بعد اكتشاف خلل | قص وتعقيم features/z-score/AE/output |
| تلاعب filename لتحريض LLM | لا يصل للـprompt | تم الصد | أزيل filename من سياق LLM |
| Prompt injection داخل RAG/log metadata | لا أدوات أو أسرار متاحة | مخفف | تعليمات صريحة باعتبار السياق غير موثوق + عرض آمن |

## الثغرات التي وُجدت وأُصلحت

### 1. SSRF وتسريب API key — Critical

كان المستخدم يستطيع ضبط `llama_url` أو `api_base_url` إلى عنوان داخلي/خبيث، ثم إجبار الخادم على الاتصال به؛ وفي API mode قد يخرج مفتاح Bearer إلى المضيف الخبيث. وُجدت أيضًا قيمة metadata غير آمنة مخزنة قديمًا. أضيف تحقق دفاعي في الإدخال وفي client نفسه، قوائم سماح، HTTPS/port restrictions، وتعقيم للقيم القديمة.

### 2. ChromaDB RCE بلا Patch — Critical

كشف `pip-audit` أن `chromadb 1.5.9` متأثر بـ`CVE-2026-45829 / PYSEC-2026-311`، ولا يوجد patched version رسمي. أزيلت المكتبة من الكود والتبعيات والبيئة، واستُبدلت بفهرس TF-IDF محلي حتمي مبني من MITRE SQLite. بيانات `data/chroma` القديمة لم تُحذف، لكنها لم تعد مستخدمة.

### 3. ربط Flow خاطئ في Batch — High

كان `detect_batch` يحذف نتائج benign ثم يعيد قائمة أقصر؛ لاحقًا كان `zip(batch_flows, batch_alerts)` ينسب التنبيه إلى Flow مجاور. أصبح الناتج بطول وترتيب الإدخال دائمًا، وأضيف اختبار mixed benign/attack.

### 4. لا حدود عامة للطلبات — High

أضيفت حدود headers، URL، JSON body، upload bytes، upload rows، query results، chat length، history length، ومعدلات upload/chat/settings/sync/explain.

### 5. نتيجة Infinity من autoencoder — Medium/High

أظهر payload رقمي خبيث anomaly score بقيمة `Infinity`، ما قد يسبب 500 عند JSON serialization. تم قص الأرقام غير المنطقية، تعقيم normalized/z-score/errors، وضمان JSON finite.

### 6. معرفة MITRE قديمة وفهرس ناقص — Medium

كان الإصدار `v19` والـcache يمنع التحديث، وكان RAG يفهرس 500 تقنية فقط. أصبح الإصدار `v19.1`، refresh كل 24 ساعة، تنزيل رسمي محدود 100MB ومتحقق منه، كتابة atomic، fallback cache، وفهرسة 709/709.

### 7. صلاحيات محلية واسعة — Medium

كانت DB بصلاحية 644 والنماذج 664. أصبحت مجلدات البيانات/النماذج 700 والملفات الحساسة 600، مع فتح Fernet key باستخدام `O_NOFOLLOW` ومنع race/symlink عند الإنشاء.

### 8. CSV injection وprompt metadata — Medium

عُقمت خلايا CSV، وأزيل اسم الملف من سياق البوت، وأضيفت تعليمات لمعاملة RAG/metadata كبيانات غير موثوقة.

## اختبار محرك كشف الهجمات

| السيناريو الاصطناعي | النتيجة | التقييم |
|---|---|---|
| Quiet baseline | Benign / none | نجح |
| DDoS volumetric | DDoS / critical / 99.93% | نجح |
| SYN port scan | DDoS / critical | **فشل التصنيف** |
| Brute-force-like flow | DDoS / critical | **فشل التصنيف** |
| Web-attack-like flow | unknown-anomaly / high | كشف شذوذ فقط، لا تصنيف ولا MITRE mapping |
| Exfiltration-like flow | DDoS / critical | **فشل التصنيف** |
| Numeric overflow payload | كان Infinity، ثم أصبح finite | نجح بعد الإصلاح |

هذه المحاكاة ليست بديلًا عن بيانات labeled حقيقية. والأهم أن raw SQLi/XSS payload غير مفحوص نصيًا؛ extractor يأخذ 32 خاصية رقمية فقط. ادعاء README القديم بأن النموذج يرى أنماط SQLi/XSS في payload لم يكن مدعومًا بهذا المسار.

## تغطية MITRE الحقيقية

- إجمالي تقنيات Enterprise المفهرسة: **709**.
- الخرائط المعرفة في الكود للأصناف المسماة: **18**، أي **2.54%** من عدد التقنيات.
- الخرائط الممكنة من أصناف النموذج الفعلية: **7**، أي نحو **0.99%**. لا يُربط unknown-anomaly بـMITRE لأن reconstruction error لا يثبت سلوك مهاجم.
- أصناف النموذج الفعلية: `Benign`, `Bot`, `DDoS`, `PortScan`.
- الأصناف المفقودة من الإعداد: `BruteForce`, `DoS`, `Infiltration`, `WebAttack`.
- أصبح `/api/detect/health` يعرض `coverage_complete: false` وهذه القوائم صراحة بدل قول "All stages ready" فقط.

النسبة ليست مقياس جودة IDS بحد ذاتها لأن MITRE يشمل سلوكيات host/cloud/identity خارج network-flow telemetry؛ لكنها تمنع ادعاء تغطية ATT&CK كاملة.

## ما يعنيه "يتعلم ويتحدث" بعد الاختبار

- **يتحدث معرفيًا:** نعم، MITRE v19.1 يُحدّث من المصدر الرسمي كل 24 ساعة عند التشغيل/المزامنة، وRAG يفهرس 709 تقنية.
- **يتعلم من الحركة تلقائيًا:** لا، وهذا آمن حاليًا. التعلم الذاتي من uploads غير الموثوقة يتيح model poisoning.
- **إعادة التدريب:** اكتملت تجربة مرشح على ستة captures رسمية، لكن المرشح فشل gates وبقي غير فعّال. العملية منفصلة، بإصدارات datasets وholdout غير ملوث وmetrics لكل class، ولا يوجد نشر تلقائي.
- **يصد الهجوم:** لا؛ يكتشف ويسجل ويشرح فقط. الحظر يحتاج response engine منفصلًا ومقيدًا ومتكاملًا مع Firewall/Proxy/EDR.

## المخاطر المتبقية والأولوية

### P0 — مانعة للإنتاج

1. تصميم candidate v2 من training/calibration فقط لمعالجة فشل statistical routing، مع captures نهائية جديدة لم تُفتح في v1.
2. توسيع support المستقل لـBruteForce وDDoS وBot وPortScan وInfiltration قبل ادعاء تغطيتها.
3. عدم الإعلان عن منع الهجمات قبل بناء IPS/Firewall response layer واختباره بسياسة fail-safe وموافقة بشرية.
4. إذا كان الاستخدام متعدد المستخدمين: إضافة هوية حقيقية، جلسات، RBAC، وعزل سجل كل محلل؛ الـAPI token الحالي مشترك ومناسب للوصول التشغيلي البسيط فقط.

### P1 — مهمة

1. تشغيل remote access خلف TLS reverse proxy فقط؛ Uvicorn يبقى loopback.
2. استبدال `joblib/pickle` بصيغ artifacts آمنة أو توقيع manifest بمفتاح منفصل. التحقق الحالي يطابق SHA-256 قبل فك الملفات ويحميها بصلاحيات محلية، لكنه لا يقاوم مهاجمًا يملك حق تعديل artifact والـmanifest معًا.
3. تثبيت إصدارات التبعيات في lockfile وإجراء pip-audit/Bandit في CI دوريًا.
4. استبدال `torchvision` dev build بإصدار رسمي قابل للتدقيق أو إزالته إن لم يكن مطلوبًا.
5. سلسلة audit غير قابلة للتعديل أضيفت لقرارات policy وfeedback؛ ما زالت مراقبة 401/403/413/429 وتغييرات sync/provider تحتاج sink تشغيلي خارجي.
6. اختبارات Browser آلية فعلية لـDOM-XSS وCSP، واختبار TLS/proxy عندما تتوفر بيئة النشر.

## أوامر التحقق المستخدمة

```bash
venv/bin/python -m pytest -q
venv/bin/bandit -r backend cyberguard -x '*/tests/*' -f txt
venv/bin/pip-audit --local --progress-spinner off
venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8765
```

## الحكم النهائي

**طبقة الويب والـAPI:** مقواة جيدًا للاستخدام المحلي بعد الإصلاحات، مع نتائج آلية وحية ناجحة.  
**طبقة المعرفة:** محدثة إلى MITRE v19.1 وRAG كامل محليًا.  
**طبقة كشف الشبكة:** تعمل للإنذار والشذوذ في وضع **evaluation-only**؛ تتحقق من artifact manifest قبل فك النماذج وترفض التشغيل عند التلاعب. أُجري اختبار مستقل على بيانات CSE-CIC-IDS2018 حقيقية النشر، لكنه أثبت فشل pipeline الكامل؛ لذلك ما زالت **غير جاهزة للإنتاج**.  
**طبقة المنع:** غير موجودة؛ النظام IDS وليس IPS.

## تحديث مجموعة البيانات والمرشح — 18 أغسطس 2026

بعد هذا التقرير الأساسي، نُزلت ستة CSV رسمية من CSE-CIC-IDS2018 (إجمالي
2,162,263,168 bytes و6,291,450 صفًا) من S3 العام المرتبط بصفحة UNB. لم ينشر
الناشر SHA-256؛ لذلك سُجلت hashes محلية بعد التحقق من الحجم وETag ولم توصف
بأنها publisher checksums. أزيل تسرب exact وnear-duplicate بين أيام الالتقاط.

دُرب مرشح `cse-cic-ids2018-v1-seed42` وقيّم على final مستقل حجمه 1,063,406
صفًا. حقق المصنف macro F1=0.9067، لكن pipeline الكامل حقق attack F1=0.000021
وفشل مقارنة StatisticalFilter وIsolation Forest بسبب front gate. الحالة
`failed_gates`، ولم يحدث promotion. راجع
`docs/CANDIDATE_EVALUATION_AR.md` للأرقام وhashes والتقسيم الكامل.
