# معمارية Smart Log وقرار الذكاء الاصطناعي

## الهدف

يحّول CyberGuard كل إنذار إلى سجل صغير ومنظم اسمه **Smart Log**. تمر الحالات المعروفة والواضحة عبر سياسة حتمية سريعة، بينما تُرسل الحالات الصعبة أو المجهولة فقط إلى نموذج لغوي لإضافة تفسير سياقي واقتراح قرار. لا يملك النموذج صلاحية تنفيذ حظر أو عزل.

هذه المعمارية تفصل أربع مسؤوليات لا يجوز دمجها:

1. **Detection:** استخراج الأدلة وتصنيف السلوك.
2. **Decision support:** تحليل الحالة المجهولة واقتراح نتيجة.
3. **Policy gate:** فرض قواعد لا يستطيع النموذج تجاوزها.
4. **Actuation:** تنفيذ إجراء على Firewall/EDR، وهو غير موجود حاليًا ويتطلب موافقة مستقلة.

## تدفق الخوارزمية

```text
CSV/JSON flow
  -> schema v1 validation (fail closed)
  -> feature extraction + normalization
  -> known-attack classifier on every accepted row
  -> statistical evidence on every accepted row
  -> autoencoder/OOD evidence when supported by the bundle
  -> deterministic routing v2
  -> persist AlertRecord
  -> derive Smart Log + evidence fingerprint
       |
       +-- known + high confidence --> deterministic policy --> alert/observe
       |
       +-- unknown/ambiguous -------> MITRE retrieval --> constrained AI JSON
                                                   --> schema validation
                                                   --> non-bypassable policy gate
                                                   --> analyst review queue
                                                   --> analyst feedback
                                                   --> offline evaluation dataset
```

خوارزمية التوجيه الحالية:

- classifier معروف اجتاز عتبة الامتناع المعايرة والمخزنة في artifact manifest وخطورته high/critical: لا يُستدعى AI؛ القرار policy.
- autoencoder أو `unknown-anomaly`: AI مسموح للتحليل، لكن القرار يبقى بحاجة إلى محلل ولا تُخمن MITRE technique.
- low/medium أو classifier امتنع عن الحسم: حالة ملتبسة تذهب للمراجعة.
- توصية `block_recommended` أو `quarantine_recommended`: توصية فقط و`executed_action=none`.
- فشل المزود أو JSON غير صالح: fallback حتمي مع `degraded=true`.

## مخطط Smart Log

```json
{
  "schema_version": "smart-log-v2",
  "event_id": "cg-alert-42",
  "alert_id": 42,
  "created_at": 1770000000.0,
  "source": {"kind": "uploaded-flow", "profile": "cicids2017-cicflowmeter"},
  "detection": {
    "type": "unknown-anomaly",
    "severity": "high",
    "stage": "autoencoder",
    "route": "unknown_anomaly_review",
    "confidence": 0.0,
    "anomaly_score": 9.5,
    "mitre_techniques": [],
    "top_features": [["flow_duration", 8.2]],
    "feature_evidence": [{
      "name": "flow_duration",
      "observed_value": 120000.0,
      "normalized_value": 2.4,
      "z_score": 8.2
    }],
    "signals": {
      "classifier": {"label": "Benign", "confidence": 0.91},
      "statistical": {"threshold": 8.0, "flagged": true},
      "autoencoder": {"reconstruction_error": 9.5, "flagged": true}
    }
  },
  "operational_mode": "evaluation_only",
  "artifact_approval_state": "evaluation_only",
  "artifact_version": "<artifact-id>",
  "pipeline_version": "cyberguard-pipeline-v2",
  "feature_schema_version": "cyberguard-flow-features-v1",
  "input_profile": "cicids2017-cicflowmeter",
  "feature_coverage_percentage": 100.0,
  "supported_classes": ["Benign", "Bot", "DDoS", "PortScan"],
  "limitations": ["active artifact is evaluation-only"],
  "review_required": true,
  "review_reason": "unknown anomaly requires contextual AI and analyst review",
  "evidence_fingerprint": "<sha256>",
  "trust_boundaries": [
    "uploaded flow fields and stored conversation content are untrusted",
    "LLM output is advisory and schema-validated",
    "no response action is executed by this service"
  ]
}
```

الـ prompt لا يستقبل `flow_json` الخام ولا اسم الملف. يستقبل نسخة مصغرة من
Smart Log وسياق MITRE محدود الحجم اجتاز minimum relevance، وكلاهما يعامل
كبيانات غير موثوقة. fingerprint يشمل الأدلة الرقمية canonical، الإشارات،
إصدار artifact/pipeline/schema، profile/coverage، نطاق الأصناف والحدود.

## بوابة القرار

| الحالة | مصدر القرار | النتيجة الآمنة | يحتاج محلل | تنفيذ تلقائي |
|---|---|---|---:|---:|
| هجوم معروف وثقة عالية | Policy | malicious + alert | لا | لا |
| unknown anomaly | Policy + AI | suspicious/needs_human | نعم | لا |
| دليل منخفض أو ملتبس | Policy + AI | needs_human + escalate | نعم | لا |
| AI يقول benign لحالة مجهولة | Policy gate | needs_human + escalate | نعم | لا |
| AI يقترح block/quarantine | Policy gate | recommendation فقط | نعم | لا |
| AI غير متوفر/مخرجاته تالفة | Policy fallback | needs_human + degraded | نعم | لا |

مخرجات AI مقيدة بـ JSON schema مغلق: verdict، confidence، recommended_action، rationale، evidence، containment، limitations. أي حقول إضافية أو قيم خارج الحدود ترفض.

## حلقة التعلم الآمنة

المسار `POST /api/decision/feedback/{alert_id}` يسجل حكم المحلل وملاحظاته. التسجيل **لا يعيد تدريب النموذج مباشرة**. التعلّم المقترح يكون offline فقط:

1. اجمع الحالات التي راجعها محلل معروف.
2. احذف التكرار وتحقق من سلامة المصدر والـ fingerprint.
3. تتطلب العينات الحساسة أو المتعارضة مراجعين اثنين.
4. أنشئ split زمنيًا وبحسب المصدر لمنع تسرب البيانات.
5. درّب candidate model دون استبدال النموذج الفعّال.
6. قارن per-class precision/recall/F1 وfalse-positive rate والمعايرة.
7. اختبر البيانات المسممة، الانجراف، وفئات لم تظهر في التدريب.
8. شغّل candidate في shadow mode.
9. رقِّ artifact موقّعًا فقط إذا تجاوز gates محددة، مع rollback محفوظ.

بهذا “يتعلم” النظام من feedback موثوق، لا من مدخل يمكن للمهاجم التحكم به.

## واجهات API

- `GET /api/decision/smart-log/{alert_id}`: عرض Smart Log مشتق من الإنذار المحفوظ.
- `GET /api/decision/queue?limit=100`: الحالات التي تحتاج مراجعة.
- `GET /api/decision/case/{alert_id}`: الأدلة والقرار والإصدارات والـaudit.
- `POST /api/decision/evaluate/{alert_id}`: policy أولًا ثم AI للحالات المجهولة.
- `POST /api/decision/feedback/{alert_id}`: حفظ قرار المحلل للتقييم والتدريب offline.
- `GET /api/decision/export-reviewed`: تصدير الحالات المراجعة غير المتعارضة افتراضيًا.
- `GET /api/decision/audit/verify`: التحقق من سلسلة audit غير القابلة للتعديل عبر التطبيق.
- `POST /api/decision/simulate-response/{alert_id}`: خطة dry-run فقط، مقيدة بـasset allowlist وTTL وidempotency؛ تبقى `executed_action=none`.

مثال feedback:

```json
{
  "verdict": "malicious",
  "notes": "Confirmed using independent packet capture"
}
```

هوية `reviewed_by` يضعها الخادم من `CG_ANALYST_ID` ولا يقبلها من جسم الطلب. عند الوصول البعيد يجب ضبط `CG_API_TOKEN`; يبقى ذلك token تشغيليًا مشتركًا وليس بديلًا عن SSO/RBAC متعدد المستخدمين.

## حدود الأمان الحالية

- لا يوجد Actuator للـ firewall أو EDR، لذلك لا يحدث block/quarantine فعليًا.
- لا يوجد online learning أو model promotion تلقائي.
- سياق MITRE وحقول السجل تُعامل كمدخل غير موثوق لمقاومة prompt injection.
- لا يجوز اعتبار anomaly وحده دليل استغلال؛ هو Unknown Anomaly للمراجعة فقط.
- التغطية الحقيقية تساوي الفئات التي تدرب عليها artifact الفعّال، لا أسماء الفئات المذكورة في الوثائق.
- يجب قياس الجودة على بيانات مستقلة قبل أي ادعاء إنتاجي.

## خطة الإنجاز التالية

1. اكتمل إدخال ستة captures رسمية CSE-CIC-IDS2018 وتدقيقها واشتقاق hashes محلية.
2. فشل المرشح الأول gates لأن statistical front gate أخفى الهجمات رغم جودة المصنف منفردًا؛ لم يُرقَّ.
3. اكتمل منطق Pipeline v2 واختباراته الحتمية؛ يلزم calibration وfinal جديدان
   مستقلان قبل أي نتيجة أو ترقية إنتاجية.
4. إضافة SSO/RBAC وهوية محلل فردية قبل الاستخدام متعدد المستخدمين.
5. تصميم response simulator فقط؛ أي actuator حقيقي يحتاج صلاحية منفصلة، allowlist، TTL، idempotency، rollback، وtwo-person approval.

## شروط القبول

- لا يرسل raw logs أو أسرار إلى AI.
- لا يستطيع AI إزالة إنذار مجهول أو تنفيذ إجراء.
- كل قرار يتضمن provider وprompt version وfingerprint.
- جميع feedback قابلة للتدقيق ولا تؤثر في النموذج online.
- فشل AI لا يكسر detection ويؤدي إلى policy fallback.
- الاختبارات تغطي JSON الخاطئ، benign override، التوصيات التدميرية، fallback، feedback، وrate limits.
