# CyberGuard Suricata Evidence Bridge v1

Suricata Evidence Bridge v1 adds a safe, bounded offline evidence ingestion path for Suricata EVE JSON, JSONL, and NDJSON logs. It connects real IDS alerts and network telemetry to CyberGuard, extracts and validates MITRE ATT&CK technique mappings from explicit rule metadata with transparent provenance, persists events transactionally, and provides advisory analysis while executing no actions on systems or networks.

---

## 1. Scope & Architecture

### What this phase implements
- Uploaded Suricata EVE JSON / JSONL / NDJSON stream ingestion at `POST /api/events/suricata/upload`.
- Versioned canonical security event contract: `cyberguard-security-event-v1`.
- Adapter version: `cyberguard-suricata-eve-v1`.
- Strict bounded parsing: streaming line-by-line reading with limits on upload bytes (100 MB default), line length (1 MB max), and total lines (500,000 max).
- Full support for Suricata `alert`, `flow`, `dns`, and `tls` event types.
- Safe accounting for unsupported/ignored event types (e.g. `stats`, `http`, `smtp`).
- Explicit ATT&CK technique extraction from allowlisted rule metadata keys (`mitre_technique_id`, `mitre_tactic_id`, `tag`).
- Granular ATT&CK validation states (`active_validated`, `syntactically_invalid`, `unknown_to_snapshot`, `revoked`, `deprecated`, `snapshot_unavailable`, `snapshot_unverified`).
- Evidence provenance semantics: `rule_match_observed=true`, `mapping_evidence_present=true`, `technique_observed=false`.
- Honest dynamic ATT&CK snapshot reporting from the active SQLite sync record.
- Transactional database storage (`security_events`, `security_event_technique_mappings`, `suricata_ingestions`) with guaranteed rollback on fatal parse errors.
- Duplicate event and re-upload handling with collision-resistant canonical `event_ref` SHA-256 hashes.
- Separation of database integer primary keys (`id`) from deterministic event references (`event_ref`).
- Advisory LLM analysis with untrusted data isolation, network identifier minimization, and deterministic fallback summaries.
- Modern dark-themed UI view with safe DOM manipulation (`textContent`, `createElement`).

### What this phase does NOT implement
- Live packet capture or raw socket listening.
- Automatic firewall, IPS, quarantine, or response execution (`executed_action = "none"`).
- Suricata daemon management or privileged host network interface binding.
- Zero-filling missing features or forcing Suricata events into the 32-feature ML model schema.
- Inference of ATT&CK techniques from signature text keywords or LLM hallucination.

---

## 2. Canonical Security Event Contract (`cyberguard-security-event-v1`)

Every accepted event is parsed into a bounded schema:

```json
{
  "schema_version": "cyberguard-security-event-v1",
  "adapter_version": "cyberguard-suricata-eve-v1",
  "event_ref": "4f9d8a1c...",
  "source_kind": "suricata_eve",
  "source_event_type": "alert",
  "sensor_id": "sensor-alpha",
  "source_line_number": 1,
  "timestamp": 1788102600.123456,
  "timestamp_iso": "2026-08-30T14:10:00.123456+00:00",
  "flow_id": 123456789,
  "community_id": "1:abc...",
  "proto": "TCP",
  "app_proto": "tls",
  "src_ip": "192.168.1.100",
  "src_port": 49200,
  "dest_ip": "198.51.100.42",
  "dest_port": 443,
  "alert_signature": "ET MALWARE CobaltStrike C2",
  "alert_signature_id": 2024001,
  "alert_category": "Trojan Activity",
  "alert_severity": "high",
  "source_sensor_severity_raw": 1,
  "source_sensor_action": "allowed",
  "executed_action": "none",
  "evidence": {
    "signature": "ET MALWARE CobaltStrike C2",
    "signature_id": 2024001,
    "category": "Trojan Activity",
    "severity_raw": 1,
    "source_action": "allowed"
  },
  "mitre_techniques": [
    {
      "technique_id": "T1071.001",
      "tactic_id": "TA0011",
      "validation_status": "active_validated",
      "signature_id": 2024001,
      "rule_match_observed": true,
      "mapping_evidence_present": true,
      "technique_observed": false,
      "evidence_kind": "suricata_rule_metadata",
      "mapping_semantics": "evidence-supported candidate ATT&CK mapping",
      "mapping_version": "suricata-rule-metadata-v1",
      "metadata_extraction_confidence": 1.0,
      "technique_occurrence_confidence": null,
      "snapshot_version": "v19.1"
    }
  ],
  "ingested_at": 1788102601.5
}
```

---

## 3. ATT&CK Mapping & Provenance

ATT&CK techniques are extracted solely from structured rule metadata keys:
- `mitre_technique_id`, `mitre_technique`, `attack_technique`, `attack_technique_id`
- `tag` strings matching `attack.t\d{4}(?:[_\.]\d{3})?`

Tactic IDs (`TA####`) are separated from technique IDs (`T####`) and never stored as techniques.

### Mapping Provenance Semantics
- `rule_match_observed: true` — Confirms that the IDS signature fired on matching network traffic.
- `technique_observed: false` — Explicitly denotes that a rule match alone is not proof that every stage of the technique occurred.
- `mapping_semantics: "evidence-supported candidate ATT&CK mapping"`
- UI displays: `Evidence-supported candidate ATT&CK mapping`, never `Observed attacker technique`.

---

## 4. Privacy & Untrusted Data Boundaries

1. **Payload & Secret Protection**: No packet payloads, payload hex/base64 strings, or credential fields are parsed or stored.
2. **Network Identifiers**: `src_ip`, `dest_ip`, `src_port`, `dest_port` are stored solely for local analyst display. They are excluded from default LLM prompt context to preserve privacy and prevent prompt manipulation.
3. **Prompt Injection Defense**: All uploaded values placed in LLM prompts are isolated inside structured, delimited JSON blocks and explicitly marked as untrusted data.
4. **Advisory Invariant**: The LLM is strictly advisory. Every analysis response includes `executed_action: "none"`.

---

## 5. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/events/suricata/upload` | Upload `.json`, `.jsonl`, `.ndjson` EVE logs; streaming validation & transactional persistence |
| `GET` | `/api/events/suricata/events` | Query imported events with type/severity/technique filters and pagination |
| `GET` | `/api/events/suricata/events/{id}` | Inspect full canonical record and ATT&CK mapping provenance |
| `POST` | `/api/events/suricata/explain/{id}` | Advisory LLM explanation with deterministic fallback summary |
| `GET` | `/api/events/suricata/stats` | Aggregated counts by event type, alert counts, and active snapshot status |
| `GET` | `/api/events/suricata/attack-status` | Active ATT&CK snapshot honesty metadata |

---

## 6. How to Generate Safe Local EVE Test Data

You do not need Suricata installed to test this feature. Safe synthetic fixtures can be generated with standard Python:

```python
import json

events = [
    {
        "timestamp": "2026-08-30T14:00:01.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.50",
        "src_port": 51234,
        "dest_ip": "198.51.100.10",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2010001,
            "rev": 1,
            "signature": "ET MALWARE Potential Beaconing",
            "category": "A Network Trojan was detected",
            "severity": 1,
            "metadata": {
                "mitre_technique_id": ["T1071.001"],
                "mitre_tactic_id": ["TA0011"]
            }
        }
    },
    {
        "timestamp": "2026-08-30T14:00:02.000000+0000",
        "event_type": "dns",
        "src_ip": "192.168.1.50",
        "src_port": 53535,
        "dest_ip": "1.1.1.1",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "rrname": "safe-test.local",
            "rrtype": "A"
        }
    }
]

with open("test_eve.jsonl", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")
```

---

## 7. Verification Commands

```bash
# Run full Pytest suite
python -m pytest -q

# Run module verification
python verify.py

# Bytecode compilation
python -m compileall -q backend cyberguard tests verify.py

# Frontend JavaScript syntax check
for file in frontend/js/*.js; do node --check "$file"; done

# Bandit security scan
bandit -r backend cyberguard -x '*/tests/*' -f txt

# Dependency vulnerability audit
pip-audit --local --progress-spinner off
```

---

## 8. Future Phases

1. **Zeek & Community ID Integration**: Correlate Zeek connection logs with Suricata EVE alerts using standardized Community ID hashes.
2. **Threat Intelligence & Inventory Enrichment**: Match Suricata signature references against CISA KEV, EPSS, and OSV databases against local asset inventory.
3. **Manual Response Workflows**: Implement audited, human-in-the-loop response actions (e.g. firewall rule proposals) with explicit multi-step human sign-off.
