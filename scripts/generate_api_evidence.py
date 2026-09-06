"""Generate real API response evidence using safe documentation IP ranges."""
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from backend.main import app
from backend.db.init_db import init_all

init_all()
client = TestClient(app)

docs = [
    {
        "timestamp": "2026-08-30T14:15:00.123456+0000",
        "flow_id": 987654321,
        "event_type": "alert",
        "src_ip": "192.0.2.45",
        "src_port": 54321,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2018934,
            "rev": 2,
            "signature": "ET MALWARE Win32/CobaltStrike Activity",
            "category": "A Network Trojan was detected",
            "severity": 1,
            "metadata": {
                "mitre_technique_id": ["T1071.001"],
                "mitre_tactic_id": ["TA0011"],
            },
        },
    },
    {
        "timestamp": "2026-08-30T14:15:01.000000+0000",
        "flow_id": 987654321,
        "event_type": "flow",
        "src_ip": "192.0.2.45",
        "src_port": 54321,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 12,
            "pkts_toclient": 18,
            "bytes_toserver": 1140,
            "bytes_toclient": 14280,
            "state": "closed",
        },
    },
    {
        "timestamp": "2026-08-30T14:15:02.000000+0000",
        "event_type": "dns",
        "src_ip": "192.0.2.45",
        "src_port": 53535,
        "dest_ip": "203.0.113.53",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "type": "query",
            "rrname": "c2.safe-evidence.example.org",
            "rrtype": "A",
        },
    },
    {
        "timestamp": "2026-08-30T14:15:03.000000+0000",
        "event_type": "tls",
        "src_ip": "192.0.2.45",
        "src_port": 54321,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "TCP",
        "tls": {
            "subject": "CN=c2.safe-evidence.example.org",
            "sni": "c2.safe-evidence.example.org",
            "version": "TLS 1.3",
            "ja4": "t13d1516h2_8daaf6152771_019a7590829f",
        },
    },
]

payload = ("\n".join(json.dumps(d) for d in docs) + "\n").encode("utf-8")

import time
sensor_id = f"sensor-edge-{int(time.time())}"

print("--- 1. POST /api/events/suricata/upload ---")
res_upload = client.post(
    f"/api/events/suricata/upload?sensor_id={sensor_id}",
    files={"file": ("eve_evidence.jsonl", payload, "application/json")},
)
print(f"Status: {res_upload.status_code}")
upload_data = res_upload.json()
print(json.dumps({k: v for k, v in upload_data.items() if k != "events"}, indent=2))

first_event_id = upload_data["events"][0]["id"]

print("\n--- 2. GET /api/events/suricata/events ---")
res_list = client.get(f"/api/events/suricata/events?sensor_id={sensor_id}&limit=5")
print(f"Status: {res_list.status_code}")
list_data = res_list.json()
print(json.dumps({"total": list_data["total"], "limit": list_data["limit"], "returned": len(list_data["events"])}, indent=2))

print(f"\n--- 3. GET /api/events/suricata/events/{first_event_id} ---")
res_detail = client.get(f"/api/events/suricata/events/{first_event_id}")
print(f"Status: {res_detail.status_code}")
print(json.dumps(res_detail.json(), indent=2))

print("\n--- 4. GET /api/events/suricata/attack-status ---")
res_status = client.get("/api/events/suricata/attack-status")
print(f"Status: {res_status.status_code}")
print(json.dumps(res_status.json(), indent=2))

print(f"\n--- 5. POST /api/events/suricata/explain/{first_event_id} ---")
res_explain = client.post(f"/api/events/suricata/explain/{first_event_id}")
print(f"Status: {res_explain.status_code}")
print(json.dumps(res_explain.json(), indent=2))
