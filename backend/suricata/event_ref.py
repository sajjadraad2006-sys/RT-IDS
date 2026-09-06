"""Deterministic event reference generation for Suricata EVE security events."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_event_ref(
    sensor_id: str,
    timestamp_iso: str,
    event_type: str,
    src_ip: str | None,
    src_port: int | None,
    dest_ip: str | None,
    dest_port: int | None,
    proto: str | None,
    flow_id: int | None = None,
    community_id: str | None = None,
    alert_signature_id: int | None = None,
    alert_signature: str | None = None,
    alert_category: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> str:
    """Compute a deterministic, collision-resistant SHA-256 reference for an event.

    Combines sensor identity, normalized timestamp, event type, network 5-tuple,
    flow/community IDs, alert signature data, and bounded event-specific evidence.
    """
    canonical_payload = {
        "sensor_id": str(sensor_id or "suricata-default").strip()[:64],
        "timestamp_iso": str(timestamp_iso or "").strip(),
        "event_type": str(event_type or "").strip().lower(),
        "src_ip": str(src_ip or "").strip(),
        "src_port": int(src_port) if src_port is not None else None,
        "dest_ip": str(dest_ip or "").strip(),
        "dest_port": int(dest_port) if dest_port is not None else None,
        "proto": str(proto or "").strip().upper(),
        "flow_id": int(flow_id) if flow_id is not None else None,
        "community_id": str(community_id or "").strip(),
        "alert_signature_id": int(alert_signature_id) if alert_signature_id is not None else None,
        "alert_signature": str(alert_signature or "").strip()[:256],
        "alert_category": str(alert_category or "").strip()[:128],
        "evidence": evidence or {},
    }
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
