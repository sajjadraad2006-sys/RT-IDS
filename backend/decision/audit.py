"""Append-only hash-chained audit helpers for analyst and policy events."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from ..db.models import AuditEvent


def append_audit_event(
    session,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: int | str,
    payload: dict[str, Any] | None = None,
) -> AuditEvent:
    previous = session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    previous_hash = previous.event_hash if previous else ""
    created_at = time.time()
    payload_json = json.dumps(payload or {}, sort_keys=True, separators=(",", ":"))
    material = json.dumps({
        "created_at": created_at,
        "actor": actor[:64],
        "action": action[:64],
        "entity_type": entity_type[:32],
        "entity_id": str(entity_id)[:64],
        "payload_json": payload_json,
        "previous_hash": previous_hash,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    event = AuditEvent(
        created_at=created_at,
        actor=actor[:64],
        action=action[:64],
        entity_type=entity_type[:32],
        entity_id=str(entity_id)[:64],
        payload_json=payload_json,
        previous_hash=previous_hash,
        event_hash=hashlib.sha256(material).hexdigest(),
    )
    session.add(event)
    return event


def verify_audit_chain(events: list[AuditEvent]) -> bool:
    previous_hash = ""
    for event in events:
        material = json.dumps({
            "created_at": event.created_at,
            "actor": event.actor,
            "action": event.action,
            "entity_type": event.entity_type,
            "entity_id": event.entity_id,
            "payload_json": event.payload_json,
            "previous_hash": previous_hash,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if event.previous_hash != previous_hash:
            return False
        if event.event_hash != hashlib.sha256(material).hexdigest():
            return False
        previous_hash = event.event_hash
    return True
