"""Canonical schemas and models for Suricata EVE security event ingestion."""
from __future__ import annotations

from enum import Enum
import time
from typing import Any
from pydantic import BaseModel, Field


SECURITY_EVENT_SCHEMA_VERSION = "cyberguard-security-event-v1"
SURICATA_ADAPTER_VERSION = "cyberguard-suricata-eve-v1"
SURICATA_RULE_MAPPING_VERSION = "suricata-rule-metadata-v1"


class AttackValidationStatus(str, Enum):
    ACTIVE_VALIDATED = "active_validated"
    SYNTACTICALLY_INVALID = "syntactically_invalid"
    UNKNOWN_TO_SNAPSHOT = "unknown_to_snapshot"
    REVOKED = "revoked"
    DEPRECATED = "deprecated"
    SNAPSHOT_UNAVAILABLE = "snapshot_unavailable"
    SNAPSHOT_UNVERIFIED = "snapshot_unverified"


class SecurityEventAttackMapping(BaseModel):
    """Structured ATT&CK technique mapping with explicit provenance semantics."""
    technique_id: str
    tactic_id: str | None = None
    validation_status: AttackValidationStatus
    signature_id: int | None = None
    rule_match_observed: bool = True
    mapping_evidence_present: bool = True
    technique_observed: bool = False
    evidence_kind: str = "suricata_rule_metadata"
    mapping_semantics: str = "evidence-supported candidate ATT&CK mapping"
    mapping_version: str = SURICATA_RULE_MAPPING_VERSION
    metadata_extraction_confidence: float = 1.0
    technique_occurrence_confidence: float | None = None
    evidence_ref: str = ""
    snapshot_version: str | None = None
    snapshot_source: str | None = None
    snapshot_indexed_time: float | None = None
    created_at: float = Field(default_factory=time.time)


class SecurityEventV1(BaseModel):
    """Canonical CyberGuard security event contract (cyberguard-security-event-v1)."""
    schema_version: str = SECURITY_EVENT_SCHEMA_VERSION
    adapter_version: str = SURICATA_ADAPTER_VERSION
    event_ref: str
    source_kind: str = "suricata_eve"
    source_event_type: str  # alert, flow, dns, tls
    sensor_id: str
    source_line_number: int
    timestamp: float
    timestamp_iso: str
    flow_id: int | None = None
    community_id: str | None = None
    proto: str | None = None
    app_proto: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    alert_signature: str | None = None
    alert_signature_id: int | None = None
    alert_category: str | None = None
    alert_severity: str | None = None
    source_sensor_severity_raw: int | str | None = None
    source_sensor_action: str | None = None
    executed_action: str = "none"
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[SecurityEventAttackMapping] = Field(default_factory=list)
    ingested_at: float = Field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class SuricataIngestionReport(BaseModel):
    """Comprehensive, bounded accounting report for a Suricata EVE upload."""
    ingestion_id: str
    source_file: str
    sensor_id: str
    adapter_version: str = SURICATA_ADAPTER_VERSION
    schema_version: str = SECURITY_EVENT_SCHEMA_VERSION
    status: str = "completed"  # completed, failed
    total_parsed: int = 0
    accepted: int = 0
    rejected_lines: int = 0
    ignored_unsupported_types: int = 0
    counts_by_event_type: dict[str, int] = Field(default_factory=dict)
    alert_events_accepted: int = 0
    eligible_for_persistence: int = 0
    persisted: int = 0
    omitted_due_to_persistence_cap: int = 0
    duplicates_in_upload: int = 0
    duplicates_already_persisted: int = 0
    newly_persisted_events: int = 0
    returned_events_count: int = 0
    caps: dict[str, int] = Field(default_factory=dict)
    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    active_attack_snapshot: dict[str, Any] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(default_factory=list)
    elapsed_seconds: float = 0.0
    executed_action: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
