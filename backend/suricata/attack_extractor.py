"""Strict ATT&CK technique extraction and snapshot validation for Suricata rule metadata."""
from __future__ import annotations

import logging
import re
from typing import Any
import sqlite3

from .schema import (
    AttackValidationStatus,
    SURICATA_RULE_MAPPING_VERSION,
    SecurityEventAttackMapping,
)

log = logging.getLogger("cyberguard.suricata.attack_extractor")

TECHNIQUE_ID_REGEX = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
TACTIC_ID_REGEX = re.compile(r"^TA\d{4}$", re.IGNORECASE)
TAG_ATTACK_REGEX = re.compile(r"^(?:attack|mitre)\.(t\d{4}(?:[_\.]\d{3})?)$", re.IGNORECASE)
TAG_TACTIC_REGEX = re.compile(r"^(?:attack|mitre)\.(ta\d{4})$", re.IGNORECASE)

ALLOWLISTED_TECHNIQUE_KEYS = {
    "mitre_technique_id",
    "mitre_technique",
    "attack_technique",
    "attack_technique_id",
}

ALLOWLISTED_TACTIC_KEYS = {
    "mitre_tactic_id",
    "mitre_tactic",
    "attack_tactic",
    "attack_tactic_id",
}


def _normalize_technique_id(raw: str) -> str:
    cleaned = raw.strip().upper().replace("_", ".")
    return cleaned


def _normalize_tactic_id(raw: str) -> str:
    return raw.strip().upper()


def get_active_attack_snapshot_info(db_path: str | None = None) -> dict[str, Any]:
    """Retrieve active ATT&CK snapshot metadata from the SQLite database."""
    try:
        from ..mitre import attack_db
        return attack_db.get_stats(db_path=db_path)
    except sqlite3.OperationalError:
        return {
            "available": False,
            "version": None,
            "version_status": "snapshot_unavailable",
            "object_count": 0,
            "technique_count": 0,
            "synced_at": None,
            "source_kind": "bundled_local_snapshot",
            "snapshot_filename": "",
            "official_release_verified": False,
        }
    except Exception as exc:
        log.debug("Failed to query active ATT&CK snapshot info: %s", exc)
        return {
            "available": False,
            "version": None,
            "version_status": "snapshot_unavailable",
            "object_count": 0,
            "technique_count": 0,
            "synced_at": None,
            "source_kind": "bundled_local_snapshot",
            "snapshot_filename": "",
            "official_release_verified": False,
            "error": str(exc),
        }


def extract_raw_attack_metadata(metadata: dict[str, Any]) -> tuple[set[str], set[str], list[str]]:
    """Extract raw candidate technique IDs and tactic IDs from allowlisted metadata keys only.

    Returns:
        (technique_ids, tactic_ids, invalid_technique_strings)
    """
    raw_technique_candidates: set[str] = set()
    raw_tactic_candidates: set[str] = set()
    invalid_technique_strings: list[str] = []

    if not isinstance(metadata, dict):
        return set(), set(), []

    for key, val in metadata.items():
        key_norm = str(key).strip().lower()
        items = val if isinstance(val, (list, tuple, set)) else [val]
        if isinstance(items, set):
            items = sorted(items, key=lambda item: str(item))

        if key_norm in ALLOWLISTED_TECHNIQUE_KEYS:
            for item in items:
                text = str(item or "").strip()
                if not text:
                    continue
                normalized = _normalize_technique_id(text)
                if TECHNIQUE_ID_REGEX.fullmatch(normalized):
                    raw_technique_candidates.add(normalized)
                elif TACTIC_ID_REGEX.fullmatch(normalized):
                    # Tactic ID found in technique key -> route to tactic candidate
                    raw_tactic_candidates.add(_normalize_tactic_id(text))
                else:
                    invalid_technique_strings.append(text[:64])

        elif key_norm in ALLOWLISTED_TACTIC_KEYS:
            for item in items:
                text = str(item or "").strip()
                if not text:
                    continue
                normalized = _normalize_tactic_id(text)
                if TACTIC_ID_REGEX.fullmatch(normalized):
                    raw_tactic_candidates.add(normalized)

        elif key_norm in ("tag", "tags"):
            for item in items:
                text = str(item or "").strip().lower()
                m_tech = TAG_ATTACK_REGEX.fullmatch(text)
                if m_tech:
                    raw_technique_candidates.add(_normalize_technique_id(m_tech.group(1)))
                    continue
                m_tac = TAG_TACTIC_REGEX.fullmatch(text)
                if m_tac:
                    raw_tactic_candidates.add(_normalize_tactic_id(m_tac.group(1)))

    return raw_technique_candidates, raw_tactic_candidates, invalid_technique_strings


def validate_and_map_attack_metadata(
    metadata: dict[str, Any],
    signature_id: int | None = None,
    db_path: str | None = None,
) -> list[SecurityEventAttackMapping]:
    """Extract allowlisted ATT&CK metadata and validate against local ATT&CK database.

    Guarantees:
    - Never derives techniques from signature text or arbitrary keywords.
    - Separates tactics from techniques.
    - Evaluates exact snapshot validation state.
    - Explicitly sets extraction confidence (1.0) and technique occurrence confidence (None).
    """
    raw_techniques, raw_tactics, invalid_strings = extract_raw_attack_metadata(metadata)
    mappings: list[SecurityEventAttackMapping] = []
    snapshot_info = get_active_attack_snapshot_info(db_path=db_path)

    # Only assign a tactic if there is exactly one unambiguous tactic in metadata (CG-SUR-005)
    primary_tactic = sorted(raw_tactics)[0] if len(raw_tactics) == 1 else None

    # Handle invalid strings
    for inv in sorted(set(invalid_strings)):
        mappings.append(
            SecurityEventAttackMapping(
                technique_id=inv,
                tactic_id=primary_tactic,
                validation_status=AttackValidationStatus.SYNTACTICALLY_INVALID,
                signature_id=signature_id,
                rule_match_observed=True,
                mapping_evidence_present=True,
                technique_observed=False,
                evidence_kind="suricata_rule_metadata",
                mapping_semantics="evidence-supported candidate ATT&CK mapping",
                mapping_version=SURICATA_RULE_MAPPING_VERSION,
                metadata_extraction_confidence=0.0,
                technique_occurrence_confidence=None,
                snapshot_version=snapshot_info.get("version"),
                snapshot_source=snapshot_info.get("snapshot_filename"),
                snapshot_indexed_time=snapshot_info.get("synced_at"),
            )
        )

    if not raw_techniques:
        return mappings

    # Query local ATT&CK database for technique records
    from ..mitre import attack_db
    try:
        for tid in sorted(raw_techniques):
            status: AttackValidationStatus
            technique_count = snapshot_info.get("technique_count", 0)
            version_status = snapshot_info.get("version_status", "unverified")

            if technique_count == 0 or version_status == "snapshot_unavailable":
                status = AttackValidationStatus.SNAPSHOT_UNAVAILABLE
            elif not snapshot_info.get("official_release_verified", False):
                status = AttackValidationStatus.SNAPSHOT_UNVERIFIED
            else:
                db_status, _ = attack_db.check_technique_status(tid, db_path=db_path)
                if db_status == "active_validated":
                    status = AttackValidationStatus.ACTIVE_VALIDATED
                elif db_status == "revoked":
                    status = AttackValidationStatus.REVOKED
                elif db_status == "deprecated":
                    status = AttackValidationStatus.DEPRECATED
                elif db_status == "snapshot_unavailable":
                    status = AttackValidationStatus.SNAPSHOT_UNAVAILABLE
                else:
                    status = AttackValidationStatus.UNKNOWN_TO_SNAPSHOT

            mappings.append(
                SecurityEventAttackMapping(
                    technique_id=tid,
                    tactic_id=primary_tactic,
                    validation_status=status,
                    signature_id=signature_id,
                    rule_match_observed=True,
                    mapping_evidence_present=True,
                    technique_observed=False,
                    evidence_kind="suricata_rule_metadata",
                    mapping_semantics="evidence-supported candidate ATT&CK mapping",
                    mapping_version=SURICATA_RULE_MAPPING_VERSION,
                    metadata_extraction_confidence=1.0,
                    technique_occurrence_confidence=None,
                    evidence_ref=f"sid:{signature_id}" if signature_id else "",
                    snapshot_version=snapshot_info.get("version"),
                    snapshot_source=snapshot_info.get("snapshot_filename"),
                    snapshot_indexed_time=snapshot_info.get("synced_at"),
                )
            )
    except Exception as exc:
        log.error("ATT&CK technique validation query failed: %s", exc)
        for tid in sorted(raw_techniques):
            mappings.append(
                SecurityEventAttackMapping(
                    technique_id=tid,
                    tactic_id=primary_tactic,
                    validation_status=AttackValidationStatus.SNAPSHOT_UNAVAILABLE,
                    signature_id=signature_id,
                    rule_match_observed=True,
                    mapping_evidence_present=True,
                    technique_observed=False,
                    evidence_kind="suricata_rule_metadata",
                    mapping_semantics="evidence-supported candidate ATT&CK mapping",
                    mapping_version=SURICATA_RULE_MAPPING_VERSION,
                    metadata_extraction_confidence=1.0,
                    technique_occurrence_confidence=None,
                    snapshot_version=None,
                    snapshot_source=None,
                    snapshot_indexed_time=None,
                )
            )

    return mappings
