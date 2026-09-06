"""Deterministic exception-focused analytical triage policy."""
from __future__ import annotations

import time

POLICY_VERSION = "triage-policy-v1"


def triage_evidence(evidence: dict) -> dict:
    """Assign an explicit analytical state without authorizing containment."""
    route = str(evidence.get("route") or "")
    confidence = min(1.0, max(0.0, float(evidence.get("confidence") or 0.0)))
    artifact_approved = bool(evidence.get("artifact_approved", False))
    conflicting = bool(evidence.get("conflicting_evidence", False))
    refs = [str(item)[:128] for item in evidence.get("evidence_refs", [])][:500]
    provenance = [str(item)[:64] for item in evidence.get("source_provenance", [])][:32]

    if not refs or not provenance:
        state = "insufficient_evidence"
        reason = "required_evidence_or_provenance_missing"
        human = True
    elif conflicting:
        state = "review_required_conflicting_evidence"
        reason = "independent_evidence_conflicts"
        human = True
    elif route == "unknown_anomaly_review":
        state = "review_required_unknown_anomaly"
        reason = "unknown_anomaly_has_no_verified_attack_identity"
        human = True
    elif route == "known_attack" and confidence >= 0.95 and artifact_approved:
        state = "auto_escalated_known_attack"
        reason = "approved_artifact_high_confidence_analytical_escalation"
        human = False
    elif route in {"known_attack", "human_review"}:
        state = "review_required_uncertain"
        reason = (
            "artifact_not_production_approved"
            if not artifact_approved else "confidence_or_evidence_below_policy_threshold"
        )
        human = True
    elif route == "benign" and artifact_approved and bool(evidence.get("allow_benign_closure")):
        state = "auto_closed_benign"
        reason = "approved_artifact_and_validated_policy_permit_closure"
        human = False
    else:
        state = "insufficient_evidence"
        reason = "route_not_eligible_for_automatic_triage"
        human = True

    unknown = state == "review_required_unknown_anomaly"
    return {
        "state": state,
        "policy_version": POLICY_VERSION,
        "reason_code": reason,
        "evidence_references": refs,
        "artifact_status": str(evidence.get("artifact_status") or "unknown")[:64],
        "confidence": confidence,
        "source_provenance": provenance,
        "timestamp": float(evidence.get("timestamp") or time.time()),
        "human_review_required": human,
        "attack_candidates": [] if unknown else list(evidence.get("attack_candidates", []))[:32],
        "cves": [] if unknown else list(evidence.get("cves", []))[:32],
        "executed_action": "none",
        "action_executed": False,
    }
