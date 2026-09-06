"""Transparent versioned incident risk decomposition."""
from __future__ import annotations

import math

FORMULA_VERSION = "transparent-risk-v1"


def _component(contribution: float, evidence: str, warning: str = "") -> dict:
    value = float(contribution)
    if not math.isfinite(value):
        value = 0.0
        warning = warning or "non-finite input was ignored"
    return {"contribution": value, "evidence": evidence, "warning": warning}


def calculate_risk(context: dict) -> dict:
    """Calculate bounded priority while exposing every weighted contribution."""
    components: dict[str, dict] = {}
    severity_weights = {"info": 0, "low": 4, "medium": 10, "high": 16, "critical": 20}
    severity = str(context.get("sensor_severity") or "missing").lower()
    components["sensor_evidence"] = _component(
        severity_weights.get(severity, 0), severity,
        "sensor severity missing or unsupported" if severity not in severity_weights else "",
    )

    classifier = context.get("classifier_confidence")
    classifier_value = float(classifier) if classifier is not None else 0.0
    if not math.isfinite(classifier_value):
        classifier_value = 0.0
    components["classifier"] = _component(
        20 * min(1.0, max(0.0, classifier_value)),
        "calibrated classifier confidence" if classifier is not None else "missing",
        "classifier confidence unavailable" if classifier is None else "",
    )

    statistical_score = context.get("statistical_score")
    calibrated = bool(context.get("statistical_calibrated", False))
    if calibrated and statistical_score is not None and math.isfinite(float(statistical_score)):
        statistical_contribution = 15 * min(1.0, max(0.0, float(statistical_score)))
        statistical_warning = ""
    else:
        statistical_contribution = 0
        statistical_warning = "statistical/OOD score is not independently calibrated"
    components["statistical_ood"] = _component(
        statistical_contribution, "statistical anomaly context", statistical_warning
    )

    criticality = context.get("asset_criticality")
    criticality_value = float(criticality) if criticality is not None else 0.0
    components["asset_criticality"] = _component(
        15 * min(1.0, max(0.0, criticality_value)),
        "asset inventory" if criticality is not None else "missing",
        "asset criticality unavailable" if criticality is None else "",
    )
    components["kev"] = _component(
        15 if context.get("kev") is True else 0,
        "valid CVE joined to CISA KEV" if context.get("kev") is True else "no valid KEV join",
    )
    epss = context.get("epss_score")
    epss_value = float(epss) if epss is not None else 0.0
    components["epss"] = _component(
        10 * min(1.0, max(0.0, epss_value)),
        "EPSS probability context" if epss is not None else "missing",
        "EPSS is probability context, not proof" if epss is not None else "EPSS unavailable",
    )
    components["software_vulnerability"] = _component(
        10 if context.get("osv_applicable") and context.get("osv_vulnerable") else 0,
        "versioned package matched OSV" if context.get("osv_applicable") else "package context unavailable",
        "OSV not applicable without ecosystem, package, and version"
        if not context.get("osv_applicable") else "",
    )
    components["attack_context"] = _component(
        5 if context.get("attack_verified") else 0,
        "verified ATT&CK candidate" if context.get("attack_verified") else "unverified or absent",
        "ATT&CK/D3FEND context is non-causal and advisory"
        if context.get("attack_verified") else "no verified ATT&CK context",
    )
    uncertainty = min(1.0, max(0.0, float(context.get("uncertainty") or 0.0)))
    components["uncertainty_adjustment"] = _component(
        -20 * uncertainty, "explicit uncertainty adjustment"
    )
    freshness = str(context.get("intelligence_freshness") or "unavailable")
    penalty = {"fresh": 0, "stale": -10, "degraded": -15, "unavailable": -20}.get(
        freshness, -20
    )
    components["freshness_penalty"] = _component(
        penalty, freshness, "stale or unavailable intelligence reduces confidence" if penalty else ""
    )

    raw_score = sum(item["contribution"] for item in components.values())
    score = round(min(100.0, max(0.0, raw_score)), 3)
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    return {
        "formula_version": FORMULA_VERSION,
        "score": score,
        "raw_score": raw_score,
        "level": level,
        "components": components,
        "limitations": [
            "Risk is prioritization, not proof of exploitation.",
            "Containment requires explicit human authorization.",
        ],
        "containment_authorized": False,
        "executed_action": "none",
    }
