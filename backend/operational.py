"""Small, read-only operational context shared by advisory AI surfaces.

The context deliberately comes from the integrity-checked active artifact
manifest.  A configured model name is not treated as evidence that an
artifact is production approved or even loadable.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any


def _first_text(*values: Any, default: str = "unknown") -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()[:128]
    return default


@lru_cache(maxsize=1)
def current_artifact_context() -> dict:
    """Return bounded, prompt-safe state for the active detection artifact."""
    context = {
        "operational_mode": "unavailable",
        "artifact_approval_state": "unverified",
        "production_approved": False,
        "artifact_version": "unknown",
        "pipeline_version": "unknown",
        "feature_schema_version": "unknown",
        "supported_classes": [],
        "evaluated_classes": [],
        "telemetry_profile": "hybrid_live_and_flow_records",
        "limitations": [
            "Detection artifacts are unavailable or have not passed integrity validation.",
            "The application analyzes network flows via live packet sniffer, Suricata EVE stream, and uploaded telemetry.",
        ],
    }
    try:
        from .detection.bundles import resolve_active_bundle_dir
        from .detection.integrity import validate_artifact_bundle

        metadata = validate_artifact_bundle(resolve_active_bundle_dir())
    except Exception:
        return context

    coverage = metadata.get("coverage_contract")
    coverage = coverage if isinstance(coverage, dict) else {}
    pipeline = metadata.get("pipeline")
    pipeline = pipeline if isinstance(pipeline, dict) else {}
    supported = (
        coverage.get("supported_labels")
        or coverage.get("trained_supported_labels")
        or coverage.get("trained_labels")
        or metadata.get("classes")
        or []
    )
    evaluated = coverage.get("evaluated_labels") or []
    supported = [str(item)[:64] for item in supported if isinstance(item, str)][:64]
    evaluated = [str(item)[:64] for item in evaluated if isinstance(item, str)][:64]
    approved = bool(metadata.get("production_approved", False))
    pipeline_version = _first_text(
        metadata.get("pipeline_version"),
        metadata.get("pipeline_schema_version"),
        metadata.get("routing_schema_version"),
        pipeline.get("version"),
        pipeline.get("schema_version"),
        default="legacy-v1-evaluation-only",
    )
    artifact_version = _first_text(
        metadata.get("artifact_version"),
        metadata.get("candidate_id"),
        metadata.get("code_revision"),
        metadata.get("schema_version"),
    )
    limitations = [
        "The application processes both live network flow streams and uploaded flow records.",
        "ATT&CK links derived from a classifier label are heuristic candidate mappings, not observed behavior.",
        "An autoencoder reconstruction error is an unknown-anomaly signal, not proof of an exploit.",
    ]
    if not approved:
        limitations.insert(
            0,
            "The active artifact is evaluation-only; detections are unverified model evidence requiring validation.",
        )
    context.update({
        "operational_mode": "production" if approved else "evaluation_only",
        "artifact_approval_state": "production_approved" if approved else "evaluation_only",
        "production_approved": approved,
        "artifact_version": artifact_version,
        "pipeline_version": pipeline_version,
        "feature_schema_version": _first_text(metadata.get("feature_schema_version")),
        "supported_classes": supported,
        "evaluated_classes": evaluated,
        "telemetry_profile": _first_text(
            coverage.get("telemetry_profile"),
            metadata.get("telemetry_profile"),
            default="uploaded_precomputed_flow_records",
        ),
        "limitations": limitations,
    })
    return context
