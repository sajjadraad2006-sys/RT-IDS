"""Typed Smart Log and guarded decision schemas."""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


DecisionText = Annotated[str, Field(max_length=500)]


class Verdict(str, Enum):
    malicious = "malicious"
    suspicious = "suspicious"
    benign = "benign"
    needs_human = "needs_human"


class RecommendedAction(str, Enum):
    observe = "observe"
    alert = "alert"
    escalate = "escalate"
    quarantine_recommended = "quarantine_recommended"
    block_recommended = "block_recommended"


class FeatureEvidence(BaseModel):
    """Finite, identifier-free evidence for one canonical flow feature."""
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    name: str = Field(max_length=64)
    observed_value: float | None = None
    normalized_value: float | None = None
    z_score: float | None = None


class DetectionEvidence(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)

    type: str = Field(max_length=64)
    severity: Literal["none", "low", "medium", "high", "critical"]
    stage: Literal["none", "statistical", "classifier", "autoencoder"]
    route: str = Field(default="unknown", max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=32)
    mitre_mapping_kind: Literal["none", "heuristic_hypothesis"] = "none"
    mitre_mapping_version: str = Field(default="none", max_length=64)
    top_features: list[tuple[str, float]] = Field(default_factory=list, max_length=10)
    feature_evidence: list[FeatureEvidence] = Field(default_factory=list, max_length=10)
    signals: dict[str, dict[str, Any]] = Field(default_factory=dict)


class SmartLog(BaseModel):
    schema_version: Literal["smart-log-v1", "smart-log-v2"] = "smart-log-v2"
    event_id: str
    alert_id: int = Field(ge=1)
    created_at: float
    source: dict[str, str]
    detection: DetectionEvidence
    operational_mode: Literal["unavailable", "evaluation_only", "production"] = "unavailable"
    artifact_approval_state: str = Field(default="unverified", max_length=64)
    artifact_version: str = Field(default="unknown", max_length=128)
    pipeline_version: str = Field(default="unknown", max_length=64)
    feature_schema_version: str = Field(default="unknown", max_length=64)
    input_profile: str = Field(default="unknown", max_length=128)
    feature_coverage_percentage: float = Field(default=0.0, ge=0.0, le=100.0)
    supported_classes: list[str] = Field(default_factory=list, max_length=64)
    limitations: list[str] = Field(default_factory=list, max_length=12)
    review_required: bool
    review_reason: str
    evidence_fingerprint: str
    trust_boundaries: list[str] = Field(default_factory=list)


class AiDecisionPayload(BaseModel):
    """The only shape accepted from an LLM response."""
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_action: RecommendedAction
    rationale: str = Field(min_length=1, max_length=2000)
    evidence: list[DecisionText] = Field(default_factory=list, max_length=8)
    containment: list[DecisionText] = Field(default_factory=list, max_length=8)
    limitations: list[DecisionText] = Field(default_factory=list, max_length=8)


class GuardedDecision(AiDecisionPayload):
    schema_version: Literal["guarded-decision-v1"] = "guarded-decision-v1"
    alert_id: int = Field(ge=1)
    source: Literal["policy", "policy+ai"]
    provider: str = Field(max_length=64)
    model_version: str = Field(default="none", max_length=128)
    policy_version: str = Field(max_length=64)
    prompt_version: str = Field(max_length=64)
    requires_human: bool
    executed_action: Literal["none"] = "none"
    degraded: bool = False
