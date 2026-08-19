"""Typed Smart Log and guarded decision schemas."""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

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


class DetectionEvidence(BaseModel):
    type: str = Field(max_length=64)
    severity: Literal["none", "low", "medium", "high", "critical"]
    stage: Literal["none", "statistical", "classifier", "autoencoder"]
    confidence: float = Field(ge=0.0, le=1.0)
    anomaly_score: float = Field(ge=0.0)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=32)
    top_features: list[tuple[str, float]] = Field(default_factory=list, max_length=10)


class SmartLog(BaseModel):
    schema_version: Literal["smart-log-v1"] = "smart-log-v1"
    event_id: str
    alert_id: int = Field(ge=1)
    created_at: float
    source: dict[str, str]
    detection: DetectionEvidence
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
