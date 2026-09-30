from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SiteType = Literal["water", "meadow", "forest_edge"]
Confidence = Literal["low", "medium", "high"]
ImpactScope = Literal["single", "local", "broad"]
AnomalyKind = Literal["water_quality", "intrusion", "injured_bird", "fire_risk", "poaching", "other"]


class ReportCreate(BaseModel):
    anomaly_kind: AnomalyKind
    site_type: SiteType
    location_name: str = Field(default="", max_length=120)
    confidence: Confidence
    impact_scope: ImpactScope
    reporter: str = Field(..., min_length=1, max_length=80)
    evidence_type: str = Field(..., min_length=1, max_length=40)
    evidence_ref: str = Field(default="", max_length=200)
    summary: str = Field(default="", max_length=1000)
    fingerprint: str | None = Field(default=None, min_length=8, max_length=128)
    related_incident_id: int | None = Field(default=None, ge=1)
    cross_incident_ids: list[int] = Field(default_factory=list, max_length=20)


class AssignRequest(BaseModel):
    assignee: str = Field(..., min_length=1, max_length=80)
    assignee_role: str = Field(..., min_length=1, max_length=80)
    actor: str = Field(..., min_length=1, max_length=80)
    reason: str = Field(default="", max_length=500)


class TransferRequest(BaseModel):
    to_assignee: str = Field(..., min_length=1, max_length=80)
    to_assignee_role: str = Field(..., min_length=1, max_length=80)
    actor: str = Field(..., min_length=1, max_length=80)
    reason: str = Field(..., min_length=2, max_length=500)


class ActorRequest(BaseModel):
    actor: str = Field(..., min_length=1, max_length=80)
    note: str = Field(default="", max_length=500)


class ConclusionRequest(BaseModel):
    actor: str = Field(..., min_length=1, max_length=80)
    conclusion: str = Field(..., min_length=2, max_length=1000)
    measures: str = Field(default="", max_length=1000)
    outcome: Literal["resolved", "false_alarm", "escalated_to_authority"] = "resolved"


class ReviewRequest(BaseModel):
    reviewer: str = Field(..., min_length=1, max_length=80)
    passed: bool
    opinion: str = Field(default="", max_length=1000)


class CloseRequest(BaseModel):
    actor: str = Field(..., min_length=1, max_length=80)


class RejectRequest(BaseModel):
    reviewer: str = Field(..., min_length=1, max_length=80)
    reason: str = Field(..., min_length=2, max_length=500)


class EscalateRequest(BaseModel):
    actor: str = Field(..., min_length=1, max_length=80)
    target_level: Literal["L1", "L2", "L3"]
    reason: str = Field(..., min_length=2, max_length=500)
    confidence: Confidence | None = None
    impact_scope: ImpactScope | None = None


class RuleVersionPublish(BaseModel):
    version: str = Field(..., min_length=2, max_length=40, pattern=r"^v?[0-9A-Za-z][0-9A-Za-z._-]*$")
    rules: dict | None = None
    actor: str = Field(..., min_length=1, max_length=80)


class RuleVersionSwitch(BaseModel):
    version: str = Field(..., min_length=2, max_length=40)
    actor: str = Field(..., min_length=1, max_length=80)
    confirm: bool = False
    reason: str = Field(default="", max_length=500)
