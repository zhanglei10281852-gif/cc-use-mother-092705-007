from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

LocationType = Literal["water", "meadow", "forest_edge"]
Confidence = Literal["low", "medium", "high"]
ImpactScope = Literal["individual", "local", "area"]


class ReportCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    location_type: LocationType
    location_name: str = Field(default="", max_length=120)
    report_type: Literal["water_quality", "human_intrusion", "injured_wildlife", "vegetation_damage", "fire_risk", "other"]
    description: str = Field(default="", max_length=4000)
    reporter: str = Field(min_length=1, max_length=80)
    confidence: Confidence
    impact_scope: ImpactScope
    evidence: str = Field(default="", max_length=4000)
    dedupe_key: str = Field(default="", max_length=120)


class EvidenceCreate(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    confidence: Confidence
    impact_scope: ImpactScope | None = None
    evidence: str = Field(min_length=1, max_length=4000)
    description: str = Field(default="", max_length=4000)
    dedupe_key: str = Field(default="", max_length=120)


class AssignRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    assignee: str = Field(min_length=1, max_length=80)
    note: str = Field(default="", max_length=1000)


class AcceptRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)


class TransferRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    to_assignee: str = Field(min_length=1, max_length=80)
    reason: str = Field(min_length=2, max_length=1000)


class EscalateRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    to_level: Literal["P1", "P2", "P3", "P4"]
    reason: str = Field(min_length=2, max_length=1000)


class ResolveRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    conclusion: str = Field(min_length=2, max_length=4000)
    conclusion_kind: Literal["confirmed", "false_positive", "monitoring"] = "confirmed"


class ReviewRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    item: Literal["reviewer_signoff", "follow_up_check", "second_reviewer"]
    note: str = Field(default="", max_length=1000)


class CloseRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    reason: str = Field(min_length=2, max_length=1000)


class RejectRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    reason: str = Field(min_length=2, max_length=1000)


class RuleVersionCreate(BaseModel):
    version: str = Field(min_length=3, max_length=40)
    rules: dict
    note: str = Field(default="", max_length=1000)


class SwitchRulesRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=80)
    target_version: str = Field(min_length=3, max_length=40)
    confirm: bool = False
    reason: str = Field(min_length=2, max_length=1000)
