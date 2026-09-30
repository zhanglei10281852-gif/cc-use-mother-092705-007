from __future__ import annotations

from fastapi import APIRouter, Query

from app.incidents.schemas import (
    AcceptRequest,
    AssignRequest,
    CloseRequest,
    EscalateRequest,
    EvidenceCreate,
    RejectRequest,
    ReportCreate,
    ResolveRequest,
    ReviewRequest,
    RuleVersionCreate,
    SwitchRulesRequest,
    TransferRequest,
)
from app.incidents.service import IncidentResponseService

router = APIRouter(prefix="/api/incidents", tags=["异常响应服务"])


def service() -> IncidentResponseService:
    return IncidentResponseService()


# ---- 上报与查重 ----

@router.post("/reports", status_code=201)
def create_report(payload: ReportCreate):
    return service().report(payload.model_dump())


@router.post("/events/{event_id}/evidence", status_code=201)
def add_evidence(event_id: int, payload: EvidenceCreate):
    return service().add_evidence(event_id, payload.model_dump())


@router.get("/events")
def list_events(status: str | None = None, level: str | None = None, assignee: str | None = None, limit: int = Query(default=100, ge=1, le=500)):
    return {"items": service().list_events(status=status, level=level, assignee=assignee, limit=limit)}


@router.get("/events/{event_id}")
def get_event(event_id: int):
    return service().get_event(event_id)


@router.get("/events/{event_id}/reports")
def get_reports(event_id: int):
    return service().get_reports(event_id)


@router.get("/events/{event_id}/timeline")
def timeline(event_id: int):
    return service().timeline(event_id)


# ---- 处置流转 ----

@router.post("/events/{event_id}/assign")
def assign(event_id: int, payload: AssignRequest):
    return service().assign(event_id, payload.assignee, payload.actor, payload.note)


@router.post("/events/{event_id}/accept")
def accept(event_id: int, payload: AcceptRequest):
    return service().accept(event_id, payload.actor)


@router.post("/events/{event_id}/transfer")
def transfer(event_id: int, payload: TransferRequest):
    return service().transfer(event_id, payload.model_dump())


@router.post("/events/{event_id}/escalate")
def escalate(event_id: int, payload: EscalateRequest):
    return service().escalate(event_id, payload.model_dump())


@router.post("/events/{event_id}/resolve")
def resolve(event_id: int, payload: ResolveRequest):
    return service().resolve(event_id, payload.model_dump())


@router.post("/events/{event_id}/review")
def review(event_id: int, payload: ReviewRequest):
    return service().grant_review_item(event_id, payload.model_dump())


@router.post("/events/{event_id}/close")
def close(event_id: int, payload: CloseRequest):
    return service().close(event_id, payload.model_dump())


@router.post("/events/{event_id}/reject")
def reject(event_id: int, payload: RejectRequest):
    return service().reject(event_id, payload.model_dump())


@router.post("/overdue/process")
def process_overdue(actor: str = Query(default="system", min_length=1)):
    return service().process_overdue(actor)


# ---- 规则版本 ----

@router.get("/rules/versions")
def list_rule_versions():
    return {"items": service().list_rule_versions()}


@router.get("/rules/current")
def current_rules():
    return service().get_rules()


@router.get("/rules/{version}")
def get_rules(version: str):
    return service().get_rules(version)


@router.post("/rules/versions", status_code=201)
def create_rule_version(payload: RuleVersionCreate, actor: str = Query(..., min_length=1)):
    return service().create_rule_version(payload.model_dump(), actor)


@router.post("/events/{event_id}/switch-rules")
def switch_rules(event_id: int, payload: SwitchRulesRequest):
    return service().switch_rules(event_id, payload.model_dump())
