from __future__ import annotations

from fastapi import APIRouter, Query

from app.anomaly.schemas import (
    ActorRequest,
    AssignRequest,
    CloseRequest,
    ConclusionRequest,
    EscalateRequest,
    RejectRequest,
    ReportCreate,
    ReviewRequest,
    RuleVersionPublish,
    RuleVersionSwitch,
    TransferRequest,
)
from app.anomaly.service import AnomalyResponseService

router = APIRouter(prefix="/api/anomaly", tags=["保护中心异常响应"])


def service() -> AnomalyResponseService:
    return AnomalyResponseService()


@router.post("/reports", status_code=201)
def report(payload: ReportCreate):
    return service().report(payload.model_dump())


@router.get("/incidents")
def list_incidents(status: str | None = None, level: str | None = Query(default=None, pattern="^L[123]$"),
                   limit: int = Query(default=100, ge=1, le=500)):
    return service().list_incidents(status=status, level=level, limit=limit)


@router.get("/dispatch-queue")
def dispatch_queue():
    return service().dispatch_queue()


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    return service().get_incident(incident_id)


@router.get("/incidents/{incident_id}/timeline")
def timeline(incident_id: int):
    return service().timeline(incident_id)


@router.get("/incidents/{incident_id}/chain")
def verify_chain(incident_id: int):
    return service().verify_chain(incident_id)


@router.post("/incidents/{incident_id}/assign")
def assign(incident_id: int, payload: AssignRequest):
    return service().assign(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/transfer")
def transfer(incident_id: int, payload: TransferRequest):
    return service().transfer(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/acknowledge")
def acknowledge(incident_id: int, payload: ActorRequest):
    return service().acknowledge(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/escalate")
def escalate(incident_id: int, payload: EscalateRequest):
    return service().manual_escalate(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/conclude")
def conclude(incident_id: int, payload: ConclusionRequest):
    return service().conclude(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/recheck")
def recheck(incident_id: int, payload: ReviewRequest):
    return service().recheck(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/senior-review")
def senior_review(incident_id: int, payload: ReviewRequest):
    return service().senior_review(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/close")
def close(incident_id: int, payload: CloseRequest):
    return service().close(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/reject")
def reject(incident_id: int, payload: RejectRequest):
    return service().reject_pending(incident_id, payload.model_dump())


@router.post("/incidents/{incident_id}/rule-version")
def switch_rule_version(incident_id: int, payload: RuleVersionSwitch):
    return service().switch_rule_version(incident_id, payload.model_dump())


@router.get("/rule-versions")
def list_rule_versions():
    return {"items": service().list_rule_versions()}


@router.get("/rule-versions/{version}")
def get_rule_version(version: str):
    return service().get_rule_version(version)


@router.post("/rule-versions", status_code=201)
def publish_rule_version(payload: RuleVersionPublish):
    data = payload.model_dump()
    actor = data.pop("actor")
    return service().publish_rule_version(data, actor)
