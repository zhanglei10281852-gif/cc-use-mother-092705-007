"""异常响应服务：分级事件、处置流转、复核关闭与不可篡改变更脉络。"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.database import get_connection, transaction
from app.incidents.repository import SCHEMA, IncidentRepository, dumps
from app.incidents.rules import (
    CONFIDENCE_ORDER,
    SCOPE_ORDER,
    REVIEW_GRANTABLE,
    default_rules,
    grade_incident,
    level_map,
    level_rank,
    validate_rules,
)


def ensure_schema() -> None:
    get_connection().executescript(SCHEMA)


def bootstrap() -> None:
    """启动时建表并植入初始规则版本。"""
    IncidentResponseService()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class IncidentResponseService:
    """依据版本化规则完成上报分级、派单处置、升级转交、复核关闭。"""

    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        self.clock = clock or SystemClock()
        ensure_schema()
        self._seed_default_rules()

    # ============ 规则版本 ============

    def _seed_default_rules(self) -> None:
        if IncidentRepository(self.connection).latest_rule_version() is not None:
            return
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            if repository.latest_rule_version() is None:
                rules = default_rules()
                now = to_storage(self.clock.now())
                repository.insert_rule_version(
                    version=rules["version"], rules=rules, digest=_sha256(dumps(rules)),
                    note="内置初始规则", actor="system", now=now,
                )

    def list_rule_versions(self) -> list[dict[str, Any]]:
        return IncidentRepository(self.connection).list_rule_versions()

    def get_rules(self, version: str | None = None) -> dict[str, Any]:
        repository = IncidentRepository(self.connection)
        row = repository.rule_version(version) if version else repository.latest_rule_version()
        if row is None:
            raise NotFoundError("规则版本不存在")
        return {"version": row["version"], "rules": json.loads(row["rules_json"]), "digest": row["rules_digest"], "note": row["note"], "created_by": row["created_by"], "created_at": row["created_at"]}

    def create_rule_version(self, payload: dict[str, Any], actor: str) -> dict[str, Any]:
        rules = payload["rules"]
        version = str(payload.get("version") or rules.get("version", "")).strip()
        rules["version"] = version
        validate_rules(rules)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            if repository.rule_version(version):
                raise ConflictError("规则版本已存在，规则内容不可覆盖")
            repository.insert_rule_version(
                version=version, rules=rules, digest=_sha256(dumps(rules)),
                note=payload.get("note", ""), actor=actor, now=now,
            )
            row = repository.rule_version(version)
        return {"version": row["version"], "digest": row["rules_digest"], "created_at": row["created_at"]}

    def switch_rules(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        """正在处理的事件只能在明确操作下切换到另一版规则；已关闭事件永不切换。"""
        if not payload.get("confirm"):
            raise ValidationError("切换规则版本属于显式操作，必须传 confirm=true")
        actor = payload["actor"]
        now_value = self.clock.now()
        now = to_storage(now_value)
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = repository.event_by_id(event_id)
            if event is None:
                raise NotFoundError("事件不存在")
            if event["status"] in {"closed", "rejected"}:
                raise ConflictError("历史事件按创建时的旧规则解释，不能切换版本")
            target = repository.rule_version(payload["target_version"])
            if target is None:
                raise NotFoundError("目标规则版本不存在")
            if target["version"] == event["rule_version"]:
                raise ConflictError("事件已经在使用该规则版本")
            new_rules = json.loads(target["rules_json"])
            old_level = event["level"]
            new_level, matched = grade_incident(
                new_rules,
                location_type=event["location_type"], report_type=event["report_type"],
                confidence=self._max_confidence(repository.reports(event_id)),
                impact_scope=self._max_scope(repository.reports(event_id)),
            )
            created_at = event["created_at"]
            levels = level_map(new_rules)
            checklist = self._merge_checklist(json.loads(event["review_checklist_json"]), new_rules["review_requirements"].get(new_level, []))
            new_status = event["status"]
            evidence_due = event["evidence_due_at"]
            if new_status == "awaiting_evidence" and new_level != new_rules["await_evidence_level"]:
                new_status = "in_progress" if event["accepted_at"] else ("assigned" if event["current_assignee"] else "open")
                evidence_due = None
            elif new_status in {"open", "escalated"} and new_level == new_rules["await_evidence_level"]:
                new_status = "awaiting_evidence"
                evidence_due = self._due(now, new_rules["await_evidence_expire_minutes"])
            connection.execute(
                """UPDATE incident_events SET rule_version=?,rules_snapshot_json=?,rules_digest=?,level=?,matched_rule=?,
                   status=?,response_due_at=?,resolve_due_at=?,evidence_due_at=?,review_checklist_json=?,updated_at=? WHERE id=?""",
                (
                    target["version"], json.dumps(new_rules, ensure_ascii=False, sort_keys=True), target["rules_digest"],
                    new_level, matched, new_status,
                    self._due(created_at, levels[new_level]["respond_minutes"]),
                    self._due(created_at, levels[new_level]["resolve_minutes"]),
                    evidence_due, dumps(checklist), now, event_id,
                ),
            )
            self._log(
                repository, event_id, "rule_switch", actor,
                {"from_version": event["rule_version"], "to_version": target["version"],
                 "from_level": old_level, "to_level": new_level, "matched_rule": matched,
                 "from_status": event["status"], "to_status": new_status, "reason": payload.get("reason", "")},
                now,
            )
            return self._detail(repository.event_by_id(event_id), repository)

    # ============ 上报与查重 ============

    def report(self, payload: dict[str, Any]) -> dict[str, Any]:
        now_value = self.clock.now()
        now = to_storage(now_value)
        fingerprint = self._fingerprint(payload)
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            rules_row = repository.latest_rule_version()
            rules = json.loads(rules_row["rules_json"])
            window_start = to_storage(now_value - timedelta(minutes=rules["duplicate_window_minutes"]))
            duplicate = repository.find_duplicate(fingerprint=fingerprint, window_start=window_start)
            if duplicate is not None:
                return self._attach_report(repository, duplicate, payload, fingerprint, rules, now, linked=True)
            level, matched = grade_incident(
                rules,
                location_type=payload["location_type"], report_type=payload["report_type"],
                confidence=payload["confidence"], impact_scope=payload["impact_scope"],
            )
            levels = level_map(rules)
            status = "awaiting_evidence" if level == rules["await_evidence_level"] else "open"
            checklist = self._fresh_checklist(rules["review_requirements"].get(level, []))
            event_id = repository.insert_event({
                "code": f"TMP-{_sha256(now + fingerprint)[:10]}",
                "title": payload["title"],
                "location_type": payload["location_type"],
                "location_name": payload.get("location_name", ""),
                "report_type": payload["report_type"],
                "description": payload.get("description", ""),
                "reporter": payload["reporter"],
                "confidence": payload["confidence"],
                "impact_scope": payload["impact_scope"],
                "level": level,
                "matched_rule": matched,
                "status": status,
                "rule_version": rules_row["version"],
                "rules_snapshot_json": json.dumps(rules, ensure_ascii=False, sort_keys=True),
                "rules_digest": rules_row["rules_digest"],
                "response_due_at": self._due(now, levels[level]["respond_minutes"]),
                "resolve_due_at": self._due(now, levels[level]["resolve_minutes"]),
                "evidence_due_at": self._due(now, rules["await_evidence_expire_minutes"]) if status == "awaiting_evidence" else None,
                "review_checklist_json": dumps(checklist),
                "created_at": now,
                "updated_at": now,
            })
            connection.execute("UPDATE incident_events SET code=? WHERE id=?", (f"INC-{event_id:06d}", event_id))
            repository.insert_report(
                event_id=event_id, reporter=payload["reporter"], confidence=payload["confidence"],
                impact_scope=payload["impact_scope"], report_type=payload["report_type"],
                description=payload.get("description", ""), evidence=payload.get("evidence", ""),
                fingerprint=fingerprint, is_followup=False, now=now,
            )
            self._log(
                repository, event_id, "create", payload["reporter"],
                {"level": level, "matched_rule": matched, "status": status, "rule_version": rules_row["version"],
                 "location_type": payload["location_type"], "report_type": payload["report_type"],
                 "confidence": payload["confidence"], "impact_scope": payload["impact_scope"]},
                now,
            )
            return self._detail(repository.event_by_id(event_id), repository)

    def add_evidence(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        """补证：低可信线索等待补证；补证可触发自动重分级且不阻塞其他事件。"""
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = repository.event_by_id(event_id)
            if event is None:
                raise NotFoundError("事件不存在")
            if event["status"] in {"closed", "rejected"}:
                raise ConflictError("已关闭事件不能再补充证据")
            fingerprint = self._fingerprint({"location_type": event["location_type"], "location_name": event["location_name"], "report_type": event["report_type"], "dedupe_key": payload.get("dedupe_key", f"evidence-{now}")})
            report_id = repository.insert_report(
                event_id=event_id, reporter=payload["actor"], confidence=payload["confidence"],
                impact_scope=payload.get("impact_scope", event["impact_scope"]),
                report_type=event["report_type"], description=payload.get("description", ""),
                evidence=payload.get("evidence", ""), fingerprint=fingerprint, is_followup=True, now=now,
            )
            detail = self._apply_cumulative_facts(repository, event, now, reason="evidence", extra={"report_id": report_id})
            detail["report_id"] = report_id
            return self._detail(repository.event_by_id(event_id), repository)

    def _attach_report(self, repository: IncidentRepository, event: sqlite3.Row, payload: dict[str, Any], fingerprint: str, rules: dict[str, Any], now: str, *, linked: bool) -> dict[str, Any]:
        """重复上报关联原事件，并按累计证据重新分级。"""
        report_id = repository.insert_report(
            event_id=event["id"], reporter=payload["reporter"], confidence=payload["confidence"],
            impact_scope=payload["impact_scope"], report_type=payload["report_type"],
            description=payload.get("description", ""), evidence=payload.get("evidence", ""),
            fingerprint=fingerprint, is_followup=False, now=now,
        )
        connection = repository.connection
        connection.execute("UPDATE incident_events SET report_count=report_count+1,updated_at=? WHERE id=?", (now, event["id"]))
        self._log(
            repository, event["id"], "duplicate_report", payload["reporter"],
            {"report_id": report_id, "fingerprint": fingerprint,
             "confidence": payload["confidence"], "impact_scope": payload["impact_scope"]},
            now,
        )
        self._apply_cumulative_facts(repository, repository.event_by_id(event["id"]), now, reason="duplicate_report", extra={"report_id": report_id})
        detail = self._detail(repository.event_by_id(event["id"]), repository)
        detail["linked_to_existing"] = linked
        return detail

    def _apply_cumulative_facts(self, repository: IncidentRepository, event: sqlite3.Row, now: str, *, reason: str, extra: dict[str, Any]) -> dict[str, Any]:
        """汇总全部上报的最高可信度/最大影响范围，按事件锁定的规则重新分级（只升不降）。"""
        reports = repository.reports(event["id"])
        confidence = self._max_confidence(reports)
        impact_scope = self._max_scope(reports)
        rules = json.loads(event["rules_snapshot_json"])
        new_level, matched = grade_incident(
            rules,
            location_type=event["location_type"], report_type=event["report_type"],
            confidence=confidence, impact_scope=impact_scope,
        )
        connection = repository.connection
        connection.execute("UPDATE incident_events SET confidence=?,impact_scope=? WHERE id=?", (confidence, impact_scope, event["id"]))
        detail: dict[str, Any] = {"reason": reason, "confidence": confidence, "impact_scope": impact_scope, **extra}
        if new_level != event["level"]:
            if level_rank(rules, new_level) > level_rank(rules, event["level"]):
                return detail  # 后续证据不会降低等级
            old_status = event["status"]
            if old_status == "awaiting_evidence":
                # 离开待补证：已接单直接进入处置中，已派单待接单则回到待接单
                new_status = "in_progress" if event["accepted_at"] else ("assigned" if event["current_assignee"] else "open")
            else:
                new_status = old_status
            levels = level_map(rules)
            checklist = self._merge_checklist(json.loads(event["review_checklist_json"]), rules["review_requirements"].get(new_level, []))
            connection.execute(
                "UPDATE incident_events SET level=?,matched_rule=?,status=?,review_checklist_json=?,updated_at=? WHERE id=?",
                (new_level, f"cumulative:{matched}", new_status, dumps(checklist), now, event["id"]),
            )
            self._log(
                repository, event["id"], "regrade", "system",
                {**detail, "from_level": event["level"], "to_level": new_level, "matched_rule": matched,
                 "from_status": old_status, "to_status": new_status},
                now,
            )
            detail.update({"from_level": event["level"], "to_level": new_level})
        return detail

    # ============ 处置流转 ============

    def assign(self, event_id: int, assignee: str, actor: str, note: str = "") -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = self._require_event(repository, event_id)
            if event["status"] in {"closed", "rejected", "reviewing", "resolved"}:
                raise ConflictError(f"当前状态 {event['status']} 不允许派单")
            connection.execute(
                "UPDATE incident_events SET current_assignee=?,assigned_at=?,accepted_at=NULL,status='assigned',updated_at=? WHERE id=?",
                (assignee, now, now, event_id),
            )
            self._set_checklist(repository, event_id, "assignee_accepted", False, None, None, now)
            self._log(repository, event_id, "assign", actor, {"assignee": assignee, "note": note}, now)
            return self._detail(repository.event_by_id(event_id), repository)

    def accept(self, event_id: int, actor: str) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = self._require_event(repository, event_id)
            if not event["current_assignee"]:
                raise ConflictError("事件尚未派单，无法接单")
            if actor != event["current_assignee"]:
                raise ConflictError("只有当前责任人可以接单")
            if event["status"] in {"closed", "rejected", "reviewing"}:
                raise ConflictError("当前状态不允许接单")
            connection.execute(
                "UPDATE incident_events SET accepted_at=COALESCE(accepted_at,?),status=CASE WHEN status='awaiting_evidence' THEN status ELSE 'in_progress' END,updated_at=? WHERE id=?",
                (now, now, event_id),
            )
            self._set_checklist(repository, event_id, "assignee_accepted", True, actor, now, now)
            self._log(repository, event_id, "accept", actor, {"accepted_at": now}, now)
            return self._detail(repository.event_by_id(event_id), repository)

    def transfer(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = self._require_event(repository, event_id)
            if event["status"] in {"closed", "rejected", "reviewing"}:
                raise ConflictError("当前状态不允许转交")
            if not payload.get("to_assignee") or payload["to_assignee"] == event["current_assignee"]:
                raise ValidationError("转交对象必须是另一名处置人")
            connection.execute(
                "UPDATE incident_events SET current_assignee=?,assigned_at=?,accepted_at=NULL,status='assigned',updated_at=? WHERE id=?",
                (payload["to_assignee"], now, now, event_id),
            )
            self._set_checklist(repository, event_id, "assignee_accepted", False, None, None, now)
            self._log(
                repository, event_id, "transfer", payload["actor"],
                {"from_assignee": event["current_assignee"], "to_assignee": payload["to_assignee"], "reason": payload.get("reason", "")},
                now,
            )
            return self._detail(repository.event_by_id(event_id), repository)

    def escalate(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = self._require_event(repository, event_id)
            self._escalate_locked(repository, event, payload["to_level"], payload["actor"], payload.get("reason", ""), trigger="manual", now=now)
            return self._detail(repository.event_by_id(event_id), repository)

    def _escalate_locked(self, repository: IncidentRepository, event: sqlite3.Row, to_level: str, actor: str, reason: str, *, trigger: str, now: str) -> None:
        """在已开启的事务内完成升级，升级后按新等级重计响应时限。"""
        event_id = event["id"]
        if event["status"] in {"closed", "rejected"}:
            raise ConflictError("已关闭事件不能升级")
        rules = json.loads(event["rules_snapshot_json"])
        levels = level_map(rules)
        if to_level not in levels:
            raise ValidationError("目标等级不在事件使用的规则版本中")
        if level_rank(rules, to_level) >= level_rank(rules, event["level"]):
            raise ConflictError("升级目标等级必须比当前等级更紧急")
        old_status = event["status"]
        new_status = "escalated" if old_status in {"open", "awaiting_evidence"} else old_status
        checklist = self._merge_checklist(json.loads(event["review_checklist_json"]), rules["review_requirements"].get(to_level, []))
        repository.connection.execute(
            "UPDATE incident_events SET level=?,matched_rule=?,status=?,review_checklist_json=?,response_due_at=?,updated_at=? WHERE id=?",
            (to_level, f"escalation:{trigger}", new_status, dumps(checklist), self._due(now, levels[to_level]["respond_minutes"]), now, event_id),
        )
        self._log(
            repository, event_id, "escalate", actor,
            {"from_level": event["level"], "to_level": to_level, "trigger": trigger,
             "reason": reason, "from_status": old_status, "to_status": new_status},
            now,
        )

    def resolve(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = self._require_event(repository, event_id)
            if event["status"] not in {"in_progress", "escalated", "assigned", "awaiting_evidence"}:
                raise ConflictError(f"当前状态 {event['status']} 不能提交现场结论")
            if event["current_assignee"] and not event["accepted_at"] and event["status"] != "awaiting_evidence":
                raise ConflictError("责任人尚未接单，不能提交现场结论")
            kind = payload.get("conclusion_kind", "confirmed")
            if kind not in {"confirmed", "false_positive", "monitoring"}:
                raise ValidationError("现场结论类型不合法")
            conclusion = f"[{kind}] {payload['conclusion']}".strip()
            connection.execute(
                "UPDATE incident_events SET field_conclusion=?,field_conclusion_by=?,field_conclusion_at=?,status='reviewing',updated_at=? WHERE id=?",
                (conclusion, payload["actor"], now, now, event_id),
            )
            self._set_checklist(repository, event_id, "field_conclusion", True, payload["actor"], now, now)
            self._log(repository, event_id, "field_conclusion", payload["actor"], {"kind": kind, "conclusion": payload["conclusion"]}, now)
            return self._detail(repository.event_by_id(event_id), repository)

    def grant_review_item(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        item = payload["item"]
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = self._require_event(repository, event_id)
            rules = json.loads(event["rules_snapshot_json"])
            required = rules["review_requirements"].get(event["level"], [])
            if item not in required:
                raise ValidationError(f"等级 {event['level']} 不要求复核项 {item}")
            if item not in REVIEW_GRANTABLE:
                raise ConflictError("该复核项由处置流程自动满足，不能手工授予")
            if event["status"] not in {"reviewing", "awaiting_evidence"}:
                raise ConflictError("只有待复核（或待补证）事件可以登记复核意见")
            if payload["actor"] == event["current_assignee"]:
                raise ConflictError("复核必须由责任人之外的独立复核人完成")
            checklist = json.loads(event["review_checklist_json"])
            if item == "second_reviewer":
                follow_up = checklist.get("follow_up_check") or {}
                if follow_up.get("by") == payload["actor"]:
                    raise ConflictError("二级复核人与跟踪复核人不能是同一人")
            self._set_checklist(repository, event_id, item, True, payload["actor"], now, now)
            self._log(repository, event_id, "review", payload["actor"], {"item": item, "note": payload.get("note", "")}, now)
            return self._detail(repository.event_by_id(event_id), repository)

    def close(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = self._require_event(repository, event_id)
            if event["status"] == "closed":
                raise ConflictError("事件已经关闭")
            if event["status"] == "rejected":
                raise ConflictError("事件已驳回")
            rules = json.loads(event["rules_snapshot_json"])
            required = rules["review_requirements"].get(event["level"], [])
            checklist = json.loads(event["review_checklist_json"])
            missing = [item for item in required if not checklist.get(item, {}).get("done")]
            if missing:
                raise ConflictError("复核条件尚未全部满足，不能关闭事件", context={"missing": missing})
            if event["status"] != "reviewing" and not (event["level"] == rules["await_evidence_level"] and event["status"] == "awaiting_evidence"):
                raise ConflictError("须先提交现场结论并完成复核才能关闭")
            if not payload.get("reason"):
                raise ValidationError("关闭事件必须说明关闭原因")
            connection.execute(
                "UPDATE incident_events SET status='closed',close_reason=?,closed_at=?,updated_at=? WHERE id=?",
                (payload["reason"], now, now, event_id),
            )
            self._log(repository, event_id, "close", payload["actor"], {"reason": payload["reason"]}, now)
            return self._detail(repository.event_by_id(event_id), repository)

    def reject(self, event_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        """待补证线索经核查证伪或无下文时驳回，不进入处置流程。"""
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            event = self._require_event(repository, event_id)
            if event["status"] not in {"awaiting_evidence", "open"}:
                raise ConflictError("只有待补证或尚未派单的线索可以驳回")
            connection.execute(
                "UPDATE incident_events SET status='rejected',close_reason=?,closed_at=?,updated_at=? WHERE id=?",
                (payload["reason"], now, now, event_id),
            )
            self._log(repository, event_id, "reject", payload["actor"], {"reason": payload["reason"]}, now)
            return self._detail(repository.event_by_id(event_id), repository)

    def process_overdue(self, actor: str = "system") -> dict[str, Any]:
        """扫描响应超时：按事件各自的规则版本触发升级或通知，只触发一次。"""
        now_value = self.clock.now()
        now = to_storage(now_value)
        escalated: list[int] = []
        notified: list[int] = []
        with transaction(immediate=True) as connection:
            repository = IncidentRepository(connection)
            rows = connection.execute(
                "SELECT * FROM incident_events WHERE status NOT IN ('closed','rejected','reviewing') AND accepted_at IS NULL AND response_due_at<>'' AND response_due_at<?",
                (now,),
            ).fetchall()
            for event in rows:
                rules = json.loads(event["rules_snapshot_json"])
                policy = next((item for item in rules.get("escalation", []) if item["level"] == event["level"] and item["trigger"] == "respond_overdue"), None)
                if policy is None or self._overdue_fired(repository, event["id"], event["level"]):
                    continue
                if "to_level" in policy:
                    self._escalate_locked(repository, event, policy["to_level"], actor, "响应时限超时自动升级", trigger="respond_overdue", now=now)
                    escalated.append(event["id"])
                else:
                    self._log(repository, event["id"], "notify", actor, {"trigger": "respond_overdue", "level": event["level"], "notify": policy.get("notify", [])}, now)
                    notified.append(event["id"])
        return {"now": now, "escalated": escalated, "notified": notified}

    # ============ 查询 ============

    def list_events(self, *, status: str | None = None, level: str | None = None, assignee: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        repository = IncidentRepository(self.connection)
        return [self._detail(row, repository) for row in repository.list_events(status=status, level=level, assignee=assignee, limit=max(1, min(limit, 500)))]

    def get_event(self, event_id: int) -> dict[str, Any]:
        repository = IncidentRepository(self.connection)
        event = repository.event_by_id(event_id)
        if event is None:
            raise NotFoundError("事件不存在")
        return self._detail(event, repository)

    def get_reports(self, event_id: int) -> dict[str, Any]:
        repository = IncidentRepository(self.connection)
        if repository.event_by_id(event_id) is None:
            raise NotFoundError("事件不存在")
        return {"items": repository.reports(event_id)}

    def timeline(self, event_id: int) -> dict[str, Any]:
        repository = IncidentRepository(self.connection)
        event = repository.event_by_id(event_id)
        if event is None:
            raise NotFoundError("事件不存在")
        entries = repository.log_entries(event_id)
        verification = self.verify_chain(event_id)
        return {"event_code": event["code"], "chain_length": len(entries), "entries": entries, "verification": verification}

    def verify_chain(self, event_id: int) -> dict[str, Any]:
        """逐条重算哈希，检测变更脉络是否被篡改。"""
        repository = IncidentRepository(self.connection)
        event = repository.event_by_id(event_id)
        if event is None:
            raise NotFoundError("事件不存在")
        entries = repository.log_entries(event_id)
        previous = ""
        for entry in entries:
            if entry["prev_hash"] != previous:
                return {"valid": False, "reason": "prev_hash_mismatch", "broken_at_seq": entry["seq"], "head": event["chain_head"]}
            expected = self._entry_hash(entry["seq"], entry["action"], entry["actor"], json.loads(entry["detail_json"]), previous, entry["created_at"])
            if expected != entry["entry_hash"]:
                return {"valid": False, "reason": "entry_hash_mismatch", "broken_at_seq": entry["seq"], "head": event["chain_head"]}
            previous = entry["entry_hash"]
        if entries and event["chain_head"] != entries[-1]["entry_hash"]:
            return {"valid": False, "reason": "chain_head_mismatch", "broken_at_seq": entries[-1]["seq"], "head": event["chain_head"]}
        if event["chain_length"] != len(entries):
            return {"valid": False, "reason": "chain_length_mismatch", "broken_at_seq": None, "head": event["chain_head"]}
        return {"valid": True, "reason": "ok", "broken_at_seq": None, "head": event["chain_head"], "length": len(entries)}

    # ============ 内部工具 ============

    def _detail(self, event: sqlite3.Row, repository: IncidentRepository) -> dict[str, Any]:
        result = dict(event)
        result["reports"] = repository.reports(event["id"])
        result["review_checklist"] = json.loads(event["review_checklist_json"])
        rules = json.loads(event["rules_snapshot_json"])
        level_info = level_map(rules).get(event["level"], {})
        result["level_name"] = level_info.get("name", "")
        result["respond_minutes"] = level_info.get("respond_minutes")
        result["resolve_minutes"] = level_info.get("resolve_minutes")
        result["required_review_items"] = rules["review_requirements"].get(event["level"], [])
        now = self.clock.now()
        result["now"] = to_storage(now)
        result["responded"] = event["accepted_at"] is not None
        result["respond_overdue"] = event["accepted_at"] is None and bool(event["response_due_at"]) and event["response_due_at"] < result["now"]
        result["resolve_overdue"] = event["status"] not in {"closed", "rejected"} and bool(event["resolve_due_at"]) and event["resolve_due_at"] < result["now"]
        result["awaiting_evidence_expired"] = event["status"] == "awaiting_evidence" and bool(event["evidence_due_at"]) and event["evidence_due_at"] < result["now"]
        result["verification"] = self.verify_chain(event["id"])
        return result

    def _require_event(self, repository: IncidentRepository, event_id: int) -> sqlite3.Row:
        event = repository.event_by_id(event_id)
        if event is None:
            raise NotFoundError("事件不存在")
        return event

    def _overdue_fired(self, repository: IncidentRepository, event_id: int, level: str) -> bool:
        rows = repository.connection.execute(
            "SELECT detail_json FROM incident_event_log WHERE event_id=? AND action IN ('escalate','notify')",
            (event_id,),
        ).fetchall()
        for row in rows:
            detail = json.loads(row["detail_json"])
            if detail.get("trigger") == "respond_overdue" and (detail.get("from_level") == level or detail.get("level") == level):
                return True
        return False

    @staticmethod
    def _fingerprint(payload: dict[str, Any]) -> str:
        basis = {
            "location_type": payload["location_type"],
            "location_name": str(payload.get("location_name", "")).strip(),
            "report_type": payload["report_type"],
            "dedupe_key": str(payload.get("dedupe_key", "")).strip(),
        }
        return _sha256(dumps(basis))

    @staticmethod
    def _max_confidence(reports: list[dict[str, Any]]) -> str:
        return max((item["confidence"] for item in reports), key=lambda value: CONFIDENCE_ORDER[value])

    @staticmethod
    def _max_scope(reports: list[dict[str, Any]]) -> str:
        return max((item["impact_scope"] for item in reports), key=lambda value: SCOPE_ORDER[value])

    @staticmethod
    def _fresh_checklist(required: list[str]) -> dict[str, dict[str, Any]]:
        return {item: {"done": False, "by": None, "at": None} for item in required}

    @staticmethod
    def _merge_checklist(previous: dict[str, Any], required: list[str]) -> dict[str, dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for item in required:
            state = previous.get(item) or {"done": False, "by": None, "at": None}
            merged[item] = {"done": bool(state.get("done")), "by": state.get("by"), "at": state.get("at")}
        return merged

    def _set_checklist(self, repository: IncidentRepository, event_id: int, item: str, done: bool, by: str | None, at: str | None, now: str) -> None:
        event = repository.event_by_id(event_id)
        checklist = json.loads(event["review_checklist_json"])
        checklist[item] = {"done": done, "by": by, "at": at}
        repository.connection.execute(
            "UPDATE incident_events SET review_checklist_json=?,updated_at=? WHERE id=?",
            (dumps(checklist), now, event_id),
        )

    def _due(self, start_iso: str, minutes: int) -> str:
        from app.core.clock import from_storage
        start = from_storage(start_iso) or self.clock.now()
        return to_storage(start + timedelta(minutes=minutes))

    @staticmethod
    def _entry_hash(seq: int, action: str, actor: str, detail: dict[str, Any], prev_hash: str, created_at: str) -> str:
        payload = dumps({"seq": seq, "action": action, "actor": actor, "detail": detail, "prev_hash": prev_hash, "created_at": created_at})
        return _sha256(payload)

    def _log(self, repository: IncidentRepository, event_id: int, action: str, actor: str, detail: dict[str, Any], now: str) -> None:
        event = repository.event_by_id(event_id)
        seq = int(event["chain_length"]) + 1
        prev_hash = event["chain_head"]
        entry_hash = self._entry_hash(seq, action, actor, detail, prev_hash, now)
        repository.append_log(event_id=event_id, seq=seq, action=action, actor=actor, detail=detail, prev_hash=prev_hash, entry_hash=entry_hash, now=now)
