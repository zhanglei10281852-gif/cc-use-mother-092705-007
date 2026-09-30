"""异常响应服务：分级事件、处置分派、升级转交、现场结论与关闭复核。

设计要点：
- 事件创建时绑定规则版本并保存分级快照，历史事件永远按旧规则解释；
- 重复上报通过指纹或显式关联并入原事件，强证据触发自动/交叉升级；
- 低可信线索进入待补证、不进入派单队列，补证后才激活；
- 变更脉络为每事件一条哈希链，且数据库触发器禁止改写或删除。
"""
from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from datetime import timedelta
from typing import Any

from app.anomaly.rules import (
    CONFIDENCE_RANK,
    IMPACT_RANK,
    LEVEL_RANK,
    RULES_V1,
    grade,
    validate_rules,
)
from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.database import get_connection, transaction

GENESIS_HASH = "0" * 64
ACTIVE_STATUSES = ("awaiting_evidence", "open", "in_progress")
ABSORBING_STATUSES = ("awaiting_evidence", "open", "in_progress")

SCHEMA = """
CREATE TABLE IF NOT EXISTS anomaly_rule_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','retired')),
    rules_json TEXT NOT NULL,
    rules_digest TEXT NOT NULL,
    published_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    activated_at TEXT
);
CREATE TABLE IF NOT EXISTS anomaly_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_no TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    anomaly_kind TEXT NOT NULL,
    site_type TEXT NOT NULL,
    location_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('awaiting_evidence','open','in_progress','resolved','closed','rejected')),
    level TEXT NOT NULL CHECK(level IN ('L1','L2','L3')),
    current_confidence TEXT NOT NULL,
    current_impact_scope TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    grading_snapshot_json TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    reporter TEXT NOT NULL,
    current_assignee TEXT NOT NULL DEFAULT '',
    current_assignee_role TEXT NOT NULL DEFAULT '',
    response_deadline_minutes INTEGER,
    response_deadline_at TEXT,
    first_responded_at TEXT,
    field_conclusion_json TEXT NOT NULL DEFAULT '',
    close_review_json TEXT NOT NULL DEFAULT '',
    duplicate_of_id INTEGER REFERENCES anomaly_incidents(id),
    closed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_anomaly_incidents_status ON anomaly_incidents(status, level, created_at);
CREATE INDEX IF NOT EXISTS idx_anomaly_incidents_fingerprint ON anomaly_incidents(fingerprint, status);
CREATE TABLE IF NOT EXISTS anomaly_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES anomaly_incidents(id) ON DELETE RESTRICT,
    reporter TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    evidence_ref TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL,
    impact_scope TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    relation TEXT NOT NULL DEFAULT 'direct' CHECK(relation IN ('direct','cross')),
    digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(incident_id, digest)
);
CREATE INDEX IF NOT EXISTS idx_anomaly_evidence_incident ON anomaly_evidence(incident_id, id);
CREATE TABLE IF NOT EXISTS anomaly_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES anomaly_incidents(id) ON DELETE RESTRICT,
    review_kind TEXT NOT NULL CHECK(review_kind IN ('recheck','senior_review')),
    reviewer TEXT NOT NULL,
    passed INTEGER NOT NULL CHECK(passed IN (0,1)),
    opinion TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_anomaly_reviews_incident ON anomaly_reviews(incident_id, id);
CREATE TABLE IF NOT EXISTS anomaly_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES anomaly_incidents(id) ON DELETE RESTRICT,
    seq INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(incident_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_anomaly_timeline_incident ON anomaly_timeline(incident_id, seq);
CREATE TRIGGER IF NOT EXISTS anomaly_timeline_no_update
BEFORE UPDATE ON anomaly_timeline
BEGIN
    SELECT RAISE(ABORT, 'anomaly_timeline 为只追加记录，禁止修改');
END;
CREATE TRIGGER IF NOT EXISTS anomaly_timeline_no_delete
BEFORE DELETE ON anomaly_timeline
BEGIN
    SELECT RAISE(ABORT, 'anomaly_timeline 为只追加记录，禁止删除');
END;
"""


def digest(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def ensure_schema() -> None:
    connection = get_connection()
    connection.executescript(SCHEMA)
    now = to_storage(SystemClock().now())
    seeded = connection.execute("SELECT 1 FROM anomaly_rule_versions WHERE version='v1'").fetchone()
    if seeded is None:
        connection.execute(
            "INSERT INTO anomaly_rule_versions(version,status,rules_json,rules_digest,published_by,created_at,activated_at) VALUES(?,?,?,?,?,?,?)",
            ("v1", "active", json.dumps(RULES_V1, ensure_ascii=False), digest(RULES_V1), "system", now, now),
        )


class AnomalyResponseService:
    """异常上报、分级、处置与复核的事务服务。"""

    def __init__(self, connection: sqlite3.Connection | None = None, clock: Clock | None = None) -> None:
        self.connection = connection or get_connection()
        self.clock = clock or SystemClock()
        ensure_schema()

    # ------------------------------------------------------------------ 规则版本

    def publish_rule_version(self, payload: dict[str, Any], actor: str) -> dict[str, Any]:
        version = payload["version"]
        rules = payload.get("rules")
        if rules is None:
            active = self._active_rule_row()
            rules = copy.deepcopy(json.loads(active["rules_json"])) if active else copy.deepcopy(RULES_V1)
        validate_rules(rules)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            existing = connection.execute("SELECT 1 FROM anomaly_rule_versions WHERE version=?", (version,)).fetchone()
            if existing:
                raise ConflictError(f"规则版本 {version} 已存在")
            connection.execute("UPDATE anomaly_rule_versions SET status='retired' WHERE status='active'")
            connection.execute(
                "INSERT INTO anomaly_rule_versions(version,status,rules_json,rules_digest,published_by,created_at,activated_at) VALUES(?,?,?,?,?,?,?)",
                (version, "active", json.dumps(rules, ensure_ascii=False), digest(rules), actor, now, now),
            )
            return self._rule_version(connection, version)

    def list_rule_versions(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT id,version,status,rules_digest,published_by,created_at,activated_at FROM anomaly_rule_versions ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_rule_version(self, version: str, *, include_rules: bool = True) -> dict[str, Any]:
        row = self._rule_version(self.connection, version)
        if row is None:
            raise NotFoundError(f"规则版本 {version} 不存在")
        return row

    def _active_rule_row(self) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM anomaly_rule_versions WHERE status='active' ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def _rule_version(self, connection: sqlite3.Connection, version: str) -> dict[str, Any] | None:
        row = connection.execute("SELECT * FROM anomaly_rule_versions WHERE version=?", (version,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["rules"] = json.loads(result.pop("rules_json"))
        return result

    def _rules_for(self, connection: sqlite3.Connection, version: str) -> dict[str, Any]:
        row = connection.execute("SELECT rules_json FROM anomaly_rule_versions WHERE version=?", (version,)).fetchone()
        if row is None:
            raise ConflictError(f"规则版本 {version} 不存在，事件无法解释")
        return json.loads(row["rules_json"])

    # ------------------------------------------------------------------ 上报入口

    def report(self, payload: dict[str, Any]) -> dict[str, Any]:
        now_value = self.clock.now()
        now = to_storage(now_value)
        fingerprint = payload.get("fingerprint") or digest([
            payload["anomaly_kind"], payload["site_type"], payload["location_name"].strip(),
        ])
        evidence_digest = digest({
            "reporter": payload["reporter"], "evidence_type": payload["evidence_type"],
            "evidence_ref": payload["evidence_ref"], "confidence": payload["confidence"],
            "impact_scope": payload["impact_scope"], "summary": payload["summary"],
        })
        cross_ids = [int(value) for value in payload.get("cross_incident_ids") or []]

        with transaction(immediate=True) as connection:
            original = self._find_original(connection, payload.get("related_incident_id"), fingerprint)
            if original is None:
                incident = self._create_incident(connection, payload, fingerprint, now_value, now)
                incident_id = incident["id"]
                self._insert_evidence(connection, incident_id, payload, "direct", evidence_digest, now)
                mode = "created"
                linked_ids: list[int] = []
            else:
                incident_id = original["id"]
                if payload.get("related_incident_id") and original["id"] != payload["related_incident_id"]:
                    raise ConflictError("显式关联的事件已关闭，不能并入；如属新异常请取消关联后上报")
                inserted = self._insert_evidence(connection, incident_id, payload, "direct", evidence_digest, now)
                incident = dict(connection.execute("SELECT * FROM anomaly_incidents WHERE id=?", (incident_id,)).fetchone())
                if inserted:
                    self._merge_evidence(
                        connection, incident, payload["confidence"], payload["impact_scope"],
                        evidence_digest, payload["reporter"], payload["summary"], now_value, now,
                        trigger="duplicate_report",
                    )
                mode = "duplicate" if inserted else "duplicate_replayed"
                linked_ids: list[int] = []

            # 交叉上报：把证据并入相关事件，满足条件时交叉升级。
            for cross_id in cross_ids:
                if cross_id == incident_id:
                    continue
                cross = connection.execute("SELECT * FROM anomaly_incidents WHERE id=?", (cross_id,)).fetchone()
                if cross is None:
                    raise NotFoundError(f"交叉关联事件 {cross_id} 不存在")
                if cross["status"] not in ABSORBING_STATUSES:
                    raise ConflictError(f"事件 {cross_id} 已结案，不能接受交叉证据")
                if self._insert_evidence(connection, cross_id, payload, "cross", evidence_digest, now):
                    self._merge_evidence(
                        connection, dict(cross), payload["confidence"], payload["impact_scope"],
                        evidence_digest, payload["reporter"], payload["summary"], now_value, now,
                        trigger="cross_report", source_incident_id=incident_id,
                    )
                    linked_ids.append(cross_id)

            result = self.get_incident(incident_id)
            result["intake"] = {"mode": mode, "fingerprint": fingerprint, "cross_linked": linked_ids}
            return result

    def _find_original(
        self, connection: sqlite3.Connection, related_id: int | None, fingerprint: str
    ) -> sqlite3.Row | None:
        if related_id is not None:
            row = connection.execute("SELECT * FROM anomaly_incidents WHERE id=?", (related_id,)).fetchone()
            if row is None:
                raise NotFoundError("关联的原事件不存在")
            if row["status"] not in ABSORBING_STATUSES:
                raise ConflictError("原事件已结案，重复上报应作为新事件受理")
            return row
        placeholders = ",".join("?" for _ in ABSORBING_STATUSES)
        return connection.execute(
            f"SELECT * FROM anomaly_incidents WHERE fingerprint=? AND status IN ({placeholders}) ORDER BY id LIMIT 1",
            (fingerprint, *ABSORBING_STATUSES),
        ).fetchone()

    def _create_incident(
        self, connection: sqlite3.Connection, payload: dict[str, Any], fingerprint: str,
        now_value: Any, now: str,
    ) -> dict[str, Any]:
        active = connection.execute("SELECT version FROM anomaly_rule_versions WHERE status='active' ORDER BY id DESC LIMIT 1").fetchone()
        if active is None:
            raise ConflictError("没有生效中的规则版本，无法分级")
        rule_version = active["version"]
        rules = self._rules_for(connection, rule_version)
        snapshot = grade(
            rules, anomaly_kind=payload["anomaly_kind"], site_type=payload["site_type"],
            confidence=payload["confidence"], impact_scope=payload["impact_scope"],
        )
        title = f"{payload['location_name'] or '未命名地点'}·{payload['anomaly_kind']}"
        day = now_value.strftime("%Y%m%d")
        seq = connection.execute("SELECT COUNT(*) FROM anomaly_incidents WHERE created_at LIKE ?", (f"{now_value.strftime('%Y-%m-%d')}%",)).fetchone()[0] + 1
        incident_no = f"INC-{day}-{seq:04d}"
        if snapshot["awaiting_evidence"]:
            status, assignee, role, deadline_at, deadline_minutes = "awaiting_evidence", "", "", None, None
        else:
            status = "open"
            assignee = snapshot["default_assignee"]["assignee"]
            role = snapshot["default_assignee"]["assignee_role"]
            deadline_minutes = snapshot["response_deadline_minutes"]
            deadline_at = to_storage(now_value + timedelta(minutes=deadline_minutes))
        cursor = connection.execute(
            """INSERT INTO anomaly_incidents(incident_no,title,anomaly_kind,site_type,location_name,status,level,
               current_confidence,current_impact_scope,rule_version,grading_snapshot_json,fingerprint,reporter,
               current_assignee,current_assignee_role,response_deadline_minutes,response_deadline_at,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (incident_no, title, payload["anomaly_kind"], payload["site_type"], payload["location_name"].strip(),
             status, snapshot["level"], payload["confidence"], payload["impact_scope"], rule_version,
             json.dumps(snapshot, ensure_ascii=False), fingerprint, payload["reporter"], assignee, role,
             deadline_minutes, deadline_at, now, now),
        )
        incident_id = cursor.lastrowid
        self._append_timeline(
            connection, incident_id, "create", payload["reporter"],
            {"incident_no": incident_no, "rule_version": rule_version, "grading": snapshot}, now,
        )
        if status == "awaiting_evidence":
            self._append_timeline(
                connection, incident_id, "evidence.awaiting", payload["reporter"],
                {"reason": "低可信线索等待补证，暂不派单、不计算处置时限"}, now,
            )
        else:
            self._append_timeline(
                connection, incident_id, "assign.auto", "system",
                {"assignee": assignee, "assignee_role": role,
                 "response_deadline_minutes": deadline_minutes, "response_deadline_at": deadline_at}, now,
            )
        return dict(connection.execute("SELECT * FROM anomaly_incidents WHERE id=?", (incident_id,)).fetchone())

    def _insert_evidence(
        self, connection: sqlite3.Connection, incident_id: int, payload: dict[str, Any],
        relation: str, evidence_digest: str, now: str,
    ) -> bool:
        try:
            connection.execute(
                """INSERT INTO anomaly_evidence(incident_id,reporter,evidence_type,evidence_ref,confidence,
                   impact_scope,summary,relation,digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (incident_id, payload["reporter"], payload["evidence_type"], payload["evidence_ref"],
                 payload["confidence"], payload["impact_scope"], payload["summary"], relation, evidence_digest, now),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def _merge_evidence(
        self, connection: sqlite3.Connection, incident: dict[str, Any], confidence: str, impact_scope: str,
        evidence_digest: str, reporter: str, summary: str, now_value: Any, now: str, *,
        trigger: str, source_incident_id: int | None = None,
    ) -> None:
        merged_confidence = confidence if CONFIDENCE_RANK[confidence] >= CONFIDENCE_RANK[incident["current_confidence"]] else incident["current_confidence"]
        merged_scope = impact_scope if IMPACT_RANK[impact_scope] >= IMPACT_RANK[incident["current_impact_scope"]] else incident["current_impact_scope"]
        rules = self._rules_for(connection, incident["rule_version"])
        snapshot = grade(
            rules, anomaly_kind=incident["anomaly_kind"], site_type=incident["site_type"],
            confidence=merged_confidence, impact_scope=merged_scope,
        )
        detail = {
            "trigger": trigger, "source_incident_id": source_incident_id,
            "from_confidence": incident["current_confidence"], "to_confidence": merged_confidence,
            "from_impact_scope": incident["current_impact_scope"], "to_impact_scope": merged_scope,
            "from_level": incident["level"], "to_level": snapshot["level"],
            "grading_reasons": snapshot["reasons"], "evidence_digest": evidence_digest[:12],
        }
        action = "evidence.linked" if trigger == "duplicate_report" else "evidence.cross.linked"
        self._append_timeline(connection, incident["id"], action, reporter, detail, now)

        activated = False
        if incident["status"] == "awaiting_evidence" and not snapshot["awaiting_evidence"]:
            activated = True

        sets = ["current_confidence=?", "current_impact_scope=?", "level=?",
                "grading_snapshot_json=?", "updated_at=?"]
        params: list[Any] = [merged_confidence, merged_scope, snapshot["level"],
                             json.dumps(snapshot, ensure_ascii=False), now]
        if activated:
            assignee = snapshot["default_assignee"]["assignee"]
            role = snapshot["default_assignee"]["assignee_role"]
            deadline_at = to_storage(now_value + timedelta(minutes=snapshot["response_deadline_minutes"]))
            sets.extend(["status='open'", "current_assignee=?", "current_assignee_role=?",
                         "response_deadline_minutes=?", "response_deadline_at=?"])
            params.extend([assignee, role, snapshot["response_deadline_minutes"], deadline_at])
        elif snapshot["level"] != incident["level"] and LEVEL_RANK[snapshot["level"]] > LEVEL_RANK[incident["level"]]:
            # 升级收紧响应时限：尚未首次响应时按新级别重排截止时间。
            if incident["first_responded_at"] is None:
                deadline_at = to_storage(now_value + timedelta(minutes=snapshot["response_deadline_minutes"]))
                sets.extend(["response_deadline_minutes=?", "response_deadline_at=?"])
                params.extend([snapshot["response_deadline_minutes"], deadline_at])
            # 尚未人工接管（无派单/转交/签收记录）时改派到新级别默认值班人；
            # 一旦人工接管则保持处置连续性，由主管显式转交。
            if not self._was_human_taken(connection, incident["id"]):
                sets.extend(["current_assignee=?", "current_assignee_role=?"])
                params.extend([snapshot["default_assignee"]["assignee"], snapshot["default_assignee"]["assignee_role"]])
                detail["reassigned_to"] = snapshot["default_assignee"]["assignee"]
        connection.execute(f"UPDATE anomaly_incidents SET {', '.join(sets)} WHERE id=?", (*params, incident["id"]))

        if activated:
            self._append_timeline(
                connection, incident["id"], "activate", reporter,
                {"reason": "补充证据满足立即响应条件", "level": snapshot["level"],
                 "assignee": snapshot["default_assignee"]["assignee"],
                 "response_deadline_minutes": snapshot["response_deadline_minutes"]}, now,
            )
        if detail.get("reassigned_to"):
            self._append_timeline(
                connection, incident["id"], "assign.auto", "system",
                {"assignee": detail["reassigned_to"],
                 "assignee_role": snapshot["default_assignee"]["assignee_role"], "reason": "自动升级改派"}, now,
            )
        if snapshot["level"] != incident["level"] and LEVEL_RANK[snapshot["level"]] > LEVEL_RANK[incident["level"]]:
            self._append_timeline(
                connection, incident["id"],
                "escalation.auto" if trigger == "duplicate_report" else "escalation.cross",
                reporter, {"from_level": incident["level"], "to_level": snapshot["level"],
                           "trigger": trigger, "source_incident_id": source_incident_id}, now,
            )

    # ------------------------------------------------------------------ 处置动作

    def assign(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            incident = self._require_active(connection, incident_id)
            if incident["status"] == "awaiting_evidence":
                raise ConflictError("事件仍在等待补证，暂不能派单")
            self._set_assignee(connection, incident, payload["assignee"], payload["assignee_role"], payload["actor"], "assign", payload.get("reason", ""), now)
            return self.get_incident(incident_id)

    def transfer(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            incident = self._require_active(connection, incident_id)
            if incident["status"] not in ("open", "in_progress"):
                raise ConflictError("仅处置中的事件可以转交")
            if payload["to_assignee"] == incident["current_assignee"]:
                raise ConflictError("转交对象与当前责任人相同")
            self._set_assignee(connection, incident, payload["to_assignee"], payload["to_assignee_role"], payload["actor"], "transfer", payload.get("reason", ""), now)
            return self.get_incident(incident_id)

    def _set_assignee(self, connection, incident, assignee, role, actor, action, reason, now) -> None:
        connection.execute(
            "UPDATE anomaly_incidents SET current_assignee=?, current_assignee_role=?, updated_at=? WHERE id=?",
            (assignee, role, now, incident["id"]),
        )
        self._append_timeline(connection, incident["id"], action, actor, {
            "from_assignee": incident["current_assignee"], "to_assignee": assignee,
            "assignee_role": role, "reason": reason,
        }, now)

    def acknowledge(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            incident = self._require_active(connection, incident_id)
            if incident["status"] != "open":
                raise ConflictError("仅待响应事件可以签收响应")
            connection.execute(
                "UPDATE anomaly_incidents SET status='in_progress', first_responded_at=COALESCE(first_responded_at,?), updated_at=? WHERE id=?",
                (now, now, incident_id),
            )
            self._append_timeline(connection, incident_id, "respond", payload["actor"],
                                  {"note": payload.get("note", ""), "responded_at": now}, now)
            return self.get_incident(incident_id)

    def conclude(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            incident = self._require_active(connection, incident_id)
            if incident["status"] not in ("open", "in_progress"):
                raise ConflictError("仅处置中的事件可以提交现场结论")
            conclusion = {
                "conclusion": payload["conclusion"], "measures": payload.get("measures", ""),
                "outcome": payload["outcome"], "concluded_by": payload["actor"], "concluded_at": now,
            }
            connection.execute(
                "UPDATE anomaly_incidents SET status='resolved', field_conclusion_json=?, updated_at=? WHERE id=?",
                (json.dumps(conclusion, ensure_ascii=False), now, incident_id),
            )
            self._append_timeline(connection, incident_id, "conclude", payload["actor"], conclusion, now)
            requirements = json.loads(incident["grading_snapshot_json"])["review_requirements"]
            self._append_timeline(connection, incident_id, "review.pending", "system",
                                  {"review_requirements": requirements}, now)
            return self.get_incident(incident_id)

    def recheck(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self._register_review(incident_id, payload, "recheck")

    def senior_review(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self._register_review(incident_id, payload, "senior_review")

    def _register_review(self, incident_id: int, payload: dict[str, Any], kind: str) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            incident = self._require_incident(connection, incident_id)
            snapshot = json.loads(incident["grading_snapshot_json"])
            if kind == "senior_review" and not snapshot["review_requirements"]["senior_review_required"]:
                raise ConflictError(f"{incident['level']} 事件不要求高级签批")
            if kind == "recheck" and not snapshot["review_requirements"]["recheck_required"]:
                raise ConflictError(f"{incident['level']} 事件不要求现场复核")
            if incident["status"] != "resolved":
                raise ConflictError("只有待结案复核的事件可以登记复核意见")
            connection.execute(
                "INSERT INTO anomaly_reviews(incident_id,review_kind,reviewer,passed,opinion,created_at) VALUES(?,?,?,?,?,?)",
                (incident_id, kind, payload["reviewer"], 1 if payload["passed"] else 0, payload.get("opinion", ""), now),
            )
            if payload["passed"]:
                self._append_timeline(connection, incident_id, f"{kind}.passed", payload["reviewer"],
                                      {"opinion": payload.get("opinion", "")}, now)
            else:
                connection.execute(
                    "UPDATE anomaly_incidents SET status='in_progress', updated_at=? WHERE id=?", (now, incident_id)
                )
                self._append_timeline(connection, incident_id, f"{kind}.rejected", payload["reviewer"],
                                      {"opinion": payload.get("opinion", ""), "action": "退回重新处置"}, now)
            return self.get_incident(incident_id)

    def close(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            incident = self._require_incident(connection, incident_id)
            if incident["status"] != "resolved":
                raise ConflictError("仅复核通过、待关闭的事件可以关闭")
            requirements = json.loads(incident["grading_snapshot_json"])["review_requirements"]
            if requirements["field_conclusion_required"] and not incident["field_conclusion_json"]:
                raise ConflictError("关闭前必须提交现场结论")
            passed_recheck = connection.execute(
                "SELECT * FROM anomaly_reviews WHERE incident_id=? AND review_kind='recheck' AND passed=1 ORDER BY id DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            passed_senior = connection.execute(
                "SELECT * FROM anomaly_reviews WHERE incident_id=? AND review_kind='senior_review' AND passed=1 ORDER BY id DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            if requirements["recheck_required"] and passed_recheck is None:
                raise ConflictError("关闭前必须有通过的现场复核")
            if requirements["senior_review_required"] and passed_senior is None:
                raise ConflictError("关闭前必须有高级签批通过")
            if requirements.get("rechecker_must_differ_from_reporter") and passed_recheck is not None:
                if passed_recheck["reviewer"] == incident["reporter"]:
                    raise ConflictError("现场复核人不能是上报人本人")
            review = {
                "closed_by": payload["actor"], "closed_at": now,
                "rechecker": passed_recheck["reviewer"] if passed_recheck else None,
                "senior_reviewer": passed_senior["reviewer"] if passed_senior else None,
                "requirements": requirements,
            }
            connection.execute(
                "UPDATE anomaly_incidents SET status='closed', close_review_json=?, closed_at=?, updated_at=? WHERE id=?",
                (json.dumps(review, ensure_ascii=False), now, now, incident_id),
            )
            self._append_timeline(connection, incident_id, "close", payload["actor"], review, now)
            return self.get_incident(incident_id)

    def reject_pending(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            incident = self._require_incident(connection, incident_id)
            if incident["status"] != "awaiting_evidence":
                raise ConflictError("仅待补证线索可以按不成立驳回")
            connection.execute("UPDATE anomaly_incidents SET status='rejected', updated_at=? WHERE id=?", (now, incident_id))
            self._append_timeline(connection, incident_id, "reject", payload["reviewer"],
                                  {"reason": payload["reason"]}, now)
            return self.get_incident(incident_id)

    def manual_escalate(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        """人工升级：显式给出合并后的可信度/影响范围，按事件绑定版本重新分级。"""
        now_value = self.clock.now()
        now = to_storage(now_value)
        with transaction(immediate=True) as connection:
            incident = self._require_incident(connection, incident_id)
            if incident["status"] not in ("open", "in_progress"):
                raise ConflictError("仅处置中的事件可以人工升级")
            target = payload["target_level"]
            if LEVEL_RANK[target] <= LEVEL_RANK[incident["level"]]:
                raise ConflictError("升级目标级别必须高于当前级别")
            # 以目标级别为准，同步抬升到满足该级别的最小影响范围/可信度输入，保持快照可解释。
            confidence = max(payload.get("confidence", incident["current_confidence"]), incident["current_confidence"], key=lambda value: CONFIDENCE_RANK[value])
            impact_scope = max(payload.get("impact_scope", incident["current_impact_scope"]), incident["current_impact_scope"], key=lambda value: IMPACT_RANK[value])
            rules = self._rules_for(connection, incident["rule_version"])
            snapshot = grade(rules, anomaly_kind=incident["anomaly_kind"], site_type=incident["site_type"],
                             confidence=confidence, impact_scope=impact_scope)
            if LEVEL_RANK[target] > LEVEL_RANK[snapshot["level"]]:
                snapshot["level"] = target
                # 快照中与级别绑定的派生项必须随人工目标级别一起重建，
                # 否则会出现 L3 事件按 L1 的时限与复核条件关闭的矛盾。
                snapshot["response_deadline_minutes"] = rules["response_deadlines"][target]
                snapshot["review_requirements"] = dict(rules["review_requirements"][target])
                snapshot["default_assignee"] = dict(rules["default_assignees"][target])
                snapshot["reasons"].append(f"人工升级为 {target}：{payload['reason']}")
            sets = ["level=?", "current_confidence=?", "current_impact_scope=?",
                    "grading_snapshot_json=?", "updated_at=?"]
            params: list[Any] = [snapshot["level"], confidence, impact_scope,
                                 json.dumps(snapshot, ensure_ascii=False), now]
            if incident["first_responded_at"] is None:
                deadline_at = to_storage(now_value + timedelta(minutes=snapshot["response_deadline_minutes"]))
                sets.extend(["response_deadline_minutes=?", "response_deadline_at=?"])
                params.extend([snapshot["response_deadline_minutes"], deadline_at])
            reassigned = None
            if not self._was_human_taken(connection, incident_id):
                reassigned = snapshot["default_assignee"]
                sets.extend(["current_assignee=?", "current_assignee_role=?"])
                params.extend([reassigned["assignee"], reassigned["assignee_role"]])
            connection.execute(f"UPDATE anomaly_incidents SET {', '.join(sets)} WHERE id=?", (*params, incident_id))
            self._append_timeline(connection, incident_id, "escalation.manual", payload["actor"], {
                "from_level": incident["level"], "to_level": snapshot["level"],
                "reason": payload["reason"], "impact_scope": impact_scope, "confidence": confidence,
            }, now)
            if reassigned is not None:
                self._append_timeline(connection, incident_id, "assign.auto", "system",
                                      {"assignee": reassigned["assignee"], "assignee_role": reassigned["assignee_role"],
                                       "reason": "人工升级改派"}, now)
            return self.get_incident(incident_id)

    # ------------------------------------------------------------------ 规则切换

    def switch_rule_version(self, incident_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        if not payload.get("confirm"):
            raise ConflictError("切换规则版本属于显式操作，必须 confirm=true")
        now_value = self.clock.now()
        now = to_storage(now_value)
        with transaction(immediate=True) as connection:
            incident = self._require_incident(connection, incident_id)
            if incident["status"] not in ACTIVE_STATUSES:
                raise ConflictError("只有正在处理的事件可以切换规则版本；已结案事件始终按原版本解释")
            target = connection.execute("SELECT * FROM anomaly_rule_versions WHERE version=?", (payload["version"],)).fetchone()
            if target is None:
                raise NotFoundError(f"规则版本 {payload['version']} 不存在")
            if target["status"] != "active":
                raise ConflictError("只能切换到生效中的规则版本")
            if target["version"] == incident["rule_version"]:
                raise ConflictError("事件已绑定该规则版本")
            snapshot = grade(
                json.loads(target["rules_json"]), anomaly_kind=incident["anomaly_kind"],
                site_type=incident["site_type"], confidence=incident["current_confidence"],
                impact_scope=incident["current_impact_scope"],
            )
            # 已经在处置的事件不会因为新规的“待补证”条件倒退，只按新规重定级。
            if incident["status"] != "awaiting_evidence":
                snapshot["awaiting_evidence"] = False
            previous_snapshot = json.loads(incident["grading_snapshot_json"])
            sets = ["rule_version=?", "grading_snapshot_json=?", "level=?", "updated_at=?"]
            params: list[Any] = [payload["version"], json.dumps(snapshot, ensure_ascii=False), snapshot["level"], now]
            new_status = incident["status"]
            if incident["status"] == "awaiting_evidence" and not snapshot["awaiting_evidence"]:
                new_status = "open"
                sets.extend(["status='open'", "current_assignee=?", "current_assignee_role=?",
                             "response_deadline_minutes=?", "response_deadline_at=?"])
                params.extend([snapshot["default_assignee"]["assignee"], snapshot["default_assignee"]["assignee_role"],
                               snapshot["response_deadline_minutes"],
                               to_storage(now_value + timedelta(minutes=snapshot["response_deadline_minutes"]))])
            elif incident["first_responded_at"] is None and not snapshot["awaiting_evidence"]:
                sets.extend(["response_deadline_minutes=?", "response_deadline_at=?"])
                params.extend([snapshot["response_deadline_minutes"],
                               to_storage(now_value + timedelta(minutes=snapshot["response_deadline_minutes"]))])
            connection.execute(f"UPDATE anomaly_incidents SET {', '.join(sets)} WHERE id=?", (*params, incident_id))
            self._append_timeline(connection, incident_id, "rule_version.switch", payload["actor"], {
                "from_version": incident["rule_version"], "to_version": payload["version"],
                "from_level": previous_snapshot["level"], "to_level": snapshot["level"],
                "reason": payload.get("reason", ""), "new_status": new_status,
            }, now)
            return self.get_incident(incident_id)

    # ------------------------------------------------------------------ 查询

    def get_incident(self, incident_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM anomaly_incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise NotFoundError("异常事件不存在")
        return self._serialize_incident(row)

    def list_incidents(self, *, status: str | None = None, level: str | None = None, limit: int = 100) -> dict[str, Any]:
        sql = "SELECT * FROM anomaly_incidents WHERE 1=1"
        params: list[Any] = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if level:
            sql += " AND level=?"
            params.append(level)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        rows = self.connection.execute(sql, params).fetchall()
        return {"items": [self._serialize_incident(row) for row in rows]}

    def dispatch_queue(self) -> dict[str, Any]:
        """派单队列：高等级优先、同级按响应截止时间排序；待补证线索单列且不占队列。"""
        rows = self.connection.execute(
            "SELECT * FROM anomaly_incidents WHERE status IN ('open','in_progress') "
            "ORDER BY CASE level WHEN 'L3' THEN 0 WHEN 'L2' THEN 1 ELSE 2 END, "
            "response_deadline_at IS NULL, response_deadline_at, id"
        ).fetchall()
        pending = self.connection.execute(
            "SELECT * FROM anomaly_incidents WHERE status='awaiting_evidence' ORDER BY id"
        ).fetchall()
        return {
            "queue": [self._serialize_incident(row) for row in rows],
            "awaiting_evidence": [self._serialize_incident(row) for row in pending],
        }

    def timeline(self, incident_id: int) -> dict[str, Any]:
        self.get_incident(incident_id)
        rows = self.connection.execute(
            "SELECT * FROM anomaly_timeline WHERE incident_id=? ORDER BY seq", (incident_id,)
        ).fetchall()
        entries = []
        for row in rows:
            item = {
                "seq": row["seq"], "action": row["action"], "actor": row["actor"],
                "detail": json.loads(row["detail_json"]), "created_at": row["created_at"],
                "prev_hash": row["prev_hash"], "entry_hash": row["entry_hash"],
            }
            entries.append(item)
        verification = self.verify_chain(incident_id)
        return {"incident_id": incident_id, "entries": entries, "chain": verification}

    def verify_chain(self, incident_id: int) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT * FROM anomaly_timeline WHERE incident_id=? ORDER BY seq", (incident_id,)
        ).fetchall()
        previous = GENESIS_HASH
        broken: list[int] = []
        for expected_seq, row in enumerate(rows, start=1):
            if row["seq"] != expected_seq:
                broken.append(row["seq"])
            if row["prev_hash"] != previous:
                broken.append(row["seq"])
            expected = self._hash_entry(row["incident_id"], row["seq"], row["action"], row["actor"],
                                        row["detail_json"], row["created_at"], previous)
            if expected != row["entry_hash"]:
                broken.append(row["seq"])
            previous = row["entry_hash"]
        return {
            "valid": not broken,
            "entries": len(rows),
            "broken_seq": sorted(set(broken)),
            "chain_tip": previous if rows else GENESIS_HASH,
        }

    # ------------------------------------------------------------------ 内部工具

    def _serialize_incident(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["grading_snapshot"] = json.loads(result.pop("grading_snapshot_json"))
        result["field_conclusion"] = json.loads(result.pop("field_conclusion_json") or "null")
        result["close_review"] = json.loads(result.pop("close_review_json") or "null")
        result["response"] = self._response_state(row)
        evidence = self.connection.execute(
            "SELECT id,reporter,evidence_type,evidence_ref,confidence,impact_scope,summary,relation,created_at FROM anomaly_evidence WHERE incident_id=? ORDER BY id",
            (row["id"],),
        ).fetchall()
        result["evidence"] = [dict(item) for item in evidence]
        result["reviews"] = [dict(item) for item in self.connection.execute(
            "SELECT id,review_kind,reviewer,passed,opinion,created_at FROM anomaly_reviews WHERE incident_id=? ORDER BY id",
            (row["id"],),
        ).fetchall()]
        return result

    def _response_state(self, row: sqlite3.Row) -> dict[str, Any]:
        if row["status"] == "awaiting_evidence":
            return {"state": "awaiting_evidence", "deadline_at": None, "overdue": False}
        if row["first_responded_at"]:
            return {"state": "responded", "deadline_at": row["response_deadline_at"],
                    "responded_at": row["first_responded_at"], "overdue": False,
                    "met_deadline": row["first_responded_at"] <= (row["response_deadline_at"] or "")}
        overdue = bool(row["response_deadline_at"]) and to_storage(self.clock.now()) > row["response_deadline_at"]
        return {"state": "overdue" if overdue else "pending",
                "deadline_at": row["response_deadline_at"], "overdue": overdue}

    def _require_incident(self, connection: sqlite3.Connection, incident_id: int) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM anomaly_incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise NotFoundError("异常事件不存在")
        return row

    def _require_active(self, connection: sqlite3.Connection, incident_id: int) -> sqlite3.Row:
        row = self._require_incident(connection, incident_id)
        if row["status"] not in ACTIVE_STATUSES:
            raise ConflictError("事件已结案，不能再执行该操作")
        return row

    def _was_human_taken(self, connection: sqlite3.Connection, incident_id: int) -> bool:
        row = connection.execute(
            "SELECT 1 FROM anomaly_timeline WHERE incident_id=? AND action IN ('assign','transfer','respond') LIMIT 1",
            (incident_id,),
        ).fetchone()
        return row is not None

    def _append_timeline(self, connection: sqlite3.Connection, incident_id: int, action: str,
                         actor: str, detail: dict[str, Any], now: str) -> None:
        seq_row = connection.execute(
            "SELECT COALESCE(MAX(seq),0)+1 AS next_seq FROM anomaly_timeline WHERE incident_id=?", (incident_id,)
        ).fetchone()
        seq = seq_row["next_seq"]
        previous = connection.execute(
            "SELECT entry_hash FROM anomaly_timeline WHERE incident_id=? ORDER BY seq DESC LIMIT 1", (incident_id,)
        ).fetchone()
        prev_hash = previous["entry_hash"] if previous else GENESIS_HASH
        detail_json = json.dumps(detail, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        entry_hash = self._hash_entry(incident_id, seq, action, actor, detail_json, now, prev_hash)
        connection.execute(
            "INSERT INTO anomaly_timeline(incident_id,seq,action,actor,detail_json,prev_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (incident_id, seq, action, actor, detail_json, prev_hash, entry_hash, now),
        )

    @staticmethod
    def _hash_entry(incident_id: int, seq: int, action: str, actor: str,
                    detail_json: str, created_at: str, prev_hash: str) -> str:
        body = json.dumps(
            {"incident_id": incident_id, "seq": seq, "action": action, "actor": actor,
             "detail": json.loads(detail_json), "created_at": created_at, "prev_hash": prev_hash},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(body.encode()).hexdigest()
