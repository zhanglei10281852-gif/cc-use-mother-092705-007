"""异常响应领域的 SQLite 表结构与读写。"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS incident_rule_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL UNIQUE,
    rules_json TEXT NOT NULL,
    rules_digest TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    location_type TEXT NOT NULL CHECK(location_type IN ('water','meadow','forest_edge')),
    location_name TEXT NOT NULL DEFAULT '',
    report_type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    reporter TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),
    impact_scope TEXT NOT NULL CHECK(impact_scope IN ('individual','local','area')),
    level TEXT NOT NULL,
    matched_rule TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','assigned','in_progress','awaiting_evidence','escalated','resolved','reviewing','closed','rejected')),
    rule_version TEXT NOT NULL,
    rules_snapshot_json TEXT NOT NULL,
    rules_digest TEXT NOT NULL,
    current_assignee TEXT,
    assigned_at TEXT,
    accepted_at TEXT,
    response_due_at TEXT,
    resolve_due_at TEXT,
    evidence_due_at TEXT,
    field_conclusion TEXT,
    field_conclusion_by TEXT,
    field_conclusion_at TEXT,
    close_reason TEXT,
    closed_at TEXT,
    duplicate_of_id INTEGER REFERENCES incident_events(id),
    report_count INTEGER NOT NULL DEFAULT 1,
    review_checklist_json TEXT NOT NULL DEFAULT '{}',
    chain_head TEXT NOT NULL DEFAULT '',
    chain_length INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_status_level ON incident_events(status, level, created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_dup ON incident_events(duplicate_of_id);
CREATE TABLE IF NOT EXISTS incident_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES incident_events(id) ON DELETE RESTRICT,
    reporter TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK(confidence IN ('low','medium','high')),
    impact_scope TEXT NOT NULL CHECK(impact_scope IN ('individual','local','area')),
    report_type TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL,
    is_followup INTEGER NOT NULL DEFAULT 0 CHECK(is_followup IN (0,1)),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_reports_event ON incident_reports(event_id, id);
CREATE TABLE IF NOT EXISTS incident_event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES incident_events(id) ON DELETE RESTRICT,
    seq INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(event_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_incident_log_event ON incident_event_log(event_id, seq);
"""


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class IncidentRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    # ---- 规则版本 ----
    def insert_rule_version(self, *, version: str, rules: dict[str, Any], digest: str, note: str, actor: str, now: str) -> None:
        self.connection.execute(
            "INSERT INTO incident_rule_versions(version,rules_json,rules_digest,note,created_by,created_at) VALUES(?,?,?,?,?,?)",
            (version, json.dumps(rules, ensure_ascii=False, sort_keys=True), digest, note, actor, now),
        )

    def rule_version(self, version: str) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM incident_rule_versions WHERE version=?", (version,)).fetchone()

    def latest_rule_version(self) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM incident_rule_versions ORDER BY id DESC LIMIT 1").fetchone()

    def list_rule_versions(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT id,version,rules_digest,note,created_by,created_at FROM incident_rule_versions ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    # ---- 事件 ----
    def event_by_id(self, event_id: int) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM incident_events WHERE id=?", (event_id,)).fetchone()

    def event_by_code(self, code: str) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM incident_events WHERE code=?", (code,)).fetchone()

    def list_events(self, *, status: str | None, level: str | None, assignee: str | None, limit: int) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if status:
            clauses.append("status=?")
            values.append(status)
        if level:
            clauses.append("level=?")
            values.append(level)
        if assignee:
            clauses.append("current_assignee=?")
            values.append(assignee)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        values.append(limit)
        rows = self.connection.execute("SELECT * FROM incident_events" + where + " ORDER BY id DESC LIMIT ?", values).fetchall()
        return [dict(row) for row in rows]

    def find_duplicate(self, *, fingerprint: str, window_start: str) -> sqlite3.Row | None:
        return self.connection.execute(
            """
            SELECT e.* FROM incident_events e
            JOIN incident_reports r ON r.event_id = e.id
            WHERE r.fingerprint=? AND r.is_followup=0 AND e.created_at>=?
              AND e.status NOT IN ('closed','rejected')
            ORDER BY e.id ASC LIMIT 1
            """,
            (fingerprint, window_start),
        ).fetchone()

    def insert_event(self, values: dict[str, Any]) -> int:
        columns = ", ".join(values)
        placeholders = ", ".join("?" for _ in values)
        cursor = self.connection.execute(f"INSERT INTO incident_events({columns}) VALUES({placeholders})", tuple(values.values()))
        return int(cursor.lastrowid)

    def insert_report(self, *, event_id: int, reporter: str, confidence: str, impact_scope: str, report_type: str, description: str, evidence: str, fingerprint: str, is_followup: bool, now: str) -> int:
        cursor = self.connection.execute(
            "INSERT INTO incident_reports(event_id,reporter,confidence,impact_scope,report_type,description,evidence,fingerprint,is_followup,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (event_id, reporter, confidence, impact_scope, report_type, description, evidence, fingerprint, 1 if is_followup else 0, now),
        )
        return int(cursor.lastrowid)

    def reports(self, event_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM incident_reports WHERE event_id=? ORDER BY id", (event_id,)).fetchall()
        return [dict(row) for row in rows]

    def log_entries(self, event_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM incident_event_log WHERE event_id=? ORDER BY seq", (event_id,)).fetchall()
        return [dict(row) for row in rows]

    def append_log(self, *, event_id: int, seq: int, action: str, actor: str, detail: dict[str, Any], prev_hash: str, entry_hash: str, now: str) -> None:
        self.connection.execute(
            "INSERT INTO incident_event_log(event_id,seq,action,actor,detail_json,prev_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (event_id, seq, action, actor, json.dumps(detail, ensure_ascii=False, sort_keys=True), prev_hash, entry_hash, now),
        )
        self.connection.execute(
            "UPDATE incident_events SET chain_head=?,chain_length=?,updated_at=? WHERE id=?",
            (entry_hash, seq, now, event_id),
        )
