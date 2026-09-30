from __future__ import annotations

import argparse
import json

from fastapi.testclient import TestClient

from app.database import database_path, get_connection, init_db
from app.main import app


def command_init() -> int:
    init_db()
    print(json.dumps({"database": str(database_path()), "status": "initialized"}, ensure_ascii=False))
    return 0


def command_check() -> int:
    init_db()
    connection = get_connection()
    result = {
        "database": str(database_path()),
        "integrity": connection.execute("PRAGMA integrity_check").fetchone()[0],
        "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
        "journal_mode": connection.execute("PRAGMA journal_mode").fetchone()[0],
        "tables": connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0],
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["integrity"] == "ok" and result["foreign_keys"] == 1 else 1


def command_smoke() -> int:
    with TestClient(app) as client:
        root = client.get("/")
        health = client.get("/api/system/health")
    result = {"root": root.json(), "health": health.json(), "status_codes": [root.status_code, health.status_code]}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status_codes"] == [200, 200] else 1


def command_compute_demo() -> int:
    template = {
        "code": "monte-carlo-demo",
        "name": "蒙特卡洛演示",
        "algorithm": "monte-carlo",
        "parameter_schema": {
            "samples": {"type": "integer", "required": True, "minimum": 10, "maximum": 1000000},
            "seed": {"type": "integer", "required": True},
        },
        "default_parameters": {},
        "max_runtime_seconds": 60,
        "max_attempts": 3,
    }
    with TestClient(app) as client:
        created = client.post("/api/compute/templates?actor=cli-demo", json=template)
        if created.status_code not in {201, 409}:
            print(created.text)
            return 1
        task = client.post(
            "/api/compute/tasks",
            json={
                "template_code": "monte-carlo-demo",
                "project_code": "demo",
                "requested_by": "cli-user",
                "parameters": {"samples": 1000, "seed": 42},
                "priority": 80,
                "idempotency_key": "compute-demo-000001",
            },
        )
        claimed = client.post(
            "/api/compute/tasks/claim",
            json={"worker_id": "cli-worker", "capabilities": ["monte-carlo"], "lease_seconds": 60},
        )
    result = {"task": task.status_code, "claimed": claimed.status_code, "task_id": task.json().get("id")}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if task.status_code == 202 and claimed.status_code == 200 and claimed.json().get("task") else 1


def command_incident_demo() -> int:
    with TestClient(app) as client:
        water = client.post(
            "/api/incidents/reports",
            json={
                "title": "镜湖水质突变", "location_type": "water", "location_name": "镜湖西岸",
                "report_type": "water_quality", "description": "水体浑浊异味",
                "reporter": "ranger-li", "confidence": "medium", "impact_scope": "local",
                "evidence": "水样 W-12", "dedupe_key": "demo-water-001",
            },
        )
        duplicate = client.post(
            "/api/incidents/reports",
            json={
                "title": "镜湖水质突变", "location_type": "water", "location_name": "镜湖西岸",
                "report_type": "water_quality", "reporter": "ranger-wang",
                "confidence": "high", "impact_scope": "area", "evidence": "水样 W-13",
                "dedupe_key": "demo-water-001",
            },
        )
        bird = client.post(
            "/api/incidents/reports",
            json={
                "title": "受伤苍鹭", "location_type": "meadow", "location_name": "南草甸",
                "report_type": "injured_wildlife", "description": "左翼受伤",
                "reporter": "ranger-chen", "confidence": "medium", "impact_scope": "individual",
                "evidence": "影像记录", "dedupe_key": "demo-bird-001",
            },
        )
        water_id = water.json()["id"]
        bird_id = bird.json()["id"]
        client.post(f"/api/incidents/events/{water_id}/assign", json={"actor": "dispatcher", "assignee": "team-a"})
        client.post(f"/api/incidents/events/{water_id}/accept", json={"actor": "team-a"})
        escalated = client.post(f"/api/incidents/events/{bird_id}/escalate", json={"actor": "director", "to_level": "P1", "reason": "属重点保护物种"})
        timeline = client.get(f"/api/incidents/events/{water_id}/timeline")
    result = {
        "water_level": water.json()["level"],
        "duplicate_linked": duplicate.json().get("id") == water_id and duplicate.json().get("report_count") == 2,
        "bird_level_after_escalation": escalated.json()["level"],
        "water_timeline_valid": timeline.json()["verification"]["valid"],
        "water_timeline_entries": timeline.json()["chain_length"],
    }
    ok = (
        result["water_level"] == "P1"
        and result["duplicate_linked"]
        and result["bird_level_after_escalation"] == "P1"
        and result["water_timeline_valid"]
        and result["water_timeline_entries"] >= 4
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="compute-operations", description="科学计算任务运营服务维护入口")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化 SQLite 数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="执行本地 API 冒烟检查")
    subparsers.add_parser("compute-demo", help="执行计算任务提交与领取演示")
    subparsers.add_parser("incident-demo", help="执行异常响应分级、重复上报与升级演示")
    args = parser.parse_args()
    return {"init-db": command_init, "check-db": command_check, "smoke": command_smoke, "compute-demo": command_compute_demo, "incident-demo": command_incident_demo}[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
