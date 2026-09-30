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


def command_anomaly_demo() -> int:
    def report(client, **overrides):
        payload = {
            "anomaly_kind": "injured_bird",
            "site_type": "meadow",
            "location_name": "北片草甸",
            "confidence": "medium",
            "impact_scope": "single",
            "reporter": "巡查员甲",
            "evidence_type": "photo",
            "evidence_ref": "IMG-0001",
            "summary": "发现异常",
        }
        payload.update(overrides)
        response = client.post("/api/anomaly/reports", json=payload)
        assert response.status_code == 201, response.text
        return response.json()

    with TestClient(app) as client:
        # A：东水面水质突变，中可信单点 → L2（类型底线）
        event_a = report(client, anomaly_kind="water_quality", site_type="water", location_name="东水面",
                         confidence="medium", impact_scope="single", reporter="巡查员乙", evidence_ref="W-1",
                         summary="水体浑浊有异味")
        # B：南草甸游客闯入，中可信单点 → L1
        event_b = report(client, anomaly_kind="intrusion", site_type="meadow", location_name="南草甸",
                         confidence="medium", impact_scope="single", reporter="巡查员丙", evidence_ref="V-1",
                         summary="游客离开栈道")
        # 交叉上报：对 A 是高可信大范围重复证据，对 B 是交叉证据
        linked = client.post("/api/anomaly/reports", json={
            "anomaly_kind": "water_quality", "site_type": "water", "location_name": "东水面",
            "confidence": "high", "impact_scope": "local", "reporter": "巡查员乙",
            "evidence_type": "lab_report", "evidence_ref": "LAB-9",
            "summary": "污染扩散并波及草甸", "related_incident_id": event_a["id"],
            "cross_incident_ids": [event_b["id"]],
        })
        assert linked.status_code == 201, linked.text
        after_a = client.get(f"/api/anomaly/incidents/{event_a['id']}").json()
        after_b = client.get(f"/api/anomaly/incidents/{event_b['id']}").json()
        chain_a = client.get(f"/api/anomaly/incidents/{event_a['id']}/chain").json()
        chain_b = client.get(f"/api/anomaly/incidents/{event_b['id']}/chain").json()
        queue = client.get("/api/anomaly/dispatch-queue").json()
    result = {
        "event_a": {"id": event_a["id"], "level": after_a["level"],
                    "deadline_minutes": after_a["response_deadline_minutes"],
                    "assignee": after_a["current_assignee"], "chain_valid": chain_a["valid"]},
        "event_b": {"id": event_b["id"], "level": after_b["level"],
                    "deadline_minutes": after_b["response_deadline_minutes"],
                    "assignee": after_b["current_assignee"], "chain_valid": chain_b["valid"]},
        "intake": linked.json()["intake"],
        "queue_levels": [item["level"] for item in queue["queue"]],
    }
    print(json.dumps(result, ensure_ascii=False))
    ok = (after_a["level"] == "L3" and after_b["level"] == "L2"
          and chain_a["valid"] and chain_b["valid"]
          and linked.json()["intake"]["cross_linked"] == [event_b["id"]])
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="compute-operations", description="科学计算任务运营服务维护入口")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化 SQLite 数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="执行本地 API 冒烟检查")
    subparsers.add_parser("compute-demo", help="执行计算任务提交与领取演示")
    subparsers.add_parser("anomaly-demo", help="执行异常响应交叉升级与重复上报演示")
    args = parser.parse_args()
    return {"init-db": command_init, "check-db": command_check, "smoke": command_smoke,
            "compute-demo": command_compute_demo, "anomaly-demo": command_anomaly_demo}[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
