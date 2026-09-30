from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from app.core.clock import FrozenClock
from app.database import close_connection, get_connection
from app.incidents.service import IncidentResponseService


def report_payload(**overrides):
    payload = {
        "title": "水质异常",
        "location_type": "water",
        "location_name": "镜湖西岸监测点",
        "report_type": "water_quality",
        "description": "巡查发现水体浑浊并伴有异味",
        "reporter": "ranger-li",
        "confidence": "medium",
        "impact_scope": "local",
        "evidence": "水样编号 W-12，现场快检溶解氧偏低",
        "dedupe_key": "WQ-20260930-01",
    }
    payload.update(overrides)
    return payload


def minutes_between(start: str, end: str) -> float:
    return (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds() / 60.0


@pytest.fixture()
def frozen_service(tmp_path, monkeypatch):
    monkeypatch.setenv("TOWNSHIP_DATABASE_PATH", str(tmp_path / "incidents.db"))
    close_connection()
    clock = FrozenClock(datetime(2026, 9, 30, 8, 0, tzinfo=UTC))
    return IncidentResponseService(clock=clock), clock


def test_grading_by_location_confidence_and_scope_produces_distinct_deadlines(client):
    water = client.post("/api/incidents/reports", json=report_payload()).json()
    assert water["level"] == "P1"
    assert water["status"] == "open"
    assert minutes_between(water["created_at"], water["response_due_at"]) == 30
    assert minutes_between(water["created_at"], water["resolve_due_at"]) == 240

    bird = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="受伤白鹭", location_type="meadow", location_name="北草甸",
            report_type="injured_wildlife", impact_scope="individual",
            evidence="右腿受伤，无法飞行", dedupe_key="BIRD-01",
        ),
    ).json()
    assert bird["level"] == "P3"
    assert minutes_between(bird["created_at"], bird["response_due_at"]) == 1440

    intruder = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="游客闯入", location_type="forest_edge", location_name="东侧林缘",
            report_type="human_intrusion", confidence="high",
            evidence="影像截图三张", dedupe_key="INTRUDER-01",
        ),
    ).json()
    assert intruder["level"] == "P2"

    weak = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="疑似异常", location_type="forest_edge", location_name="西侧林缘",
            report_type="other", confidence="low", impact_scope="individual",
            evidence="听同事提及，暂无照片", dedupe_key="WEAK-01",
        ),
    ).json()
    assert weak["level"] == "P4"
    assert weak["status"] == "awaiting_evidence"
    assert weak["evidence_due_at"]


def test_duplicate_report_links_to_original_and_accumulates_counts(client):
    first = client.post("/api/incidents/reports", json=report_payload()).json()
    second_payload = report_payload(
        description="另一位巡查员在同一监测点独立上报",
        reporter="ranger-wang", evidence="第二份水样 W-13",
    )
    second = client.post("/api/incidents/reports", json=second_payload)
    assert second.status_code == 201, second.text
    body = second.json()
    assert body["id"] == first["id"]
    assert body["linked_to_existing"] is True
    assert body["report_count"] == 2
    assert len(body["reports"]) == 2

    detail = client.get(f"/api/incidents/events/{first['id']}").json()
    timeline = client.get(f"/api/incidents/events/{first['id']}/timeline").json()
    actions = [entry["action"] for entry in timeline["entries"]]
    assert "duplicate_report" in actions
    assert timeline["verification"]["valid"] is True
    assert detail["verification"]["length"] == timeline["chain_length"]


def test_low_confidence_clue_awaits_evidence_then_regrades_without_blocking_others(client):
    weak = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="疑似排污", location_type="water", location_name="南湾",
            report_type="water_quality", confidence="low", impact_scope="individual",
            evidence="口头反映", dedupe_key="WAIT-01",
        ),
    ).json()
    assert weak["level"] == "P4"

    urgent = client.post("/api/incidents/reports", json=report_payload(dedupe_key="URGENT-01")).json()
    assert urgent["level"] == "P1"
    # 高等级事件可独立派单处置，不被待补证线索阻塞
    assigned = client.post(f"/api/incidents/events/{urgent['id']}/assign", json={"actor": "dispatcher", "assignee": "water-team-a"}).json()
    assert assigned["current_assignee"] == "water-team-a"

    evidence = client.post(
        f"/api/incidents/events/{weak['id']}/evidence",
        json={"actor": "ranger-li", "confidence": "high", "impact_scope": "area", "evidence": "复检确认排污口并定位", "dedupe_key": "ev-1"},
    )
    assert evidence.status_code == 201, evidence.text
    upgraded = evidence.json()
    assert upgraded["level"] == "P1"
    assert upgraded["status"] == "open"
    timeline = client.get(f"/api/incidents/events/{weak['id']}/timeline").json()
    assert any(entry["action"] == "regrade" for entry in timeline["entries"])


def test_assign_accept_transfer_and_current_assignee(client):
    event = client.post("/api/incidents/reports", json=report_payload()).json()
    client.post(f"/api/incidents/events/{event['id']}/assign", json={"actor": "dispatcher", "assignee": "wang"})
    wrong = client.post(f"/api/incidents/events/{event['id']}/accept", json={"actor": "zhao"})
    assert wrong.status_code == 409
    accepted = client.post(f"/api/incidents/events/{event['id']}/accept", json={"actor": "wang"})
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "in_progress"

    transfer = client.post(
        f"/api/incidents/events/{event['id']}/transfer",
        json={"actor": "wang", "to_assignee": "chen", "reason": "需要水质化验专业组接手"},
    )
    assert transfer.status_code == 200
    assert transfer.json()["current_assignee"] == "chen"
    assert transfer.json()["accepted_at"] is None

    timeline = client.get(f"/api/incidents/events/{event['id']}/timeline").json()
    assert [entry["action"] for entry in timeline["entries"]] == ["create", "assign", "accept", "transfer"]
    assert timeline["verification"]["valid"] is True


def test_escalation_tightens_deadline_and_downgrade_is_rejected(client):
    bird = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="受伤鸟类", location_type="meadow", location_name="草甸",
            report_type="injured_wildlife", dedupe_key="ESC-01",
        ),
    ).json()
    assert bird["level"] == "P3"
    escalated = client.post(
        f"/api/incidents/events/{bird['id']}/escalate",
        json={"actor": "duty", "to_level": "P1", "reason": "媒体关注且位于核心栖息区"},
    ).json()
    assert escalated["level"] == "P1"
    assert minutes_between(escalated["updated_at"], escalated["response_due_at"]) == 30
    assert escalated["required_review_items"] == ["assignee_accepted", "field_conclusion", "follow_up_check", "second_reviewer"]

    downgrade = client.post(
        f"/api/incidents/events/{bird['id']}/escalate",
        json={"actor": "duty", "to_level": "P3", "reason": "尝试降回"},
    )
    assert downgrade.status_code == 409


def test_close_requires_level_specific_review_conditions(client):
    event = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="游客闯入", location_type="forest_edge", location_name="林缘",
            report_type="human_intrusion", confidence="high", dedupe_key="CLOSE-01",
        ),
    ).json()
    assert event["level"] == "P2"
    client.post(f"/api/incidents/events/{event['id']}/assign", json={"actor": "dispatcher", "assignee": "guard"})
    client.post(f"/api/incidents/events/{event['id']}/accept", json={"actor": "guard"})

    early_close = client.post(f"/api/incidents/events/{event['id']}/close", json={"actor": "guard", "reason": "处理完毕"})
    assert early_close.status_code == 409

    resolved = client.post(
        f"/api/incidents/events/{event['id']}/resolve",
        json={"actor": "guard", "conclusion": "已劝离闯入游客并加固围栏"},
    )
    assert resolved.json()["status"] == "reviewing"

    self_review = client.post(f"/api/incidents/events/{event['id']}/review", json={"actor": "guard", "item": "reviewer_signoff"})
    assert self_review.status_code == 409

    missing_still = client.post(f"/api/incidents/events/{event['id']}/close", json={"actor": "supervisor", "reason": "完成"})
    assert missing_still.status_code == 409
    assert "reviewer_signoff" in missing_still.json()["error"]["context"]["missing"]

    client.post(f"/api/incidents/events/{event['id']}/review", json={"actor": "supervisor", "item": "reviewer_signoff", "note": "复核通过"})
    closed = client.post(f"/api/incidents/events/{event['id']}/close", json={"actor": "supervisor", "reason": "现场与复核均通过"})
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"

    reopen_attempt = client.post(
        f"/api/incidents/events/{event['id']}/resolve",
        json={"actor": "guard", "conclusion": "又想改"},
    )
    assert reopen_attempt.status_code == 409


def test_p1_close_needs_two_independent_reviews(client):
    event = client.post("/api/incidents/reports", json=report_payload(dedupe_key="P1CLOSE-01")).json()
    client.post(f"/api/incidents/events/{event['id']}/assign", json={"actor": "dispatcher", "assignee": "hazmat"})
    client.post(f"/api/incidents/events/{event['id']}/accept", json={"actor": "hazmat"})
    client.post(
        f"/api/incidents/events/{event['id']}/resolve",
        json={"actor": "hazmat", "conclusion": "切断污染源并完成换水消杀"},
    )
    client.post(f"/api/incidents/events/{event['id']}/review", json={"actor": "reviewer-a", "item": "follow_up_check", "note": "24 小时复检合格"})
    same_person = client.post(f"/api/incidents/events/{event['id']}/review", json={"actor": "reviewer-a", "item": "second_reviewer"})
    assert same_person.status_code == 409
    client.post(f"/api/incidents/events/{event['id']}/review", json={"actor": "reviewer-b", "item": "second_reviewer", "note": "二级复核同意关闭"})
    closed = client.post(f"/api/incidents/events/{event['id']}/close", json={"actor": "reviewer-b", "reason": "一级事件双复核完成"})
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"


def test_overdue_response_auto_escalates_once_per_rule_version(frozen_service):
    service, clock = frozen_service
    event = service.report(report_payload(
        title="受伤鸟类", location_type="meadow", location_name="草甸",
        report_type="injured_wildlife", dedupe_key="OVD-01",
    ))
    assert event["level"] == "P3"
    assert service.process_overdue() == {"now": service.get_event(event["id"])["now"], "escalated": [], "notified": []}
    clock.advance(hours=25)
    result = service.process_overdue("monitor")
    assert result["escalated"] == [event["id"]]
    upgraded = service.get_event(event["id"])
    assert upgraded["level"] == "P2"
    # 再次扫描不重复升级
    assert service.process_overdue("monitor")["escalated"] == []
    timeline = service.timeline(event["id"])
    triggers = [entry for entry in timeline["entries"] if entry["action"] == "escalate"]
    assert len(triggers) == 1
    assert json.loads(triggers[0]["detail_json"])["trigger"] == "respond_overdue"


def test_rule_versions_keep_history_on_old_rules_while_active_event_switches_explicitly(client):
    old = client.post("/api/incidents/reports", json=report_payload(dedupe_key="VER-OLD")).json()
    assert old["rule_version"] == "2026.1"

    current = client.get("/api/incidents/rules/current").json()
    new_rules = current["rules"]
    # 新规则：水质事件的响应时限缩短到 15 分钟，且中可信即可判 P1（与旧版一致），改时限即可区分
    new_rules["levels"][0]["respond_minutes"] = 15
    created = client.post(
        "/api/incidents/rules/versions?actor=director",
        json={"version": "2026.2", "rules": new_rules, "note": "缩短一级响应时限"},
    )
    assert created.status_code == 201, created.text
    duplicate = client.post("/api/incidents/rules/versions?actor=director", json={"version": "2026.2", "rules": new_rules})
    assert duplicate.status_code == 409

    after = client.post("/api/incidents/reports", json=report_payload(dedupe_key="VER-NEW")).json()
    assert after["rule_version"] == "2026.2"
    assert minutes_between(after["created_at"], after["response_due_at"]) == 15

    # 历史事件仍按旧规则解释
    old_detail = client.get(f"/api/incidents/events/{old['id']}").json()
    assert old_detail["rule_version"] == "2026.1"
    assert old_detail["respond_minutes"] == 30

    # 未确认的切换被拒绝
    no_confirm = client.post(
        f"/api/incidents/events/{old['id']}/switch-rules",
        json={"actor": "director", "target_version": "2026.2", "reason": "尝试切换"},
    )
    assert no_confirm.status_code == 422
    switched = client.post(
        f"/api/incidents/events/{old['id']}/switch-rules",
        json={"actor": "director", "target_version": "2026.2", "confirm": True, "reason": "试点新时限"},
    )
    assert switched.status_code == 200, switched.text
    body = switched.json()
    assert body["rule_version"] == "2026.2"
    assert body["respond_minutes"] == 15
    timeline = client.get(f"/api/incidents/events/{old['id']}/timeline").json()
    assert any(entry["action"] == "rule_switch" for entry in timeline["entries"])

    # 已关闭事件永远不能切换版本
    client.post(f"/api/incidents/events/{after['id']}/assign", json={"actor": "d", "assignee": "a"})
    client.post(f"/api/incidents/events/{after['id']}/accept", json={"actor": "a"})
    client.post(f"/api/incidents/events/{after['id']}/resolve", json={"actor": "a", "conclusion": "处理完成"})
    client.post(f"/api/incidents/events/{after['id']}/review", json={"actor": "boss", "item": "follow_up_check"})
    client.post(f"/api/incidents/events/{after['id']}/review", json={"actor": "auditor", "item": "second_reviewer"})
    client.post(f"/api/incidents/events/{after['id']}/close", json={"actor": "auditor", "reason": "办结"})
    closed_switch = client.post(
        f"/api/incidents/events/{after['id']}/switch-rules",
        json={"actor": "director", "target_version": "2026.1", "confirm": True, "reason": "回退旧规则"},
    )
    assert closed_switch.status_code == 409


def test_timeline_is_tamper_evident(client):
    event = client.post("/api/incidents/reports", json=report_payload(dedupe_key="TAMPER-01")).json()
    client.post(f"/api/incidents/events/{event['id']}/assign", json={"actor": "dispatcher", "assignee": "wang"})
    timeline = client.get(f"/api/incidents/events/{event['id']}/timeline").json()
    assert timeline["verification"]["valid"] is True

    connection = get_connection()
    connection.execute("UPDATE incident_event_log SET actor='forged' WHERE event_id=? AND seq=1", (event["id"],))
    bad = client.get(f"/api/incidents/events/{event['id']}/timeline").json()
    assert bad["verification"]["valid"] is False
    assert bad["verification"]["reason"] in {"entry_hash_mismatch", "chain_head_mismatch"}

    good = client.post(
        "/api/incidents/reports",
        json=report_payload(dedupe_key="TAMPER-02", location_name="北湖"),
    ).json()
    assert client.get(f"/api/incidents/events/{good['id']}/timeline").json()["verification"]["valid"] is True


def test_awaiting_clue_can_be_rejected_but_handling_event_cannot(client):
    weak = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="疑似异常", location_type="forest_edge", location_name="西坡",
            report_type="other", confidence="low", impact_scope="individual",
            evidence="无实证", dedupe_key="REJECT-01",
        ),
    ).json()
    rejected = client.post(f"/api/incidents/events/{weak['id']}/reject", json={"actor": "supervisor", "reason": "核查后确认是雾气误判"})
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    more_evidence = client.post(
        f"/api/incidents/events/{weak['id']}/evidence",
        json={"actor": "ranger-li", "confidence": "high", "evidence": "迟到的照片"},
    )
    assert more_evidence.status_code == 409

    urgent = client.post("/api/incidents/reports", json=report_payload(dedupe_key="REJECT-02")).json()
    client.post(f"/api/incidents/events/{urgent['id']}/assign", json={"actor": "d", "assignee": "a"})
    reject_handling = client.post(f"/api/incidents/events/{urgent['id']}/reject", json={"actor": "d", "reason": "不允许驳回处置中事件"})
    assert reject_handling.status_code == 409


def test_cross_escalation_and_duplicate_scenario_end_to_end(client):
    # 水质突变：一级
    water = client.post("/api/incidents/reports", json=report_payload()).json()
    # 单只受伤鸟类：三级
    bird = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="受伤苍鹭", location_type="meadow", location_name="南草甸",
            report_type="injured_wildlife", impact_scope="individual",
            evidence="左翼受伤", dedupe_key="BIRD-X-01",
        ),
    ).json()
    # 低可信线索：待补证
    weak = client.post(
        "/api/incidents/reports",
        json=report_payload(
            title="疑似烟点", location_type="forest_edge", location_name="北坡林缘",
            report_type="fire_risk", confidence="low", impact_scope="individual",
            evidence="远处似有烟，未确认", dedupe_key="FIRE-X-01",
        ),
    ).json()
    assert [item["level"] for item in (water, bird, weak)] == ["P1", "P3", "P4"]

    # 水质事件收到重复上报并转交
    client.post("/api/incidents/reports", json=report_payload(reporter="ranger-zhao", evidence="第三份水样"))
    client.post(f"/api/incidents/events/{water['id']}/assign", json={"actor": "dispatcher", "assignee": "team-a"})
    client.post(f"/api/incidents/events/{water['id']}/transfer", json={"actor": "team-a", "to_assignee": "team-hazmat", "reason": "需专业防化处置"})

    # 鸟类事件连续升级到一级
    client.post(f"/api/incidents/events/{bird['id']}/escalate", json={"actor": "duty", "to_level": "P2", "reason": "栖息地周边有施工"})
    client.post(f"/api/incidents/events/{bird['id']}/escalate", json={"actor": "director", "to_level": "P1", "reason": "属保护物种"})

    water_detail = client.get(f"/api/incidents/events/{water['id']}").json()
    bird_detail = client.get(f"/api/incidents/events/{bird['id']}").json()
    assert water_detail["current_assignee"] == "team-hazmat"
    assert water_detail["report_count"] == 2
    assert water_detail["respond_minutes"] == bird_detail["respond_minutes"] == 30
    assert bird_detail["level"] == "P1"

    water_timeline = client.get(f"/api/incidents/events/{water['id']}/timeline").json()
    bird_timeline = client.get(f"/api/incidents/events/{bird['id']}/timeline").json()
    assert water_timeline["verification"]["valid"] is True
    assert bird_timeline["verification"]["valid"] is True
    bird_actions = [(entry["action"], entry["actor"]) for entry in bird_timeline["entries"]]
    assert ("escalate", "duty") in bird_actions and ("escalate", "director") in bird_actions
