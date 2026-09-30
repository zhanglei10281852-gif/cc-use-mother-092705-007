from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from app.anomaly.service import GENESIS_HASH, AnomalyResponseService, digest
from app.core.clock import FrozenClock
from app.database import get_connection


def report_payload(**overrides):
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
    return payload


def create(client, **overrides):
    response = client.post("/api/anomaly/reports", json=report_payload(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------- 分级与时限


def test_grading_by_site_confidence_and_scope(client):
    water = create(client, anomaly_kind="water_quality", site_type="water", location_name="东水面",
                   confidence="high", impact_scope="local", reporter="巡查员乙", evidence_ref="W-1")
    assert water["level"] == "L3"
    assert water["status"] == "open"
    assert water["response_deadline_minutes"] == 60
    assert water["current_assignee"] == "值班主管"
    assert water["grading_snapshot"]["inputs"]["site_type"] == "water"

    intrusion = create(client, anomaly_kind="intrusion", site_type="forest_edge", location_name="西林缘",
                       confidence="medium", impact_scope="local", reporter="巡查员丙", evidence_ref="F-1")
    assert intrusion["level"] == "L2"
    assert intrusion["response_deadline_minutes"] == 240
    assert intrusion["current_assignee"] == "区域管护员"

    bird = create(client, confidence="low", impact_scope="single", reporter="巡查员甲", evidence_ref="B-1")
    assert bird["level"] == "L1"
    assert bird["status"] == "awaiting_evidence"
    assert bird["response_deadline_at"] is None
    assert bird["current_assignee"] == ""


def test_kind_floor_raises_water_quality_even_at_medium_single(client):
    # 水面 + 中可信 + 单点，矩阵基线为 L1，但水质突变类型底线 L2
    incident = create(client, anomaly_kind="water_quality", site_type="water", location_name="西水面",
                      confidence="medium", impact_scope="single", reporter="巡查员乙", evidence_ref="W-2")
    assert incident["level"] == "L2"
    assert incident["status"] == "open"
    assert any("底线" in reason for reason in incident["grading_snapshot"]["reasons"])


# ---------------------------------------------------- 低可信线索不阻塞高等级


def test_dispatch_queue_prioritises_high_level_and_holds_pending_evidence(client):
    create(client, confidence="low", reporter="巡查员甲", evidence_ref="P-1")  # 待补证
    create(client, anomaly_kind="water_quality", site_type="water", location_name="东水面",
           confidence="medium", impact_scope="single", reporter="巡查员乙", evidence_ref="Q-1")  # L2
    create(client, anomaly_kind="water_quality", site_type="water", location_name="南水面",
           confidence="high", impact_scope="local", reporter="巡查员乙", evidence_ref="Q-2")  # L3

    queue = client.get("/api/anomaly/dispatch-queue").json()
    levels = [item["level"] for item in queue["queue"]]
    assert levels[0] == "L3"
    assert levels == sorted(levels, key=lambda value: {"L3": 0, "L2": 1, "L1": 2}[value])
    assert all(item["status"] != "awaiting_evidence" for item in queue["queue"])
    assert len(queue["awaiting_evidence"]) == 1


def test_supplementary_evidence_activates_pending_incident(client):
    incident = create(client, confidence="low", reporter="巡查员甲", evidence_ref="P-2")
    assert incident["status"] == "awaiting_evidence"

    follow_up = client.post("/api/anomaly/reports", json=report_payload(
        confidence="high", reporter="巡查员甲", evidence_ref="P-2-CONFIRM", summary="补拍清晰影像"))
    assert follow_up.status_code == 201, follow_up.text
    body = follow_up.json()
    assert body["intake"]["mode"] == "duplicate"
    assert body["id"] == incident["id"]
    assert body["status"] == "open"
    assert body["current_assignee"] == "巡查值班班长"
    assert body["response_deadline_minutes"] == 1440
    actions = [entry["action"] for entry in client.get(f"/api/anomaly/incidents/{incident['id']}/timeline").json()["entries"]]
    assert "activate" in actions


# ----------------------------------------------------------- 重复与交叉升级


def test_duplicate_reports_link_and_cross_escalation(client):
    # 原事件 A：水质突变 中可信单点 → L2（类型底线）
    event_a = create(client, anomaly_kind="water_quality", site_type="water", location_name="东水面",
                     confidence="medium", impact_scope="single", reporter="巡查员乙", evidence_ref="A-1")
    # 原事件 B：草甸游客闯入 中可信单点 → L1
    event_b = create(client, anomaly_kind="intrusion", site_type="meadow", location_name="南草甸",
                     confidence="medium", impact_scope="single", reporter="巡查员丙", evidence_ref="B-1")
    assert event_a["level"] == "L2"
    assert event_b["level"] == "L1"

    # 一次上报：对 A 是更强证据的重复上报（L2→L3），对 B 是交叉证据（L1→L2）
    linked = client.post("/api/anomaly/reports", json=report_payload(
        anomaly_kind="water_quality", site_type="water", location_name="东水面",
        confidence="high", impact_scope="local", reporter="巡查员乙", evidence_ref="A-2",
        summary="扩散至邻近水域并波及草甸", related_incident_id=event_a["id"],
        cross_incident_ids=[event_b["id"]]))
    assert linked.status_code == 201, linked.text
    data = linked.json()
    assert data["id"] == event_a["id"]
    assert data["intake"]["mode"] == "duplicate"
    assert data["intake"]["cross_linked"] == [event_b["id"]]

    updated_a = client.get(f"/api/anomaly/incidents/{event_a['id']}").json()
    updated_b = client.get(f"/api/anomaly/incidents/{event_b['id']}").json()
    assert updated_a["level"] == "L3"
    assert updated_a["current_impact_scope"] == "local"
    assert updated_a["response_deadline_minutes"] == 60
    assert updated_b["level"] == "L2"
    assert updated_b["response_deadline_minutes"] == 240

    timeline_a = client.get(f"/api/anomaly/incidents/{event_a['id']}/timeline").json()
    actions_a = [entry["action"] for entry in timeline_a["entries"]]
    assert "escalation.auto" in actions_a
    assert timeline_a["chain"]["valid"] is True
    timeline_b = client.get(f"/api/anomaly/incidents/{event_b['id']}/timeline").json()
    assert "escalation.cross" in [entry["action"] for entry in timeline_b["entries"]]
    assert timeline_b["chain"]["valid"] is True

    # 完全相同的证据重放：幂等，不产生新升级
    replay = client.post("/api/anomaly/reports", json=report_payload(
        anomaly_kind="water_quality", site_type="water", location_name="东水面",
        confidence="high", impact_scope="local", reporter="巡查员乙", evidence_ref="A-2",
        summary="扩散至邻近水域并波及草甸", related_incident_id=event_a["id"],
        cross_incident_ids=[event_b["id"]]))
    assert replay.status_code == 201
    assert replay.json()["intake"]["mode"] == "duplicate_replayed"
    count_a = client.get(f"/api/anomaly/incidents/{event_a['id']}/timeline").json()["chain"]["entries"]
    assert count_a == timeline_a["chain"]["entries"]


def test_duplicate_into_closed_incident_rejected(client):
    event = create(client, reporter="巡查员甲", evidence_ref="C-1")
    # L1：补证激活 → 结论 → 关闭
    client.post("/api/anomaly/reports", json=report_payload(confidence="high", evidence_ref="C-2"))
    incident_id = event["id"]
    client.post(f"/api/anomaly/incidents/{incident_id}/acknowledge", json={"actor": "巡查值班班长"})
    client.post(f"/api/anomaly/incidents/{incident_id}/conclude",
                json={"actor": "巡查值班班长", "conclusion": "伤鸟已送救助站", "outcome": "resolved"})
    closed = client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"})
    assert closed.status_code == 200

    response = client.post("/api/anomaly/reports", json=report_payload(
        reporter="巡查员甲", evidence_ref="C-3", related_incident_id=incident_id))
    assert response.status_code == 409


# ------------------------------------------------------------- 处置与转交


def test_assign_transfer_and_first_response(client):
    incident = create(client, confidence="low", reporter="巡查员甲", evidence_ref="D-1")
    incident_id = incident["id"]
    # 待补证不能派单
    blocked = client.post(f"/api/anomaly/incidents/{incident_id}/assign",
                          json={"assignee": "管护员丁", "assignee_role": "steward", "actor": "值班主管"})
    assert blocked.status_code == 409

    client.post("/api/anomaly/reports", json=report_payload(confidence="high", evidence_ref="D-2"))
    assigned = client.post(f"/api/anomaly/incidents/{incident_id}/assign",
                           json={"assignee": "管护员丁", "assignee_role": "steward", "actor": "值班主管"})
    assert assigned.status_code == 200
    assert assigned.json()["current_assignee"] == "管护员丁"

    transferred = client.post(f"/api/anomaly/incidents/{incident_id}/transfer",
                              json={"to_assignee": "兽医戊", "to_assignee_role": "vet",
                                    "actor": "管护员丁", "reason": "需要专业救助"})
    assert transferred.status_code == 200
    assert transferred.json()["current_assignee"] == "兽医戊"

    ack = client.post(f"/api/anomaly/incidents/{incident_id}/acknowledge", json={"actor": "兽医戊"})
    assert ack.json()["status"] == "in_progress"
    assert ack.json()["first_responded_at"]
    assert ack.json()["response"]["state"] == "responded"


# --------------------------------------------------------------- 关闭复核条件


def test_l2_close_requires_recheck_and_reviewer_must_differ(client):
    incident = create(client, anomaly_kind="intrusion", site_type="forest_edge", location_name="西林缘",
                      confidence="high", impact_scope="local", reporter="巡查员丙", evidence_ref="E-1")
    incident_id = incident["id"]
    client.post(f"/api/anomaly/incidents/{incident_id}/acknowledge", json={"actor": "区域管护员"})
    client.post(f"/api/anomaly/incidents/{incident_id}/conclude",
                json={"actor": "区域管护员", "conclusion": "游客已劝离，围挡修复", "outcome": "resolved"})

    assert client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"}).status_code == 409
    # 上报人本人复核不允许通过关闭
    own = client.post(f"/api/anomaly/incidents/{incident_id}/recheck",
                      json={"reviewer": "巡查员丙", "passed": True, "opinion": "已确认"})
    assert own.status_code == 200
    assert client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"}).status_code == 409
    # 他人复核通过后才能关闭
    other = client.post(f"/api/anomaly/incidents/{incident_id}/recheck",
                        json={"reviewer": "复核员己", "passed": True, "opinion": "现场复查无复发"})
    assert other.status_code == 200
    closed = client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"})
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["close_review"]["rechecker"] == "复核员己"


def test_l3_close_requires_recheck_and_senior_review(client):
    incident = create(client, anomaly_kind="water_quality", site_type="water", location_name="东水面",
                      confidence="high", impact_scope="local", reporter="巡查员乙", evidence_ref="F-1")
    incident_id = incident["id"]
    client.post(f"/api/anomaly/incidents/{incident_id}/acknowledge", json={"actor": "值班主管"})
    client.post(f"/api/anomaly/incidents/{incident_id}/conclude",
                json={"actor": "值班主管", "conclusion": "污染截断，水质恢复", "outcome": "resolved"})
    client.post(f"/api/anomaly/incidents/{incident_id}/recheck",
                json={"reviewer": "复核员己", "passed": True})
    # 仅现场复核仍不能关闭 L3
    assert client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"}).status_code == 409
    senior = client.post(f"/api/anomaly/incidents/{incident_id}/senior-review",
                         json={"reviewer": "保护中心主任", "passed": True, "opinion": "同意结案"})
    assert senior.status_code == 200
    closed = client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"})
    assert closed.status_code == 200
    assert closed.json()["close_review"]["senior_reviewer"] == "保护中心主任"


def test_failed_recheck_reopens_incident(client):
    incident = create(client, anomaly_kind="intrusion", site_type="forest_edge", location_name="北林缘",
                      confidence="high", impact_scope="local", reporter="巡查员丙", evidence_ref="G-1")
    incident_id = incident["id"]
    client.post(f"/api/anomaly/incidents/{incident_id}/acknowledge", json={"actor": "区域管护员"})
    client.post(f"/api/anomaly/incidents/{incident_id}/conclude",
                json={"actor": "区域管护员", "conclusion": "已处理", "outcome": "resolved"})
    rejected = client.post(f"/api/anomaly/incidents/{incident_id}/recheck",
                           json={"reviewer": "复核员己", "passed": False, "opinion": "仍有游客逗留"})
    assert rejected.json()["status"] == "in_progress"


def test_low_confidence_incident_can_be_rejected(client):
    incident = create(client, confidence="low", reporter="巡查员甲", evidence_ref="H-1")
    rejected = client.post(f"/api/anomaly/incidents/{incident['id']}/reject",
                           json={"reviewer": "值班主管", "reason": "核实为光影误判"})
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"


# ------------------------------------------------------------- 变更脉络不可篡改


def test_timeline_hash_chain_and_tamper_protection(client):
    incident = create(client, anomaly_kind="water_quality", site_type="water", location_name="北水面",
                      confidence="high", impact_scope="local", reporter="巡查员乙", evidence_ref="I-1")
    timeline = client.get(f"/api/anomaly/incidents/{incident['id']}/timeline").json()
    entries = timeline["entries"]
    assert entries[0]["action"] == "create"
    assert entries[0]["prev_hash"] == GENESIS_HASH
    assert entries[1]["action"] == "assign.auto"
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]

    # 手工重算首条哈希应一致
    first = entries[0]
    expected_body = {
        "incident_id": incident["id"], "seq": 1, "action": "create", "actor": "巡查员乙",
        "detail": first["detail"], "created_at": first["created_at"], "prev_hash": GENESIS_HASH,
    }
    assert first["entry_hash"] == digest(expected_body)

    connection = get_connection()
    with pytest.raises(sqlite3.Error):
        connection.execute("UPDATE anomaly_timeline SET actor='hacker' WHERE seq=1 AND incident_id=?", (incident["id"],))
    with pytest.raises(sqlite3.Error):
        connection.execute("DELETE FROM anomaly_timeline WHERE incident_id=?", (incident["id"],))
    assert client.get(f"/api/anomaly/incidents/{incident['id']}/chain").json()["valid"] is True


# ----------------------------------------------------------------- 规则版本化


def _v2_rules(client):
    v1 = client.get("/api/anomaly/rule-versions/v1").json()["rules"]
    v2 = {**v1}
    v2["grading_matrix"] = {
        site: {confidence: dict(scope) for confidence, scope in confidences.items()}
        for site, confidences in v1["grading_matrix"].items()
    }
    # 新规：草甸中可信单点也按 L2 处置；L1 时限缩短为 720 分钟
    v2["grading_matrix"]["meadow"]["medium"]["single"] = "L2"
    v2["response_deadlines"] = {**v1["response_deadlines"], "L1": 720}
    return v2


def test_new_rules_apply_forward_only_and_explicit_switch(client):
    old = create(client, confidence="medium", reporter="巡查员甲", evidence_ref="J-1")
    assert old["rule_version"] == "v1"
    assert old["level"] == "L1"
    assert old["response_deadline_minutes"] == 1440

    published = client.post("/api/anomaly/rule-versions",
                            json={"version": "v2", "rules": _v2_rules(client), "actor": "保护中心主任"})
    assert published.status_code == 201, published.text
    assert published.json()["status"] == "active"
    versions = client.get("/api/anomaly/rule-versions").json()["items"]
    assert {item["version"]: item["status"] for item in versions}["v1"] == "retired"

    # 规则调整后新建事件按 v2 解释
    new = create(client, location_name="南片草甸", confidence="medium", reporter="巡查员甲", evidence_ref="J-2")
    assert new["rule_version"] == "v2"
    assert new["level"] == "L2"
    assert new["response_deadline_minutes"] == 240

    # 历史事件仍按旧规则解释
    old_refetched = client.get(f"/api/anomaly/incidents/{old['id']}").json()
    assert old_refetched["level"] == "L1"
    assert old_refetched["response_deadline_minutes"] == 1440
    assert old_refetched["grading_snapshot"]["response_deadline_minutes"] == 1440

    # 处理中的事件必须显式确认才能切换版本
    no_confirm = client.post(f"/api/anomaly/incidents/{old['id']}/rule-version",
                             json={"version": "v2", "actor": "值班主管"})
    assert no_confirm.status_code == 409
    switched = client.post(f"/api/anomaly/incidents/{old['id']}/rule-version",
                           json={"version": "v2", "actor": "值班主管", "confirm": True, "reason": "按新规重新评估"})
    assert switched.status_code == 200
    body = switched.json()
    assert body["rule_version"] == "v2"
    assert body["level"] == "L2"
    actions = [entry["action"] for entry in client.get(f"/api/anomaly/incidents/{old['id']}/timeline").json()["entries"]]
    assert "rule_version.switch" in actions


def test_closed_incident_cannot_switch_rule_version(client):
    incident = create(client, confidence="medium", reporter="巡查员甲", evidence_ref="K-1")
    incident_id = incident["id"]
    client.post(f"/api/anomaly/incidents/{incident_id}/acknowledge", json={"actor": "巡查值班班长"})
    client.post(f"/api/anomaly/incidents/{incident_id}/conclude",
                json={"actor": "巡查值班班长", "conclusion": "已放生", "outcome": "resolved"})
    client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"})
    client.post("/api/anomaly/rule-versions", json={"version": "v2", "rules": _v2_rules(client), "actor": "主任"})

    response = client.post(f"/api/anomaly/incidents/{incident_id}/rule-version",
                           json={"version": "v2", "actor": "值班主管", "confirm": True})
    assert response.status_code == 409
    assert client.get(f"/api/anomaly/incidents/{incident_id}").json()["rule_version"] == "v1"


# ---------------------------------------------------------------- 时限计算


def test_response_deadline_and_overdue_with_injected_clock(client):
    clock = FrozenClock(datetime(2026, 9, 30, 8, 0, tzinfo=UTC))
    service = AnomalyResponseService(get_connection(), clock=clock)
    result = service.report(report_payload(
        anomaly_kind="water_quality", site_type="water", location_name="东水面",
        confidence="high", impact_scope="local", reporter="巡查员乙", evidence_ref="T-1"))
    assert result["response"]["state"] == "pending"
    assert result["response"]["overdue"] is False
    assert result["response_deadline_at"] == "2026-09-30T09:00:00+00:00"

    clock.advance(minutes=61)
    overdue = service.get_incident(result["id"])
    assert overdue["response"]["state"] == "overdue"
    assert overdue["response"]["overdue"] is True

    # 签收后即使过点也不再标记超期派单
    clock.advance(minutes=-61)
    service.acknowledge(result["id"], {"actor": "值班主管", "note": "到场"})
    clock.advance(minutes=120)
    responded = service.get_incident(result["id"])
    assert responded["response"]["state"] == "responded"
    assert responded["response"]["overdue"] is False


def test_manual_escalation_tightens_deadline(client):
    incident = create(client, confidence="medium", reporter="巡查员甲", evidence_ref="L-1")
    incident_id = incident["id"]
    escalated = client.post(f"/api/anomaly/incidents/{incident_id}/escalate",
                            json={"actor": "值班主管", "target_level": "L3", "reason": "发现盗猎迹象",
                                  "confidence": "high", "impact_scope": "broad"})
    assert escalated.status_code == 200
    assert escalated.json()["level"] == "L3"
    assert escalated.json()["response_deadline_minutes"] == 60
    assert escalated.json()["current_assignee"] == "值班主管"
    actions = [entry["action"] for entry in client.get(f"/api/anomaly/incidents/{incident_id}/timeline").json()["entries"]]
    assert "escalation.manual" in actions

    # 人工升级为 L3 后，关闭条件按 L3 执行（现场复核 + 高级签批）
    client.post(f"/api/anomaly/incidents/{incident_id}/acknowledge", json={"actor": "值班主管"})
    client.post(f"/api/anomaly/incidents/{incident_id}/conclude",
                json={"actor": "值班主管", "conclusion": "盗猎痕迹清除并设卡", "outcome": "escalated_to_authority"})
    assert client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"}).status_code == 409
    client.post(f"/api/anomaly/incidents/{incident_id}/recheck",
                json={"reviewer": "复核员己", "passed": True})
    assert client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"}).status_code == 409
    client.post(f"/api/anomaly/incidents/{incident_id}/senior-review",
                json={"reviewer": "保护中心主任", "passed": True})
    closed = client.post(f"/api/anomaly/incidents/{incident_id}/close", json={"actor": "值班主管"})
    assert closed.status_code == 200
