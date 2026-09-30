"""保护中心异常分级规则。

规则按版本整体发布，事件在创建时绑定一个规则版本，此后分级依据、
响应时限与关闭复核条件都按该版本解释（见 anomaly.service）。
"""
from __future__ import annotations

from typing import Any

from app.core.errors import ValidationError

SITE_TYPES = ("water", "meadow", "forest_edge")
CONFIDENCE_LEVELS = ("low", "medium", "high")
IMPACT_SCOPES = ("single", "local", "broad")
INCIDENT_LEVELS = ("L1", "L2", "L3")

SITE_TYPE_LABELS = {
    "water": "水面",
    "meadow": "草甸",
    "forest_edge": "林缘",
}
CONFIDENCE_LABELS = {"low": "低可信", "medium": "中可信", "high": "高可信"}
IMPACT_SCOPE_LABELS = {"single": "单点/单只", "local": "局部", "broad": "大范围"}
LEVEL_LABELS = {"L1": "一般", "L2": "较重", "L3": "紧急"}
ANOMALY_KIND_LABELS = {
    "water_quality": "水质突变",
    "intrusion": "游客闯入",
    "injured_bird": "受伤鸟类",
    "fire_risk": "火情隐患",
    "poaching": "疑似盗猎",
    "other": "其他异常",
}

CONFIDENCE_RANK = {value: index for index, value in enumerate(CONFIDENCE_LEVELS)}
IMPACT_RANK = {value: index for index, value in enumerate(IMPACT_SCOPES)}
LEVEL_RANK = {value: index for index, value in enumerate(INCIDENT_LEVELS)}


# v1：现行规则。水面/水质风险优先，草甸与林缘的低可信线索允许等待补证。
RULES_V1: dict[str, Any] = {
    "grading_matrix": {
        # 地点类型 -> 证据可信度 -> 影响范围 -> 基线级别
        "water": {
            "high": {"single": "L2", "local": "L3", "broad": "L3"},
            "medium": {"single": "L1", "local": "L2", "broad": "L3"},
            "low": {"single": "L1", "local": "L2", "broad": "L2"},
        },
        "meadow": {
            "high": {"single": "L1", "local": "L2", "broad": "L3"},
            "medium": {"single": "L1", "local": "L1", "broad": "L2"},
            "low": {"single": "L1", "local": "L1", "broad": "L1"},
        },
        "forest_edge": {
            "high": {"single": "L1", "local": "L2", "broad": "L3"},
            "medium": {"single": "L1", "local": "L2", "broad": "L2"},
            "low": {"single": "L1", "local": "L1", "broad": "L1"},
        },
    },
    # 异常类型底线：不论证据自评如何，达到相应影响范围时级别不得更低
    "kind_floor": {
        "water_quality": {"single": "L2", "local": "L3", "broad": "L3"},
        "intrusion": {"single": "L1", "local": "L2", "broad": "L2"},
        "fire_risk": {"single": "L2", "local": "L3", "broad": "L3"},
        "poaching": {"single": "L2", "local": "L3", "broad": "L3"},
    },
    "response_deadlines": {
        # 各级别首次响应时限（分钟）
        "L1": 1440,
        "L2": 240,
        "L3": 60,
    },
    "review_requirements": {
        "L1": {
            "field_conclusion_required": True,
            "recheck_required": False,
            "senior_review_required": False,
            "rechecker_must_differ_from_reporter": False,
        },
        "L2": {
            "field_conclusion_required": True,
            "recheck_required": True,
            "senior_review_required": False,
            "rechecker_must_differ_from_reporter": True,
        },
        "L3": {
            "field_conclusion_required": True,
            "recheck_required": True,
            "senior_review_required": True,
            "rechecker_must_differ_from_reporter": True,
        },
    },
    # 分级后的默认值班分派（可被人工 assign / transfer 覆盖）
    "default_assignees": {
        "L1": {"assignee": "巡查值班班长", "assignee_role": "patrol_lead"},
        "L2": {"assignee": "区域管护员", "assignee_role": "steward"},
        "L3": {"assignee": "值班主管", "assignee_role": "duty_manager"},
    },
}


def max_level(left: str, right: str) -> str:
    return left if LEVEL_RANK[left] >= LEVEL_RANK[right] else right


def validate_rules(rules: dict[str, Any]) -> None:
    if not isinstance(rules, dict):
        raise ValidationError("规则必须是结构化对象")
    matrix = rules.get("grading_matrix")
    if not isinstance(matrix, dict):
        raise ValidationError("规则缺少 grading_matrix")
    for site in SITE_TYPES:
        site_matrix = matrix.get(site)
        if not isinstance(site_matrix, dict):
            raise ValidationError(f"grading_matrix 缺少地点类型 {site}")
        for confidence in CONFIDENCE_LEVELS:
            scope_matrix = site_matrix.get(confidence)
            if not isinstance(scope_matrix, dict):
                raise ValidationError(f"grading_matrix.{site} 缺少可信度 {confidence}")
            for scope in IMPACT_SCOPES:
                if scope_matrix.get(scope) not in INCIDENT_LEVELS:
                    raise ValidationError(f"grading_matrix.{site}.{confidence}.{scope} 级别非法")
    deadlines = rules.get("response_deadlines")
    if not isinstance(deadlines, dict):
        raise ValidationError("规则缺少 response_deadlines")
    for level in INCIDENT_LEVELS:
        value = deadlines.get(level)
        if not isinstance(value, int) or value <= 0:
            raise ValidationError(f"response_deadlines.{level} 必须是正整数分钟")
    reviews = rules.get("review_requirements")
    if not isinstance(reviews, dict):
        raise ValidationError("规则缺少 review_requirements")
    for level in INCIDENT_LEVELS:
        requirements = reviews.get(level)
        if not isinstance(requirements, dict) or "field_conclusion_required" not in requirements:
            raise ValidationError(f"review_requirements.{level} 结构不完整")
    assignees = rules.get("default_assignees")
    if not isinstance(assignees, dict):
        raise ValidationError("规则缺少 default_assignees")
    for level in INCIDENT_LEVELS:
        assignment = assignees.get(level)
        if not isinstance(assignment, dict) or not assignment.get("assignee") or not assignment.get("assignee_role"):
            raise ValidationError(f"default_assignees.{level} 结构不完整")
    for kind, floors in (rules.get("kind_floor") or {}).items():
        if not isinstance(floors, dict):
            raise ValidationError(f"kind_floor.{kind} 必须是对象")
        for scope, level in floors.items():
            if scope not in IMPACT_SCOPES or level not in INCIDENT_LEVELS:
                raise ValidationError(f"kind_floor.{kind}.{scope} 取值非法")


def grade(
    rules: dict[str, Any],
    *,
    anomaly_kind: str,
    site_type: str,
    confidence: str,
    impact_scope: str,
) -> dict[str, Any]:
    """依据某一版规则解释一次（或合并后的）线索，返回分级快照。

    返回内容整体写入事件 grading_snapshot，之后响应时限与复核条件
    都从该快照读取，保证历史事件不被新规则重新解释。
    """
    base = rules["grading_matrix"][site_type][confidence][impact_scope]
    level = base
    reasons = [
        f"{SITE_TYPE_LABELS[site_type]}·{CONFIDENCE_LABELS[confidence]}·"
        f"{IMPACT_SCOPE_LABELS[impact_scope]} 基线级别为 {LEVEL_LABELS[base]}"
    ]
    floor = (rules.get("kind_floor") or {}).get(anomaly_kind, {}).get(impact_scope)
    if floor:
        level = max_level(level, floor)
        reasons.append(f"{ANOMALY_KIND_LABELS.get(anomaly_kind, anomaly_kind)} 类型底线为 {LEVEL_LABELS[floor]}")
    # 低可信线索：只有在类型底线把事件抬到 L2 及以上时才立即响应，
    # 否则进入待补证，且不进入派单队列，避免拖住高等级事件。
    awaiting_evidence = confidence == "low" and level == "L1"
    if awaiting_evidence:
        reasons.append("证据可信度低且无高等级底线，进入待补证，不占用处置时限")
    return {
        "level": level,
        "awaiting_evidence": awaiting_evidence,
        "reasons": reasons,
        "response_deadline_minutes": rules["response_deadlines"][level],
        "review_requirements": dict(rules["review_requirements"][level]),
        "default_assignee": dict(rules["default_assignees"][level]),
        "inputs": {
            "anomaly_kind": anomaly_kind,
            "site_type": site_type,
            "confidence": confidence,
            "impact_scope": impact_scope,
        },
    }
