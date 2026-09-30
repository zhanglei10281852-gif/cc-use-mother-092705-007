"""异常响应规则：版本化的分级矩阵、时限与复核条件。"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.core.errors import ValidationError

CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}
SCOPE_ORDER = {"individual": 0, "local": 1, "area": 2}
LOCATION_TYPES = ("water", "meadow", "forest_edge")
CONFIDENCE_LEVELS = ("low", "medium", "high")
IMPACT_SCOPES = ("individual", "local", "area")

# 复核项中允许由独立复核人授予的部分；其余由处置流程自动满足。
REVIEW_GRANTABLE = ("reviewer_signoff", "follow_up_check", "second_reviewer")

DEFAULT_RULES: dict[str, Any] = {
    "version": "2026.1",
    "levels": [
        {"code": "P1", "name": "一级·紧急", "respond_minutes": 30, "resolve_minutes": 240},
        {"code": "P2", "name": "二级·高", "respond_minutes": 120, "resolve_minutes": 1440},
        {"code": "P3", "name": "三级·常规", "respond_minutes": 1440, "resolve_minutes": 4320},
        {"code": "P4", "name": "观察·待补证", "respond_minutes": 2880, "resolve_minutes": 10080},
    ],
    # 按顺序匹配第一条全部成立的规则。
    "grading": [
        {"id": "area-outbreak", "when": {"impact_scope": "area"}, "confidence_min": "medium", "level": "P1"},
        {"id": "water-quality-shock", "when": {"location_type": "water", "report_type": "water_quality"}, "confidence_min": "medium", "level": "P1"},
        {"id": "high-confidence-local", "when": {"impact_scope": "local"}, "confidence_min": "high", "level": "P2"},
        {"id": "human-intrusion", "when": {"report_type": "human_intrusion"}, "confidence_min": "medium", "impact_scope_min": "local", "level": "P2"},
        {"id": "injured-wildlife", "when": {"report_type": "injured_wildlife"}, "confidence_min": "medium", "level": "P3"},
        {"id": "thin-clue", "when": {}, "confidence": "low", "level": "P4"},
        {"id": "fallback", "when": {}, "level": "P3"},
    ],
    "await_evidence_level": "P4",
    "await_evidence_expire_minutes": 4320,
    "duplicate_window_minutes": 360,
    "review_requirements": {
        "P1": ["assignee_accepted", "field_conclusion", "follow_up_check", "second_reviewer"],
        "P2": ["assignee_accepted", "field_conclusion", "reviewer_signoff"],
        "P3": ["field_conclusion", "reviewer_signoff"],
        "P4": ["reviewer_signoff"],
    },
    "escalation": [
        {"level": "P2", "trigger": "respond_overdue", "to_level": "P1"},
        {"level": "P3", "trigger": "respond_overdue", "to_level": "P2"},
        {"level": "P1", "trigger": "respond_overdue", "notify": ["duty_officer", "reserve-director"]},
    ],
}


def default_rules() -> dict[str, Any]:
    return deepcopy(DEFAULT_RULES)


def level_codes(rules: dict[str, Any]) -> list[str]:
    return [item["code"] for item in rules["levels"]]


def level_map(rules: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["code"]: item for item in rules["levels"]}


def level_rank(rules: dict[str, Any], code: str) -> int:
    codes = level_codes(rules)
    if code not in codes:
        raise ValidationError(f"未知事件等级：{code}")
    return codes.index(code)


def grade_incident(
    rules: dict[str, Any],
    *,
    location_type: str,
    report_type: str,
    confidence: str,
    impact_scope: str,
) -> tuple[str, str]:
    """按规则矩阵分级，返回 (等级代码, 命中规则 id)。"""
    facts = {"location_type": location_type, "report_type": report_type, "confidence": confidence, "impact_scope": impact_scope}
    for rule in rules["grading"]:
        if any(facts.get(key) != value for key, value in rule.get("when", {}).items()):
            continue
        if "confidence" in rule and confidence != rule["confidence"]:
            continue
        if "confidence_min" in rule and CONFIDENCE_ORDER[confidence] < CONFIDENCE_ORDER[rule["confidence_min"]]:
            continue
        if "impact_scope_min" in rule and SCOPE_ORDER[impact_scope] < SCOPE_ORDER[rule["impact_scope_min"]]:
            continue
        return rule["level"], rule.get("id", "")
    raise ValidationError("分级规则没有任何可命中的兜底条目")


def validate_rules(rules: dict[str, Any]) -> None:
    version = str(rules.get("version", "")).strip()
    if not 3 <= len(version) <= 40:
        raise ValidationError("规则版本号必须为 3-40 个字符")
    levels = rules.get("levels")
    if not isinstance(levels, list) or not levels:
        raise ValidationError("规则至少需要一个事件等级")
    codes: set[str] = set()
    for item in levels:
        code = item.get("code")
        if not isinstance(code, str) or not code:
            raise ValidationError("事件等级缺少 code")
        if code in codes:
            raise ValidationError(f"事件等级重复：{code}")
        codes.add(code)
        for field in ("respond_minutes", "resolve_minutes"):
            value = item.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValidationError(f"等级 {code} 的 {field} 必须为正整数")
        if not item.get("name"):
            raise ValidationError(f"等级 {code} 缺少名称")

    grading = rules.get("grading")
    if not isinstance(grading, list) or not grading:
        raise ValidationError("分级规则不能为空")
    for rule in grading:
        if rule.get("level") not in codes:
            raise ValidationError(f"分级规则 {rule.get('id', '?')} 引用了未定义等级")
        when = rule.get("when", {})
        if not isinstance(when, dict):
            raise ValidationError("分级条件 when 必须是对象")
        if "location_type" in when and when["location_type"] not in LOCATION_TYPES:
            raise ValidationError("分级条件中的 location_type 不合法")
        if "confidence_min" in rule and rule["confidence_min"] not in CONFIDENCE_LEVELS:
            raise ValidationError("分级条件中的 confidence_min 不合法")
        if "confidence" in rule and rule["confidence"] not in CONFIDENCE_LEVELS:
            raise ValidationError("分级条件中的 confidence 不合法")
        if "impact_scope_min" in rule and rule["impact_scope_min"] not in IMPACT_SCOPES:
            raise ValidationError("分级条件中的 impact_scope_min 不合法")

    requirements = rules.get("review_requirements", {})
    if not isinstance(requirements, dict):
        raise ValidationError("复核条件必须是对象")
    for code in codes:
        missing = [item for item in requirements.get(code, []) if item not in set(REVIEW_GRANTABLE) | {"assignee_accepted", "field_conclusion"}]
        if missing:
            raise ValidationError(f"等级 {code} 包含未知复核项：{', '.join(missing)}")

    for item in rules.get("escalation", []):
        if item.get("level") not in codes:
            raise ValidationError("升级规则引用了未定义等级")
        if item.get("trigger") != "respond_overdue":
            raise ValidationError("暂只支持 respond_overdue 升级触发")
        if "to_level" in item and item["to_level"] not in codes:
            raise ValidationError("升级目标等级未定义")

    await_level = rules.get("await_evidence_level")
    if await_level not in codes:
        raise ValidationError("待补证等级未定义")
    window = rules.get("duplicate_window_minutes")
    if not isinstance(window, int) or window <= 0:
        raise ValidationError("重复上报时间窗必须为正整数")
    expire = rules.get("await_evidence_expire_minutes")
    if not isinstance(expire, int) or expire <= 0:
        raise ValidationError("补证等待时限必须为正整数")
