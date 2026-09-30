# 城市生态运营服务

这是一个面向城市湿地保护团队的 Python 后端服务。项目提供本地 HTTP 接口、SQLite 持久化、身份与角色管理、审计记录、任务编排和可扩展的生态数据处理边界，便于在单机环境中保存运营状态并复核业务决定。

## 运行环境

- Python 3.11 或更高版本
- SQLite 3（使用 Python 标准库）

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据文件位于 `data/compute-operations.db`，可以复制 `.env.example` 后调整本地路径。

## 初始化与启动

```bash
python -m app.cli init-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康接口为 `GET /api/system/health`。所有状态变化都写入 SQLite，并由应用内事务保证关联记录的一致性。

## 测试

```bash
python -m pytest
```

测试覆盖参数校验、身份权限、事务边界、任务状态、失败恢复、审计写入和现有生态计算接口。

## 编译检查

```bash
python -m compileall -q app tests
```

## 本地验收

```bash
python -m app.cli check-db
python -m app.cli smoke
```

`check-db` 检查 SQLite 完整性和外键设置，`smoke` 在进程内调用健康接口并验证基础路由。项目不依赖外部数据库、消息队列或网络服务。

```bash
python -m app.cli incident-demo
```

`incident-demo` 演示异常响应：水质突变分级、重复上报关联、交叉升级与变更脉络校验。

## 异常响应服务

`app/incidents/` 提供保护中心异常（水质突变、游客闯入、受伤野生动物等）的分级响应能力。

- **分级**：按「地点类型 × 证据可信度 × 影响范围」匹配版本化规则矩阵，生成 P1–P4 事件，并写入响应时限 `response_due_at` 与处置时限 `resolve_due_at`。
- **低可信线索**：判为观察级（P4）进入 `awaiting_evidence`，设补证时限，不占用处置队列；补证后按累计证据自动重分级，只升不降。
- **重复上报**：同地点 + 同类型 + 同一去重键在时间窗内重复上报时关联原事件（`report_count` 累加），并可能因证据增强触发重分级。
- **处置流转**：派单 `/assign`、接单 `/accept`、转交 `/transfer`、升级 `/escalate`、现场结论 `/resolve`、复核 `/review`、关闭 `/close`、驳回 `/reject`；当前责任人记录在 `current_assignee`。
- **复核关闭**：每个等级在规则中定义复核条件（如 P1 需跟踪复核 + 二级复核，且两名复核人不能相同），未全部满足时关闭会被拒绝并返回缺失项。
- **超时处理**：`POST /api/incidents/overdue/process` 按事件各自规则版本对响应超时自动升级或通知，只触发一次；事件详情给出 `respond_overdue`/`resolve_overdue` 标记。
- **规则版本**：`GET/POST /api/incidents/rules/...` 管理不可覆盖的规则版本。事件创建时锁定 `rule_version` 与规则快照，历史事件永远按旧规则解释；处理中事件只能通过 `POST /api/incidents/events/{id}/switch-rules`（须 `confirm=true` 并说明原因）显式切换。
- **变更脉络**：每次创建、重复上报、重分级、派单、转交、升级、现场结论、复核、关闭、规则切换都写入 `incident_event_log`，条目以 `prev_hash`/`entry_hash` 串成哈希链；`GET /api/incidents/events/{id}/timeline` 返回脉络与 `verification`，任何篡改都会使校验失败。

