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

## 保护中心异常响应

`POST /api/anomaly/reports` 接收巡查员在水面、草甸和林缘的上报，按「地点类型 × 证据可信度 × 影响范围」矩阵叠加异常类型底线，生成 L1/L2/L3 分级事件并写入响应时限（默认 1440/240/60 分钟）与默认责任人。低可信线索进入待补证、不进派单队列；重复上报（指纹或 `related_incident_id`）并入原事件，`cross_incident_ids` 可把证据交叉关联到其他事件并触发交叉升级。

处置接口包括 `assign`、`transfer`、`acknowledge`、`escalate`、`conclude`、`recheck`、`senior-review`、`close`、`reject`。关闭前按事件绑定版本的复核要求校验（L2 需他人现场复核、L3 还需高级签批）；每次升级、转交、结论和规则版本切换都写入 `anomaly_timeline` 哈希链（`GET /api/anomaly/incidents/{id}/chain` 校验），数据库触发器禁止修改或删除脉络记录。

规则通过 `/api/anomaly/rule-versions` 整体发布；事件创建时绑定版本并保存分级快照，历史事件永远按旧规则解释，处理中事件须在 `POST /api/anomaly/incidents/{id}/rule-version` 中显式 `confirm` 才能切换。`GET /api/anomaly/dispatch-queue` 按等级和时限输出派单队列。

```bash
python -m app.cli anomaly-demo
```

该命令通过真实 HTTP 接口完成一组交叉升级与重复上报，并输出两个事件的等级、响应时限、当前责任人与哈希链校验结果。
