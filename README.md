# 建立科研采样许可与保管链基础平台

本项目是一套可离线运行的 Python 服务端平台，供国家森林公园管理局、保护站、生态监测人员和巡护队管理野生动植物观察、采样标本、保护站资源、巡护路线、风险告警与处置工单。业务状态、角色权限、幂等结果和审计事件保存在 SQLite 中，可在单个 Linux 应用容器内运行。

## 目录

- src/collection_logistics/：保护站、巡护路线、应急资源、调拨计划和治理情景；
- src/taxonomy_lab/：调查协议、观察记录、异常复核、分析任务租约和生态结论；
- src/biosafety_ops/：园区监测、风险告警、处置工单和资源分配；
- src/sample_chain/：科研采样许可版本、样本保管链、拆分合并、跨机构借出归还与销毁核账；
- fixtures/：离线验收使用的调查协议与结构化观察记录；
- tests/：领域规则、事务边界、权限、HTTP API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时只依赖 Python 标准库与 SQLite

## 测试

~~~bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
~~~

## 构建检查

~~~bash
python3 -m compileall -q src tests
~~~

## 离线验收

~~~bash
PYTHONPATH=src python3 -m collection_logistics.acceptance --workspace .
PYTHONPATH=src python3 -m taxonomy_lab.acceptance --workspace .
PYTHONPATH=src python3 -m biosafety_ops.acceptance
PYTHONPATH=src python3 -m sample_chain.acceptance --workspace .
~~~

前三条命令会在临时 SQLite 数据库中完成保护站和路线登记、资源调拨、生态观察分析与风险处置，不访问外部网络。`sample_chain` 验收则贯通许可签发、现场封装、保护站暂存、实验室借出、拆分销毁、剩余材料归还、许可撤回与数量核账。

## HTTP 服务

~~~bash
PYTHONPATH=src python3 -m collection_logistics.api --database park.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m taxonomy_lab.api --database ecology.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m biosafety_ops.api --database safety.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m sample_chain.api --database chain.sqlite3 --host 127.0.0.1 --port 8083
~~~

服务提供浏览器无关的 JSON 接口和健康检查。进程重启后可以继续读取 SQLite 中的业务状态与审计历史。

## 科研采样许可与保管链（sample_chain）

- 许可按 `(permit_id, version)` 不可变保存，含物种/生境范围、数量上限、有效期与文档 `sha256`；新版本可声明 `supersedes_version`，撤回只追加事件并阻止未来动作，不改动合法历史。
- 样本记录来源许可版本、范围、封签摘要、地点与经手人；采集即占用许可额度，超量或超出有效期被拒绝。
- 拆分、合并必须数量守恒（子项合计等于父项可用量）；借出、归还、调拨以整样本为单位并在确认时预留数量，部分数量先拆分。
- 跨机构交接为"发起 → 接收方封签核验确认"两阶段，明细整单原子生效（全有或全无），归还单须指回原借出单。
- 销毁需独立见证人，并计入守恒核账：采集总量 = 现存总量 + 已销毁总量。
- 敏感物种的地点与联系人按角色最小披露：管理局、审计、保护站及原始采集团队可见，借用实验室等其它机构得到 `***`。
- 所有写操作进入前向链接的 `chain_audit_events`（SHA-256），可经 `GET /audit/chain` 验证防篡改。

主要接口（请求头带 `X-Actor-Id`）：`POST /permits`、`POST /permits/{id}/{version}/revoke`、`GET /permits/{id}[/{version}]`、`POST /samples`、`POST /samples/split`、`POST /samples/merge`、`POST /samples/destroy`、`GET /samples/{id}/provenance`、`POST /handoffs`、`POST /handoffs/{id}/confirm|reject|cancel`、`GET /handoffs?state=proposed`、`GET /conservation`、`GET /audit/chain`。`provenance` 返回来源、当前责任方、剩余额度与缺失交接（待确认、逾期未还）。
