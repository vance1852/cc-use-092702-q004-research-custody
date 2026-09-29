# 建立科研采样许可与保管链基础平台

本项目是一套可离线运行的 Python 服务端平台，供国家森林公园管理局、保护站、生态监测人员和巡护队管理野生动植物观察、采样标本、保护站资源、巡护路线、风险告警与处置工单。业务状态、角色权限、幂等结果和审计事件保存在 SQLite 中，可在单个 Linux 应用容器内运行。

## 目录

- src/collection_logistics/：保护站、巡护路线、应急资源、调拨计划和治理情景；
- src/taxonomy_lab/：调查协议、观察记录、异常复核、分析任务租约和生态结论；
- src/biosafety_ops/：园区监测、风险告警、处置工单和资源分配；
- src/custody_chain/：科研采样许可版本、物种/生境范围与数量上限、封签摘要、
  样本保管台账（采集、拆分、合并、借出、归还、销毁）和跨机构双方确认交接；
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
PYTHONPATH=src python3 -m custody_chain.acceptance --workspace .
~~~

四条命令会在临时 SQLite 数据库中完成保护站和路线登记、资源调拨、生态观察分析、风险处置，以及“现场封装→保护站暂存→实验室借出→销毁耗损→剩余归还→许可撤回”的许可与保管链贯通演练，不访问外部网络。

## 科研采样许可与保管链

src/custody_chain/ 把许可版本、物种/生境范围、数量上限、封签摘要和经手人串成只追加的记录：

- permit_versions、custody_ledger、custody_events 只 INSERT；修订新增版本行，撤回只置状态，历史不可覆盖（哈希链可检出篡改）；
- 拆分、合并在单事务内强制进出数量严格相等；销毁记录减少量；交接必须整件发出，部分移交先拆分；
- 借出、归还、跨机构交接为“提出→双方两人确认”两阶段，确认时一次写入出/入两条台账腿，任一失败整笔回滚（全有或全无），归还必须能追溯到原借入机构；
- 许可撤回只阻止此后的新采集和新操作，已登记的台账、交接和额度全部保留；
- 敏感物种的精确地点与许可联系人按角色最小披露：主管部门、审计、属地保护站可见，借出实验室等其他机构只见 REDACTED；
- GET /samples/{id} 一次返回来源许可版本（含范围内容 SHA-256）、当前责任方、余额与剩余额度；GET /samples/{id}/chain 返回逐笔台账与在途缺失交接；GET /transfers/missing 汇总所有缺失确认。

## HTTP 服务

~~~bash
PYTHONPATH=src python3 -m collection_logistics.api --database park.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m taxonomy_lab.api --database ecology.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m biosafety_ops.api --database safety.sqlite3 --host 127.0.0.1 --port 8082
PYTHONPATH=src python3 -m custody_chain.api --database custody.sqlite3 --host 127.0.0.1 --port 8083
~~~

服务提供浏览器无关的 JSON 接口和健康检查。进程重启后可以继续读取 SQLite 中的业务状态与审计历史。
