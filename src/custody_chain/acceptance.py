"""贯通科研采样许可、保管链、跨机构交接与最小披露的离线验收。

故事线：高校团队凭许可在缓冲区采集少量植物叶片，现场封签后移交保护站暂存，
保护站整件借出给实验室，实验室销毁分析耗损部分，剩余材料整件归还保护站；
随后许可被撤回，新采集被阻止但合法历史完整可核。
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from .clock import FrozenClock
from .errors import InvalidState
from .service import CustodyChainService


def seal(label: str) -> str:
    import hashlib
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def run(workspace: Path) -> dict[str, object]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    clock = FrozenClock(datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc))
    service = CustodyChainService(connection, clock)

    # 四方主体：主管部门、属地保护站、高校团队（许可持有者）、实验室。
    service.create_user("auth1", "林管局许可官", "authority", "林管局")
    service.create_user("station1", "保护站保管员", "station", "保护站A")
    service.create_user("team1", "高校团队领队", "researcher", "高校团队")
    service.create_user("lab1", "实验室接收员", "lab", "实验室B")

    # 1) 主管部门授予许可：两个物种、一个生境、分别设上限，其中一种为敏感物种。
    permit = service.grant_permit("auth1", {
        "permit_id": "P-2026-001",
        "version": 1,
        "species": ["SP-GINSENG", "SP-ORCHID"],
        "habitats": ["H-BROADLEAF"],
        "quantity_caps": {"SP-GINSENG": "50", "SP-ORCHID": "10"},
        "sensitive_species": ["SP-ORCHID"],
        "holder_org": "高校团队",
        "contact_name": "高校科研处李老师",
        "contact_ref": "+86-000-11112222",
        "valid_from": "2026-09-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "note": "缓冲区少量叶片采集",
    })

    # 2) 现场封装登记：20 克普通物种、5 克敏感物种，封签摘要入链。
    clock.advance(hours=2)
    collected_g = service.collect_sample("team1", {
        "sample_id": "S-LEAF-001",
        "permit_id": "P-2026-001",
        "permit_version": 1,
        "species": "SP-GINSENG",
        "habitat": "H-BROADLEAF",
        "quantity": "20",
        "unit": "g",
        "location": "缓冲区 3 号样线",
        "location_detail": "栎阔叶林缘西北 120m",
        "collected_at": "2026-09-20T09:40:00Z",
        "seal_digest": seal("field-seal-001"),
        "collector_id": "team1",
    })
    service.collect_sample("team1", {
        "sample_id": "S-LEAF-002",
        "permit_id": "P-2026-001",
        "permit_version": 1,
        "species": "SP-ORCHID",
        "habitat": "H-BROADLEAF",
        "quantity": "5",
        "unit": "g",
        "location": "缓冲区 7 号样线",
        "location_detail": "沟谷密林隐蔽点位",
        "collected_at": "2026-09-20T10:05:00Z",
        "seal_digest": seal("field-seal-002"),
        "collector_id": "team1",
    })

    # 3) 移交保护站暂存：团队发起、保护站确认（双方、两人、全有或全无）。
    clock.advance(hours=3)
    service.propose_transfer("team1", {
        "transfer_id": "T-HANDOVER-001",
        "direction": "handover",
        "destination_org": "保护站A",
        "custodian_id": "team1",
        "seal_digest": seal("field-seal-001"),
        "parts": [{"sample_id": "S-LEAF-001", "quantity": "20"}],
        "note": "当日送检暂存",
    })
    missing_during = service.missing_handovers("station1")
    assert len(missing_during["pending_transfers"]) == 1
    assert missing_during["complete"] is False
    service.confirm_transfer("station1", "T-HANDOVER-001", "station1", seal("station-seal-001"))
    # 敏感样本同样入站暂存。
    service.propose_transfer("team1", {
        "transfer_id": "T-HANDOVER-002",
        "direction": "handover",
        "destination_org": "保护站A",
        "custodian_id": "team1",
        "seal_digest": seal("field-seal-002"),
        "parts": [{"sample_id": "S-LEAF-002", "quantity": "5"}],
    })
    service.confirm_transfer("station1", "T-HANDOVER-002", "station1", seal("station-seal-002"))

    # 4) 保护站整件借出给实验室。
    clock.advance(days=1)
    service.propose_transfer("station1", {
        "transfer_id": "T-LOAN-001",
        "direction": "loan",
        "destination_org": "实验室B",
        "custodian_id": "station1",
        "seal_digest": seal("station-seal-001"),
        "parts": [{"sample_id": "S-LEAF-001", "quantity": "20"}],
    })
    service.confirm_transfer("lab1", "T-LOAN-001", "lab1", seal("lab-seal-001"))

    # 5) 实验室销毁分析耗损 8 克（数量守恒：余额 20 -> 12，销毁单独入账）。
    clock.advance(days=2)
    destroy = service.apply_operation("lab1", "destroy", {
        "operation_id": "O-DESTROY-001",
        "inputs": [{"sample_id": "S-LEAF-001", "quantity": "8"}],
        "outputs": [],
        "custodian_id": "lab1",
        "note": "制片与理化分析耗损",
    })
    assert destroy["balances"]["S-LEAF-001"] == "12"
    assert destroy["conservation"]["destroyed_total"] == "8"

    # 6) 剩余 12 克整件归还保护站；归还必须能追溯到此前的借入。
    clock.advance(days=1)
    service.propose_transfer("lab1", {
        "transfer_id": "T-RETURN-001",
        "direction": "return",
        "destination_org": "保护站A",
        "custodian_id": "lab1",
        "seal_digest": seal("lab-seal-001"),
        "parts": [{"sample_id": "S-LEAF-001", "quantity": "12"}],
    })
    service.confirm_transfer("station1", "T-RETURN-001", "station1", seal("station-seal-003"))

    # 7) 核对：当前责任方、剩余额度、缺失交接、守恒恒等式。
    status = service.sample_status("station1", "S-LEAF-001")
    assert status["current_custodian_org"] == "保护站A"
    assert status["balance_units"] == "12"
    # 一次核对即可拿到来源许可版本、当前责任方、剩余额度。
    assert status["permit_scope_sha256"] == permit["content_sha256"]
    assert status["quota"] == {"target": "SP-GINSENG", "cap": "50", "collected": "20", "remaining": "30"}
    permit_view = service.permit_status("auth1", "P-2026-001")
    quotas = {item["target"]: item for item in permit_view["quotas"]}
    assert quotas["SP-GINSENG"]["collected"] == "20"
    assert quotas["SP-GINSENG"]["remaining"] == "30"
    assert quotas["SP-ORCHID"]["remaining"] == "5"
    missing = service.missing_handovers("auth1")
    assert missing["complete"] is True

    chain = service.sample_chain("auth1", "S-LEAF-001")
    changes = sum(Decimal(row["change_units"]) for row in chain["ledger"])
    destroyed = sum(
        -Decimal(row["change_units"])
        for row in chain["ledger"]
        if row["event_type"] == "sample.destroyed"
    )
    # 采集 20 = 现存 12 + 销毁 8；交接出/入腿两两抵消。
    assert changes == Decimal("12")
    assert destroyed == Decimal("8")
    assert chain["pending_transfers"] == []
    assert chain["unpaired_transfer_entries"] == []

    # 8) 敏感物种最小披露：实验室看不到精确地点与物种名，保护站可以。
    lab_view = service.sample_status("lab1", "S-LEAF-002")
    assert lab_view["species"] == "REDACTED"
    assert lab_view["location"] == "REDACTED"
    station_view = service.sample_status("station1", "S-LEAF-002")
    assert station_view["species"] == "SP-ORCHID"
    assert station_view["location_detail"] == "沟谷密林隐蔽点位"
    lab_permit = service.permit_status("lab1", "P-2026-001")
    assert lab_permit["contact"]["name"] == "REDACTED"
    station_permit = service.permit_status("station1", "P-2026-001")
    assert station_permit["contact"]["name"] == "高校科研处李老师"

    # 9) 许可撤回：阻止尚未发生的动作，但不抹去合法历史。
    service.create_user("audit1", "独立审计员", "auditor", "审计署")
    audit_before = service.audit_chain("audit1")
    service.revoke_permit("auth1", "P-2026-001", 1, "项目终止，撤回采样许可")
    blocked = False
    try:
        service.collect_sample("team1", {
            "sample_id": "S-LEAF-003",
            "permit_id": "P-2026-001",
            "permit_version": 1,
            "species": "SP-GINSENG",
            "habitat": "H-BROADLEAF",
            "quantity": "1",
            "unit": "g",
            "location": "缓冲区 3 号样线",
            "collected_at": "2026-09-25T09:00:00Z",
            "seal_digest": seal("should-not-happen"),
            "collector_id": "team1",
        })
    except InvalidState:
        blocked = True
    assert blocked is True
    history_after = service.sample_chain("audit1", "S-LEAF-001")
    assert len(history_after["ledger"]) == len(chain["ledger"])
    revoked_view = service.permit_status("audit1", "P-2026-001")
    assert revoked_view["state"] == "revoked"
    assert revoked_view["revocation"]["reason"] == "项目终止，撤回采样许可"
    audit_after = service.audit_chain("audit1")
    assert audit_after["valid"] is True
    # 期间只有撤回事件入链，被阻止的采集不留任何记录。
    assert audit_after["events"] == audit_before["events"] + 1

    connection.close()
    return {
        "status": "ok",
        "workspace": workspace.name,
        "permit": {"permit_id": permit["permit_id"], "content_sha256": permit["content_sha256"]},
        "collected_ginseng_remaining_quota": quotas["SP-GINSENG"]["remaining"],
        "final_custodian": status["current_custodian_org"],
        "final_balance": status["balance_units"],
        "destroyed": str(destroyed),
        "missing_handovers_complete": missing["complete"],
        "sensitive_redacted_for_lab": lab_view["location"] == "REDACTED",
        "post_revocation_collect_blocked": blocked,
        "history_entries_preserved": len(history_after["ledger"]),
        "audit": audit_after,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行科研采样许可与保管链离线验收")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(json.dumps(run(args.workspace), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
