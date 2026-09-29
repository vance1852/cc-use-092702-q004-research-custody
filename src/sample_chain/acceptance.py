"""贯通许可版本、采集封装、跨机构交接、拆分合并、借出归还、销毁与核对的离线验收。"""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .clock import FrozenClock
from .service import SampleChainService


def _seal(letter: str) -> str:
    return "sha256:" + letter * 64


def run(workspace: Path) -> dict[str, object]:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    clock = FrozenClock(datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc))
    service = SampleChainService(connection, clock)

    # 机构与角色。
    service.create_user("admin", "管理局许可专员", "authority")
    for org_id, name, kind in (
        ("park-authority", "国家森林公园管理局", "authority"),
        ("station-north", "北部保护站", "station"),
        ("university-botany", "高校植物学团队", "university"),
        ("lab-genetic", "遗传分析实验室", "laboratory"),
    ):
        service.register_org("admin", org_id, name, kind)
    service.create_user("warden", "保护站值班员", "station", "station-north")
    service.create_user("leader", "高校采样领队", "researcher", "university-botany")
    service.create_user("analyst", "实验室分析师", "lab", "lab-genetic")
    service.create_user("auditor", "独立审计员", "auditor")

    # 许可：版本 1，含一个敏感物种上限 100g、一个常见树种上限 500g。
    permit_v1 = service.issue_permit(
        "admin",
        {
            "permit_id": "PRC-2026-BUFFER-07",
            "version": 1,
            "team_id": "university-botany",
            "title": "缓冲区珍稀兰科与建群树种叶片采样",
            "holder_contact": "领队 138-0000-0001",
            "scope": [
                {"key": "orchid-nobilis", "kind": "species", "label": "珍稀兰科", "unit": "g",
                 "cap_units": "100", "sensitive": True},
                {"key": "oak-fagaceae", "kind": "species", "label": "壳斗科建群树种", "unit": "g",
                 "cap_units": "500", "sensitive": False},
            ],
            "valid_from": "2026-09-01T00:00:00Z",
            "valid_until": "2026-10-31T23:59:59Z",
        },
    )

    # 现场封装：敏感物种 60g，记录封签摘要、地点与联系人。
    service.collect_sample(
        "leader",
        {
            "sample_id": "LEAF-ORCHID-0001",
            "permit_id": "PRC-2026-BUFFER-07",
            "permit_version": 1,
            "scope_key": "orchid-nobilis",
            "site_id": "BUFFER-GULLY-07",
            "site_label": "缓冲区七号沟",
            "site_detail": "加密 GPS 坐标（仅责任方与管理局可见）",
            "site_contact": "护林员 139-0000-0002",
            "quantity": "60",
            "seal_digest": _seal("a"),
            "collected_at": "2026-09-20T06:30:00Z",
            "idempotency_key": "collect-orchid-1",
        },
    )

    # 超量采集必须被阻止（累计将达 110g > 100g）。
    over_cap_blocked = False
    try:
        service.collect_sample(
            "leader",
            {
                "sample_id": "LEAF-ORCHID-0002",
                "permit_id": "PRC-2026-BUFFER-07",
                "permit_version": 1,
                "scope_key": "orchid-nobilis",
                "site_id": "BUFFER-GULLY-07",
                "site_label": "缓冲区七号沟",
                "quantity": "50",
                "seal_digest": _seal("b"),
                "collected_at": "2026-09-20T06:45:00Z",
                "idempotency_key": "collect-orchid-2",
            },
        )
    except Exception:
        over_cap_blocked = True

    # 高校 -> 保护站暂存（双方确认，封签不符时整单不生效）。
    service.propose_handoff(
        "leader",
        {
            "handoff_id": "HANDOFF-STATION-IN-01",
            "kind": "transfer",
            "to_org": "station-north",
            "to_contact": "保护站值班员",
            "note": "下山后保护站暂存",
            "lines": [{"sample_id": "LEAF-ORCHID-0001", "quantity": "60"}],
            "idempotency_key": "handoff-in-1",
        },
    )
    service.confirm_handoff(
        "warden", "HANDOFF-STATION-IN-01", {"LEAF-ORCHID-0001": _seal("a")}
    )

    # 保护站 -> 实验室借出，约定归还时间。
    clock.advance(hours=2)
    service.propose_handoff(
        "warden",
        {
            "handoff_id": "HANDOFF-LOAN-LAB-01",
            "kind": "loan",
            "to_org": "lab-genetic",
            "to_contact": "实验室收发室",
            "expected_return_at": "2026-09-25T00:00:00Z",
            "lines": [{"sample_id": "LEAF-ORCHID-0001", "quantity": "60"}],
            "idempotency_key": "handoff-loan-1",
        },
    )
    service.confirm_handoff(
        "analyst", "HANDOFF-LOAN-LAB-01", {"LEAF-ORCHID-0001": _seal("a")}
    )

    # 实验室拆分成 40g 待还 + 20g 制片分析。
    service.split_sample(
        "analyst",
        {
            "parent_sample_id": "LEAF-ORCHID-0001",
            "idempotency_key": "split-lab-1",
            "outputs": [
                {"sample_id": "LEAF-ORCHID-0001-R", "quantity": "40", "seal_digest": _seal("c")},
                {"sample_id": "LEAF-ORCHID-0001-D", "quantity": "20", "seal_digest": _seal("d")},
            ],
        },
    )
    # 20g 制片分析销毁，需独立见证人（高校领队）。
    service.destroy_sample(
        "analyst",
        {
            "destruction_id": "DESTROY-0001",
            "sample_id": "LEAF-ORCHID-0001-D",
            "quantity": "20",
            "reason": "切片制片与试剂反应后不可复用",
            "witness_id": "leader",
            "idempotency_key": "destroy-1",
        },
    )

    # 剩余 40g 归还原保护站（指向原借出单，双方确认）。
    clock.advance(days=2)
    service.propose_handoff(
        "analyst",
        {
            "handoff_id": "HANDOFF-RETURN-01",
            "kind": "return",
            "to_org": "station-north",
            "parent_handoff_id": "HANDOFF-LOAN-LAB-01",
            "note": "返还剩余叶片材料",
            "lines": [{"sample_id": "LEAF-ORCHID-0001-R", "quantity": "40"}],
            "idempotency_key": "handoff-return-1",
        },
    )
    service.confirm_handoff(
        "warden", "HANDOFF-RETURN-01", {"LEAF-ORCHID-0001-R": _seal("c")}
    )

    provenance = service.sample_provenance("auditor", "LEAF-ORCHID-0001-R")
    # 借用实验室只接触封签样本，对敏感地点与联系人必须脱敏；
    # 采集团队本人与管理局/审计可看明文。
    borrower_view = service.sample_provenance("analyst", "LEAF-ORCHID-0001-R")["sample"]
    collector_view = service.sample_provenance("leader", "LEAF-ORCHID-0001-R")["sample"]
    permit_view = service.permit_view("admin", "PRC-2026-BUFFER-07")

    # 许可撤回：只阻止未来动作，不抹历史。
    service.revoke_permit("admin", "PRC-2026-BUFFER-07", 1, "项目提前结题")
    post_revoke_blocked = False
    try:
        service.propose_handoff(
            "warden",
            {
                "handoff_id": "HANDOFF-AFTER-REVOKE",
                "kind": "loan",
                "to_org": "lab-genetic",
                "lines": [{"sample_id": "LEAF-ORCHID-0001-R", "quantity": "40"}],
                "idempotency_key": "handoff-after-revoke",
            },
        )
    except Exception:
        post_revoke_blocked = True

    result = {
        "status": "ok",
        "permit": {
            "permit_id": permit_v1["permit_id"],
            "document_sha256": permit_v1["document_sha256"],
            "scope": permit_view["scope"],
        },
        "over_cap_blocked": over_cap_blocked,
        "provenance": {
            "sample_id": provenance["sample"]["sample_id"],
            "source_permit_sha256": provenance["source"]["permit_document_sha256"],
            "current_responsible_party": provenance["sample"]["current_responsible_party"],
            "remaining_on_hand": provenance["sample"]["on_hand_quantity"],
            "lineage_events": [event["type"] for event in provenance["lineage"]],
            "handoffs": [(h["kind"], h["state"]) for h in provenance["handoffs"]],
        },
        "minimum_disclosure": {
            "borrower_site_label": borrower_view["site_label"],
            "borrower_redacted_fields": borrower_view.get("redacted"),
            "collector_site_label": collector_view["site_label"],
        },
        "post_revoke_blocked": post_revoke_blocked,
        "conservation": service.conservation_report("auditor"),
        "audit": service.audit_chain("auditor"),
        "workspace": workspace.name,
    }
    connection.close()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行科研采样许可与保管链服务离线验收")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    print(json.dumps(run(args.workspace), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
