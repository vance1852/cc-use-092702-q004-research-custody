"""科研采样许可与保管链事务用例。

核心保证：
- 许可与保管历史只追加（permit_versions / custody_ledger / custody_events），
  代码路径没有 UPDATE/DELETE，撤回与修订只能新增记录；
- split / merge 在单事务内校验进出数量严格相等，destroy 记录减少量，
  loan / return / handover 必须整件提出、双方确认，确认时一次写入出/入两条
  台账腿，任一失败整笔回滚（全有或全无）；
- 许可撤回只把 permits.state 置为 revoked，阻止此后的新动作，历史行原样保留；
- 敏感物种地点与许可联系人按角色与机构归属最小披露。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from decimal import Decimal
from typing import Any, Mapping

from .clock import SystemClock, parse_utc, utc_text
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .models import OperationDraft, PermitDraft, CollectionDraft
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "authority": {"permit.write", "permit.revoke", "report.read"},
    "station": {"sample.collect", "custody.op", "transfer.propose", "transfer.confirm", "report.read"},
    "researcher": {"sample.collect", "custody.op", "transfer.propose", "transfer.confirm", "report.read"},
    "lab": {"custody.op", "transfer.propose", "transfer.confirm", "report.read"},
    "auditor": {"report.read", "audit.read"},
}

ZERO = Decimal("0")
SENSITIVE_REDACTION = "REDACTED"


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def dec(value: object) -> Decimal:
    return Decimal(str(value))


def num(value: Decimal) -> str:
    return format(value, "f")


class CustodyChainService:
    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return utc_text(self.clock.now())

    # ------------------------------------------------------------------ 用户

    def create_user(self, user_id: str, display_name: str, role: str, org: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed("未知角色")
        if not user_id.strip() or not display_name.strip() or not org.strip():
            raise ValidationFailed("用户编号、名称和机构不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO custody_users(user_id,display_name,role,org,created_at) VALUES(?,?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, org.strip(), self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("用户已经存在") from exc
        return {"user_id": user_id.strip(), "role": role, "org": org.strip()}

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM custody_users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound("用户不存在")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _user_in_org(self, user_id: str, permission: str, org: str) -> sqlite3.Row:
        user = self._require(user_id, permission)
        if user["org"] != org:
            raise Forbidden("只有当前责任方机构成员可以执行此操作")
        return user

    # ------------------------------------------------------------------ 审计

    def _audit(
        self,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
    ) -> str:
        previous = self.connection.execute(
            "SELECT event_hash FROM custody_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = "0" * 64 if previous is None else previous["event_hash"]
        body = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": payload,
            "created_at": self._now(),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        self.connection.execute(
            "INSERT INTO custody_events(entity_type,entity_id,event_type,actor_id,payload_json,"
            "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                entity_type,
                entity_id,
                event_type,
                actor_id,
                canonical_json(payload),
                previous_hash,
                event_hash,
                body["created_at"],
            ),
        )
        return event_hash

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute("SELECT * FROM custody_events ORDER BY event_id").fetchall()
        previous_hash = "0" * 64
        valid = True
        first_bad: int | None = None
        for row in rows:
            body = {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
                valid = False
                first_bad = row["event_id"]
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash, "first_invalid_event_id": first_bad}

    # ------------------------------------------------------------------ 台账

    def _ledger(
        self,
        *,
        event_type: str,
        correlation_id: str,
        sample_id: str,
        permit_id: str,
        change: Decimal,
        balance_after: Decimal,
        actor_id: str,
        custodian_id: str,
        counterparty_org: str | None = None,
        seal_digest: str | None = None,
        transfer_id: str | None = None,
        leg: str | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO custody_ledger(event_type,correlation_id,sample_id,permit_id,change_units,"
            "balance_after,counterparty_org,custodian_id,seal_digest,transfer_id,leg,payload_json,actor_id,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_type,
                correlation_id,
                sample_id,
                permit_id,
                num(change),
                num(balance_after),
                counterparty_org,
                custodian_id,
                seal_digest,
                transfer_id,
                leg,
                canonical_json(payload or {}),
                actor_id,
                self._now(),
            ),
        )

    # ------------------------------------------------------------------ 许可

    def _permit_row(self, permit_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM permits WHERE permit_id=?", (permit_id,)).fetchone()
        if row is None:
            raise NotFound("许可不存在")
        return row

    def _permit_version(self, permit_id: str, version: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM permit_versions WHERE permit_id=? AND version=?", (permit_id, version)
        ).fetchone()
        if row is None:
            raise NotFound(f"许可 {permit_id} 版本 {version} 不存在")
        return row

    def _current_permit_version(self, permit_id: str) -> sqlite3.Row:
        permit = self._permit_row(permit_id)
        return self._permit_version(permit_id, int(permit["current_version"]))

    def _require_active_permit(self, permit_id: str) -> sqlite3.Row:
        permit = self._permit_row(permit_id)
        if permit["state"] != "active":
            raise InvalidState("许可已撤回，不能再执行新动作")
        version = self._permit_version(permit_id, int(permit["current_version"]))
        now = self.clock.now()
        valid_from = parse_utc(version["valid_from"], "valid_from")
        if now < valid_from:
            raise InvalidState("许可尚未生效")
        if version["valid_until"]:
            if now > parse_utc(version["valid_until"], "valid_until"):
                raise InvalidState("许可已过有效期")
        return version

    @staticmethod
    def _permit_content(draft: PermitDraft) -> dict[str, Any]:
        return {
            "species": draft.species,
            "habitats": draft.habitats,
            "quantity_caps": {key: num(value) for key, value in draft.quantity_caps.items()},
            "sensitive_species": draft.sensitive_species,
            "holder_org": draft.holder_org,
            "contact_name": draft.contact_name,
            "contact_ref": draft.contact_ref,
            "valid_from": draft.valid_from,
            "valid_until": draft.valid_until,
            "note": draft.note,
        }

    def grant_permit(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "permit.write")
        draft = PermitDraft.from_dict(raw)
        if draft.version != 1:
            raise ValidationFailed("首次授予许可的 version 必须为 1")
        if draft.supersedes_version is not None:
            raise ValidationFailed("首次授予许可不能指定 supersedes_version")
        content = self._permit_content(draft)
        content_sha = digest(content)
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO permits(permit_id,current_version,state,created_at,updated_at) VALUES(?,1,'active',?,?)",
                    (draft.permit_id, now, now),
                )
                self.connection.execute(
                    "INSERT INTO permit_versions(permit_id,version,scope_json,quantity_caps_json,sensitive_species_json,"
                    "holder_org,contact_name,contact_ref,valid_from,valid_until,note,content_sha256,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        draft.permit_id,
                        1,
                        canonical_json({"species": draft.species, "habitats": draft.habitats}),
                        canonical_json(content["quantity_caps"]),
                        canonical_json(draft.sensitive_species),
                        draft.holder_org,
                        draft.contact_name,
                        draft.contact_ref,
                        draft.valid_from,
                        draft.valid_until,
                        draft.note,
                        content_sha,
                        actor["user_id"],
                        now,
                    ),
                )
                self._audit("permit", draft.permit_id, "permit.granted", actor["user_id"],
                            {"version": 1, "scope_hash": content_sha, "holder_org": draft.holder_org})
        except sqlite3.IntegrityError as exc:
            raise Conflict("许可编号已经存在") from exc
        return {"permit_id": draft.permit_id, "version": 1, "state": "active", "content_sha256": content_sha}

    def revise_permit(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "permit.write")
        draft = PermitDraft.from_dict(raw)
        permit = self._permit_row(draft.permit_id)
        if permit["state"] != "active":
            raise InvalidState("许可已撤回，不能再修订")
        current_version = int(permit["current_version"])
        if draft.version != current_version + 1:
            raise Conflict(f"新版本号必须是当前版本 {current_version} 的下一个版本")
        if draft.supersedes_version is not None and draft.supersedes_version != current_version:
            raise ValidationFailed("supersedes_version 必须等于当前版本")
        content = self._permit_content(draft)
        content_sha = digest(content)
        # 收紧额度不能低于历史已采集量：合法历史不因修订变成超额。
        usage_rows = self.connection.execute(
            "SELECT target_key,collected_units FROM permit_quota_usage WHERE permit_id=?",
            (draft.permit_id,),
        ).fetchall()
        for row in usage_rows:
            cap = draft.quantity_caps.get(row["target_key"])
            if cap is not None and cap < dec(row["collected_units"]):
                raise Conflict(f"额度键 {row['target_key']} 新上限不能低于已采集量 {row['collected_units']}")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO permit_versions(permit_id,version,scope_json,quantity_caps_json,sensitive_species_json,"
                    "holder_org,contact_name,contact_ref,valid_from,valid_until,note,content_sha256,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        draft.permit_id,
                        draft.version,
                        canonical_json({"species": draft.species, "habitats": draft.habitats}),
                        canonical_json(content["quantity_caps"]),
                        canonical_json(draft.sensitive_species),
                        draft.holder_org,
                        draft.contact_name,
                        draft.contact_ref,
                        draft.valid_from,
                        draft.valid_until,
                        draft.note,
                        content_sha,
                        actor["user_id"],
                        now,
                    ),
                )
                self.connection.execute(
                    "UPDATE permits SET current_version=?,updated_at=? WHERE permit_id=? AND current_version=?",
                    (draft.version, now, draft.permit_id, current_version),
                )
                self._audit("permit", draft.permit_id, "permit.revised", actor["user_id"],
                            {"version": draft.version, "supersedes_version": current_version, "scope_hash": content_sha})
        except sqlite3.IntegrityError as exc:
            raise Conflict("许可版本冲突") from exc
        return {"permit_id": draft.permit_id, "version": draft.version, "state": "active",
                "supersedes_version": current_version, "content_sha256": content_sha}

    def revoke_permit(self, actor_id: str, permit_id: str, expected_version: int, reason: str) -> dict[str, Any]:
        actor = self._require(actor_id, "permit.revoke")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationFailed("撤回原因不能为空")
        permit = self._permit_row(permit_id)
        if int(permit["current_version"]) != expected_version:
            raise Conflict("expected_version 与当前许可版本不一致")
        if permit["state"] == "revoked":
            raise InvalidState("许可已经处于撤回状态")
        now = self._now()
        with transaction(self.connection, immediate=True):
            updated = self.connection.execute(
                "UPDATE permits SET state='revoked',updated_at=? WHERE permit_id=? AND state='active'",
                (now, permit_id),
            )
            if updated.rowcount != 1:
                raise InvalidState("许可状态已被其他操作改变")
            self.connection.execute(
                "INSERT INTO permit_revocations(permit_id,version,reason,revoked_by,revoked_at) VALUES(?,?,?,?,?)",
                (permit_id, expected_version, reason.strip(), actor["user_id"], now),
            )
            self._audit("permit", permit_id, "permit.revoked", actor["user_id"],
                        {"version": expected_version, "reason": reason.strip()})
        # 撤回不删除任何历史：此前的采集、拆分、交接全部原样可查。
        return {"permit_id": permit_id, "state": "revoked", "version": expected_version, "revoked_at": now}

    # ------------------------------------------------------------------ 采集

    def collect_sample(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "sample.collect")
        draft = CollectionDraft.from_dict(raw)
        try:
            collected_at = parse_utc(draft.collected_at, "collected_at")
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        permit = self._permit_row(draft.permit_id)
        if permit["state"] != "active":
            raise InvalidState("许可已撤回，不能登记新采集")
        version = self._permit_version(draft.permit_id, draft.permit_version)
        if draft.permit_version != int(permit["current_version"]):
            raise InvalidState("必须按许可最新有效版本采集")
        if collected_at < parse_utc(version["valid_from"], "valid_from"):
            raise InvalidState("采集时间早于许可生效时间")
        if version["valid_until"] and collected_at > parse_utc(version["valid_until"], "valid_until"):
            raise InvalidState("采集时间晚于许可有效期")
        scope = json.loads(version["scope_json"])
        caps = json.loads(version["quantity_caps_json"])
        sensitive = json.loads(version["sensitive_species_json"])
        if draft.species not in scope["species"]:
            raise Forbidden(f"物种 {draft.species} 不在许可范围内")
        if draft.habitat not in scope["habitats"]:
            raise Forbidden(f"生境 {draft.habitat} 不在许可范围内")
        target_key = draft.species if draft.species in caps else draft.habitat
        if target_key not in caps:
            raise Forbidden("许可未给该物种或生境配置数量上限")
        cap = dec(caps[target_key])
        usage_row = self.connection.execute(
            "SELECT * FROM permit_quota_usage WHERE permit_id=? AND target_key=?",
            (draft.permit_id, target_key),
        ).fetchone()
        used = ZERO if usage_row is None else dec(usage_row["collected_units"])
        if usage_row is not None and usage_row["unit"] != draft.unit:
            raise Conflict(f"额度 {target_key} 的计量单位必须为 {usage_row['unit']}")
        if used + draft.quantity > cap:
            raise Conflict(f"超出许可剩余额度：上限 {num(cap)}，已采 {num(used)}，本次申请 {num(draft.quantity)}")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                if usage_row is None:
                    self.connection.execute(
                        "INSERT INTO permit_quota_usage(permit_id,target_key,unit,collected_units) VALUES(?,?,?,?)",
                        (draft.permit_id, target_key, draft.unit, num(draft.quantity)),
                    )
                else:
                    self.connection.execute(
                        "UPDATE permit_quota_usage SET collected_units=? WHERE permit_id=? AND target_key=?",
                        (num(used + draft.quantity), draft.permit_id, target_key),
                    )
                self.connection.execute(
                    "INSERT INTO samples(sample_id,permit_id,permit_version,species,habitat,unit,location,"
                    "location_detail,sensitive,collected_units,balance_units,reserved_units,custodian_org,"
                    "custodian_id,seal_digest,status,collected_by,collected_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        draft.sample_id,
                        draft.permit_id,
                        draft.permit_version,
                        draft.species,
                        draft.habitat,
                        draft.unit,
                        draft.location,
                        draft.location_detail,
                        1 if draft.species in sensitive else 0,
                        num(draft.quantity),
                        num(draft.quantity),
                        "0",
                        actor["org"],
                        draft.collector_id,
                        draft.seal_digest,
                        "active",
                        actor["user_id"],
                        draft.collected_at,
                        now,
                        now,
                    ),
                )
                self._ledger(
                    event_type="sample.collected",
                    correlation_id=draft.sample_id,
                    sample_id=draft.sample_id,
                    permit_id=draft.permit_id,
                    change=draft.quantity,
                    balance_after=draft.quantity,
                    actor_id=actor["user_id"],
                    custodian_id=draft.collector_id,
                    seal_digest=draft.seal_digest,
                    payload={"species": draft.species, "habitat": draft.habitat, "location": draft.location,
                             "location_detail": draft.location_detail, "permit_version": draft.permit_version,
                             "collected_at": draft.collected_at},
                )
                self._audit("sample", draft.sample_id, "sample.collected", actor["user_id"],
                            {"permit_id": draft.permit_id, "permit_version": draft.permit_version,
                             "species": draft.species, "habitat": draft.habitat, "quantity": num(draft.quantity),
                             "unit": draft.unit, "seal_digest": draft.seal_digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("样本编号已经存在或引用不存在") from exc
        return {"sample_id": draft.sample_id, "state": "active", "balance_units": num(draft.quantity),
                "custodian_org": actor["org"], "quota_remaining": num(cap - used - draft.quantity)}

    # ------------------------------------------------------- 拆分/合并/销毁

    def _locked_sample(self, sample_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM samples WHERE sample_id=? ", (sample_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"样本 {sample_id} 不存在")
        return row

    @staticmethod
    def _parts_total(parts: list) -> Decimal:
        return sum((part.quantity for part in parts), ZERO)

    def _replayable_operation(self, operation_id: str, request_sha: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,result_json FROM operations WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_sha:
            raise Conflict("操作编号对应不同的请求内容")
        return json.loads(row["result_json"])

    def apply_operation(self, actor_id: str, kind: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "custody.op")
        draft = OperationDraft.from_dict(raw, kind)
        request_sha = digest({"kind": kind, "raw": raw})
        replay = self._replayable_operation(draft.operation_id, request_sha)
        if replay is not None:
            return replay
        if not draft.inputs:
            raise ValidationFailed("至少需要一个输入样本")
        input_rows = [self._locked_sample(part.sample_id) for part in draft.inputs]
        for row, part in zip(input_rows, draft.inputs):
            self._require_active_permit(row["permit_id"])
            if row["custodian_org"] != actor["org"]:
                raise Forbidden(f"样本 {row['sample_id']} 不在当前责任方机构名下")
            if row["status"] != "active":
                raise InvalidState(f"样本 {row['sample_id']} 状态为 {row['status']}，不可操作")
            if dec(row["reserved_units"]) != 0:
                raise InvalidState(f"样本 {row['sample_id']} 存在未完成交接，不能操作")
            if dec(row["balance_units"]) < part.quantity:
                raise Conflict(f"样本 {row['sample_id']} 余额不足")
            # 拆分与合并必须整件参与：要分出一部分，就把整件余额全部拆成输出，
            # 原样本耗尽；部分耗损只能通过 destroy 登记。
            if kind in ("split", "merge") and part.quantity != dec(row["balance_units"]):
                raise InvalidState(
                    f"样本 {row['sample_id']} 的拆分/合并数量必须等于当前余额 {row['balance_units']}；"
                    "部分耗损请登记销毁"
                )
        permit_ids = {row["permit_id"] for row in input_rows}
        units = {row["unit"] for row in input_rows}
        species_set = {row["species"] for row in input_rows}
        habitats = {row["habitat"] for row in input_rows}
        if len(permit_ids) != 1:
            raise ValidationFailed("一次操作只能处理同一许可下的样本")
        if len(units) != 1:
            raise ValidationFailed("一次操作中的样本计量单位必须一致")
        permit_id = input_rows[0]["permit_id"]
        unit = input_rows[0]["unit"]
        in_total = self._parts_total(draft.inputs)
        out_total = self._parts_total(draft.outputs)
        now = self._now()

        if kind == "split":
            if len(draft.inputs) != 1 or len(draft.outputs) < 2:
                raise ValidationFailed("拆分必须有一个输入和至少两个输出")
            if out_total != in_total:
                raise Conflict(f"拆分不守恒：输入 {num(in_total)}，输出合计 {num(out_total)}")
        elif kind == "merge":
            if len(draft.inputs) < 2 or len(draft.outputs) != 1:
                raise ValidationFailed("合并必须有至少两个输入和一个输出")
            if out_total != in_total:
                raise Conflict(f"合并不守恒：输入合计 {num(in_total)}，输出 {num(out_total)}")
            if len(species_set) != 1 or len(habitats) != 1:
                raise ValidationFailed("不允许跨物种或跨生境合并")
        elif kind == "destroy":
            if draft.outputs:
                raise ValidationFailed("销毁不能产生输出样本")
            if len(draft.inputs) != 1:
                raise ValidationFailed("销毁只能指定一个输入样本")
        if draft.seal_digest is None and kind in ("split", "merge"):
            raise ValidationFailed("拆分与合并必须提供新封签摘要")

        existing_outputs = [
            row["sample_id"] for row in self.connection.execute(
                f"SELECT sample_id FROM samples WHERE sample_id IN ({','.join('?' for _ in draft.outputs)})",
                [part.sample_id for part in draft.outputs],
            ).fetchall()
        ]
        if existing_outputs:
            raise Conflict(f"输出样本编号已经存在：{', '.join(existing_outputs)}")

        result: dict[str, Any] = {"operation_id": draft.operation_id, "kind": kind, "balances": {}}
        with transaction(self.connection, immediate=True):
            template = input_rows[0]
            # 输入样本扣减
            for row, part in zip(input_rows, draft.inputs):
                new_balance = dec(row["balance_units"]) - part.quantity
                status = "active"
                if kind == "destroy":
                    status = "destroyed" if new_balance == 0 else "active"
                elif new_balance == 0:
                    status = "depleted"
                self.connection.execute(
                    "UPDATE samples SET balance_units=?,status=?,revision=revision+1,updated_at=? "
                    "WHERE sample_id=? AND revision=?",
                    (num(new_balance), status, now, row["sample_id"], row["revision"]),
                )
                event_type = {"split": "sample.split", "merge": "sample.merged", "destroy": "sample.destroyed"}[kind]
                self._ledger(
                    event_type=event_type,
                    correlation_id=draft.operation_id,
                    sample_id=row["sample_id"],
                    permit_id=row["permit_id"],
                    change=-part.quantity,
                    balance_after=new_balance,
                    actor_id=actor["user_id"],
                    custodian_id=draft.custodian_id,
                    seal_digest=draft.seal_digest,
                    payload={"kind": kind, "unit": unit},
                )
                result["balances"][row["sample_id"]] = num(new_balance)
            # 输出样本创建（split / merge）
            for part in draft.outputs:
                self.connection.execute(
                    "INSERT INTO samples(sample_id,permit_id,permit_version,species,habitat,unit,location,"
                    "location_detail,sensitive,collected_units,balance_units,reserved_units,custodian_org,"
                    "custodian_id,seal_digest,status,collected_by,collected_at,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        part.sample_id,
                        permit_id,
                        template["permit_version"],
                        template["species"],
                        template["habitat"],
                        unit,
                        template["location"],
                        template["location_detail"],
                        template["sensitive"],
                        "0",
                        num(part.quantity),
                        "0",
                        actor["org"],
                        draft.custodian_id,
                        draft.seal_digest,
                        "active",
                        actor["user_id"],
                        now,
                        now,
                        now,
                    ),
                )
                self._ledger(
                    event_type="sample.split" if kind == "split" else "sample.merged",
                    correlation_id=draft.operation_id,
                    sample_id=part.sample_id,
                    permit_id=permit_id,
                    change=part.quantity,
                    balance_after=part.quantity,
                    actor_id=actor["user_id"],
                    custodian_id=draft.custodian_id,
                    seal_digest=draft.seal_digest,
                    payload={"kind": kind, "unit": unit, "derived_from": [r["sample_id"] for r in input_rows]},
                )
                result["balances"][part.sample_id] = num(part.quantity)
            result["conservation"] = {
                "input_total": num(in_total),
                "output_total": num(ZERO if kind == "destroy" else out_total),
                "destroyed_total": num(in_total if kind == "destroy" else ZERO),
                "balanced": kind == "destroy" or in_total == out_total,
            }
            self.connection.execute(
                "INSERT INTO operations(operation_id,kind,request_sha256,idempotency_key,result_json,actor_id,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (draft.operation_id, kind, request_sha, draft.idempotency_key,
                 canonical_json(result), actor["user_id"], now),
            )
            self._audit("operation", draft.operation_id, f"sample.{kind}" if kind != "destroy" else "sample.destroyed",
                        actor["user_id"],
                        {"inputs": [(p.sample_id, num(p.quantity)) for p in draft.inputs],
                         "outputs": [(p.sample_id, num(p.quantity)) for p in draft.outputs],
                         "conservation": result["conservation"]})
        return result

    # ------------------------------------------------------------- 跨机构交接

    def propose_transfer(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "transfer.propose")
        transfer_id = raw.get("transfer_id")
        if not isinstance(transfer_id, str) or not transfer_id.strip():
            raise ValidationFailed("transfer_id 不能为空")
        direction = raw.get("direction", "loan")
        if direction not in ("loan", "return", "handover"):
            raise ValidationFailed("direction 必须是 loan、return 或 handover")
        destination_org = raw.get("destination_org")
        if not isinstance(destination_org, str) or not destination_org.strip():
            raise ValidationFailed("destination_org 不能为空")
        destination_org = destination_org.strip()
        custodian_id = raw.get("custodian_id")
        if not isinstance(custodian_id, str) or not custodian_id.strip():
            raise ValidationFailed("发出方经手人 custodian_id 不能为空")
        seal = raw.get("seal_digest")
        if seal is not None:
            from .models import seal_digest as parse_seal
            seal = parse_seal(seal)
        parts_raw = raw.get("parts")
        if not isinstance(parts_raw, list) or not parts_raw:
            raise ValidationFailed("parts 必须是非空数组")
        parts: list[dict[str, Any]] = []
        for item in parts_raw:
            if not isinstance(item, Mapping):
                raise ValidationFailed("parts 元素必须是对象")
            sid = item.get("sample_id")
            qty = quantity_field(item.get("quantity"))
            parts.append({"sample_id": str(sid), "quantity": qty})
        idem = raw.get("idempotency_key")
        proposal = {
            "direction": direction,
            "parts": [{"sample_id": p["sample_id"], "quantity": num(p["quantity"])} for p in parts],
            "seal_digest": seal,
            "note": raw.get("note"),
            "custodian_id": custodian_id.strip(),
        }
        request_sha = digest({"raw": raw})
        existing = self.connection.execute(
            "SELECT state,request_sha256,proposal_json FROM transfers WHERE transfer_id=?", (transfer_id,)
        ).fetchone()
        if existing is not None:
            if existing["request_sha256"] != request_sha:
                raise Conflict("交接编号对应不同的请求内容")
            return {"transfer_id": transfer_id, "state": existing["state"], "replayed": True}

        sample_rows = []
        for part in parts:
            row = self._locked_sample(part["sample_id"])
            self._require_active_permit(row["permit_id"])
            if row["custodian_org"] != actor["org"]:
                raise Forbidden(f"样本 {row['sample_id']} 不在当前责任方机构名下")
            if row["status"] != "active":
                raise InvalidState(f"样本 {row['sample_id']} 状态为 {row['status']}，不可交接")
            if dec(row["reserved_units"]) != 0:
                raise InvalidState(f"样本 {row['sample_id']} 已有在途交接")
            if part["quantity"] != dec(row["balance_units"]):
                raise InvalidState(
                    f"样本 {row['sample_id']} 必须整件交接（余额 {row['balance_units']}）；部分移交请先拆分"
                )
            sample_rows.append(row)
        if destination_org == actor["org"]:
            raise ValidationFailed("跨机构交接的接收方不能与发出方相同")
        destination_users = self.connection.execute(
            "SELECT count(*) FROM custody_users WHERE org=? AND active=1", (destination_org,)
        ).fetchone()[0]
        if not destination_users:
            raise ValidationFailed(f"接收机构 {destination_org} 没有在册的活跃用户，无法完成双方确认")
        if direction == "return":
            for row in sample_rows:
                prior = self.connection.execute(
                    "SELECT counterparty_org FROM custody_ledger WHERE sample_id=? AND leg='in' "
                    "ORDER BY entry_id DESC LIMIT 1",
                    (row["sample_id"],),
                ).fetchone()
                if prior is None or prior["counterparty_org"] != destination_org:
                    raise InvalidState(f"样本 {row['sample_id']} 没有从 {destination_org} 借入的记录，不能归还")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO transfers(transfer_id,direction,proposal_json,request_sha256,state,origin_org,"
                    "destination_org,proposed_by,proposed_at,idempotency_key) VALUES(?,?,?,?,'proposed',?,?,?,?,?)",
                    (transfer_id, direction, canonical_json(proposal), request_sha, actor["org"],
                     destination_org, actor["user_id"], now, idem),
                )
                for row, part in zip(sample_rows, parts):
                    self.connection.execute(
                        "UPDATE samples SET reserved_units=balance_units,revision=revision+1,updated_at=? "
                        "WHERE sample_id=? AND revision=?",
                        (now, row["sample_id"], row["revision"]),
                    )
                self._audit("transfer", transfer_id, "transfer.proposed", actor["user_id"],
                            {"direction": direction, "origin_org": actor["org"], "destination_org": destination_org,
                             "parts": proposal["parts"], "seal_digest": seal})
        except sqlite3.IntegrityError as exc:
            raise Conflict("交接编号或幂等键冲突") from exc
        return {"transfer_id": transfer_id, "state": "proposed", "direction": direction,
                "origin_org": actor["org"], "destination_org": destination_org, "parts": proposal["parts"]}

    def _transfer_or_404(self, transfer_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM transfers WHERE transfer_id=?", (transfer_id,)).fetchone()
        if row is None:
            raise NotFound("交接单不存在")
        return row

    def confirm_transfer(
        self,
        actor_id: str,
        transfer_id: str,
        receiving_custodian_id: str,
        receiving_seal_digest: str,
    ) -> dict[str, Any]:
        actor = self._require(actor_id, "transfer.confirm")
        from .models import seal_digest as parse_seal
        seal = parse_seal(receiving_seal_digest)
        transfer = self._transfer_or_404(transfer_id)
        if transfer["state"] != "proposed":
            raise InvalidState(f"交接单状态为 {transfer['state']}，不能确认")
        if actor["org"] != transfer["destination_org"]:
            raise Forbidden("只有接收方机构成员可以确认接收")
        if actor["user_id"] == transfer["proposed_by"]:
            raise Forbidden("交接必须由不同的两个人完成双方确认")
        receiver = self._user(receiving_custodian_id)
        if receiver["org"] != transfer["destination_org"]:
            raise Forbidden("接收经手人必须属于接收方机构")
        proposal = json.loads(transfer["proposal_json"])
        parts = proposal["parts"]
        # 撤回只阻止尚未发生的动作：确认前许可仍须有效。
        sample_rows = []
        for part in parts:
            row = self._locked_sample(part["sample_id"])
            self._require_active_permit(row["permit_id"])
            qty = dec(part["quantity"])
            if dec(row["reserved_units"]) != qty or dec(row["balance_units"]) != qty:
                raise InvalidState(f"样本 {row['sample_id']} 的预留或余额与交接提案不一致")
            if row["custodian_org"] != transfer["origin_org"]:
                raise InvalidState(f"样本 {row['sample_id']} 当前责任方与交接发出方不一致")
            sample_rows.append(row)
        event_name = {"loan": "sample.loaned", "return": "sample.returned", "handover": "sample.handed_over"}
        now = self._now()
        with transaction(self.connection, immediate=True):
            for row, part in zip(sample_rows, parts):
                qty = dec(part["quantity"])
                # 出腿：发出方余额视角归零
                self._ledger(
                    event_type=event_name[transfer["direction"]],
                    correlation_id=transfer_id,
                    sample_id=row["sample_id"],
                    permit_id=row["permit_id"],
                    change=-qty,
                    balance_after=ZERO,
                    actor_id=transfer["proposed_by"],
                    custodian_id=proposal["custodian_id"],
                    counterparty_org=transfer["destination_org"],
                    seal_digest=proposal["seal_digest"],
                    transfer_id=transfer_id,
                    leg="out",
                    payload={"org": transfer["origin_org"], "unit": row["unit"]},
                )
                # 入腿：接收方视角持有全额，与出腿严格配对，合计变化为 0。
                self._ledger(
                    event_type=event_name[transfer["direction"]],
                    correlation_id=transfer_id,
                    sample_id=row["sample_id"],
                    permit_id=row["permit_id"],
                    change=qty,
                    balance_after=qty,
                    actor_id=actor["user_id"],
                    custodian_id=receiving_custodian_id,
                    counterparty_org=transfer["origin_org"],
                    seal_digest=seal,
                    transfer_id=transfer_id,
                    leg="in",
                    payload={"org": transfer["destination_org"], "unit": row["unit"]},
                )
                self.connection.execute(
                    "UPDATE samples SET custodian_org=?,custodian_id=?,seal_digest=?,reserved_units='0',"
                    "revision=revision+1,updated_at=? WHERE sample_id=? AND revision=?",
                    (transfer["destination_org"], receiving_custodian_id, seal, now,
                     row["sample_id"], row["revision"]),
                )
            updated = self.connection.execute(
                "UPDATE transfers SET state='confirmed',confirmed_by=?,confirmed_at=?,receiving_seal_digest=? "
                "WHERE transfer_id=? AND state='proposed'",
                (actor["user_id"], now, seal, transfer_id),
            )
            if updated.rowcount != 1:
                raise InvalidState("交接单状态已被其他操作改变")
            self._audit("transfer", transfer_id, "transfer.confirmed", actor["user_id"],
                        {"origin_org": transfer["origin_org"], "destination_org": transfer["destination_org"],
                         "parts": parts, "issued_seal_digest": proposal["seal_digest"],
                         "receiving_seal_digest": seal, "legs": len(parts) * 2})
        return {"transfer_id": transfer_id, "state": "confirmed", "confirmed_at": now,
                "custodian_org": transfer["destination_org"], "custodian_id": receiving_custodian_id}

    def reject_transfer(self, actor_id: str, transfer_id: str, reason: str) -> dict[str, Any]:
        actor = self._require(actor_id, "transfer.confirm")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationFailed("拒绝原因不能为空")
        transfer = self._transfer_or_404(transfer_id)
        if transfer["state"] != "proposed":
            raise InvalidState(f"交接单状态为 {transfer['state']}，不能拒绝")
        if actor["org"] not in (transfer["origin_org"], transfer["destination_org"]):
            raise Forbidden("只有交接双方机构可以拒绝或撤销交接")
        proposal = json.loads(transfer["proposal_json"])
        sample_rows = [self._locked_sample(part["sample_id"]) for part in proposal["parts"]]
        now = self._now()
        with transaction(self.connection, immediate=True):
            for row in sample_rows:
                self.connection.execute(
                    "UPDATE samples SET reserved_units='0',revision=revision+1,updated_at=? "
                    "WHERE sample_id=? AND revision=?",
                    (now, row["sample_id"], row["revision"]),
                )
            updated = self.connection.execute(
                "UPDATE transfers SET state='rejected',rejection_reason=?,rejected_by=?,rejected_at=? "
                "WHERE transfer_id=? AND state='proposed'",
                (reason.strip(), actor["user_id"], now, transfer_id),
            )
            if updated.rowcount != 1:
                raise InvalidState("交接单状态已被其他操作改变")
            self._audit("transfer", transfer_id, "transfer.rejected", actor["user_id"],
                        {"rejection_reason": reason.strip(), "by_org": actor["org"]})
        return {"transfer_id": transfer_id, "state": "rejected", "rejected_at": now}

    # ------------------------------------------------------------------ 核对

    @staticmethod
    def _can_see_sensitive(viewer: sqlite3.Row, sample: sqlite3.Row, holder_org: str) -> bool:
        # 敏感物种精确地点按角色最小披露：主管部门、审计、属地保护站可见；
        # 采集团队仅在自己就是许可持有者时可见；借出实验室等其他责任方不可见。
        role = viewer["role"]
        if role in ("authority", "auditor", "station"):
            return True
        if role == "researcher":
            return viewer["org"] == holder_org
        return False

    def _sample_view(self, viewer: sqlite3.Row, sample: sqlite3.Row, version: sqlite3.Row) -> dict[str, Any]:
        can_see = self._can_see_sensitive(viewer, sample, version["holder_org"])
        sensitive = bool(sample["sensitive"])
        caps = json.loads(version["quantity_caps_json"])
        target_key = sample["species"] if sample["species"] in caps else sample["habitat"]
        cap = dec(caps[target_key])
        usage_row = self.connection.execute(
            "SELECT collected_units FROM permit_quota_usage WHERE permit_id=? AND target_key=?",
            (sample["permit_id"], target_key),
        ).fetchone()
        used = ZERO if usage_row is None else dec(usage_row["collected_units"])
        quota = {
            "target": target_key,
            "cap": num(cap),
            "collected": num(used),
            "remaining": num(cap - used),
        }
        view = {
            "sample_id": sample["sample_id"],
            "permit_id": sample["permit_id"],
            "permit_version": sample["permit_version"],
            "permit_scope_sha256": version["content_sha256"],
            "species": sample["species"],
            "habitat": sample["habitat"],
            "unit": sample["unit"],
            "sensitive": sensitive,
            "collected_at": sample["collected_at"],
            "collected_by": sample["collected_by"],
            "collected_units": sample["collected_units"],
            "balance_units": sample["balance_units"],
            "reserved_units": sample["reserved_units"],
            "status": sample["status"],
            "revision": sample["revision"],
            "current_custodian_org": sample["custodian_org"],
            "current_custodian_id": sample["custodian_id"],
            "seal_digest": sample["seal_digest"],
            "quota": quota,
        }
        if sensitive and not can_see:
            view["species"] = SENSITIVE_REDACTION
            view["quota"]["target"] = SENSITIVE_REDACTION
            view["location"] = SENSITIVE_REDACTION
            view["location_detail"] = SENSITIVE_REDACTION
            view["contact_disclosure"] = "redacted"
        else:
            view["location"] = sample["location"]
            view["location_detail"] = sample["location_detail"]
        return view

    def sample_status(self, actor_id: str, sample_id: str) -> dict[str, Any]:
        viewer = self._require(actor_id, "report.read")
        sample = self._locked_sample(sample_id)
        version = self._permit_version(sample["permit_id"], int(sample["permit_version"]))
        return self._sample_view(viewer, sample, version)

    def sample_chain(self, actor_id: str, sample_id: str) -> dict[str, Any]:
        viewer = self._require(actor_id, "report.read")
        sample = self._locked_sample(sample_id)
        version = self._permit_version(sample["permit_id"], int(sample["permit_version"]))
        rows = self.connection.execute(
            "SELECT entry_id,event_type,correlation_id,change_units,balance_after,counterparty_org,"
            "custodian_id,seal_digest,transfer_id,leg,actor_id,created_at FROM custody_ledger "
            "WHERE sample_id=? ORDER BY entry_id",
            (sample_id,),
        ).fetchall()
        can_see = self._can_see_sensitive(viewer, sample, version["holder_org"])
        entries = []
        for row in rows:
            entry = {
                "entry_id": row["entry_id"],
                "event_type": row["event_type"],
                "correlation_id": row["correlation_id"],
                "change_units": row["change_units"],
                "balance_after": row["balance_after"],
                "counterparty_org": row["counterparty_org"],
                "custodian_id": row["custodian_id"],
                "seal_digest": row["seal_digest"],
                "transfer_id": row["transfer_id"],
                "leg": row["leg"],
                "actor_id": row["actor_id"],
                "created_at": row["created_at"],
            }
            if not can_see and row["event_type"] == "sample.collected":
                entry["seal_digest"] = SENSITIVE_REDACTION if entry["seal_digest"] else None
            entries.append(entry)
        unpaired = self.connection.execute(
            "SELECT entry_id,leg,transfer_id FROM custody_ledger WHERE sample_id=? AND transfer_id IS NOT NULL "
            "AND transfer_id NOT IN (SELECT transfer_id FROM custody_ledger c2 WHERE c2.transfer_id IS NOT NULL "
            "GROUP BY transfer_id HAVING SUM(CASE WHEN leg='in' THEN 1 ELSE 0 END)>0 "
            "AND SUM(CASE WHEN leg='out' THEN 1 ELSE 0 END)>0)",
            (sample_id,),
        ).fetchall()
        pending_rows = self.connection.execute(
            "SELECT transfer_id,direction,origin_org,destination_org,proposed_by,proposed_at,proposal_json "
            "FROM transfers WHERE state='proposed' ORDER BY proposed_at"
        ).fetchall()
        pending = []
        for row in pending_rows:
            proposal = json.loads(row["proposal_json"])
            if any(part["sample_id"] == sample_id for part in proposal["parts"]):
                pending.append({
                    "transfer_id": row["transfer_id"],
                    "direction": row["direction"],
                    "origin_org": row["origin_org"],
                    "destination_org": row["destination_org"],
                    "proposed_by": row["proposed_by"],
                    "proposed_at": row["proposed_at"],
                    "missing_confirmation_from": row["destination_org"],
                })
        return {
            "sample": self._sample_view(viewer, sample, version),
            "ledger": entries,
            "pending_transfers": pending,
            "unpaired_transfer_entries": [dict(row) for row in unpaired],
        }

    def permit_status(self, actor_id: str, permit_id: str) -> dict[str, Any]:
        viewer = self._require(actor_id, "report.read")
        permit = self._permit_row(permit_id)
        version = self._permit_version(permit_id, int(permit["current_version"]))
        caps = json.loads(version["quantity_caps_json"])
        quotas = []
        for target, cap_text in sorted(caps.items()):
            usage_row = self.connection.execute(
                "SELECT collected_units,unit FROM permit_quota_usage WHERE permit_id=? AND target_key=?",
                (permit_id, target),
            ).fetchone()
            used = ZERO if usage_row is None else dec(usage_row["collected_units"])
            cap = dec(cap_text)
            quotas.append({
                "target": target,
                "unit": None if usage_row is None else usage_row["unit"],
                "cap": num(cap),
                "collected": num(used),
                "remaining": num(cap - used),
            })
        revocation = self.connection.execute(
            "SELECT version,reason,revoked_by,revoked_at FROM permit_revocations WHERE permit_id=?",
            (permit_id,),
        ).fetchone()
        sensitive_species = json.loads(version["sensitive_species_json"])
        # 联系人最小披露：许可涉及敏感物种时，仅主管部门、审计、属地保护站以及
        # 许可持有机构自身可见联系人；借出实验室等其他机构只能看到脱敏占位。
        contact_visible = viewer["role"] in ("authority", "auditor", "station") or (
            sensitive_species == [] or viewer["org"] == version["holder_org"]
        )
        if not contact_visible:
            contact = {"name": SENSITIVE_REDACTION, "ref": SENSITIVE_REDACTION, "disclosure": "redacted"}
        else:
            contact = {"name": version["contact_name"], "ref": version["contact_ref"]}
        return {
            "permit_id": permit_id,
            "state": permit["state"],
            "current_version": permit["current_version"],
            "scope": json.loads(version["scope_json"]),
            "sensitive_species": sensitive_species,
            "holder_org": version["holder_org"],
            "contact": contact,
            "valid_from": version["valid_from"],
            "valid_until": version["valid_until"],
            "quotas": quotas,
            "content_sha256": version["content_sha256"],
            "revocation": None if revocation is None else dict(revocation),
        }

    def missing_handovers(self, actor_id: str) -> dict[str, Any]:
        """缺失交接 = 已提出未确认的在途交接，以及台账上出腿/入腿不配对的记录。"""
        self._require(actor_id, "report.read")
        pending = self.connection.execute(
            "SELECT transfer_id,direction,origin_org,destination_org,proposed_by,proposed_at,proposal_json "
            "FROM transfers WHERE state='proposed' ORDER BY proposed_at"
        ).fetchall()
        pending_view = []
        for row in pending:
            proposal = json.loads(row["proposal_json"])
            pending_view.append({
                "transfer_id": row["transfer_id"],
                "direction": row["direction"],
                "origin_org": row["origin_org"],
                "destination_org": row["destination_org"],
                "proposed_by": row["proposed_by"],
                "proposed_at": row["proposed_at"],
                "parts": proposal["parts"],
                "missing_confirmation_from": row["destination_org"],
            })
        unpaired = self.connection.execute(
            "SELECT transfer_id, sample_id, leg, entry_id FROM custody_ledger "
            "WHERE transfer_id IS NOT NULL AND transfer_id IN ("
            "SELECT transfer_id FROM custody_ledger GROUP BY transfer_id "
            "HAVING SUM(CASE WHEN leg='out' THEN 1 ELSE 0 END) <> SUM(CASE WHEN leg='in' THEN 1 ELSE 0 END))"
        ).fetchall()
        return {
            "pending_transfers": pending_view,
            "unpaired_ledger_entries": [dict(row) for row in unpaired],
            "complete": not pending_view and not unpaired,
        }


def quantity_field(value: object) -> Decimal:
    from .models import quantity as parse_quantity
    return parse_quantity(value, "quantity")
