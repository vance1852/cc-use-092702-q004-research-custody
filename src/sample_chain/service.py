"""科研采样许可与样本保管链的事务用例。

记录只追加、不覆盖：许可版本、采集、拆分、合并、交接、销毁都写入哈希链审计；
数量在每次变换中保持守恒；跨机构交接必须双方确认且整单原子生效。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Mapping

from .clock import SystemClock, parse_utc, utc_text
from .errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from .models import (
    CollectionDraft,
    HandoffDraft,
    MergeDraft,
    PermitDraft,
    PermitScope,
    SplitDraft,
)
from .storage import initialize, transaction


QUANT = Decimal("0.001")
ZERO = Decimal("0")

ROLE_PERMISSIONS = {
    "authority": {"permit.write", "permit.revoke", "audit.read", "report.read", "chain.read"},
    "station": {"custody.move", "sample.dispose", "report.read", "chain.read"},
    "researcher": {
        "sample.collect",
        "sample.transform",
        "sample.dispose",
        "custody.move",
        "report.read",
        "chain.read",
    },
    "lab": {"sample.transform", "sample.dispose", "custody.move", "report.read", "chain.read"},
    "auditor": {"audit.read", "report.read", "chain.read"},
}

PRIVILEGED_ROLES = {"authority", "auditor"}


def q(value: Decimal) -> str:
    return format(value.quantize(QUANT, rounding=ROUND_HALF_UP), "f")


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class SampleChainService:
    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    # ------------------------------------------------------------------ 基础

    def _now(self) -> str:
        return utc_text(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM chain_users WHERE user_id=?", (user_id,)
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

    def _org(self, org_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM organizations WHERE org_id=?", (org_id,)
        ).fetchone()
        if row is None:
            raise NotFound("机构不存在")
        if not row["active"]:
            raise InvalidState("机构已停用")
        return row

    def _audit(
        self,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        previous = self.connection.execute(
            "SELECT event_hash FROM chain_audit_events ORDER BY event_id DESC LIMIT 1"
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
            "INSERT INTO chain_audit_events(entity_type,entity_id,event_type,actor_id,payload_json,"
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

    def _replay(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        stored = self.connection.execute(
            "SELECT request_sha256,response_json FROM chain_idempotency WHERE scope=? AND idempotency_key=?",
            (scope, key),
        ).fetchone()
        if stored is None:
            return None
        if stored["request_sha256"] != request_digest:
            raise Conflict("幂等键对应不同的请求内容")
        return json.loads(stored["response_json"])

    def _store_replay(self, scope: str, key: str, request_digest: str, response: Mapping[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO chain_idempotency(scope,idempotency_key,request_sha256,response_json,created_at) "
            "VALUES(?,?,?,?,?)",
            (scope, key, request_digest, canonical_json(response), self._now()),
        )

    def create_user(
        self, user_id: str, display_name: str, role: str, org_id: str | None = None
    ) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed("未知角色")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        if org_id is not None:
            self._org(org_id)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO chain_users(user_id,display_name,role,org_id,created_at) VALUES(?,?,?,?,?)",
                    (user_id.strip(), display_name.strip(), role, org_id, self._now()),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("用户已经存在") from exc
        return {"user_id": user_id.strip(), "role": role, "org_id": org_id}

    def register_org(self, actor_id: str, org_id: str, name: str, kind: str) -> dict[str, Any]:
        self._require(actor_id, "permit.write")
        if kind not in {"authority", "station", "university", "laboratory"}:
            raise ValidationFailed("kind 不是受支持的机构类型")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO organizations(org_id,name,kind,created_at) VALUES(?,?,?,?)",
                    (org_id, name, kind, self._now()),
                )
                self._audit("organization", org_id, "organization.registered", actor_id, {"name": name, "kind": kind})
        except sqlite3.IntegrityError as exc:
            raise Conflict("机构编号已经存在") from exc
        return {"org_id": org_id, "name": name, "kind": kind}

    # ------------------------------------------------------------------ 许可

    @staticmethod
    def _permit_document(draft: PermitDraft) -> dict[str, Any]:
        return {
            "permit_id": draft.permit_id,
            "version": draft.version,
            "team_id": draft.team_id,
            "title": draft.title,
            "holder_contact": draft.holder_contact,
            "scope": [scope.as_dict() for scope in draft.scopes],
            "valid_from": draft.valid_from,
            "valid_until": draft.valid_until,
            "supersedes_version": draft.supersedes_version,
        }

    def _permit_row(self, permit_id: str, version: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM permits WHERE permit_id=? AND version=?", (permit_id, version)
        ).fetchone()
        if row is None:
            raise NotFound("许可版本不存在")
        return row

    def issue_permit(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "permit.write")
        draft = PermitDraft.from_dict(raw)
        document = self._permit_document(draft)
        document_sha256 = digest(document)
        try:
            with transaction(self.connection, immediate=True):
                if draft.supersedes_version is not None:
                    previous = self.connection.execute(
                        "SELECT version FROM permits WHERE permit_id=? AND version=?",
                        (draft.permit_id, draft.supersedes_version),
                    ).fetchone()
                    if previous is None:
                        raise NotFound("被替代的许可版本不存在")
                self.connection.execute(
                    "INSERT INTO permits(permit_id,version,team_id,title,holder_contact,scope_json,"
                    "valid_from,valid_until,supersedes_version,document_sha256,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        draft.permit_id,
                        draft.version,
                        draft.team_id,
                        draft.title,
                        draft.holder_contact,
                        canonical_json([scope.as_dict() for scope in draft.scopes]),
                        draft.valid_from,
                        draft.valid_until,
                        draft.supersedes_version,
                        document_sha256,
                        actor_id,
                        self._now(),
                    ),
                )
                self._audit(
                    "permit",
                    f"{draft.permit_id}:{draft.version}",
                    "permit.issued",
                    actor_id,
                    {"document_sha256": document_sha256, "scope": document["scope"]},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("许可编号与版本已经存在") from exc
        return {
            "permit_id": draft.permit_id,
            "version": draft.version,
            "state": "active",
            "document_sha256": document_sha256,
        }

    def revoke_permit(self, actor_id: str, permit_id: str, version: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "permit.revoke")
        if not reason.strip():
            raise ValidationFailed("撤回原因不能为空")
        row = self._permit_row(permit_id, version)
        if row["state"] != "active":
            raise InvalidState("许可版本已经撤回")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE permits SET state='revoked',revoked_at=?,revoke_reason=?,revoked_by=? "
                "WHERE permit_id=? AND version=? AND state='active'",
                (self._now(), reason.strip(), actor_id, permit_id, version),
            )
            if cursor.rowcount != 1:
                raise InvalidState("许可状态已变化")
            # 撤回只追加事件，绝不修改或删除既有采集与交接历史。
            self._audit(
                "permit",
                f"{permit_id}:{version}",
                "permit.revoked",
                actor_id,
                {"reason": reason.strip()},
            )
        return {"permit_id": permit_id, "version": version, "state": "revoked"}

    @staticmethod
    def _scope_map(permit_row: sqlite3.Row) -> dict[str, PermitScope]:
        return {
            item["key"]: PermitScope(
                key=item["key"],
                kind=item["kind"],
                label=item["label"],
                unit=item["unit"],
                cap_units=Decimal(item["cap_units"]),
                sensitive=bool(item["sensitive"]),
            )
            for item in json.loads(permit_row["scope_json"])
        }

    def _quota_used(self, permit_id: str, version: int, scope_key: str) -> Decimal:
        """某许可版本下某范围的累计采集量；拆分与合并不重复计量。"""
        rows = self.connection.execute(
            "SELECT s.initial_quantity FROM samples s "
            "JOIN sample_lineage l ON l.child_sample_id=s.sample_id AND l.relation='collected' "
            "WHERE s.permit_id=? AND s.permit_version=? AND s.scope_key=?",
            (permit_id, version, scope_key),
        ).fetchall()
        return sum((Decimal(row["initial_quantity"]) for row in rows), ZERO)

    def permit_view(self, actor_id: str, permit_id: str, version: int | None = None) -> dict[str, Any]:
        viewer = self._require(actor_id, "report.read")
        if version is None:
            row = self.connection.execute(
                "SELECT * FROM permits WHERE permit_id=? ORDER BY version DESC LIMIT 1",
                (permit_id,),
            ).fetchone()
            if row is None:
                raise NotFound("许可不存在")
        else:
            row = self._permit_row(permit_id, version)
        privileged = viewer["role"] in PRIVILEGED_ROLES
        scope_view = []
        for item in json.loads(row["scope_json"]):
            used = self._quota_used(permit_id, row["version"], item["key"])
            cap = Decimal(item["cap_units"])
            scope_view.append(
                {
                    **item,
                    "used_units": q(used),
                    "remaining_units": q(cap - used),
                    "within_cap": used <= cap,
                }
            )
        result = {
            "permit_id": row["permit_id"],
            "version": row["version"],
            "team_id": row["team_id"],
            "title": row["title"],
            "state": row["state"],
            "valid_from": row["valid_from"],
            "valid_until": row["valid_until"],
            "supersedes_version": row["supersedes_version"],
            "document_sha256": row["document_sha256"],
            "scope": scope_view,
        }
        if privileged:
            result["holder_contact"] = row["holder_contact"]
            if row["state"] == "revoked":
                result["revoked_at"] = row["revoked_at"]
                result["revoke_reason"] = row["revoke_reason"]
                result["revoked_by"] = row["revoked_by"]
        else:
            result["holder_contact"] = "***"
        return result

    # ------------------------------------------------------------------ 样本

    def _sample(self, sample_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM samples WHERE sample_id=?", (sample_id,)
        ).fetchone()
        if row is None:
            raise NotFound("样本不存在")
        return row

    @staticmethod
    def _available(row: sqlite3.Row) -> Decimal:
        return Decimal(row["on_hand_quantity"]) - Decimal(row["reserved_quantity"])

    def _returned_under(self, parent_handoff_id: str, root_sample_id: str) -> Decimal:
        """某借出单下，按根样本统计已完成归还的数量（含借出后拆分的子样本）。"""
        rows = self.connection.execute(
            "SELECT l.quantity AS qty FROM handoffs h "
            "JOIN handoff_lines l ON l.handoff_id=h.handoff_id "
            "JOIN samples s ON s.sample_id=l.sample_id "
            "WHERE h.parent_handoff_id=? AND h.state='completed' "
            "AND (s.root_sample_id=? OR s.sample_id=?)",
            (parent_handoff_id, root_sample_id, root_sample_id),
        ).fetchall()
        return sum((Decimal(r["qty"]) for r in rows), ZERO)

    def collect_sample(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "sample.collect")
        if not actor["org_id"]:
            raise Forbidden("采集人必须归属于一个机构")
        draft = CollectionDraft.from_dict(raw)
        request_digest = digest(raw)
        replayed = self._replay("collect", draft.idempotency_key, request_digest)
        if replayed is not None:
            return replayed
        permit = self._permit_row(draft.permit_id, draft.permit_version)
        scopes = self._scope_map(permit)
        scope = scopes.get(draft.scope_key)
        if scope is None:
            raise ValidationFailed("采集范围不在许可中")
        if permit["state"] != "active":
            raise InvalidState("许可版本已撤回，不能新增采集")
        collected_at = parse_utc(draft.collected_at)
        if collected_at < parse_utc(permit["valid_from"]) or collected_at > parse_utc(permit["valid_until"]):
            raise InvalidState("采集时间不在许可有效期内")
        if collected_at > self.clock.now():
            raise ValidationFailed("采集时间不能晚于当前时间")
        used = self._quota_used(draft.permit_id, draft.permit_version, draft.scope_key)
        if used + draft.quantity > scope.cap_units:
            raise Conflict("采集数量超出许可数量上限")
        response = {
            "sample_id": draft.sample_id,
            "permit_id": draft.permit_id,
            "permit_version": draft.permit_version,
            "state": "on_hand",
            "custodian_org": actor["org_id"],
            "on_hand_quantity": q(draft.quantity),
            "seal_digest": draft.seal_digest,
            "remaining_units": q(scope.cap_units - used - draft.quantity),
        }
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO samples(sample_id,permit_id,permit_version,scope_key,sensitive,"
                    "site_id,site_label,site_detail,site_contact,initial_quantity,on_hand_quantity,"
                    "custodian_org,seal_digest,state,root_sample_id,generation,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        draft.sample_id,
                        draft.permit_id,
                        draft.permit_version,
                        draft.scope_key,
                        1 if scope.sensitive else 0,
                        draft.site_id,
                        draft.site_label,
                        draft.site_detail,
                        draft.site_contact,
                        q(draft.quantity),
                        q(draft.quantity),
                        actor["org_id"],
                        draft.seal_digest,
                        "on_hand",
                        draft.sample_id,
                        0,
                        actor_id,
                        self._now(),
                    ),
                )
                self.connection.execute(
                    "INSERT INTO sample_lineage(child_sample_id,parent_sample_id,relation,event_id,"
                    "quantity,created_at) VALUES(?,?,?,?,?,?)",
                    (draft.sample_id, None, "collected", draft.sample_id, q(draft.quantity), self._now()),
                )
                self._store_replay("collect", draft.idempotency_key, request_digest, response)
                self._audit(
                    "sample",
                    draft.sample_id,
                    "sample.collected",
                    actor_id,
                    {
                        "permit_id": draft.permit_id,
                        "permit_version": draft.permit_version,
                        "scope_key": draft.scope_key,
                        "quantity": q(draft.quantity),
                        "seal_digest": draft.seal_digest,
                        "site_id": draft.site_id,
                        # 敏感地点与联系人不入明文审计，仅绑定指纹以防篡改。
                        "site_facts_sha256": digest(
                            {
                                "site_label": draft.site_label,
                                "site_detail": draft.site_detail,
                                "site_contact": draft.site_contact,
                            }
                        ),
                        "custodian_org": actor["org_id"],
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("样本编号或幂等键冲突") from exc
        return response

    def _insert_child(
        self,
        child_id: str,
        parent_row: sqlite3.Row,
        quantity: Decimal,
        seal_digest: str,
        root_sample_id: str,
        generation: int,
        custodian_org: str,
        state: str,
        actor_id: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO samples(sample_id,permit_id,permit_version,scope_key,sensitive,"
            "site_id,site_label,site_detail,site_contact,initial_quantity,on_hand_quantity,"
            "custodian_org,seal_digest,state,root_sample_id,generation,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                child_id,
                parent_row["permit_id"],
                parent_row["permit_version"],
                parent_row["scope_key"],
                parent_row["sensitive"],
                parent_row["site_id"],
                parent_row["site_label"],
                parent_row["site_detail"],
                parent_row["site_contact"],
                q(quantity),
                q(quantity),
                custodian_org,
                seal_digest,
                state,
                root_sample_id,
                generation,
                actor_id,
                self._now(),
            ),
        )

    def split_sample(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "sample.transform")
        draft = SplitDraft.from_dict(raw)
        request_digest = digest(raw)
        replayed = self._replay("split", draft.idempotency_key, request_digest)
        if replayed is not None:
            return replayed
        parent = self._sample(draft.parent_sample_id)
        # 许可撤回后仍允许持有人为归还与核账而拆分；不转移给新方、不扩大授权。
        self._assert_custodian(actor, parent)
        if parent["state"] not in ("on_hand", "out_on_loan"):
            raise InvalidState("只有在库或借出中的样本可以拆分")
        available = self._available(parent)
        if available <= ZERO:
            raise InvalidState("样本没有可拆分的剩余数量")
        total = sum((item.quantity for item in draft.outputs), ZERO)
        if total != available:
            raise Conflict(f"拆分数量不守恒：子样本合计 {q(total)} 不等于可拆数量 {q(available)}")
        # 借出中的样本拆分后，子样本继承借出状态，仍由同一实验室负责。
        child_state = parent["state"]
        response = {
            "parent_sample_id": draft.parent_sample_id,
            "state": "consumed",
            "outputs": [
                {"sample_id": item.sample_id, "quantity": q(item.quantity), "seal_digest": item.seal_digest}
                for item in draft.outputs
            ],
        }
        try:
            with transaction(self.connection, immediate=True):
                for output in draft.outputs:
                    exists = self.connection.execute(
                        "SELECT 1 FROM samples WHERE sample_id=?", (output.sample_id,)
                    ).fetchone()
                    if exists is not None:
                        raise Conflict(f"子样本编号 {output.sample_id} 已存在")
                    self._insert_child(
                        output.sample_id,
                        parent,
                        output.quantity,
                        output.seal_digest,
                        parent["root_sample_id"],
                        parent["generation"] + 1,
                        parent["custodian_org"],
                        child_state,
                        actor_id,
                    )
                    self.connection.execute(
                        "INSERT INTO sample_lineage(child_sample_id,parent_sample_id,relation,event_id,"
                        "quantity,created_at) VALUES(?,?,?,?,?,?)",
                        (
                            output.sample_id,
                            draft.parent_sample_id,
                            "split",
                            draft.parent_sample_id,
                            q(output.quantity),
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "UPDATE samples SET state='consumed',on_hand_quantity='0' WHERE sample_id=?",
                    (draft.parent_sample_id,),
                )
                self._store_replay("split", draft.idempotency_key, request_digest, response)
                self._audit(
                    "sample",
                    draft.parent_sample_id,
                    "sample.split",
                    actor_id,
                    {"outputs": response["outputs"]},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("样本编号冲突") from exc
        return response

    def merge_samples(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "sample.transform")
        draft = MergeDraft.from_dict(raw)
        request_digest = digest(raw)
        replayed = self._replay("merge", draft.idempotency_key, request_digest)
        if replayed is not None:
            return replayed
        inputs = [self._sample(item.sample_id) for item in draft.inputs]
        first = inputs[0]
        # 撤回后仍允许持有人合并既有样本以便核账与归还。
        for row, portion in zip(inputs, draft.inputs):
            self._assert_custodian(actor, row)
            if row["state"] not in ("on_hand", "out_on_loan"):
                raise InvalidState(f"样本 {row['sample_id']} 处于终态，不能合并")
            if row["state"] != first["state"]:
                raise Conflict("处于不同保管状态的样本不能合并")
            if self._available(row) <= ZERO:
                raise InvalidState(f"样本 {row['sample_id']} 没有可用数量")
            if row["seal_digest"] != portion.seal_digest:
                raise Conflict(f"样本 {row['sample_id']} 封签摘要不符")
            if (
                row["permit_id"] != first["permit_id"]
                or row["permit_version"] != first["permit_version"]
                or row["scope_key"] != first["scope_key"]
                or row["custodian_org"] != first["custodian_org"]
            ):
                raise Conflict("只能合并且同一许可版本、同一范围、同一责任机构的样本")
        total = sum((item.quantity for item in draft.inputs), ZERO)
        if total != draft.output.quantity:
            raise Conflict(f"合并数量不守恒：输出 {q(draft.output.quantity)} 不等于输入合计 {q(total)}")
        roots = {row["root_sample_id"] for row in inputs}
        root = next(iter(roots)) if len(roots) == 1 else draft.output.sample_id
        response = {
            "sample_id": draft.output.sample_id,
            "state": "on_hand",
            "quantity": q(draft.output.quantity),
            "inputs": [row["sample_id"] for row in inputs],
        }
        try:
            with transaction(self.connection, immediate=True):
                if self.connection.execute(
                    "SELECT 1 FROM samples WHERE sample_id=?", (draft.output.sample_id,)
                ).fetchone() is not None:
                    raise Conflict("合并输出样本编号已存在")
                self._insert_child(
                    draft.output.sample_id,
                    first,
                    draft.output.quantity,
                    draft.output.seal_digest,
                    root,
                    max(row["generation"] for row in inputs) + 1,
                    first["custodian_org"],
                    first["state"],
                    actor_id,
                )
                for row, portion in zip(inputs, draft.inputs):
                    self.connection.execute(
                        "UPDATE samples SET state='consumed',on_hand_quantity='0' WHERE sample_id=?",
                        (row["sample_id"],),
                    )
                    self.connection.execute(
                        "INSERT INTO sample_lineage(child_sample_id,parent_sample_id,relation,event_id,"
                        "quantity,created_at) VALUES(?,?,?,?,?,?)",
                        (
                            draft.output.sample_id,
                            row["sample_id"],
                            "merge",
                            draft.output.sample_id,
                            q(portion.quantity),
                            self._now(),
                        ),
                    )
                self._store_replay("merge", draft.idempotency_key, request_digest, response)
                self._audit(
                    "sample",
                    draft.output.sample_id,
                    "sample.merged",
                    actor_id,
                    {"inputs": response["inputs"], "quantity": q(draft.output.quantity)},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("样本编号冲突") from exc
        return response

    @staticmethod
    def _assert_custodian(actor: sqlite3.Row, sample_row: sqlite3.Row) -> None:
        if actor["org_id"] != sample_row["custodian_org"]:
            raise Forbidden("只有当前责任机构可以处置该样本")

    # ------------------------------------------------------------------ 交接

    def propose_handoff(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "custody.move")
        draft = HandoffDraft.from_dict(raw)
        request_digest = digest(raw)
        replayed = self._replay("handoff", draft.idempotency_key, request_digest)
        if replayed is not None:
            return replayed
        if not actor["org_id"]:
            raise Forbidden("交接发起人必须归属于一个机构")
        to_org = self._org(draft.to_org)
        from_org = self._org(actor["org_id"])
        if to_org["org_id"] == from_org["org_id"]:
            raise ValidationFailed("交接双方机构不能相同")
        parent = None
        if draft.kind == "return":
            parent = self.connection.execute(
                "SELECT * FROM handoffs WHERE handoff_id=?", (draft.parent_handoff_id,)
            ).fetchone()
            if parent is None:
                raise NotFound("原借出交接不存在")
            if parent["kind"] != "loan" or parent["state"] != "completed":
                raise InvalidState("归还必须指向已完成的借出交接")
            if parent["to_org"] != from_org["org_id"] or parent["from_org"] != to_org["org_id"]:
                raise Forbidden("归还方向与原借出交接不一致")
        elif draft.kind == "loan":
            self._permit_gate(draft, "许可撤回后不能新增借出")
        else:
            self._permit_gate(draft, "许可撤回后不能新增调拨")
        # 先整单校验全部明细，任一不满足则不写入任何预留（全有或全无）。
        checked: list[tuple[sqlite3.Row, Decimal, str]] = []
        parent_roots: dict[str, Decimal] = {}
        if parent is not None:
            # 借出后样本可能在借用方被拆分，因此按根样本追踪借出余额。
            for line in self.connection.execute(
                "SELECT l.sample_id,l.quantity,s.root_sample_id FROM handoff_lines l "
                "JOIN samples s ON s.sample_id=l.sample_id WHERE l.handoff_id=?",
                (parent["handoff_id"],),
            ).fetchall():
                root = line["root_sample_id"] or line["sample_id"]
                parent_roots[root] = parent_roots.get(root, ZERO) + Decimal(line["quantity"])
        for line in draft.lines:
            sample = self._sample(line.sample_id)
            if sample["custodian_org"] != from_org["org_id"]:
                raise Forbidden(f"样本 {line.sample_id} 不属于发起机构")
            if draft.kind == "return":
                root = sample["root_sample_id"] or line.sample_id
                if root not in parent_roots:
                    raise Conflict(f"样本 {line.sample_id} 不属于原借出交接 {parent['handoff_id']}")
                if sample["state"] != "out_on_loan":
                    raise InvalidState(f"样本 {line.sample_id} 不在借出状态，不能归还")
                if Decimal(sample["reserved_quantity"]) != ZERO:
                    raise Conflict(f"样本 {line.sample_id} 已有待确认交接，不能重复发起")
                on_hand = Decimal(sample["on_hand_quantity"])
                # 整体归还当前剩余材料；实验室分析消耗必须已有销毁记录。
                if line.quantity != on_hand:
                    raise Conflict(
                        f"样本 {line.sample_id} 必须按当前剩余数量 {q(on_hand)} 整体归还"
                    )
                # 该校验与全链守恒共同保证归还不超过原借出数量。
                returned = self._returned_under(parent["handoff_id"], root)
                if returned + line.quantity > parent_roots[root]:
                    raise Conflict(
                        f"根样本 {root} 累计归还将超过原借出数量 {q(parent_roots[root])}"
                    )
            else:
                if sample["state"] != "on_hand":
                    raise InvalidState(f"样本 {line.sample_id} 当前不在可交接状态")
                # 交接以整样本为单位：部分数量必须先拆分成独立子样本，
                # 以保证任一时刻每个样本只有一个责任机构。
                if Decimal(sample["reserved_quantity"]) != ZERO:
                    raise Conflict(f"样本 {line.sample_id} 已有待确认交接，不能重复发起")
                if line.quantity != Decimal(sample["on_hand_quantity"]):
                    raise Conflict(
                        f"样本 {line.sample_id} 必须按在册数量 {sample['on_hand_quantity']} 整体交接；"
                        "部分数量请先拆分"
                    )
            checked.append((sample, line.quantity, sample["seal_digest"]))
        response = {
            "handoff_id": draft.handoff_id,
            "kind": draft.kind,
            "from_org": from_org["org_id"],
            "to_org": to_org["org_id"],
            "state": "proposed",
            "lines": [
                {"sample_id": line.sample_id, "quantity": q(line.quantity)} for line in draft.lines
            ],
        }
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO handoffs(handoff_id,kind,from_org,to_org,to_contact,expected_return_at,"
                    "parent_handoff_id,note,state,proposed_by,proposed_at,idempotency_key) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        draft.handoff_id,
                        draft.kind,
                        from_org["org_id"],
                        to_org["org_id"],
                        draft.to_contact,
                        draft.expected_return_at,
                        draft.parent_handoff_id,
                        draft.note,
                        "proposed",
                        actor_id,
                        self._now(),
                        draft.idempotency_key,
                    ),
                )
                for sample, quantity, seal in checked:
                    # 条件式原子预留：仅当该样本尚无待确认预留时生效，
                    # 串行事务下第二个并发交接会命中 0 行而整单回滚。
                    cursor = self.connection.execute(
                        "UPDATE samples SET reserved_quantity=? "
                        "WHERE sample_id=? AND CAST(reserved_quantity AS REAL)=0",
                        (q(quantity), sample["sample_id"]),
                    )
                    if cursor.rowcount != 1:
                        raise Conflict(f"样本 {sample['sample_id']} 已被其它待确认交接占用")
                    self.connection.execute(
                        "INSERT INTO handoff_lines(handoff_id,sample_id,quantity,seal_digest) VALUES(?,?,?,?)",
                        (draft.handoff_id, sample["sample_id"], q(quantity), seal),
                    )
                self._store_replay("handoff", draft.idempotency_key, request_digest, response)
                self._audit(
                    "handoff",
                    draft.handoff_id,
                    "handoff.proposed",
                    actor_id,
                    {
                        "kind": draft.kind,
                        "from_org": from_org["org_id"],
                        "to_org": to_org["org_id"],
                        "lines": response["lines"],
                        "parent_handoff_id": draft.parent_handoff_id,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("交接编号或幂等键冲突") from exc
        return response

    def _permit_gate(self, draft: HandoffDraft, message: str) -> None:
        for line in draft.lines:
            sample = self._sample(line.sample_id)
            permit = self._permit_row(sample["permit_id"], sample["permit_version"])
            if permit["state"] != "active":
                raise InvalidState(message)

    def _load_proposed(self, handoff_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM handoffs WHERE handoff_id=?", (handoff_id,)
        ).fetchone()
        if row is None:
            raise NotFound("交接不存在")
        if row["state"] != "proposed":
            raise InvalidState("交接不是待确认状态")
        return row

    def confirm_handoff(
        self, actor_id: str, handoff_id: str, seals: Mapping[str, str] | None = None
    ) -> dict[str, Any]:
        actor = self._require(actor_id, "custody.move")
        handoff = self._load_proposed(handoff_id)
        if actor["org_id"] != handoff["to_org"]:
            raise Forbidden("只有接收机构可以确认交接")
        seals = seals or {}
        lines = self.connection.execute(
            "SELECT * FROM handoff_lines WHERE handoff_id=?", (handoff_id,)
        ).fetchall()
        if set(seals) != {line["sample_id"] for line in lines}:
            raise ValidationFailed("必须为每条明细提供接收封签摘要")
        for line in lines:
            if seals[line["sample_id"]].lower() != line["seal_digest"]:
                raise InvalidState(f"样本 {line['sample_id']} 封签核验失败，交接不能生效")
        now = self._now()
        with transaction(self.connection, immediate=True):
            # 抢占式状态迁移：仅当仍为 proposed 时生效，串行事务下重复确认命中 0 行，
            # 从而不会重复转移责任方或重复写入谱系。
            claim = self.connection.execute(
                "UPDATE handoffs SET state='completed',confirmer_id=?,confirmed_at=?,"
                "completed_by=?,completed_at=? WHERE handoff_id=? AND state='proposed'",
                (actor_id, now, actor_id, now, handoff_id),
            )
            if claim.rowcount != 1:
                raise InvalidState("交接已被处理，状态已变化")
            for line in lines:
                sample = self._sample(line["sample_id"])
                quantity = Decimal(line["quantity"])
                reserved = Decimal(sample["reserved_quantity"]) - quantity
                if handoff["kind"] == "loan":
                    new_state = "out_on_loan"
                else:
                    # transfer 与 return 完成后材料回到在库责任方。
                    new_state = "on_hand"
                self.connection.execute(
                    "UPDATE samples SET custodian_org=?,reserved_quantity=?,state=? WHERE sample_id=?",
                    (handoff["to_org"], q(max(ZERO, reserved)), new_state, sample["sample_id"]),
                )
                self.connection.execute(
                    "INSERT INTO sample_lineage(child_sample_id,parent_sample_id,relation,event_id,"
                    "quantity,created_at) VALUES(?,?,?,?,?,?)",
                    (sample["sample_id"], None, "handoff", handoff_id, q(quantity), now),
                )
            self._audit(
                "handoff",
                handoff_id,
                "handoff.confirmed",
                actor_id,
                {
                    "by": actor_id,
                    "lines": [
                        {"sample_id": line["sample_id"], "quantity": line["quantity"]} for line in lines
                    ],
                },
            )
        return {
            "handoff_id": handoff_id,
            "state": "completed",
            "custodian_org": handoff["to_org"],
            "confirmed_by": actor_id,
            "confirmed_at": now,
        }

    def reject_handoff(self, actor_id: str, handoff_id: str, reason: str) -> dict[str, Any]:
        actor = self._require(actor_id, "custody.move")
        handoff = self._load_proposed(handoff_id)
        if actor["org_id"] != handoff["to_org"]:
            raise Forbidden("只有接收机构可以拒收交接")
        if not reason.strip():
            raise ValidationFailed("拒收原因不能为空")
        self._release(handoff, "rejected", actor_id, reason)
        return {"handoff_id": handoff_id, "state": "rejected"}

    def cancel_handoff(self, actor_id: str, handoff_id: str, reason: str) -> dict[str, Any]:
        actor = self._require(actor_id, "custody.move")
        handoff = self._load_proposed(handoff_id)
        if actor["user_id"] != handoff["proposed_by"]:
            raise Forbidden("只有原发起人可以撤销交接")
        if not reason.strip():
            raise ValidationFailed("撤销原因不能为空")
        self._release(handoff, "cancelled", actor_id, reason)
        return {"handoff_id": handoff_id, "state": "cancelled"}

    def _release(self, handoff: sqlite3.Row, state: str, actor_id: str, reason: str) -> None:
        with transaction(self.connection, immediate=True):
            lines = self.connection.execute(
                "SELECT * FROM handoff_lines WHERE handoff_id=?", (handoff["handoff_id"],)
            ).fetchall()
            for line in lines:
                sample = self._sample(line["sample_id"])
                reserved = Decimal(sample["reserved_quantity"]) - Decimal(line["quantity"])
                self.connection.execute(
                    "UPDATE samples SET reserved_quantity=? WHERE sample_id=?",
                    (q(max(ZERO, reserved)), sample["sample_id"]),
                )
            self.connection.execute(
                "UPDATE handoffs SET state=? WHERE handoff_id=? AND state='proposed'",
                (state, handoff["handoff_id"]),
            )
            self._audit(
                "handoff",
                handoff["handoff_id"],
                f"handoff.{state}",
                actor_id,
                {"reason": reason},
            )

    # ------------------------------------------------------------------ 销毁

    def destroy_sample(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        actor = self._require(actor_id, "sample.dispose")
        destruction_id = raw.get("destruction_id")
        sample_id = raw.get("sample_id")
        reason = str(raw.get("reason", "")).strip()
        witness_id = raw.get("witness_id")
        idempotency_key = raw.get("idempotency_key")
        from .models import identifier as _id, positive_quantity  # 局部导入保持与其它用例一致
        destruction_id = _id(destruction_id, "destruction_id")
        sample_id = _id(sample_id, "sample_id")
        key = _id(idempotency_key, "idempotency_key")
        quantity = positive_quantity(raw.get("quantity"), "quantity")
        if not reason:
            raise ValidationFailed("销毁原因不能为空")
        if not witness_id or not str(witness_id).strip():
            raise ValidationFailed("销毁必须有见证人")
        witness = self._user(str(witness_id))
        if witness["user_id"] == actor["user_id"]:
            raise ValidationFailed("见证人不能与经手人相同")
        request_digest = digest(raw)
        replayed = self._replay("destroy", key, request_digest)
        if replayed is not None:
            return replayed
        sample = self._sample(sample_id)
        self._assert_custodian(actor, sample)
        if sample["state"] not in ("on_hand", "out_on_loan"):
            raise InvalidState("当前状态的样本不能销毁")
        if quantity > self._available(sample):
            raise Conflict("销毁数量超过可用数量（含已预留交接数量）")
        remaining = Decimal(sample["on_hand_quantity"]) - quantity
        new_state = "destroyed" if remaining <= ZERO else sample["state"]
        response = {
            "destruction_id": destruction_id,
            "sample_id": sample_id,
            "destroyed_quantity": q(quantity),
            "remaining_quantity": q(max(ZERO, remaining)),
            "state": new_state,
        }
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO destructions(destruction_id,sample_id,quantity,reason,witness_id,"
                    "idempotency_key,destroyed_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        destruction_id,
                        sample_id,
                        q(quantity),
                        reason,
                        witness["user_id"],
                        key,
                        actor["user_id"],
                        self._now(),
                    ),
                )
                self.connection.execute(
                    "UPDATE samples SET on_hand_quantity=?,state=? WHERE sample_id=?",
                    (q(max(ZERO, remaining)), new_state, sample_id),
                )
                self._store_replay("destroy", key, request_digest, response)
                self._audit(
                    "sample",
                    sample_id,
                    "sample.destroyed",
                    actor["user_id"],
                    {
                        "destruction_id": destruction_id,
                        "quantity": q(quantity),
                        "reason": reason,
                        "witness_id": witness["user_id"],
                        "remaining_state": new_state,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("销毁编号或幂等键冲突") from exc
        return response

    # ------------------------------------------------------------------ 核对

    def _can_see_sensitive(self, viewer: sqlite3.Row, sample_row: sqlite3.Row) -> bool:
        # 按角色最小披露：管理局与审计可全见；保护站属园区管护体系可见；
        # 仅最初的采集团队可见其自采样本；借用实验室等其它机构一律脱敏。
        if viewer["role"] in PRIVILEGED_ROLES or viewer["role"] == "station":
            return True
        root_id = sample_row["root_sample_id"] or sample_row["sample_id"]
        root = self.connection.execute(
            "SELECT created_by FROM samples WHERE sample_id=?", (root_id,)
        ).fetchone()
        if root is None or viewer["org_id"] is None:
            return False
        collector = self.connection.execute(
            "SELECT org_id FROM chain_users WHERE user_id=?", (root["created_by"],)
        ).fetchone()
        return collector is not None and collector["org_id"] == viewer["org_id"]

    def _public_sample(self, row: sqlite3.Row, viewer: sqlite3.Row) -> dict[str, Any]:
        data = {
            "sample_id": row["sample_id"],
            "permit_id": row["permit_id"],
            "permit_version": row["permit_version"],
            "scope_key": row["scope_key"],
            "sensitive": bool(row["sensitive"]),
            "site_id": row["site_id"],
            "initial_quantity": row["initial_quantity"],
            "on_hand_quantity": row["on_hand_quantity"],
            "reserved_quantity": row["reserved_quantity"],
            "available_quantity": q(self._available(row)),
            "custodian_org": row["custodian_org"],
            "seal_digest": row["seal_digest"],
            "state": row["state"],
            "root_sample_id": row["root_sample_id"],
            "generation": row["generation"],
        }
        custodian = self.connection.execute(
            "SELECT name,kind FROM organizations WHERE org_id=?", (row["custodian_org"],)
        ).fetchone()
        data["current_responsible_party"] = (
            None if custodian is None else {"org_id": row["custodian_org"], "name": custodian["name"], "kind": custodian["kind"]}
        )
        if self._can_see_sensitive(viewer, row):
            data["site_label"] = row["site_label"]
            data["site_detail"] = row["site_detail"]
            data["site_contact"] = row["site_contact"]
        else:
            data["site_label"] = "***"
            data["site_detail"] = "***"
            data["site_contact"] = "***"
            data["redacted"] = ["site_label", "site_detail", "site_contact"]
        return data

    def sample_provenance(self, actor_id: str, sample_id: str) -> dict[str, Any]:
        viewer = self._require(actor_id, "report.read")
        sample = self._sample(sample_id)
        permit = self._permit_row(sample["permit_id"], sample["permit_version"])
        scope = self._scope_map(permit).get(sample["scope_key"])
        used = self._quota_used(sample["permit_id"], sample["permit_version"], sample["scope_key"])
        # 以根样本为家族：借出后拆分出的子样本也能看到最初封装与各手交接。
        root_id = sample["root_sample_id"] or sample_id
        family = [
            row["sample_id"]
            for row in self.connection.execute(
                "SELECT sample_id FROM samples WHERE root_sample_id=? OR sample_id=? ORDER BY sample_id",
                (root_id, root_id),
            ).fetchall()
        ]
        placeholders = ",".join("?" for _ in family)
        events: list[dict[str, Any]] = []
        for row in self.connection.execute(
            f"SELECT * FROM sample_lineage WHERE child_sample_id IN ({placeholders}) "
            f"OR parent_sample_id IN ({placeholders}) ORDER BY lineage_id",
            (*family, *family),
        ).fetchall():
            events.append(
                {
                    "type": row["relation"],
                    "event_id": row["event_id"],
                    "child_sample_id": row["child_sample_id"],
                    "parent_sample_id": row["parent_sample_id"],
                    "quantity": row["quantity"],
                    "at": row["created_at"],
                }
            )
        for row in self.connection.execute(
            f"SELECT d.*,u.display_name AS witness_name FROM destructions d "
            f"JOIN chain_users u ON u.user_id=d.witness_id WHERE d.sample_id IN ({placeholders}) "
            "ORDER BY d.created_at",
            family,
        ).fetchall():
            events.append(
                {
                    "type": "destruction",
                    "event_id": row["destruction_id"],
                    "sample_id": row["sample_id"],
                    "quantity": row["quantity"],
                    "reason": row["reason"],
                    "destroyed_by": row["destroyed_by"],
                    "witness_id": row["witness_id"],
                    "witness_name": row["witness_name"],
                    "at": row["created_at"],
                }
            )
        events.sort(key=lambda item: item["at"])
        loans = self.connection.execute(
            f"SELECT * FROM handoffs h JOIN handoff_lines l ON l.handoff_id=h.handoff_id "
            f"WHERE l.sample_id IN ({placeholders}) ORDER BY h.proposed_at,h.handoff_id",
            family,
        ).fetchall()
        loan_view: dict[str, Any] | None = None
        if sample["state"] == "out_on_loan":
            # 借出后可能已拆分，借出单挂在父样本上，因此按根样本家族查找。
            parent = self.connection.execute(
                f"SELECT h.* FROM handoffs h JOIN handoff_lines l ON l.handoff_id=h.handoff_id "
                f"WHERE l.sample_id IN ({placeholders}) AND h.kind='loan' AND h.state='completed' "
                "ORDER BY h.completed_at DESC LIMIT 1",
                family,
            ).fetchone()
            overdue = False
            if parent is not None and parent["expected_return_at"] is not None:
                overdue = parse_utc(parent["expected_return_at"]) < self.clock.now()
            loan_view = {
                "open_quantity": q(Decimal(sample["on_hand_quantity"])),
                "lender_org": None if parent is None else parent["from_org"],
                "borrower_org": None if parent is None else parent["to_org"],
                "handoff_id": None if parent is None else parent["handoff_id"],
                "expected_return_at": None if parent is None else parent["expected_return_at"],
                "overdue": overdue,
                "missing_return_handoff": overdue,
            }
        pending = [
            {
                "handoff_id": row["handoff_id"],
                "kind": row["kind"],
                "from_org": row["from_org"],
                "to_org": row["to_org"],
                "quantity": row["quantity"],
                "awaiting_org": row["to_org"],
            }
            for row in self.connection.execute(
                "SELECT h.handoff_id,h.kind,h.from_org,h.to_org,l.quantity FROM handoffs h "
                "JOIN handoff_lines l ON l.handoff_id=h.handoff_id "
                "WHERE l.sample_id=? AND h.state='proposed' ORDER BY h.proposed_at",
                (sample_id,),
            ).fetchall()
        ]
        handoff_history = []
        for row in loans:
            entry = {
                "handoff_id": row["handoff_id"],
                "kind": row["kind"],
                "state": row["state"],
                "from_org": row["from_org"],
                "to_org": row["to_org"],
                "quantity": row["quantity"],
                "seal_digest": row["seal_digest"],
                "proposed_by": row["proposed_by"],
                "proposed_at": row["proposed_at"],
                "confirmer_id": row["confirmer_id"],
                "completed_at": row["completed_at"],
                "parent_handoff_id": row["parent_handoff_id"],
            }
            if viewer["role"] in PRIVILEGED_ROLES or viewer["org_id"] in (row["from_org"], row["to_org"]):
                entry["to_contact"] = row["to_contact"]
            else:
                entry["to_contact"] = "***"
            handoff_history.append(entry)
        return {
            "sample": self._public_sample(sample, viewer),
            "source": {
                "collected_by": sample["created_by"],
                "collected_at": sample["created_at"],
                "permit_document_sha256": permit["document_sha256"],
                # 采集事件本身已固化在哈希链中；这里只反映许可当前状态，
                # 撤回不会回写或删除合法历史。
                "permit_state_current": permit["state"],
            },
            "permit": {
                "permit_id": permit["permit_id"],
                "version": permit["version"],
                "state": permit["state"],
                "scope_key": sample["scope_key"],
                "scope_kind": None if scope is None else scope.kind,
                "cap_units": None if scope is None else q(scope.cap_units),
                "used_units": q(used),
                "remaining_units": None if scope is None else q(scope.cap_units - used),
                "valid_from": permit["valid_from"],
                "valid_until": permit["valid_until"],
            },
            "lineage": events,
            "handoffs": handoff_history,
            "active_loan": loan_view,
            "pending_handoffs": pending,
            "missing_handoffs": (
                ["overdue_return"] if loan_view is not None and loan_view["missing_return_handoff"] else []
            )
            + (["incoming_confirmation_pending"] if pending else []),
        }

    def handoff_queue(self, actor_id: str, state: str = "proposed") -> dict[str, Any]:
        viewer = self._require(actor_id, "chain.read")
        if state not in {"proposed", "completed", "rejected", "cancelled"}:
            raise ValidationFailed("state 不受支持")
        rows = self.connection.execute(
            "SELECT * FROM handoffs WHERE state=? AND (from_org=? OR to_org=?) ORDER BY proposed_at",
            (state, viewer["org_id"] or "", viewer["org_id"] or ""),
        ).fetchall()
        items = []
        for row in rows:
            lines = self.connection.execute(
                "SELECT sample_id,quantity,seal_digest FROM handoff_lines WHERE handoff_id=?",
                (row["handoff_id"],),
            ).fetchall()
            items.append(
                {
                    "handoff_id": row["handoff_id"],
                    "kind": row["kind"],
                    "state": row["state"],
                    "from_org": row["from_org"],
                    "to_org": row["to_org"],
                    "parent_handoff_id": row["parent_handoff_id"],
                    "expected_return_at": row["expected_return_at"],
                    "proposed_by": row["proposed_by"],
                    "confirmer_id": row["confirmer_id"],
                    "lines": [dict(line) for line in lines],
                    "awaiting_action": (
                        None
                        if row["state"] != "proposed"
                        else ("confirm" if viewer["org_id"] == row["to_org"] else "cancel")
                    ),
                }
            )
        return {"state": state, "items": items}

    def conservation_report(self, actor_id: str) -> dict[str, Any]:
        """全链数量守恒核对：采集总量 = 现存总量 + 已销毁总量。"""
        self._require(actor_id, "chain.read")
        collected_rows = self.connection.execute(
            "SELECT s.initial_quantity AS qty FROM samples s "
            "JOIN sample_lineage l ON l.child_sample_id=s.sample_id AND l.relation='collected'"
        ).fetchall()
        on_hand_rows = self.connection.execute("SELECT on_hand_quantity AS qty FROM samples").fetchall()
        destroyed_rows = self.connection.execute("SELECT quantity AS qty FROM destructions").fetchall()
        collected = sum((Decimal(r["qty"]) for r in collected_rows), ZERO)
        on_hand = sum((Decimal(r["qty"]) for r in on_hand_rows), ZERO)
        destroyed = sum((Decimal(r["qty"]) for r in destroyed_rows), ZERO)
        reserved_rows = self.connection.execute(
            "SELECT reserved_quantity AS qty FROM samples WHERE CAST(reserved_quantity AS REAL)>0"
        ).fetchall()
        reserved_in_loan = sum((Decimal(r["qty"]) for r in reserved_rows), ZERO)
        balanced = on_hand + destroyed == collected
        return {
            "collected_units": q(collected),
            "accounted_on_hand_units": q(on_hand),
            "destroyed_units": q(destroyed),
            "reserved_in_pending_handoffs_units": q(reserved_in_loan),
            "balanced": balanced,
        }

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute("SELECT * FROM chain_audit_events ORDER BY event_id").fetchall()
        previous_hash = "0" * 64
        valid = True
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
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash}
