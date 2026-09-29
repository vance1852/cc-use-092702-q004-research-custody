"""科研采样许可与保管链领域输入契约。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence

from .clock import parse_utc
from .errors import ValidationFailed


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
SEAL_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ORG_KINDS = {"authority", "station", "university", "laboratory"}
SCOPE_KINDS = {"species", "habitat"}
HANDOFF_KINDS = {"loan", "return", "transfer"}


def required_text(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{field} 不能为空")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{field} 不能超过 {maximum} 个字符")
    return result


def optional_text(value: object, field: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return required_text(value, field, maximum)


def identifier(value: object, field: str) -> str:
    result = required_text(value, field, 64)
    if not IDENTIFIER.fullmatch(result):
        raise ValidationFailed(f"{field} 格式不正确")
    return result


def decimal_value(
    value: object,
    field: str,
    *,
    minimum: Decimal | None = None,
    inclusive: bool = True,
) -> Decimal:
    if isinstance(value, bool):
        raise ValidationFailed(f"{field} 必须是数值")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValidationFailed(f"{field} 必须是十进制数值") from exc
    if not result.is_finite():
        raise ValidationFailed(f"{field} 必须是有限数值")
    if minimum is not None:
        if inclusive and result < minimum:
            raise ValidationFailed(f"{field} 不能小于 {minimum}")
        if not inclusive and result <= minimum:
            raise ValidationFailed(f"{field} 必须大于 {minimum}")
    return result


def positive_quantity(value: object, field: str) -> Decimal:
    return decimal_value(value, field, minimum=Decimal("0"), inclusive=False)


def seal_digest(value: object, field: str = "seal_digest") -> str:
    result = required_text(value, field, 96).lower()
    if not SEAL_DIGEST.fullmatch(result):
        raise ValidationFailed(f"{field} 必须是 sha256: 加 64 位十六进制摘要")
    return result


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationFailed(f"{field} 必须是对象")
    return value


def _sequence(value: object, field: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValidationFailed(f"{field} 必须是数组")
    return value


@dataclass(frozen=True, slots=True)
class PermitScope:
    """许可中一条物种或生境范围及其数量上限。"""

    key: str
    kind: str
    label: str
    unit: str
    cap_units: Decimal
    sensitive: bool

    @classmethod
    def from_dict(cls, raw: object, field: str = "scope") -> "PermitScope":
        data = _mapping(raw, field)
        kind = required_text(data.get("kind"), f"{field}.kind", 16).lower()
        if kind not in SCOPE_KINDS:
            raise ValidationFailed(f"{field}.kind 必须是 species 或 habitat")
        return cls(
            key=identifier(data.get("key"), f"{field}.key"),
            kind=kind,
            label=required_text(data.get("label"), f"{field}.label"),
            unit=required_text(data.get("unit"), f"{field}.unit", 16),
            cap_units=positive_quantity(data.get("cap_units"), f"{field}.cap_units"),
            sensitive=bool(data.get("sensitive", False)),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind,
            "label": self.label,
            "unit": self.unit,
            "cap_units": format(self.cap_units, "f"),
            "sensitive": self.sensitive,
        }


@dataclass(frozen=True, slots=True)
class PermitDraft:
    permit_id: str
    version: int
    team_id: str
    title: str
    holder_contact: str
    scopes: tuple[PermitScope, ...]
    valid_from: str
    valid_until: str
    supersedes_version: int | None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PermitDraft":
        version = raw.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValidationFailed("version 必须是正整数")
        supersedes = raw.get("supersedes_version")
        if supersedes is not None:
            if isinstance(supersedes, bool) or not isinstance(supersedes, int) or supersedes <= 0:
                raise ValidationFailed("supersedes_version 必须是正整数")
            if supersedes >= version:
                raise ValidationFailed("新版本号必须大于被替代版本")
        scopes = tuple(
            PermitScope.from_dict(item, f"scope[{index}]")
            for index, item in enumerate(_sequence(raw.get("scope"), "scope"))
        )
        if not scopes:
            raise ValidationFailed("scope 至少包含一条物种或生境范围")
        keys = [item.key for item in scopes]
        if len(set(keys)) != len(keys):
            raise ValidationFailed("scope.key 不能重复")
        valid_from = required_text(raw.get("valid_from"), "valid_from", 40)
        valid_until = required_text(raw.get("valid_until"), "valid_until", 40)
        try:
            start = parse_utc(valid_from, "valid_from")
            end = parse_utc(valid_until, "valid_until")
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        if end <= start:
            raise ValidationFailed("valid_until 必须晚于 valid_from")
        return cls(
            permit_id=identifier(raw.get("permit_id"), "permit_id"),
            version=version,
            team_id=identifier(raw.get("team_id"), "team_id"),
            title=required_text(raw.get("title"), "title"),
            holder_contact=required_text(raw.get("holder_contact"), "holder_contact"),
            scopes=scopes,
            valid_from=valid_from,
            valid_until=valid_until,
            supersedes_version=supersedes,
        )

    def scope(self, key: str) -> PermitScope | None:
        return next((item for item in self.scopes if item.key == key), None)


@dataclass(frozen=True, slots=True)
class CollectionDraft:
    sample_id: str
    permit_id: str
    permit_version: int
    scope_key: str
    site_id: str
    site_label: str
    site_detail: str | None
    site_contact: str | None
    quantity: Decimal
    seal_digest: str
    collected_at: str
    idempotency_key: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CollectionDraft":
        version = raw.get("permit_version")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValidationFailed("permit_version 必须是正整数")
        collected_at = required_text(raw.get("collected_at"), "collected_at", 40)
        try:
            parse_utc(collected_at, "collected_at")
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        return cls(
            sample_id=identifier(raw.get("sample_id"), "sample_id"),
            permit_id=identifier(raw.get("permit_id"), "permit_id"),
            permit_version=version,
            scope_key=identifier(raw.get("scope_key"), "scope_key"),
            site_id=identifier(raw.get("site_id"), "site_id"),
            site_label=required_text(raw.get("site_label"), "site_label"),
            site_detail=optional_text(raw.get("site_detail"), "site_detail", 512),
            site_contact=optional_text(raw.get("site_contact"), "site_contact"),
            quantity=positive_quantity(raw.get("quantity"), "quantity"),
            seal_digest=seal_digest(raw.get("seal_digest")),
            collected_at=collected_at,
            idempotency_key=identifier(raw.get("idempotency_key"), "idempotency_key"),
        )


@dataclass(frozen=True, slots=True)
class SamplePortion:
    sample_id: str
    quantity: Decimal
    seal_digest: str

    @classmethod
    def from_dict(cls, raw: object, field: str) -> "SamplePortion":
        data = _mapping(raw, field)
        return cls(
            sample_id=identifier(data.get("sample_id"), f"{field}.sample_id"),
            quantity=positive_quantity(data.get("quantity"), f"{field}.quantity"),
            seal_digest=seal_digest(data.get("seal_digest"), f"{field}.seal_digest"),
        )


@dataclass(frozen=True, slots=True)
class SplitDraft:
    parent_sample_id: str
    outputs: tuple[SamplePortion, ...]
    idempotency_key: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SplitDraft":
        outputs = tuple(
            SamplePortion.from_dict(item, f"outputs[{index}]")
            for index, item in enumerate(_sequence(raw.get("outputs"), "outputs"))
        )
        if not outputs:
            raise ValidationFailed("outputs 至少包含一个拆分子样本")
        ids = [item.sample_id for item in outputs]
        if len(set(ids)) != len(ids):
            raise ValidationFailed("outputs.sample_id 不能重复")
        return cls(
            parent_sample_id=identifier(raw.get("parent_sample_id"), "parent_sample_id"),
            outputs=outputs,
            idempotency_key=identifier(raw.get("idempotency_key"), "idempotency_key"),
        )


@dataclass(frozen=True, slots=True)
class MergeDraft:
    output: SamplePortion
    inputs: tuple[SamplePortion, ...]
    idempotency_key: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "MergeDraft":
        output = SamplePortion.from_dict(raw.get("output"), "output")
        inputs = tuple(
            SamplePortion.from_dict(item, f"inputs[{index}]")
            for index, item in enumerate(_sequence(raw.get("inputs"), "inputs"))
        )
        if len(inputs) < 2:
            raise ValidationFailed("inputs 至少需要两个被合并样本")
        ids = [item.sample_id for item in inputs]
        if len(set(ids)) != len(ids):
            raise ValidationFailed("inputs.sample_id 不能重复")
        if output.sample_id in ids:
            raise ValidationFailed("合并输出不能与输入样本相同")
        return cls(
            output=output,
            inputs=inputs,
            idempotency_key=identifier(raw.get("idempotency_key"), "idempotency_key"),
        )


@dataclass(frozen=True, slots=True)
class HandoffLine:
    sample_id: str
    quantity: Decimal

    @classmethod
    def from_dict(cls, raw: object, field: str) -> "HandoffLine":
        data = _mapping(raw, field)
        return cls(
            sample_id=identifier(data.get("sample_id"), f"{field}.sample_id"),
            quantity=positive_quantity(data.get("quantity"), f"{field}.quantity"),
        )


@dataclass(frozen=True, slots=True)
class HandoffDraft:
    handoff_id: str
    kind: str
    to_org: str
    to_contact: str | None
    lines: tuple[HandoffLine, ...]
    expected_return_at: str | None
    parent_handoff_id: str | None
    note: str | None
    idempotency_key: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "HandoffDraft":
        kind = required_text(raw.get("kind"), "kind", 16).lower()
        if kind not in HANDOFF_KINDS:
            raise ValidationFailed("kind 必须是 loan、return 或 transfer")
        lines = tuple(
            HandoffLine.from_dict(item, f"lines[{index}]")
            for index, item in enumerate(_sequence(raw.get("lines"), "lines"))
        )
        if not lines:
            raise ValidationFailed("lines 至少包含一条样本明细")
        ids = [item.sample_id for item in lines]
        if len(set(ids)) != len(ids):
            raise ValidationFailed("lines.sample_id 不能重复")
        expected = raw.get("expected_return_at")
        if expected is not None:
            try:
                expected = parse_utc(str(expected), "expected_return_at")
            except ValueError as exc:
                raise ValidationFailed(str(exc)) from exc
            expected = expected.isoformat().replace("+00:00", "Z")
        parent = raw.get("parent_handoff_id")
        if parent is not None:
            parent = identifier(parent, "parent_handoff_id")
        if kind == "return" and parent is None:
            raise ValidationFailed("归还交接必须通过 parent_handoff_id 指回借出交接")
        return cls(
            handoff_id=identifier(raw.get("handoff_id"), "handoff_id"),
            kind=kind,
            to_org=identifier(raw.get("to_org"), "to_org"),
            to_contact=optional_text(raw.get("to_contact"), "to_contact"),
            lines=lines,
            expected_return_at=expected,
            parent_handoff_id=parent,
            note=optional_text(raw.get("note"), "note", 512),
            idempotency_key=identifier(raw.get("idempotency_key"), "idempotency_key"),
        )
