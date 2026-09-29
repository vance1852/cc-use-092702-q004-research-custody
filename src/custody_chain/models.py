"""科研采样许可与保管链领域输入契约。

所有数量统一使用十进制文本（单位由业务自行约定，如克、片、份），
范围以物种标识或生境标识两个集合表达，敏感物种单独打标。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Mapping

from .errors import ValidationFailed


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
SEAL_DIGEST = re.compile(r"^[a-f0-9]{64}$")
ROLES = {"authority", "station", "researcher", "lab", "auditor"}
EVENT_KINDS = {
    "permit.granted",
    "permit.revised",
    "permit.revoked",
    "sample.collected",
    "sample.split",
    "sample.merged",
    "sample.loaned",
    "sample.returned",
    "sample.destroyed",
    "transfer.proposed",
    "transfer.confirmed",
    "transfer.rejected",
}
OPERATION_KINDS = {"split", "merge", "loan", "return", "destroy"}


def required_text(value: object, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{name} 不能为空")
    result = value.strip()
    if len(result) > maximum:
        raise ValidationFailed(f"{name} 不能超过 {maximum} 个字符")
    return result


def optional_text(value: object, name: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    return required_text(value, name, maximum)


def identifier(value: object, name: str) -> str:
    result = required_text(value, name, 64)
    if not IDENTIFIER.fullmatch(result):
        raise ValidationFailed(f"{name} 格式不正确")
    return result


def quantity(value: object, name: str, *, minimum: Decimal = Decimal("0.001")) -> Decimal:
    if isinstance(value, bool):
        raise ValidationFailed(f"{name} 必须是十进制数值")
    try:
        result = Decimal(str(value))
    except Exception as exc:  # InvalidOperation/ValueError/TypeError
        raise ValidationFailed(f"{name} 必须是十进制数值") from exc
    if not result.is_finite() or result < minimum:
        raise ValidationFailed(f"{name} 必须是不小于 {minimum} 的有限数值")
    return result


def identifier_set(value: object, name: str) -> list[str]:
    if not isinstance(value, (list, tuple, set)) or not value:
        raise ValidationFailed(f"{name} 必须是非空数组")
    result: list[str] = []
    for item in value:
        parsed = identifier(item, f"{name} 元素")
        if parsed in result:
            raise ValidationFailed(f"{name} 存在重复条目 {parsed}")
        result.append(parsed)
    return result


def string_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValidationFailed(f"{name} 必须是数组")
    result: list[str] = []
    for item in value:
        result.append(required_text(item, f"{name} 元素", 256))
    return result


def seal_digest(value: object, name: str = "seal_digest") -> str:
    result = required_text(value, name, 64).lower()
    if not SEAL_DIGEST.fullmatch(result):
        raise ValidationFailed(f"{name} 必须是 64 位小写十六进制 SHA-256 摘要")
    return result


@dataclass(frozen=True, slots=True)
class PermitDraft:
    """许可授予或修订的输入。"""

    permit_id: str
    version: int
    species: list[str]
    habitats: list[str]
    quantity_caps: dict[str, Decimal]
    sensitive_species: list[str]
    holder_org: str
    contact_name: str
    contact_ref: str
    valid_from: str
    valid_until: str | None
    note: str | None
    supersedes_version: int | None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PermitDraft":
        permit_id = identifier(raw.get("permit_id"), "permit_id")
        version = raw.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ValidationFailed("version 必须是不小于 1 的整数")
        species = identifier_set(raw.get("species"), "species")
        habitats = identifier_set(raw.get("habitats"), "habitats")
        caps_raw = raw.get("quantity_caps")
        if not isinstance(caps_raw, Mapping) or not caps_raw:
            raise ValidationFailed("quantity_caps 必须是非空对象")
        caps: dict[str, Decimal] = {}
        for key, value in caps_raw.items():
            target = identifier(key, "quantity_caps 键")
            if target not in species and target not in habitats:
                raise ValidationFailed(f"额度键 {target} 必须出现在 species 或 habitats 中")
            caps[target] = quantity(value, f"quantity_caps.{key}")
        sensitive_raw = raw.get("sensitive_species", [])
        sensitive = string_list(sensitive_raw, "sensitive_species")
        for item in sensitive:
            if item not in species:
                raise ValidationFailed(f"敏感物种 {item} 必须在 species 范围内")
        valid_from = required_text(raw.get("valid_from"), "valid_from", 40)
        valid_until = optional_text(raw.get("valid_until"), "valid_until", 40)
        if valid_until is not None and valid_until <= valid_from:
            raise ValidationFailed("valid_until 必须晚于 valid_from")
        supersedes = raw.get("supersedes_version")
        if supersedes is not None and (isinstance(supersedes, bool) or not isinstance(supersedes, int) or supersedes < 1):
            raise ValidationFailed("supersedes_version 必须是不小于 1 的整数")
        return cls(
            permit_id=permit_id,
            version=version,
            species=species,
            habitats=habitats,
            quantity_caps=caps,
            sensitive_species=sensitive,
            holder_org=required_text(raw.get("holder_org"), "holder_org"),
            contact_name=required_text(raw.get("contact_name"), "contact_name"),
            contact_ref=required_text(raw.get("contact_ref"), "contact_ref"),
            valid_from=valid_from,
            valid_until=valid_until,
            note=optional_text(raw.get("note"), "note", 1024),
            supersedes_version=supersedes,
        )


@dataclass(frozen=True, slots=True)
class CollectionDraft:
    """现场采集封装登记输入。"""

    sample_id: str
    permit_id: str
    permit_version: int
    species: str
    habitat: str
    quantity: Decimal
    unit: str
    location: str
    location_detail: str | None
    collected_at: str
    seal_digest: str
    collector_id: str
    note: str | None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CollectionDraft":
        return cls(
            sample_id=identifier(raw.get("sample_id"), "sample_id"),
            permit_id=identifier(raw.get("permit_id"), "permit_id"),
            permit_version=positive_int(raw.get("permit_version"), "permit_version"),
            species=identifier(raw.get("species"), "species"),
            habitat=identifier(raw.get("habitat"), "habitat"),
            quantity=quantity(raw.get("quantity"), "quantity"),
            unit=required_text(raw.get("unit"), "unit", 16),
            location=required_text(raw.get("location"), "location"),
            location_detail=optional_text(raw.get("location_detail"), "location_detail", 512),
            collected_at=required_text(raw.get("collected_at"), "collected_at", 40),
            seal_digest=seal_digest(raw.get("seal_digest")),
            collector_id=identifier(raw.get("collector_id"), "collector_id"),
            note=optional_text(raw.get("note"), "note", 1024),
        )


def positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValidationFailed(f"{name} 必须是不小于 1 的整数")
    return value


@dataclass(frozen=True, slots=True)
class OperationPart:
    sample_id: str
    quantity: Decimal

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "OperationPart":
        return cls(
            sample_id=identifier(raw.get("sample_id"), "sample_id"),
            quantity=quantity(raw.get("quantity"), "quantity"),
        )


@dataclass(frozen=True, slots=True)
class OperationDraft:
    """拆分、合并、借出、归还、销毁的统一输入。"""

    kind: str
    operation_id: str
    inputs: list[OperationPart]
    outputs: list[OperationPart]
    destination_org: str | None
    custodian_id: str
    seal_digest: str | None
    expected_revision: int
    note: str | None
    idempotency_key: str | None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], kind: str) -> "OperationDraft":
        if kind not in OPERATION_KINDS:
            raise ValidationFailed("未知操作类型")
        inputs = [OperationPart.from_dict(item) for item in require_parts(raw.get("inputs"), "inputs")]
        outputs = [OperationPart.from_dict(item) for item in optional_parts(raw.get("outputs", []), "outputs")]
        idem = raw.get("idempotency_key")
        return cls(
            kind=kind,
            operation_id=identifier(raw.get("operation_id"), "operation_id"),
            inputs=inputs,
            outputs=outputs,
            destination_org=optional_text(raw.get("destination_org"), "destination_org"),
            custodian_id=identifier(raw.get("custodian_id"), "custodian_id"),
            seal_digest=None if raw.get("seal_digest") is None else seal_digest(raw.get("seal_digest")),
            expected_revision=positive_int(raw.get("expected_revision", 1), "expected_revision"),
            note=optional_text(raw.get("note"), "note", 1024),
            idempotency_key=None if idem is None else identifier(idem, "idempotency_key"),
        )


def require_parts(value: object, name: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not value or not all(isinstance(item, Mapping) for item in value):
        raise ValidationFailed(f"{name} 必须是非空对象数组")
    return value


def optional_parts(value: object, name: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise ValidationFailed(f"{name} 必须是对象数组")
    return value
