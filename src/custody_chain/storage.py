"""科研采样许可与保管链的 SQLite 模式和事务辅助。

设计要点：
- custody_ledger 与 permit_versions、custody_events 只追加，代码路径中不存在
  UPDATE/DELETE，历史不可覆盖；
- samples 是可更新的当前状态指针（余额、当前责任方、版本号），每次变动都在
  custody_ledger 留下带运行余额的台账行并在 custody_events 留下哈希链事件；
- 跨机构交接 transfers 必须从 proposed 走到 confirmed/rejected，确认在单事务内
  一次完成（全有或全无）。
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS custody_users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('authority','station','researcher','lab','auditor')),
    org TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permits (
    permit_id TEXT PRIMARY KEY,
    current_version INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','revoked')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 许可版本只追加：修订写入新版本行，旧行永不修改。
CREATE TABLE IF NOT EXISTS permit_versions (
    permit_id TEXT NOT NULL REFERENCES permits(permit_id),
    version INTEGER NOT NULL,
    scope_json TEXT NOT NULL,
    quantity_caps_json TEXT NOT NULL,
    sensitive_species_json TEXT NOT NULL,
    holder_org TEXT NOT NULL,
    contact_name TEXT NOT NULL,
    contact_ref TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    note TEXT,
    content_sha256 TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES custody_users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(permit_id, version)
);

CREATE TABLE IF NOT EXISTS permit_revocations (
    permit_id TEXT PRIMARY KEY REFERENCES permits(permit_id),
    version INTEGER NOT NULL,
    reason TEXT NOT NULL,
    revoked_by TEXT NOT NULL REFERENCES custody_users(user_id),
    revoked_at TEXT NOT NULL
);

-- 按许可 + 范围键（物种或生境）累计已采集量，用于剩余额度核对。
CREATE TABLE IF NOT EXISTS permit_quota_usage (
    permit_id TEXT NOT NULL REFERENCES permits(permit_id),
    target_key TEXT NOT NULL,
    unit TEXT NOT NULL,
    collected_units TEXT NOT NULL,
    PRIMARY KEY(permit_id, target_key)
);

CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    permit_id TEXT NOT NULL REFERENCES permits(permit_id),
    permit_version INTEGER NOT NULL,
    species TEXT NOT NULL,
    habitat TEXT NOT NULL,
    unit TEXT NOT NULL,
    location TEXT NOT NULL,
    location_detail TEXT,
    sensitive INTEGER NOT NULL DEFAULT 0 CHECK(sensitive IN (0,1)),
    collected_units TEXT NOT NULL,
    balance_units TEXT NOT NULL,
    reserved_units TEXT NOT NULL DEFAULT '0',
    custodian_org TEXT NOT NULL,
    custodian_id TEXT NOT NULL,
    seal_digest TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','depleted','destroyed')),
    revision INTEGER NOT NULL DEFAULT 1,
    collected_by TEXT NOT NULL REFERENCES custody_users(user_id),
    collected_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_samples_permit ON samples(permit_id, species);
CREATE INDEX IF NOT EXISTS idx_samples_custodian ON samples(custodian_org, status);

-- 保管台账：只追加。change_units 带符号，destroy 事件为负、其余守恒变动正负相抵。
CREATE TABLE IF NOT EXISTS custody_ledger (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    sample_id TEXT NOT NULL REFERENCES samples(sample_id),
    permit_id TEXT NOT NULL,
    change_units TEXT NOT NULL,
    balance_after TEXT NOT NULL,
    counterparty_org TEXT,
    custodian_id TEXT NOT NULL,
    seal_digest TEXT,
    transfer_id TEXT,
    leg TEXT CHECK(leg IS NULL OR leg IN ('out','in')),
    payload_json TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES custody_users(user_id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_sample ON custody_ledger(sample_id, entry_id);
CREATE INDEX IF NOT EXISTS idx_ledger_correlation ON custody_ledger(correlation_id);

CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('split','merge','destroy')),
    request_sha256 TEXT NOT NULL,
    idempotency_key TEXT UNIQUE,
    result_json TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES custody_users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transfers (
    transfer_id TEXT PRIMARY KEY,
    direction TEXT NOT NULL CHECK(direction IN ('loan','return','handover')),
    proposal_json TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'proposed' CHECK(state IN ('proposed','confirmed','rejected')),
    origin_org TEXT NOT NULL,
    destination_org TEXT NOT NULL,
    proposed_by TEXT NOT NULL REFERENCES custody_users(user_id),
    proposed_at TEXT NOT NULL,
    confirmed_by TEXT REFERENCES custody_users(user_id),
    confirmed_at TEXT,
    receiving_seal_digest TEXT,
    rejection_reason TEXT,
    rejected_by TEXT REFERENCES custody_users(user_id),
    rejected_at TEXT,
    idempotency_key TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_transfers_state ON transfers(state, proposed_at);

CREATE TABLE IF NOT EXISTS custody_idempotency (
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(scope, idempotency_key)
);

CREATE TABLE IF NOT EXISTS custody_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_custody_events_entity
ON custody_events(entity_type, entity_id, event_id);
"""


def connect(path: str | Path, *, check_same_thread: bool = True) -> sqlite3.Connection:
    connection = sqlite3.connect(
        str(path), isolation_level=None, timeout=10, check_same_thread=check_same_thread
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=5000")
    initialize(connection)
    return connection


def initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)


@contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()
