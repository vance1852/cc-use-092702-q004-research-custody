"""科研采样许可与保管链服务的 SQLite 模式和事务辅助。"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .errors import Conflict


# 单容器内 ThreadingHTTPServer 复用同一连接，用写锁串行化写事务；
# 多进程竞争仍由 busy_timeout 与条件式更新兜底。
_WRITE_LOCK = threading.RLock()


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS chain_users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('authority','station','researcher','lab','auditor')),
    org_id TEXT,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    org_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('authority','station','university','laboratory')),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permits (
    permit_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    team_id TEXT NOT NULL,
    title TEXT NOT NULL,
    holder_contact TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    supersedes_version INTEGER,
    document_sha256 TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','revoked')),
    revoked_at TEXT,
    revoke_reason TEXT,
    revoked_by TEXT,
    created_by TEXT NOT NULL REFERENCES chain_users(user_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(permit_id, version)
);

CREATE INDEX IF NOT EXISTS idx_permits_team ON permits(team_id, version);

CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    permit_id TEXT NOT NULL,
    permit_version INTEGER NOT NULL,
    scope_key TEXT NOT NULL,
    sensitive INTEGER NOT NULL DEFAULT 0 CHECK(sensitive IN (0,1)),
    site_id TEXT NOT NULL,
    site_label TEXT NOT NULL,
    site_detail TEXT,
    site_contact TEXT,
    initial_quantity TEXT NOT NULL,
    on_hand_quantity TEXT NOT NULL,
    reserved_quantity TEXT NOT NULL DEFAULT '0',
    custodian_org TEXT NOT NULL,
    seal_digest TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'on_hand'
        CHECK(state IN ('on_hand','in_transit','out_on_loan','consumed','destroyed')),
    root_sample_id TEXT,
    generation INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL REFERENCES chain_users(user_id),
    created_at TEXT NOT NULL,
    FOREIGN KEY(permit_id, permit_version) REFERENCES permits(permit_id, version)
);

CREATE INDEX IF NOT EXISTS idx_samples_permit ON samples(permit_id, permit_version, scope_key);
CREATE INDEX IF NOT EXISTS idx_samples_custodian ON samples(custodian_org, state);

CREATE TABLE IF NOT EXISTS sample_lineage (
    lineage_id INTEGER PRIMARY KEY AUTOINCREMENT,
    child_sample_id TEXT NOT NULL REFERENCES samples(sample_id),
    parent_sample_id TEXT REFERENCES samples(sample_id),
    relation TEXT NOT NULL CHECK(relation IN ('collected','split','merge','handoff')),
    event_id TEXT NOT NULL,
    quantity TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lineage_child ON sample_lineage(child_sample_id, lineage_id);
CREATE INDEX IF NOT EXISTS idx_lineage_parent ON sample_lineage(parent_sample_id, lineage_id);

CREATE TABLE IF NOT EXISTS handoffs (
    handoff_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('loan','return','transfer')),
    from_org TEXT NOT NULL,
    to_org TEXT NOT NULL,
    to_contact TEXT,
    expected_return_at TEXT,
    parent_handoff_id TEXT REFERENCES handoffs(handoff_id),
    note TEXT,
    state TEXT NOT NULL DEFAULT 'proposed'
        CHECK(state IN ('proposed','confirmed','cancelled','completed','rejected')),
    proposed_by TEXT NOT NULL REFERENCES chain_users(user_id),
    proposed_at TEXT NOT NULL,
    confirmer_id TEXT,
    confirmed_at TEXT,
    completed_by TEXT,
    completed_at TEXT,
    idempotency_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS handoff_lines (
    handoff_id TEXT NOT NULL REFERENCES handoffs(handoff_id),
    sample_id TEXT NOT NULL REFERENCES samples(sample_id),
    quantity TEXT NOT NULL,
    seal_digest TEXT NOT NULL,
    PRIMARY KEY(handoff_id, sample_id)
);

CREATE INDEX IF NOT EXISTS idx_handoffs_state ON handoffs(state, proposed_at);
CREATE INDEX IF NOT EXISTS idx_handoffs_parent ON handoffs(parent_handoff_id);

CREATE TABLE IF NOT EXISTS destructions (
    destruction_id TEXT PRIMARY KEY,
    sample_id TEXT NOT NULL REFERENCES samples(sample_id),
    quantity TEXT NOT NULL,
    reason TEXT NOT NULL,
    witness_id TEXT REFERENCES chain_users(user_id),
    idempotency_key TEXT NOT NULL UNIQUE,
    destroyed_by TEXT NOT NULL REFERENCES chain_users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chain_idempotency (
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(scope, idempotency_key)
);

CREATE TABLE IF NOT EXISTS chain_audit_events (
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

CREATE INDEX IF NOT EXISTS idx_chain_audit_entity
ON chain_audit_events(entity_type, entity_id, event_id);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    # ThreadingHTTPServer 会在工作线程中复用连接；写事务统一用 BEGIN IMMEDIATE
    # 串行化，配合 busy_timeout 避免跨线程并发写入冲突。
    connection = sqlite3.connect(
        str(path), isolation_level=None, timeout=10, check_same_thread=False
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
    with _WRITE_LOCK:
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        except sqlite3.OperationalError as exc:
            # 跨进程写锁竞争（SQLITE_BUSY/locked）：转换为领域并发冲突，由上层返回 409。
            raise Conflict("数据正被其它请求修改，请重试") from exc
        try:
            yield
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()


def row_dict(row: sqlite3.Row | None) -> dict[str, object] | None:
    return None if row is None else dict(row)
