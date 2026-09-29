from __future__ import annotations

import json
import sqlite3
import unittest

from custody_chain.api import JsonApplication
from custody_chain.service import CustodyChainService


def hashlib_seal(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CustodyApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(CustodyChainService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def call(self, method: str, path: str, actor: str | None = None, payload: dict | None = None):
        body = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else b""
        headers = {"X-Actor-Id": actor} if actor else {}
        return self.app.handle(method, path, headers, body)

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_requires_actor_header(self) -> None:
        response = self.call("GET", "/permits/P1")
        self.assertEqual(response.status, 422)

    def test_end_to_end_over_http(self) -> None:
        self.assertEqual(self.call("POST", "/users", payload={
            "user_id": "a1", "display_name": "许可官", "role": "authority", "org": "林管局"}) .status, 201)
        self.assertEqual(self.call("POST", "/users", payload={
            "user_id": "t1", "display_name": "领队", "role": "researcher", "org": "高校"}).status, 201)
        self.assertEqual(self.call("POST", "/users", payload={
            "user_id": "s1", "display_name": "保管员", "role": "station", "org": "保护站"}).status, 201)
        self.assertEqual(self.call("POST", "/users", payload={
            "user_id": "d1", "display_name": "审计员", "role": "auditor", "org": "审计署"}).status, 201)
        permit = self.call("POST", "/permits", "a1", {
            "permit_id": "P1", "version": 1,
            "species": ["SP-A"], "habitats": ["H1"], "quantity_caps": {"SP-A": "5"},
            "sensitive_species": [], "holder_org": "高校",
            "contact_name": "甲", "contact_ref": "1",
            "valid_from": "2026-09-01T00:00:00Z",
        })
        self.assertEqual(permit.status, 201)
        collected = self.call("POST", "/samples", "t1", {
            "sample_id": "S1", "permit_id": "P1", "permit_version": 1,
            "species": "SP-A", "habitat": "H1", "quantity": "5", "unit": "g",
            "location": "点位", "collected_at": "2026-09-20T09:00:00Z",
            "seal_digest": hashlib_seal("s1"), "collector_id": "t1",
        })
        self.assertEqual(collected.status, 201)
        self.assertEqual(collected.body["quota_remaining"], "0")
        split = self.call("POST", "/samples/split", "t1", {
            "operation_id": "O1",
            "inputs": [{"sample_id": "S1", "quantity": "5"}],
            "outputs": [{"sample_id": "S1A", "quantity": "3"}, {"sample_id": "S1B", "quantity": "2"}],
            "custodian_id": "t1", "seal_digest": hashlib_seal("split"),
        })
        self.assertEqual(split.status, 201)
        proposed = self.call("POST", "/transfers", "t1", {
            "transfer_id": "T1", "direction": "handover", "destination_org": "保护站",
            "custodian_id": "t1",
            "parts": [{"sample_id": "S1A", "quantity": "3"}],
        })
        self.assertEqual(proposed.status, 201)
        missing = self.call("GET", "/transfers/missing", "s1")
        self.assertFalse(missing.body["complete"])
        confirmed = self.call("POST", "/transfers/T1/confirm", "s1", {
            "receiving_custodian_id": "s1", "receiving_seal_digest": hashlib_seal("recv")})
        self.assertEqual(confirmed.status, 200)
        status = self.call("GET", "/samples/S1A", "s1")
        self.assertEqual(status.body["current_custodian_org"], "保护站")
        chain = self.call("GET", "/samples/S1A/chain", "s1")
        self.assertEqual(len(chain.body["unpaired_transfer_entries"]), 0)
        revoked = self.call("POST", "/permits/P1/revoke", "a1",
                            {"expected_version": 1, "reason": "终止"})
        self.assertEqual(revoked.status, 200)
        audit = self.call("GET", "/audit/chain", "s1")
        self.assertEqual(audit.status, 403)
        self.assertEqual(self.call("GET", "/audit/chain", "d1").body["valid"], True)


if __name__ == "__main__":
    unittest.main()
