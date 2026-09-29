from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from sample_chain.api import JsonApplication
from sample_chain.clock import FrozenClock
from sample_chain.errors import Conflict, Forbidden, InvalidState
from sample_chain.service import SampleChainService


def seal(letter: str) -> str:
    return "sha256:" + letter * 64


class ChainTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc))
        self.service = SampleChainService(self.connection, self.clock)
        self.service.create_user("admin", "管理局", "authority")
        for org_id, name, kind in (
            ("park-authority", "管理局", "authority"),
            ("station-north", "北部保护站", "station"),
            ("university-botany", "高校植物学团队", "university"),
            ("university-other", "高校其他团队", "university"),
            ("lab-genetic", "遗传实验室", "laboratory"),
        ):
            self.service.register_org("admin", org_id, name, kind)
        self.service.create_user("warden", "值班员", "station", "station-north")
        self.service.create_user("leader", "领队", "researcher", "university-botany")
        self.service.create_user("other", "外团队", "researcher", "university-other")
        self.service.create_user("analyst", "分析师", "lab", "lab-genetic")
        self.service.create_user("auditor", "审计员", "auditor")
        self.permit_payload = {
            "permit_id": "P1",
            "version": 1,
            "team_id": "university-botany",
            "title": "缓冲区采样许可",
            "holder_contact": "领队 138",
            "scope": [
                {"key": "orchid", "kind": "species", "label": "珍稀兰科", "unit": "g",
                 "cap_units": "100", "sensitive": True},
                {"key": "oak", "kind": "species", "label": "壳斗科", "unit": "g",
                 "cap_units": "500", "sensitive": False},
            ],
            "valid_from": "2026-09-01T00:00:00Z",
            "valid_until": "2026-10-31T23:59:59Z",
        }
        self.service.issue_permit("admin", self.permit_payload)

    def tearDown(self) -> None:
        self.connection.close()

    def collect(
        self,
        sample_id: str,
        quantity: str,
        scope_key: str = "orchid",
        key: str | None = None,
        seal_letter: str = "a",
    ):
        return self.service.collect_sample(
            "leader",
            {
                "sample_id": sample_id,
                "permit_id": "P1",
                "permit_version": 1,
                "scope_key": scope_key,
                "site_id": "GULLY-7",
                "site_label": "缓冲区七号沟",
                "site_detail": "加密坐标",
                "site_contact": "护林员 139",
                "quantity": quantity,
                "seal_digest": seal(seal_letter),
                "collected_at": "2026-09-20T06:30:00Z",
                "idempotency_key": key or f"collect-{sample_id}",
            },
        )


class PermitTests(ChainTestBase):
    def test_permit_version_hashes_its_document(self) -> None:
        result = self.service.issue_permit(
            "admin",
            {**self.permit_payload, "permit_id": "P1", "version": 2,
             "supersedes_version": 1, "title": "更新后的许可"},
        )
        self.assertEqual(result["version"], 2)
        self.assertEqual(len(result["document_sha256"]), 64)
        view = self.service.permit_view("admin", "P1")
        self.assertEqual(view["version"], 2)  # 最新版本

    def test_new_version_must_supersede_existing(self) -> None:
        with self.assertRaises(Exception):
            self.service.issue_permit(
                "admin",
                {**self.permit_payload, "version": 3, "supersedes_version": 2},
            )

    def test_cap_enforced_and_remaining_quota(self) -> None:
        self.collect("S1", "60")
        with self.assertRaises(Conflict):
            self.collect("S2", "50")  # 60 + 50 > 100
        view = self.service.permit_view("admin", "P1", 1)
        orchid = view["scope"][0]
        self.assertEqual(orchid["used_units"], "60.000")
        self.assertEqual(orchid["remaining_units"], "40.000")
        self.assertTrue(orchid["within_cap"])

    def test_out_of_validity_window_rejected(self) -> None:
        payload = {
            "sample_id": "SX", "permit_id": "P1", "permit_version": 1, "scope_key": "orchid",
            "site_id": "G7", "site_label": "沟", "quantity": "1", "seal_digest": seal("a"),
            "collected_at": "2026-11-01T00:00:00Z", "idempotency_key": "k-late",
        }
        with self.assertRaises(InvalidState):
            self.service.collect_sample("leader", payload)

    def test_only_authority_issues_permit(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.issue_permit("leader", {**self.permit_payload, "permit_id": "P2"})


class CollectionTests(ChainTestBase):
    def test_collect_records_custodian_and_seal(self) -> None:
        result = self.collect("S1", "60")
        self.assertEqual(result["custodian_org"], "university-botany")
        self.assertEqual(result["state"], "on_hand")
        self.assertEqual(result["remaining_units"], "40.000")

    def test_idempotent_replay_and_conflict(self) -> None:
        first = self.collect("S1", "60", key="same-key")
        second = self.collect("S1", "60", key="same-key")
        self.assertEqual(first, second)
        # 同幂等键但不同内容 -> 冲突，且不写入第二条样本。
        with self.assertRaises(Conflict):
            self.collect("S9", "61", key="same-key")
        count = self.connection.execute("SELECT count(*) FROM samples").fetchone()[0]
        self.assertEqual(count, 1)

    def test_bad_seal_digest_rejected(self) -> None:
        with self.assertRaises(Exception):
            self.service.collect_sample("leader", {
                "sample_id": "S1", "permit_id": "P1", "permit_version": 1, "scope_key": "orchid",
                "site_id": "G7", "site_label": "沟", "quantity": "1", "seal_digest": "not-a-hash",
                "collected_at": "2026-09-20T06:30:00Z", "idempotency_key": "k",
            })


class ConservationTests(ChainTestBase):
    def test_split_must_conserve(self) -> None:
        self.collect("S1", "60")
        with self.assertRaises(Conflict):
            self.service.split_sample("leader", {
                "parent_sample_id": "S1", "idempotency_key": "sp-bad",
                "outputs": [
                    {"sample_id": "S1a", "quantity": "40", "seal_digest": seal("c")},
                    {"sample_id": "S1b", "quantity": "10", "seal_digest": seal("d")},
                ],
            })
        state = self.service.sample_provenance("auditor", "S1")["sample"]["state"]
        self.assertEqual(state, "on_hand")  # 失败不改变状态

    def test_split_then_merge_conserves(self) -> None:
        self.collect("S1", "60")
        self.service.split_sample("leader", {
            "parent_sample_id": "S1", "idempotency_key": "sp",
            "outputs": [
                {"sample_id": "S1a", "quantity": "40", "seal_digest": seal("c")},
                {"sample_id": "S1b", "quantity": "20", "seal_digest": seal("d")},
            ],
        })
        # 把两份重新合并回一个样本。
        self.service.merge_samples("leader", {
            "output": {"sample_id": "S2", "quantity": "60", "seal_digest": seal("e")},
            "inputs": [
                {"sample_id": "S1a", "quantity": "40", "seal_digest": seal("c")},
                {"sample_id": "S1b", "quantity": "20", "seal_digest": seal("d")},
            ],
            "idempotency_key": "mg",
        })
        report = self.service.conservation_report("auditor")
        self.assertTrue(report["balanced"])
        self.assertEqual(report["accounted_on_hand_units"], "60.000")

    def test_merge_mismatch_rejected(self) -> None:
        self.collect("S1", "30", key="c-s1")
        self.collect("S2", "40", key="c-s2")
        with self.assertRaises(Conflict):
            self.service.merge_samples("leader", {
                "output": {"sample_id": "S3", "quantity": "99", "seal_digest": seal("e")},
                "inputs": [
                    {"sample_id": "S1", "quantity": "30", "seal_digest": seal("a")},
                    {"sample_id": "S2", "quantity": "40", "seal_digest": seal("a")},
                ],
                "idempotency_key": "mg-bad",
            })


class HandoffTests(ChainTestBase):
    def _to_station(self, sample_id="S1", quantity="60"):
        self.collect(sample_id, quantity)
        self.service.propose_handoff("leader", {
            "handoff_id": "H-IN", "kind": "transfer", "to_org": "station-north",
            "lines": [{"sample_id": sample_id, "quantity": quantity}],
            "idempotency_key": "h-in",
        })
        self.service.confirm_handoff("warden", "H-IN", {sample_id: seal("a")})

    def test_only_receiver_confirms(self) -> None:
        self.collect("S1", "60")
        self.service.propose_handoff("leader", {
            "handoff_id": "H1", "kind": "transfer", "to_org": "station-north",
            "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "h1",
        })
        with self.assertRaises(Forbidden):
            self.service.confirm_handoff("leader", "H1", {"S1": seal("a")})
        with self.assertRaises(Forbidden):
            self.service.confirm_handoff("analyst", "H1", {"S1": seal("a")})

    def test_seal_mismatch_blocks_completion(self) -> None:
        self.collect("S1", "60")
        self.service.propose_handoff("leader", {
            "handoff_id": "H1", "kind": "transfer", "to_org": "station-north",
            "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "h1",
        })
        with self.assertRaises(InvalidState):
            self.service.confirm_handoff("warden", "H1", {"S1": seal("b")})
        # 交接仍待确认，责任方未变，数量已预留。
        sample = self.service.sample_provenance("auditor", "S1")["sample"]
        self.assertEqual(sample["custodian_org"], "university-botany")
        self.assertEqual(sample["reserved_quantity"], "60.000")
        handoff = self.connection.execute(
            "SELECT state FROM handoffs WHERE handoff_id='H1'"
        ).fetchone()
        self.assertEqual(handoff["state"], "proposed")

    def test_all_or_nothing_when_one_line_invalid(self) -> None:
        self.collect("S1", "60")  # 高校持有
        self.collect("S2", "30", key="collect-S2")  # 同样在高校
        # 先把 S1 调到保护站，使其不属于高校。
        self.service.propose_handoff("leader", {
            "handoff_id": "H0", "kind": "transfer", "to_org": "station-north",
            "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "h0",
        })
        self.service.confirm_handoff("warden", "H0", {"S1": seal("a")})
        # 保护站试图一单同时借 S1（合法）与 S2（不属保护站），应整单失败。
        with self.assertRaises(Forbidden):
            self.service.propose_handoff("warden", {
                "handoff_id": "HBAD", "kind": "loan", "to_org": "lab-genetic",
                "lines": [{"sample_id": "S1", "quantity": "60"},
                          {"sample_id": "S2", "quantity": "30"}],
                "idempotency_key": "hbad",
            })
        self.assertIsNone(self.connection.execute(
            "SELECT 1 FROM handoffs WHERE handoff_id='HBAD'"
        ).fetchone())
        self.assertEqual(
            self.service.sample_provenance("auditor", "S1")["sample"]["reserved_quantity"],
            "0.000",
        )

    def test_reject_releases_reservation(self) -> None:
        self.collect("S1", "60")
        self.service.propose_handoff("leader", {
            "handoff_id": "H1", "kind": "transfer", "to_org": "station-north",
            "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "h1",
        })
        self.service.reject_handoff("warden", "H1", "封签破损")
        sample = self.service.sample_provenance("auditor", "S1")["sample"]
        self.assertEqual(sample["reserved_quantity"], "0.000")
        self.assertEqual(sample["state"], "on_hand")

    def test_loan_partial_destroy_and_return(self) -> None:
        self._to_station()
        self.service.propose_handoff("warden", {
            "handoff_id": "HLOAN", "kind": "loan", "to_org": "lab-genetic",
            "expected_return_at": "2026-09-25T00:00:00Z",
            "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "hloan",
        })
        self.service.confirm_handoff("analyst", "HLOAN", {"S1": seal("a")})
        # 借出后实验室拆分：40 留待归还、20 分析。
        self.service.split_sample("analyst", {
            "parent_sample_id": "S1", "idempotency_key": "spl",
            "outputs": [
                {"sample_id": "S1r", "quantity": "40", "seal_digest": seal("c")},
                {"sample_id": "S1d", "quantity": "20", "seal_digest": seal("d")},
            ],
        })
        self.service.destroy_sample("analyst", {
            "destruction_id": "D1", "sample_id": "S1d", "quantity": "20",
            "reason": "制片消耗", "witness_id": "leader", "idempotency_key": "d1",
        })
        # 借出逾期未还应被标记为缺失交接。
        self.clock.advance(days=10)
        overdue = self.service.sample_provenance("auditor", "S1r")
        self.assertIn("overdue_return", overdue["missing_handoffs"])
        # 归还剩余 40g。
        self.service.propose_handoff("analyst", {
            "handoff_id": "HRET", "kind": "return", "to_org": "station-north",
            "parent_handoff_id": "HLOAN",
            "lines": [{"sample_id": "S1r", "quantity": "40"}], "idempotency_key": "hret",
        })
        self.service.confirm_handoff("warden", "HRET", {"S1r": seal("c")})
        final = self.service.sample_provenance("auditor", "S1r")["sample"]
        self.assertEqual(final["custodian_org"], "station-north")
        self.assertEqual(final["state"], "on_hand")
        report = self.service.conservation_report("auditor")
        self.assertTrue(report["balanced"])
        self.assertEqual(report["accounted_on_hand_units"], "40.000")
        self.assertEqual(report["destroyed_units"], "20.000")

    def test_return_must_reference_loan_and_direction(self) -> None:
        self._to_station()
        with self.assertRaises(Exception):
            self.service.propose_handoff("warden", {
                "handoff_id": "HBADRET", "kind": "return", "to_org": "university-botany",
                "parent_handoff_id": "H-IN",
                "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "hbadret",
            })


class DestroyTests(ChainTestBase):
    def test_destroy_requires_distinct_witness_and_conserves(self) -> None:
        self.collect("S1", "60")
        with self.assertRaises(Exception):
            self.service.destroy_sample("leader", {
                "destruction_id": "D0", "sample_id": "S1", "quantity": "10",
                "reason": "x", "witness_id": "leader", "idempotency_key": "d0",
            })
        self.service.destroy_sample("leader", {
            "destruction_id": "D1", "sample_id": "S1", "quantity": "15",
            "reason": "污染灭活", "witness_id": "warden", "idempotency_key": "d1",
        })
        sample = self.service.sample_provenance("auditor", "S1")["sample"]
        self.assertEqual(sample["on_hand_quantity"], "45.000")
        self.assertEqual(sample["state"], "on_hand")
        report = self.service.conservation_report("auditor")
        self.assertTrue(report["balanced"])

    def test_only_custodian_can_destroy(self) -> None:
        self.collect("S1", "60")
        with self.assertRaises(Forbidden):
            self.service.destroy_sample("analyst", {
                "destruction_id": "D2", "sample_id": "S1", "quantity": "1",
                "reason": "x", "witness_id": "leader", "idempotency_key": "d2",
            })


class RevocationTests(ChainTestBase):
    def test_revocation_blocks_future_but_keeps_history(self) -> None:
        self.collect("S1", "60")
        events_before = self.connection.execute(
            "SELECT count(*) FROM chain_audit_events"
        ).fetchone()[0]
        self.service.revoke_permit("admin", "P1", 1, "项目终止")
        with self.assertRaises(InvalidState):
            self.collect("S2", "10", key="collect-S2")
        with self.assertRaises(InvalidState):
            self.service.propose_handoff("leader", {
                "handoff_id": "HLATE", "kind": "loan", "to_org": "lab-genetic",
                "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "hlate",
            })
        # 合法历史仍然完整可查。
        provenance = self.service.sample_provenance("auditor", "S1")
        self.assertEqual(provenance["permit"]["state"], "revoked")
        self.assertEqual(provenance["source"]["permit_state_current"], "revoked")
        self.assertEqual(provenance["sample"]["on_hand_quantity"], "60.000")
        self.assertEqual(len(provenance["lineage"]), 1)
        events_after = self.connection.execute(
            "SELECT count(*) FROM chain_audit_events"
        ).fetchone()[0]
        self.assertEqual(events_after, events_before + 1)  # 仅新增撤回事件

    def test_double_revoke_rejected(self) -> None:
        self.service.revoke_permit("admin", "P1", 1, "x")
        with self.assertRaises(InvalidState):
            self.service.revoke_permit("admin", "P1", 1, "y")

    def test_wind_down_actions_still_allowed_after_revoke(self) -> None:
        # 高校采集 -> 保护站 -> 实验室借出，随后许可撤回。
        self.collect("S1", "60")
        self.service.propose_handoff("leader", {
            "handoff_id": "HIN", "kind": "transfer", "to_org": "station-north",
            "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "hin",
        })
        self.service.confirm_handoff("warden", "HIN", {"S1": seal("a")})
        self.service.propose_handoff("warden", {
            "handoff_id": "HLOAN", "kind": "loan", "to_org": "lab-genetic",
            "expected_return_at": "2026-09-30T00:00:00Z",
            "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "hloan",
        })
        self.service.confirm_handoff("analyst", "HLOAN", {"S1": seal("a")})
        self.service.revoke_permit("admin", "P1", 1, "结题")
        # 实验室仍可拆分、销毁并归还剩余材料。
        self.service.split_sample("analyst", {
            "parent_sample_id": "S1", "idempotency_key": "sp",
            "outputs": [
                {"sample_id": "S1r", "quantity": "40", "seal_digest": seal("c")},
                {"sample_id": "S1d", "quantity": "20", "seal_digest": seal("d")},
            ],
        })
        self.service.destroy_sample("analyst", {
            "destruction_id": "D1", "sample_id": "S1d", "quantity": "20",
            "reason": "分析消耗", "witness_id": "leader", "idempotency_key": "d1",
        })
        self.service.propose_handoff("analyst", {
            "handoff_id": "HRET", "kind": "return", "to_org": "station-north",
            "parent_handoff_id": "HLOAN",
            "lines": [{"sample_id": "S1r", "quantity": "40"}], "idempotency_key": "hret",
        })
        self.service.confirm_handoff("warden", "HRET", {"S1r": seal("c")})
        self.assertEqual(
            self.service.sample_provenance("auditor", "S1r")["sample"]["custodian_org"],
            "station-north",
        )
        # 但保护站不能再把剩余材料转借给实验室。
        with self.assertRaises(InvalidState):
            self.service.propose_handoff("warden", {
                "handoff_id": "HNEW", "kind": "loan", "to_org": "lab-genetic",
                "lines": [{"sample_id": "S1r", "quantity": "40"}], "idempotency_key": "hnew",
            })


class DisclosureTests(ChainTestBase):
    def test_sensitive_fields_redacted_by_role(self) -> None:
        self.collect("S1", "60")
        self.assertEqual(
            self.service.sample_provenance("analyst", "S1")["sample"]["site_detail"], "***"
        )
        self.assertEqual(
            self.service.sample_provenance("other", "S1")["sample"]["site_contact"], "***"
        )
        # 采集团队本人、保护站、审计可见明文。
        self.assertEqual(
            self.service.sample_provenance("leader", "S1")["sample"]["site_detail"], "加密坐标"
        )
        self.assertEqual(
            self.service.sample_provenance("warden", "S1")["sample"]["site_contact"], "护林员 139"
        )
        self.assertEqual(
            self.service.sample_provenance("auditor", "S1")["sample"]["site_label"], "缓冲区七号沟"
        )

    def test_permit_holder_contact_hidden_from_non_privileged(self) -> None:
        self.assertEqual(self.service.permit_view("leader", "P1")["holder_contact"], "***")
        self.assertEqual(self.service.permit_view("admin", "P1")["holder_contact"], "领队 138")


class AuditTests(ChainTestBase):
    def test_chain_valid_and_detects_tampering(self) -> None:
        self.collect("S1", "60")
        self.assertTrue(self.service.audit_chain("auditor")["valid"])
        self.connection.execute(
            "UPDATE chain_audit_events SET payload_json='{}' WHERE event_id=1"
        )
        self.assertFalse(self.service.audit_chain("auditor")["valid"])

    def test_only_auditor_reads_chain(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.audit_chain("leader")


class MissingHandoffTests(ChainTestBase):
    def test_pending_confirmation_listed(self) -> None:
        self.collect("S1", "60")
        self.service.propose_handoff("leader", {
            "handoff_id": "H1", "kind": "transfer", "to_org": "station-north",
            "lines": [{"sample_id": "S1", "quantity": "60"}], "idempotency_key": "h1",
        })
        prov = self.service.sample_provenance("auditor", "S1")
        self.assertIn("incoming_confirmation_pending", prov["missing_handoffs"])
        self.assertEqual(prov["pending_handoffs"][0]["awaiting_org"], "station-north")
        queue = self.service.handoff_queue("warden", "proposed")
        self.assertEqual(queue["items"][0]["handoff_id"], "H1")
        self.assertEqual(queue["items"][0]["awaiting_action"], "confirm")


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.app = JsonApplication(SampleChainService(self.connection))

    def tearDown(self) -> None:
        self.connection.close()

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_requires_actor(self) -> None:
        response = self.app.handle("GET", "/permits/P1")
        self.assertEqual(response.status, 422)

    def test_unknown_route(self) -> None:
        response = self.app.handle("GET", "/nope", headers={"X-Actor-Id": "admin"})
        self.assertEqual(response.status, 404)

    def test_not_found_shape(self) -> None:
        response = self.app.handle(
            "GET", "/permits/NOPE/1", headers={"X-Actor-Id": "admin"}
        )
        self.assertEqual(response.status, 404)
        self.assertEqual(response.body["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
