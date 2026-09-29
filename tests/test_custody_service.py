from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from custody_chain.clock import FrozenClock
from custody_chain.errors import Conflict, Forbidden, InvalidState, NotFound, ValidationFailed
from custody_chain.service import CustodyChainService


def seal(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CustodyTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc))
        self.service = CustodyChainService(self.connection, self.clock)
        for uid, role, org in (
            ("auth1", "authority", "林管局"),
            ("station1", "station", "保护站A"),
            ("team1", "researcher", "高校团队"),
            ("team2", "researcher", "高校团队"),
            ("lab1", "lab", "实验室B"),
            ("lab2", "lab", "实验室B"),
            ("audit1", "auditor", "审计署"),
        ):
            self.service.create_user(uid, uid, role, org)
        self.service.grant_permit("auth1", {
            "permit_id": "P1",
            "version": 1,
            "species": ["SP-A", "SP-B"],
            "habitats": ["H1"],
            "quantity_caps": {"SP-A": "10", "SP-B": "2"},
            "sensitive_species": ["SP-B"],
            "holder_org": "高校团队",
            "contact_name": "联系人甲",
            "contact_ref": "110",
            "valid_from": "2026-09-01T00:00:00Z",
            "valid_until": "2026-12-31T23:59:59Z",
        })
        self.service.collect_sample("team1", {
            "sample_id": "S1", "permit_id": "P1", "permit_version": 1,
            "species": "SP-A", "habitat": "H1", "quantity": "10", "unit": "g",
            "location": "点位甲", "collected_at": "2026-09-20T09:00:00Z",
            "seal_digest": seal("s1"), "collector_id": "team1",
        })

    def tearDown(self) -> None:
        self.connection.close()

    def collect_second(self, sample_id: str = "S2") -> None:
        self.service.collect_sample("team1", {
            "sample_id": sample_id, "permit_id": "P1", "permit_version": 1,
            "species": "SP-B", "habitat": "H1", "quantity": "2", "unit": "g",
            "location": "点位乙", "collected_at": "2026-09-20T09:30:00Z",
            "seal_digest": seal("s2"), "collector_id": "team1",
        })


class QuotaTests(CustodyTestBase):
    def test_over_quota_rejected(self) -> None:
        with self.assertRaises(Conflict):
            self.service.collect_sample("team1", {
                "sample_id": "SX", "permit_id": "P1", "permit_version": 1,
                "species": "SP-A", "habitat": "H1", "quantity": "0.1", "unit": "g",
                "location": "x", "collected_at": "2026-09-20T10:00:00Z",
                "seal_digest": seal("sx"), "collector_id": "team1",
            })

    def test_species_out_of_scope_rejected(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.collect_sample("team1", {
                "sample_id": "SY", "permit_id": "P1", "permit_version": 1,
                "species": "SP-Z", "habitat": "H1", "quantity": "1", "unit": "g",
                "location": "y", "collected_at": "2026-09-20T10:00:00Z",
                "seal_digest": seal("sy"), "collector_id": "team1",
            })

    def test_only_authority_grants_permit(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.grant_permit("team1", {
                "permit_id": "P2", "version": 1,
                "species": ["SP-A"], "habitats": ["H1"], "quantity_caps": {"SP-A": "1"},
                "sensitive_species": [], "holder_org": "高校团队",
                "contact_name": "x", "contact_ref": "x",
                "valid_from": "2026-09-01T00:00:00Z",
            })

    def test_quota_remaining_view(self) -> None:
        view = self.service.permit_status("auth1", "P1")
        quotas = {q["target"]: q for q in view["quotas"]}
        self.assertEqual(quotas["SP-A"]["remaining"], "0")
        self.assertEqual(quotas["SP-A"]["collected"], "10")
        self.assertEqual(quotas["SP-B"]["remaining"], "2")


class ConservationTests(CustodyTestBase):
    def test_split_conserves_quantity(self) -> None:
        result = self.service.apply_operation("team1", "split", {
            "operation_id": "OP1",
            "inputs": [{"sample_id": "S1", "quantity": "10"}],
            "outputs": [{"sample_id": "S1A", "quantity": "6"}, {"sample_id": "S1B", "quantity": "4"}],
            "custodian_id": "team1",
            "seal_digest": seal("split1"),
        })
        self.assertTrue(result["conservation"]["balanced"])
        self.assertEqual(result["balances"]["S1"], "0")
        parent = self.service.sample_status("team1", "S1")
        self.assertEqual(parent["status"], "depleted")

    def test_split_imbalance_rejected_and_rolled_back(self) -> None:
        with self.assertRaises(Conflict):
            self.service.apply_operation("team1", "split", {
                "operation_id": "OP-BAD",
                "inputs": [{"sample_id": "S1", "quantity": "10"}],
                "outputs": [{"sample_id": "XA", "quantity": "6"}, {"sample_id": "XB", "quantity": "3"}],
                "custodian_id": "team1",
                "seal_digest": seal("bad"),
            })
        with self.assertRaises(NotFound):
            self.service.sample_status("team1", "XA")
        self.assertEqual(self.service.sample_status("team1", "S1")["balance_units"], "10")

    def test_split_exceeding_balance_rejected(self) -> None:
        with self.assertRaises(Conflict):
            self.service.apply_operation("team1", "split", {
                "operation_id": "OP2",
                "inputs": [{"sample_id": "S1", "quantity": "10"}],
                "outputs": [{"sample_id": "YA", "quantity": "9"}, {"sample_id": "YB", "quantity": "2"}],
                "custodian_id": "team1",
                "seal_digest": seal("y"),
            })

    def test_merge_conserves_and_requires_same_species(self) -> None:
        self.service.apply_operation("team1", "split", {
            "operation_id": "OP3",
            "inputs": [{"sample_id": "S1", "quantity": "10"}],
            "outputs": [{"sample_id": "S1A", "quantity": "7"}, {"sample_id": "S1B", "quantity": "3"}],
            "custodian_id": "team1",
            "seal_digest": seal("split3"),
        })
        merged = self.service.apply_operation("team1", "merge", {
            "operation_id": "OP4",
            "inputs": [{"sample_id": "S1A", "quantity": "7"}, {"sample_id": "S1B", "quantity": "3"}],
            "outputs": [{"sample_id": "S1M", "quantity": "10"}],
            "custodian_id": "team2",
            "seal_digest": seal("merge4"),
        })
        self.assertTrue(merged["conservation"]["balanced"])
        self.assertEqual(merged["balances"]["S1M"], "10")

    def test_partial_input_rejected(self) -> None:
        with self.assertRaises(InvalidState):
            self.service.apply_operation("team1", "split", {
                "operation_id": "OP5",
                "inputs": [{"sample_id": "S1", "quantity": "9"}],
                "outputs": [{"sample_id": "P1", "quantity": "5"}, {"sample_id": "P2", "quantity": "4"}],
                "custodian_id": "team1",
                "seal_digest": seal("p"),
            })

    def test_destroy_reduces_balance_and_records_loss(self) -> None:
        result = self.service.apply_operation("team1", "destroy", {
            "operation_id": "OP6",
            "inputs": [{"sample_id": "S1", "quantity": "3"}],
            "outputs": [],
            "custodian_id": "team1",
            "note": "分析耗损",
        })
        self.assertEqual(result["balances"]["S1"], "7")
        self.assertEqual(result["conservation"]["destroyed_total"], "3")

    def test_cross_custodian_operation_forbidden(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.apply_operation("lab1", "destroy", {
                "operation_id": "OP7",
                "inputs": [{"sample_id": "S1", "quantity": "1"}],
                "outputs": [],
                "custodian_id": "lab1",
            })

    def test_operation_idempotent_replay(self) -> None:
        raw = {
            "operation_id": "OP8",
            "inputs": [{"sample_id": "S1", "quantity": "10"}],
            "outputs": [{"sample_id": "R1", "quantity": "6"}, {"sample_id": "R2", "quantity": "4"}],
            "custodian_id": "team1",
            "seal_digest": seal("r"),
            "idempotency_key": "idem-8",
        }
        first = self.service.apply_operation("team1", "split", raw)
        second = self.service.apply_operation("team1", "split", raw)
        self.assertEqual(first, second)
        changed = dict(raw)
        changed["outputs"] = [{"sample_id": "R1", "quantity": "5"}, {"sample_id": "R2", "quantity": "5"}]
        with self.assertRaises(Conflict):
            self.service.apply_operation("team1", "split", changed)


class TransferTests(CustodyTestBase):
    def _handover_to_station(self) -> None:
        self.service.propose_transfer("team1", {
            "transfer_id": "T1", "direction": "handover", "destination_org": "保护站A",
            "custodian_id": "team1", "seal_digest": seal("s1"),
            "parts": [{"sample_id": "S1", "quantity": "10"}],
        })
        self.service.confirm_transfer("station1", "T1", "station1", seal("st1"))

    def test_propose_reserves_and_blocks_other_ops(self) -> None:
        self.service.propose_transfer("team1", {
            "transfer_id": "T0", "direction": "handover", "destination_org": "保护站A",
            "custodian_id": "team1", "seal_digest": seal("s1"),
            "parts": [{"sample_id": "S1", "quantity": "10"}],
        })
        status = self.service.sample_status("team1", "S1")
        self.assertEqual(status["reserved_units"], "10")
        with self.assertRaises(InvalidState):
            self.service.apply_operation("team1", "destroy", {
                "operation_id": "OPX",
                "inputs": [{"sample_id": "S1", "quantity": "1"}],
                "outputs": [], "custodian_id": "team1",
            })
        # 第二份在途提案也被阻止。
        with self.assertRaises(InvalidState):
            self.service.propose_transfer("team1", {
                "transfer_id": "T0B", "direction": "handover", "destination_org": "保护站A",
                "custodian_id": "team1",
                "parts": [{"sample_id": "S1", "quantity": "10"}],
            })

    def test_same_person_cannot_confirm_both_sides(self) -> None:
        self.service.propose_transfer("team1", {
            "transfer_id": "T2", "direction": "handover", "destination_org": "实验室B",
            "custodian_id": "team1", "seal_digest": seal("s1"),
            "parts": [{"sample_id": "S1", "quantity": "10"}],
        })
        with self.assertRaises(Forbidden):
            self.service.confirm_transfer("team1", "T2", "team1", seal("x"))

    def test_only_destination_confirms(self) -> None:
        self.service.propose_transfer("team1", {
            "transfer_id": "T3", "direction": "handover", "destination_org": "实验室B",
            "custodian_id": "team1", "seal_digest": seal("s1"),
            "parts": [{"sample_id": "S1", "quantity": "10"}],
        })
        with self.assertRaises(Forbidden):
            self.service.confirm_transfer("station1", "T3", "station1", seal("x"))

    def test_double_confirm_rejected(self) -> None:
        self._handover_to_station()
        with self.assertRaises(InvalidState):
            self.service.confirm_transfer("station1", "T1", "station1", seal("again"))

    def test_reject_releases_reservation(self) -> None:
        self.service.propose_transfer("team1", {
            "transfer_id": "T4", "direction": "handover", "destination_org": "实验室B",
            "custodian_id": "team1", "seal_digest": seal("s1"),
            "parts": [{"sample_id": "S1", "quantity": "10"}],
        })
        self.service.reject_transfer("lab1", "T4", "封签不符")
        self.assertEqual(self.service.sample_status("team1", "S1")["reserved_units"], "0")
        missing = self.service.missing_handovers("auth1")
        self.assertTrue(missing["complete"])

    def test_loan_and_return_cycle(self) -> None:
        self._handover_to_station()
        self.service.propose_transfer("station1", {
            "transfer_id": "T5", "direction": "loan", "destination_org": "实验室B",
            "custodian_id": "station1", "seal_digest": seal("st1"),
            "parts": [{"sample_id": "S1", "quantity": "10"}],
        })
        self.service.confirm_transfer("lab1", "T5", "lab1", seal("l1"))
        self.assertEqual(self.service.sample_status("lab1", "S1")["current_custodian_org"], "实验室B")
        # 归还给错误的机构（非借出方）在提案阶段即被拒绝。
        with self.assertRaises(InvalidState):
            self.service.propose_transfer("lab1", {
                "transfer_id": "T6BAD", "direction": "return", "destination_org": "高校团队",
                "custodian_id": "lab1",
                "parts": [{"sample_id": "S1", "quantity": "10"}],
            })
        # 正确归还给保护站。
        self.service.propose_transfer("lab1", {
            "transfer_id": "T6", "direction": "return", "destination_org": "保护站A",
            "custodian_id": "lab1", "seal_digest": seal("l1"),
            "parts": [{"sample_id": "S1", "quantity": "10"}],
        })
        self.service.confirm_transfer("station1", "T6", "station1", seal("st2"))
        self.assertEqual(self.service.sample_status("station1", "S1")["current_custodian_org"], "保护站A")
        chain = self.service.sample_chain("audit1", "S1")
        # 每次交接两条腿（出+入），共 3 次交接 = 6 条。
        transfer_legs = [e for e in chain["ledger"] if e["transfer_id"]]
        self.assertEqual(len(transfer_legs), 6)
        self.assertEqual(chain["unpaired_transfer_entries"], [])

    def test_missing_handover_lists_pending(self) -> None:
        self.service.propose_transfer("team1", {
            "transfer_id": "T7", "direction": "handover", "destination_org": "实验室B",
            "custodian_id": "team1",
            "parts": [{"sample_id": "S1", "quantity": "10"}],
        })
        missing = self.service.missing_handovers("auth1")
        self.assertFalse(missing["complete"])
        self.assertEqual(missing["pending_transfers"][0]["missing_confirmation_from"], "实验室B")


class PermitRevisionTests(CustodyTestBase):
    def test_revision_must_be_next_version(self) -> None:
        with self.assertRaises(Conflict):
            self.service.revise_permit("auth1", {
                "permit_id": "P1", "version": 3,
                "species": ["SP-A", "SP-B"], "habitats": ["H1"],
                "quantity_caps": {"SP-A": "10", "SP-B": "2"},
                "sensitive_species": [], "holder_org": "高校团队",
                "contact_name": "联系人甲", "contact_ref": "110",
                "valid_from": "2026-09-01T00:00:00Z",
            })

    def test_caps_cannot_shrink_below_used(self) -> None:
        with self.assertRaises(Conflict):
            self.service.revise_permit("auth1", {
                "permit_id": "P1", "version": 2,
                "species": ["SP-A", "SP-B"], "habitats": ["H1"],
                "quantity_caps": {"SP-A": "9", "SP-B": "2"},
                "sensitive_species": [], "holder_org": "高校团队",
                "contact_name": "联系人甲", "contact_ref": "110",
                "valid_from": "2026-09-01T00:00:00Z",
            })

    def test_revise_ok_and_old_version_remains(self) -> None:
        result = self.service.revise_permit("auth1", {
            "permit_id": "P1", "version": 2, "supersedes_version": 1,
            "species": ["SP-A", "SP-B", "SP-C"], "habitats": ["H1"],
            "quantity_caps": {"SP-A": "10", "SP-B": "2", "SP-C": "5"},
            "sensitive_species": ["SP-B"], "holder_org": "高校团队",
            "contact_name": "联系人甲", "contact_ref": "110",
            "valid_from": "2026-09-01T00:00:00Z",
        })
        self.assertEqual(result["version"], 2)
        old = self.connection.execute(
            "SELECT version FROM permit_versions WHERE permit_id='P1' ORDER BY version"
        ).fetchall()
        self.assertEqual([r["version"] for r in old], [1, 2])

    def test_revocation_blocks_new_actions_but_keeps_history(self) -> None:
        self.service.revoke_permit("auth1", "P1", 1, "终止")
        with self.assertRaises(InvalidState):
            self.service.collect_sample("team1", {
                "sample_id": "SN", "permit_id": "P1", "permit_version": 1,
                "species": "SP-B", "habitat": "H1", "quantity": "1", "unit": "g",
                "location": "z", "collected_at": "2026-09-21T09:00:00Z",
                "seal_digest": seal("sn"), "collector_id": "team1",
            })
        with self.assertRaises(InvalidState):
            self.service.apply_operation("team1", "destroy", {
                "operation_id": "OPR",
                "inputs": [{"sample_id": "S1", "quantity": "1"}],
                "outputs": [], "custodian_id": "team1",
            })
        # 历史仍可核对。
        chain = self.service.sample_chain("audit1", "S1")
        self.assertEqual(chain["sample"]["balance_units"], "10")
        self.assertEqual(chain["sample"]["status"], "active")

    def test_revoke_wrong_version_conflicts(self) -> None:
        with self.assertRaises(Conflict):
            self.service.revoke_permit("auth1", "P1", 9, "终止")

    def test_researcher_cannot_revoke(self) -> None:
        with self.assertRaises(Forbidden):
            self.service.revoke_permit("team1", "P1", 1, "终止")


class DisclosureTests(CustodyTestBase):
    def test_sensitive_location_redacted_for_lab_but_not_station(self) -> None:
        self.collect_second()
        lab_view = self.service.sample_status("lab1", "S2")
        self.assertEqual(lab_view["species"], "REDACTED")
        self.assertEqual(lab_view["location"], "REDACTED")
        self.assertEqual(lab_view["quota"]["target"], "REDACTED")
        self.assertEqual(lab_view["quota"]["remaining"], "0")
        station_view = self.service.sample_status("station1", "S2")
        self.assertEqual(station_view["species"], "SP-B")
        self.assertEqual(station_view["location"], "点位乙")
        self.assertEqual(station_view["quota"]["remaining"], "0")
        auditor_view = self.service.sample_status("audit1", "S2")
        self.assertEqual(auditor_view["location"], "点位乙")
        # 普通物种不对任何角色脱敏。
        normal = self.service.sample_status("lab1", "S1")
        self.assertEqual(normal["species"], "SP-A")
        self.assertEqual(normal["location"], "点位甲")

    def test_contact_redacted_for_lab_on_sensitive_permit(self) -> None:
        lab = self.service.permit_status("lab1", "P1")
        self.assertEqual(lab["contact"]["name"], "REDACTED")
        team = self.service.permit_status("team1", "P1")
        self.assertEqual(team["contact"]["name"], "联系人甲")
        auth = self.service.permit_status("auth1", "P1")
        self.assertEqual(auth["contact"]["name"], "联系人甲")


class TamperTests(CustodyTestBase):
    def test_ledger_and_event_tables_are_insert_only_in_code(self) -> None:
        import inspect
        source = inspect.getsource(__import__("custody_chain.service", fromlist=["x"]))
        for table in ("custody_ledger", "permit_versions", "custody_events"):
            self.assertNotIn(f"UPDATE {table}", source)
            self.assertNotIn(f"DELETE FROM {table}", source)

    def test_hash_chain_detects_tampering(self) -> None:
        self.service.apply_operation("team1", "destroy", {
            "operation_id": "OPT",
            "inputs": [{"sample_id": "S1", "quantity": "1"}],
            "outputs": [], "custodian_id": "team1",
        })
        before = self.service.audit_chain("audit1")
        self.assertTrue(before["valid"])
        self.connection.execute("UPDATE custody_events SET payload_json='{}' WHERE event_id=1")
        after = self.service.audit_chain("audit1")
        self.assertFalse(after["valid"])
        self.assertEqual(after["first_invalid_event_id"], 1)


if __name__ == "__main__":
    unittest.main()
