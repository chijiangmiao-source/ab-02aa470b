"""Unit tests for the digest rules, proofs, and persistent batch semantics."""

from __future__ import annotations

import contextlib
import hashlib
import tempfile
import unittest
from pathlib import Path

from app import tree
from app.storage import (
    InvalidBatchError,
    MAX_BATCH_ITEMS,
    StaleRootError,
    Storage,
    normalize_status,
)

EMPTY0_HEX = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
LEAF_0A3F_REV = "cf8664a5aa8b6b92be73d389545b580289953b4b01a8b44a3d2f4e63a44767a4"
LEAF_0000_NR = "cfc66af7710b364a82e05ad7018cbd4ae460e47b9cc7ffc047e56476a149bd50"
ROOT_0000_REV = "442bcdc48401461ab297c45275ca319f1de2abd06a396e35630bb123661e0ffe"


@contextlib.contextmanager
def temp_db():
    with tempfile.TemporaryDirectory() as d:
        db = Storage(str(Path(d) / "t.db"))
        try:
            yield db
        finally:
            db.close()


class DigestRuleTests(unittest.TestCase):
    def test_leaf_formula_matches_raw_sha256(self) -> None:
        raw = hashlib.sha256(b"\x52\x0a\x3f\x01").hexdigest()
        self.assertEqual(raw, LEAF_0A3F_REV)
        self.assertEqual(tree.leaf_digest(bytes.fromhex("0a3f"), 1).hex(), raw)
        self.assertEqual(tree.leaf_digest(bytes.fromhex("0000"), 0).hex(), LEAF_0000_NR)

    def test_empty_digests_recurse_with_branch_rule(self) -> None:
        self.assertEqual(tree.EMPTY[0].hex(), EMPTY0_HEX)
        for h in range(1, tree.TREE_LEVELS + 1):
            expect = hashlib.sha256(
                tree.BRANCH_PREFIX + tree.EMPTY[h - 1] + tree.EMPTY[h - 1]
            ).digest()
            self.assertEqual(tree.EMPTY[h], expect)
        self.assertEqual(len(tree.EMPTY), 17)

    def test_path_bits_high_to_low(self) -> None:
        bits = list(tree.path_bits(bytes.fromhex("0A3F")))
        # 0x0A3F = 0000 1010 0011 1111
        self.assertEqual(bits, [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1])
        self.assertEqual(len(bits), 16)

    def test_serial_validation(self) -> None:
        self.assertEqual(tree.serial_to_key("abcd"), b"\xab\xcd")
        self.assertEqual(tree.serial_to_key("ABCD"), b"\xab\xcd")
        for bad in ("", "abc", "abcde", "zzzz", None, 1234):
            with self.assertRaises(ValueError):
                tree.serial_to_key(bad)  # type: ignore[arg-type]

    def test_single_leaf_root_hand_built(self) -> None:
        # Independently bubble a leaf up through sixteen empty subtrees.
        cur = hashlib.sha256(b"\x52\x00\x00\x01").digest()
        for i in range(16):
            cur = hashlib.sha256(b"\x02" + cur + tree.EMPTY[i]).digest()
        self.assertEqual(cur.hex(), ROOT_0000_REV)

    def test_single_leaf_tree_matches_hand_built(self) -> None:
        with temp_db() as s:
            _v, root = s.submit_batch(
                tree.EMPTY[16].hex(),
                [{"serial": "0000", "status": "revoked"}],
            )
            self.assertEqual(root.hex(), ROOT_0000_REV)
            proof = s.proof_for(1, bytes.fromhex("0000"))
            self.assertTrue(proof.included)
            for i, (_lvl, bit, sib) in enumerate(proof.siblings()):
                self.assertEqual(bit, 0)  # proof merge bit order is LSB first
                self.assertEqual(sib, tree.EMPTY[i])
            self.assertTrue(proof.verify(root))


class ProofTamperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.storage = Storage(str(Path(cls._tmp.name) / "p.db"))
        _v, cls.root1 = cls.storage.submit_batch(tree.EMPTY[16].hex(), [
            {"serial": "0A3F", "status": "revoked"},
            {"serial": "F00D", "status": "revoked"},
            {"serial": "0042", "status": "revoked"},
        ])
        _v, cls.root2 = cls.storage.submit_batch(cls.root1.hex(), [
            {"serial": "0A3F", "status": "unrevoked"},
        ])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.storage.close()
        cls._tmp.cleanup()

    def test_inclusion_proof_tamper_every_sibling_position(self) -> None:
        proof = self.storage.proof_for(2, bytes.fromhex("F00D"))
        self.assertTrue(proof.included)
        self.assertEqual(proof.status, tree.STATUS_REVOKED)
        self.assertTrue(proof.verify(self.root2))
        for i in range(16):
            bad = bytearray(proof.chain)
            bad[i * 32] ^= 0xFF
            tampered = tree.Proof(proof.key, proof.status, bytes(bad), proof.included)
            self.assertFalse(tampered.verify(self.root2), f"position {i}")

    def test_non_inclusion_proof_and_tamper(self) -> None:
        proof = self.storage.proof_for(1, bytes.fromhex("1234"))
        self.assertFalse(proof.included)
        self.assertEqual(proof.status, tree.STATUS_NOT_REVOKED)
        self.assertTrue(proof.verify(self.root1))
        bad = bytearray(proof.chain)
        bad[15 * 32 + 7] ^= 0x01
        tampered = tree.Proof(proof.key, proof.status, bytes(bad), False)
        self.assertFalse(tampered.verify(self.root1))

    def test_claimed_status_byte_binds_leaf(self) -> None:
        proof = self.storage.proof_for(2, bytes.fromhex("0A3F"))
        self.assertEqual(proof.status, tree.STATUS_NOT_REVOKED)
        # claiming the other status produces a leaf digest that cannot reach r2
        lying = tree.Proof(proof.key, tree.STATUS_REVOKED, proof.chain, True)
        self.assertFalse(lying.verify(self.root2))

    def test_wrong_root_rejects_proof(self) -> None:
        proof = self.storage.proof_for(2, bytes.fromhex("F00D"))
        wrong = bytearray(self.root2)
        wrong[0] ^= 1
        self.assertFalse(proof.verify(bytes(wrong)))

    def test_chain_length_validation(self) -> None:
        with self.assertRaises(ValueError):
            tree.Proof(b"\x00\x00", 0, b"short")
        with self.assertRaises(ValueError):
            tree.Proof(b"\x00\x00", 9, tree.EMPTY[0] * 16)

    def test_to_dict_shapes(self) -> None:
        proof = self.storage.proof_for(1, bytes.fromhex("1234"))
        d = proof.to_dict()
        self.assertEqual(d["kind"], "non_inclusion")
        self.assertFalse(d["included"])
        self.assertEqual(len(d["siblings"]), 16)
        for item in d["siblings"]:
            self.assertEqual(len(item["digest"]), 64)
        self.assertEqual(d["computed_root"], self.root1.hex())


class BatchValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Storage(str(Path(self.tmp.name) / "b.db"))

    def tearDown(self) -> None:
        self.s.close()
        self.tmp.cleanup()

    def test_genesis_and_empty_batch_rejected(self) -> None:
        v, root = self.s.latest()
        self.assertEqual(v, 0)
        self.assertEqual(root, tree.EMPTY[16])
        with self.assertRaises(InvalidBatchError):
            self.s.submit_batch(root.hex(), [])

    def test_illegal_serial_status_duplicate_size(self) -> None:
        _v, root = self.s.latest()
        cases = [
            [{"serial": "0A3F", "status": 2}],
            [{"serial": "0A3F", "status": "revoked"}, {"serial": "0a3f", "status": 0}],
            [{"serial": "GGG1", "status": 1}],
            [{"serial": "0A3", "status": 1}],
            [{"serial": "0A3F", "status": "maybe"}],
            [{"serial": "0A3F", "status": True}],
            [{"serial": "0A3F", "status": None}],
        ]
        for items in cases:
            with self.assertRaises(InvalidBatchError):
                self.s.submit_batch(root.hex(), items)
        with self.assertRaises(InvalidBatchError):
            self.s.submit_batch(
                root.hex(),
                [{"serial": "%04X" % i, "status": 1}
                 for i in range(MAX_BATCH_ITEMS + 1)],
            )
        # no version was produced by any rejected attempt
        self.assertEqual(self.s.latest()[0], 0)

    def test_malformed_expected_root_rejected(self) -> None:
        _v, root = self.s.latest()
        for bad in ("not-hex", "abc", "g" * 64, root.hex()[:62]):
            with self.assertRaises(InvalidBatchError):
                self.s.submit_batch(bad, [{"serial": "0A3F", "status": 1}])
        self.assertEqual(self.s.latest()[0], 0)

    def test_stale_root_rejects_whole_batch_and_persists_nothing(self) -> None:
        _v, r0 = self.s.latest()
        v1, r1 = self.s.submit_batch(r0.hex(), [{"serial": "0A3F", "status": 1}])
        # a second operator still holds r0
        with self.assertRaises(StaleRootError):
            self.s.submit_batch(r0.hex(), [{"serial": "0042", "status": 1}])
        self.assertEqual(self.s.latest(), (v1, r1))
        rows = self.s.conn.execute("SELECT COUNT(*) c FROM versions").fetchone()
        self.assertEqual(rows["c"], 2)  # genesis + v1 only
        # the stale item exists nowhere
        self.assertFalse(self.s.exists_at(bytes.fromhex("0042"), v1))
        self.assertIsNone(self.s.stored_proof(2, bytes.fromhex("0042")))

    def test_batch_applies_all_updates(self) -> None:
        _v, r0 = self.s.latest()
        v1, r1 = self.s.submit_batch(r0.hex(), [
            {"serial": "0A3F", "status": "revoked"},
            {"serial": "0042", "status": 1},
            {"serial": "BEEF", "status": 0},  # explicit not-revoked writes a leaf
        ])
        self.assertEqual(v1, 1)
        for ser, st in (("0a3f", 1), ("0042", 1), ("beef", 0)):
            self.assertEqual(self.s.state_at(bytes.fromhex(ser), v1), st)
            proof = self.s.proof_for(v1, bytes.fromhex(ser))
            self.assertTrue(proof.included)
            self.assertTrue(proof.verify(r1))
        rows = self.s.conn.execute(
            "SELECT COUNT(*) c FROM proofs WHERE version=1"
        ).fetchone()
        self.assertEqual(rows["c"], 3)

    def test_batch_limit_boundary_accepted(self) -> None:
        _v, r0 = self.s.latest()
        items = [{"serial": "%04X" % i, "status": 1} for i in range(MAX_BATCH_ITEMS)]
        v1, r1 = self.s.submit_batch(r0.hex(), items)
        for i in range(MAX_BATCH_ITEMS):
            self.assertTrue(
                self.s.proof_for(v1, bytes.fromhex("%04X" % i)).verify(r1)
            )

    def test_status_normalization(self) -> None:
        self.assertEqual(normalize_status(0), 0)
        self.assertEqual(normalize_status(1), 1)
        self.assertEqual(normalize_status("revoked"), 1)
        self.assertEqual(normalize_status("Not_Revoked"), 0)
        self.assertEqual(normalize_status("unrevoked"), 0)
        for bad in (2, -1, "nope", None, True):
            with self.assertRaises(InvalidBatchError):
                normalize_status(bad)

    def test_persistence_across_reopen(self) -> None:
        path = str(Path(self.tmp.name) / "r.db")
        with Storage(path) as s:
            _v, r0 = s.latest()
            s.submit_batch(r0.hex(), [{"serial": "0A3F", "status": 1}])
        with Storage(path) as s:
            v, root = s.latest()
            self.assertEqual(v, 1)
            self.assertTrue(s.proof_for(1, bytes.fromhex("0a3f")).verify(root))
            self.assertFalse(s.proof_for(0, bytes.fromhex("0a3f")).included)


class HistoryImmutabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Storage(str(Path(self.tmp.name) / "h.db"))
        _v, r0 = self.s.latest()
        self.r0 = r0
        self.v1, self.r1 = self.s.submit_batch(r0.hex(), [
            {"serial": "0A3F", "status": "revoked"},
        ])
        self.v2, self.r2 = self.s.submit_batch(self.r1.hex(), [
            {"serial": "0A3F", "status": "not_revoked"},
            {"serial": "0042", "status": "revoked"},
        ])

    def tearDown(self) -> None:
        self.s.close()
        self.tmp.cleanup()

    def test_historical_non_inclusion_at_old_versions(self) -> None:
        # Acceptance centrepiece: 0042 is revoked at v2, but at v0 and v1 its
        # slot is provably empty — historical non-inclusion against old roots.
        p0 = self.s.proof_for(0, bytes.fromhex("0042"))
        self.assertFalse(p0.included)
        self.assertEqual(p0.status, tree.STATUS_NOT_REVOKED)
        self.assertTrue(p0.verify(self.r0))
        p1 = self.s.proof_for(1, bytes.fromhex("0042"))
        self.assertFalse(p1.included)
        self.assertTrue(p1.verify(self.r1))

    def test_old_version_results_never_change(self) -> None:
        before = self.s.proof_for(self.v1, bytes.fromhex("0a3f"))
        self.assertEqual(before.status, tree.STATUS_REVOKED)
        self.assertTrue(before.verify(self.r1))
        self.s.submit_batch(self.r2.hex(), [
            {"serial": "1234", "status": 1},
            {"serial": "5678", "status": 1},
        ])
        after = self.s.proof_for(self.v1, bytes.fromhex("0a3f"))
        self.assertEqual(after.status, tree.STATUS_REVOKED)
        self.assertTrue(after.verify(self.r1))
        self.assertEqual(self.s.get_version(self.v1)["root"], self.r1)
        v3, _ = self.s.latest()
        self.assertEqual(self.s.state_at(bytes.fromhex("0a3f"), v3), 0)
        self.assertEqual(self.s.state_at(bytes.fromhex("0042"), v3), 1)

    def test_historical_inclusion_survives_status_change(self) -> None:
        p = self.s.proof_for(self.v2, bytes.fromhex("0a3f"))
        self.assertEqual(p.status, tree.STATUS_NOT_REVOKED)
        self.assertTrue(p.included)
        self.assertTrue(p.verify(self.r2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
