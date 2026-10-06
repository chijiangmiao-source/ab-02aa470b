"""End-to-end HTTP smoke tests against the real running server.

The client recomputes every proof itself with raw ``hashlib`` (never trusting
the server's ``computed_root``), covering:

* batch updates through the JSON API and independently verified roots/proofs;
* historical non-inclusion proofs at old versions;
* stale-root conflict (409, no new version observable);
* tampering with any sibling digest -> root check observably fails.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from app import tree
from app.server import build_server

HOST = "127.0.0.1"


def _request(method: str, url: str, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def client_recompute(root_hex: str, state: dict) -> bytes:
    """Independently recompute the root from an /api/state response."""
    proof = state["proof"]
    key = bytes.fromhex(proof["serial"])
    status = 1 if proof["status"] == "revoked" else 0
    current = (
        hashlib.sha256(tree.LEAF_PREFIX + key + bytes([status])).digest()
        if proof["included"]
        else tree.EMPTY[0]
    )
    key_int = int.from_bytes(key, "big")
    siblings = proof["siblings"]
    assert len(siblings) == 16
    for i, sib in enumerate(siblings):
        sibling = bytes.fromhex(sib["digest"])
        bit = (key_int >> i) & 1
        current = (
            hashlib.sha256(tree.BRANCH_PREFIX + current + sibling).digest()
            if bit == 0
            else hashlib.sha256(tree.BRANCH_PREFIX + sibling + current).digest()
        )
    return current


class HttpSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db_path = str(Path(cls.tmp.name) / "http.db")
        cls.server = build_server(cls.db_path, HOST, 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://{HOST}:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.tmp.cleanup()

    def get(self, path: str):
        return _request("GET", self.base + path)

    def post(self, path: str, payload):
        return _request("POST", self.base + path, payload)

    # -------------------------------------------------------------- scenarios

    def test_01_health_and_page(self) -> None:
        status, body = self.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["latest_version"], 0)
        self.assertEqual(body["latest_root"], tree.EMPTY[16].hex())

        with urllib.request.urlopen(self.base + "/", timeout=10) as resp:
            page = resp.read().decode("utf-8")
        self.assertEqual(resp.status, 200)
        self.assertIn("短序列号", page)
        with urllib.request.urlopen(self.base + "/static/app.js", timeout=10) as resp:
            js = resp.read().decode("utf-8")
        self.assertIn("SHA-256", js)

    def test_02_genesis_non_inclusion(self) -> None:
        status, body = self.get("/api/state?version=0&serial=0A3F")
        self.assertEqual(status, 200)
        self.assertEqual(body["root"], tree.EMPTY[16].hex())
        self.assertFalse(body["proof"]["included"])
        self.assertEqual(body["status"], "not_revoked")
        self.assertEqual(client_recompute(body["root"], body).hex(), body["root"])

    def test_03_batch_update_creates_version_and_verifies(self) -> None:
        _, versions = self.get("/api/versions")
        r0 = versions["versions"][-1]["root"]

        status, body = self.post("/api/batches", {
            "expected_root": r0,
            "items": [
                {"serial": "0A3F", "status": "revoked"},
                {"serial": "0042", "status": "revoked"},
            ],
            "comment": "first revocation batch",
        })
        self.assertEqual(status, 201, body)
        self.assertEqual(body["version"], 1)
        r1 = body["root"]
        self.assertEqual(len(r1), 64)
        self.assertNotEqual(r1, r0)

        # health reflects the new root
        _, health = self.get("/health")
        self.assertEqual(health["latest_version"], 1)
        self.assertEqual(health["latest_root"], r1)

        # both items independently verify against the new root
        for serial, st in (("0A3F", "revoked"), ("0042", "revoked")):
            _, state = self.get(f"/api/state?version=1&serial={serial}")
            self.assertTrue(state["proof"]["included"])
            self.assertEqual(state["status"], st)
            self.assertEqual(client_recompute(r1, state).hex(), r1)

        # version listing contains genesis + v1
        _, listing = self.get("/api/versions")
        numbers = [v["version"] for v in listing["versions"]]
        self.assertEqual(numbers, [0, 1])

    def test_04_history_non_inclusion_after_later_revocation(self) -> None:
        # Revoke 1234 in a later batch ...
        _, versions = self.get("/api/versions")
        r1 = next(v["root"] for v in versions["versions"] if v["version"] == 1)
        status, body = self.post("/api/batches", {
            "expected_root": r1,
            "items": [{"serial": "1234", "status": "revoked"}],
        })
        self.assertEqual(status, 201, body)
        r2 = body["root"]

        # ... at v1, 1234 must remain a provably empty slot (non-inclusion).
        s_old, old = self.get("/api/state?version=1&serial=1234")
        self.assertEqual(s_old, 200)
        self.assertFalse(old["proof"]["included"])
        self.assertEqual(old["status"], "not_revoked")
        self.assertEqual(client_recompute(old["root"], old).hex(), old["root"])
        self.assertEqual(old["root"], r1)

        # and at v2 it is an inclusion proof for revoked
        s_new, new = self.get("/api/state?version=2&serial=1234")
        self.assertTrue(new["proof"]["included"])
        self.assertEqual(new["status"], "revoked")
        self.assertEqual(client_recompute(r2, new).hex(), r2)

        # old-version query for the first batch's serial is unchanged too
        _, frozen = self.get("/api/state?version=1&serial=0A3F")
        self.assertEqual(frozen["status"], "revoked")
        self.assertEqual(client_recompute(r1, frozen).hex(), r1)

    def test_05_stale_root_conflict_is_observable_and_creates_nothing(self) -> None:
        _, versions = self.get("/api/versions")
        latest = versions["versions"][-1]
        # hold the *previous* root
        old = versions["versions"][-2]
        status, body = self.post("/api/batches", {
            "expected_root": old["root"],
            "items": [{"serial": "DEAD", "status": "revoked"}],
        })
        self.assertEqual(status, 409)
        self.assertEqual(body["code"], "stale_root")
        self.assertEqual(body["latest_version"], latest["version"])
        self.assertEqual(body["latest_root"], latest["root"])

        # observable consequence: still only the same versions, no v3
        _, after = self.get("/api/versions")
        self.assertEqual([v["version"] for v in after["versions"]], [0, 1, 2])
        s, state = self.get("/api/state?version=2&serial=DEAD")
        self.assertEqual(s, 200)
        self.assertFalse(state["proof"]["included"])

    def test_06_illegal_batches_rejected(self) -> None:
        _, versions = self.get("/api/versions")
        root = versions["versions"][-1]["root"]
        bad_batches = [
            {"expected_root": root, "items": []},
            {"expected_root": root,
             "items": [{"serial": "ZZZZ", "status": "revoked"}]},
            {"expected_root": root,
             "items": [{"serial": "0A3F", "status": 3}]},
            {"expected_root": root,
             "items": [{"serial": "111", "status": "revoked"}]},
            {"expected_root": root,
             "items": [{"serial": "AAAA", "status": "revoked"},
                       {"serial": "aaaa", "status": "revoked"}]},
            {"expected_root": "zz" + root[2:],
             "items": [{"serial": "AAAA", "status": "revoked"}]},
        ]
        for payload in bad_batches:
            status, body = self.post("/api/batches", payload)
            self.assertEqual(status, 400, payload)
            self.assertEqual(body["code"], "invalid_batch")
        _, after = self.get("/api/versions")
        self.assertEqual([v["version"] for v in after["versions"]], [0, 1, 2])

    def test_07_tampered_sibling_fails_root_check_at_every_level(self) -> None:
        _, state = self.get("/api/state?version=2&serial=1234")
        root = bytes.fromhex(state["root"])
        self.assertTrue(state["proof"]["included"])
        for i in range(16):
            tampered = json.loads(json.dumps(state))  # deep copy
            digest = tampered["proof"]["siblings"][i]["digest"]
            flipped = ("f" if digest[-1] != "f" else "0")
            tampered["proof"]["siblings"][i]["digest"] = digest[:-1] + flipped
            computed = client_recompute(state["root"], tampered)
            self.assertNotEqual(
                computed, root,
                f"tampering sibling at merge level {i + 1} went undetected",
            )

    def test_08_unrevocation_changes_new_version_only(self) -> None:
        _, versions = self.get("/api/versions")
        r2 = next(v["root"] for v in versions["versions"] if v["version"] == 2)
        status, body = self.post("/api/batches", {
            "expected_root": r2,
            "items": [{"serial": "1234", "status": "unrevoked"}],
        })
        self.assertEqual(status, 201, body)
        r3 = body["root"]
        _, now = self.get("/api/state?version=3&serial=1234")
        self.assertEqual(now["status"], "not_revoked")
        self.assertTrue(now["proof"]["included"])  # slot holds a status-0 leaf
        self.assertEqual(client_recompute(r3, now).hex(), r3)
        # v2 history unchanged: still revoked there
        _, then = self.get("/api/state?version=2&serial=1234")
        self.assertEqual(then["status"], "revoked")
        self.assertEqual(client_recompute(r2, then).hex(), r2)

    def test_09_unknown_version_and_bad_serial_are_4xx(self) -> None:
        self.assertEqual(self.get("/api/state?version=99&serial=0000")[0], 404)
        self.assertEqual(self.get("/api/state?version=0&serial=zz")[0], 400)
        self.assertEqual(self.get("/api/state?version=x&serial=0000")[0], 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
