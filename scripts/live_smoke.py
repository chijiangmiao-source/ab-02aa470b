#!/usr/bin/env python3
"""Live acceptance smoke test against the running deployed service.

Runs entirely over HTTP and recomputes proofs locally (raw hashlib), covering
the four required observable outcomes:

  1. a revocation batch update creates a version whose root/proofs verify;
  2. a historical non-inclusion proof at the *previous* version for a serial
     only revoked in the new batch;
  3. a stale expected root is rejected (HTTP 409) and creates no version;
  4. tampering with any of the 16 sibling digests makes the local root check
     fail.

Exit code 0 = pass, 1 = fail.  Safe to run repeatedly against a persistent
deployment: it draws random serials and anchors every expectation to the
roots/versions returned by the service itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import tree  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://web:8080").rstrip("/")


def fail(msg: str) -> None:
    print("FAIL:", msg)
    sys.exit(1)


def request(method: str, path: str, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        BASE_URL + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def recompute(state: dict) -> bytes:
    proof = state["proof"]
    key = bytes.fromhex(proof["serial"])
    status = 1 if proof["status"] == "revoked" else 0
    current = (
        hashlib.sha256(tree.LEAF_PREFIX + key + bytes([status])).digest()
        if proof["included"]
        else tree.EMPTY[0]
    )
    key_int = int.from_bytes(key, "big")
    assert len(proof["siblings"]) == 16
    for i, sib in enumerate(proof["siblings"]):
        sibling = bytes.fromhex(sib["digest"])
        bit = (key_int >> i) & 1
        if bit == 0:
            current = hashlib.sha256(tree.BRANCH_PREFIX + current + sibling).digest()
        else:
            current = hashlib.sha256(tree.BRANCH_PREFIX + sibling + current).digest()
    return current


def expect(cond: bool, msg: str) -> None:
    if not cond:
        fail(msg)
    print("  ok -", msg)


def main() -> int:
    print("Live smoke against", BASE_URL)

    # ---- health + page
    status, health = request("GET", "/health")
    expect(status == 200 and health["status"] == "ok",
           "GET /health reports ok")
    with urllib.request.urlopen(BASE_URL + "/", timeout=10) as resp:
        page = resp.read().decode("utf-8")
    expect(resp.status == 200 and "短序列号" in page, "reviewer page is served")

    # ---- anchor: latest version/root before our batch
    status, versions = request("GET", "/api/versions")
    expect(status == 200, "GET /api/versions")
    before = versions["versions"][-1]
    old_version, old_root = before["version"], before["root"]
    print("  anchored at v%d root %s..." % (old_version, old_root[:16]))

    # random serials unique to this run
    seed = int.from_bytes(os.urandom(4), "big")
    s1 = "%04X" % (0x8000 | (seed & 0x3FFF))
    s2 = "%04X" % (0x4000 | ((seed >> 14) & 0x3FFF))
    if s1 == s2:
        s2 = "0001"

    # ---- 1) batch update
    status, body = request("POST", "/api/batches", {
        "expected_root": old_root,
        "items": [
            {"serial": s1, "status": "revoked"},
            {"serial": s2, "status": "revoked"},
        ],
        "comment": "live smoke batch",
    })
    expect(status == 201, "batch update accepted (HTTP 201): %s" % body)
    new_version = body.get("version")
    new_root = body.get("root")
    expect(new_version == old_version + 1,
           "new version is exactly old+1 (%d)" % new_version)
    expect(isinstance(new_root, str) and len(new_root) == 64 and new_root != old_root,
           "new root is a distinct 32-byte hash")

    for serial in (s1, s2):
        st, state = request("GET", "/api/state?version=%d&serial=%s"
                                   % (new_version, serial))
        expect(st == 200, "query %s at v%d" % (serial, new_version))
        expect(state["status"] == "revoked" and state["proof"]["included"],
               "%s is revoked with an inclusion proof at v%d" % (serial, new_version))
        expect(recompute(state).hex() == new_root,
               "local recomputation for %s matches published v%d root"
               % (serial, new_version))

    # ---- 2) historical non-inclusion at the previous version
    st, old_state = request("GET", "/api/state?version=%d&serial=%s"
                                    % (old_version, s1))
    expect(st == 200, "historical query for %s at v%d" % (s1, old_version))
    expect(not old_state["proof"]["included"],
           "%s slot is provably empty (non-inclusion) at old v%d"
           % (s1, old_version))
    expect(old_state["status"] == "not_revoked",
           "%s defaults to not_revoked at old v%d" % (s1, old_version))
    expect(recompute(old_state).hex() == old_root,
           "historical non-inclusion proof recomputes to the OLD root %s"
           % old_root[:16])

    # later batches must not change that old answer
    st, repeat = request("GET", "/api/state?version=%d&serial=%s"
                                 % (old_version, s1))
    expect(repeat["proof"]["included"] is False
           and repeat["root"] == old_root,
           "old version query result is immutable after subsequent updates")

    # ---- 3) stale root conflict
    status, conflict = request("POST", "/api/batches", {
        "expected_root": old_root,  # no longer latest
        "items": [{"serial": "DEAD", "status": "revoked"}],
    })
    expect(status == 409 and conflict.get("code") == "stale_root",
           "stale root rejected with HTTP 409 code=stale_root")
    expect(conflict.get("latest_version") == new_version
           and conflict.get("latest_root") == new_root,
           "conflict response reports the actual latest version/root")
    st, versions_after = request("GET", "/api/versions")
    expect(versions_after["versions"][-1]["version"] == new_version,
           "no version was created by the stale-root request")
    st, dead = request("GET", "/api/state?version=%d&serial=DEAD" % new_version)
    expect(not dead["proof"]["included"],
           "stale batch items were not persisted (DEAD absent at v%d)"
           % new_version)

    # ---- 4) tampered sibling digest
    st, state = request("GET", "/api/state?version=%d&serial=%s"
                                % (new_version, s1))
    root = bytes.fromhex(new_root)
    for i in range(16):
        tampered = json.loads(json.dumps(state))
        d = tampered["proof"]["siblings"][i]["digest"]
        tampered["proof"]["siblings"][i]["digest"] = d[:-1] + (
            "0" if d[-1] != "0" else "1")
        expect(recompute(tampered) != root,
               "tampering sibling at merge level %d makes root check fail"
               % (i + 1))

    # ---- invalid batches are observable 400s
    for label, payload in (
        ("duplicate serial", {
            "expected_root": new_root,
            "items": [{"serial": "AAAA", "status": "revoked"},
                      {"serial": "aaaa", "status": "revoked"}]}),
        ("illegal status", {
            "expected_root": new_root,
            "items": [{"serial": "AAAA", "status": 9}]}),
        ("oversized batch", {
            "expected_root": new_root,
            "items": [{"serial": "%04X" % (i & 0xFFFF), "status": 1}
                      for i in range(33)]}),
    ):
        st, body = request("POST", "/api/batches", payload)
        expect(st == 400 and body.get("code") == "invalid_batch",
               "%s rejected with HTTP 400" % label)

    print("\nLIVE SMOKE PASSED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as exc:
        fail("cannot reach service at %s: %s" % (BASE_URL, exc))
