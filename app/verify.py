"""一次性验收服务：构建检查 + 代码测试 + API/HTTP 冒烟。

用法：
    python -m app.verify                # 自启临时服务，全部本地完成
    BASE_URL=http://web:8000 python -m app.verify   # 追加跨服务 HTTP 冒烟

退出码 0 = 验收通过，非 0 = 失败。
"""

from __future__ import annotations

import compileall
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
import urllib.parse

from . import hashing as H
from .server import build_server
from .store import (
    BatchError,
    Proof,
    StaleRootError,
    Store,
    parse_serial,
    verify_proof,
)

PASS = 0
FAILED_STEPS: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" -- {detail}" if detail else ""), flush=True)
    if not ok:
        FAILED_STEPS.append(name)


def http(method: str, url: str, payload=None, expect_status=None):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw_body = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw_body = exc.read().decode("utf-8")
        status = exc.code
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        body = {"_raw": raw_body}
    if expect_status is not None:
        ok = status == expect_status
        label = f"HTTP {method} {url.split('/api')[-1] or url} -> {expect_status}"
        check(label, ok, "" if ok else f"got {status}: {body}")
    return status, body


def independent_recompute(d: dict) -> tuple[bytes, bool]:
    """完全不信任服务端返回的 recomputed 字段，用本模块摘要规则独立复算。"""
    node = bytes.fromhex(d["leaf_digest"])
    siblings = [bytes.fromhex(s) for s in d["siblings"]]
    for i in range(H.TREE_LEVELS - 1, -1, -1):
        sibling = siblings[i]
        node = (H.branch_digest(node, sibling) if d["path_bits"][i] == 0
                else H.branch_digest(sibling, node))
    return node, node == bytes.fromhex(d["root"])


# --------------------------------------------------------------------- 代码测试

def test_hashing_contract() -> None:
    print("\n== 摘要规范 ==", flush=True)
    check("空叶 = SHA256(0x02)",
          H.EMPTY_LEAF == hashlib.sha256(b"\x02").digest())
    check("叶子 = SHA256(0x00||serial_be(2)||status)",
          H.leaf_digest(0x00A1, 1)
          == hashlib.sha256(b"\x00\x00\xa1\x01").digest())
    l, r = H.leaf_digest(1), H.leaf_digest(2)
    check("分支 = SHA256(0x01||left||right)",
          H.branch_digest(l, r)
          == hashlib.sha256(b"\x01" + l + r).digest())
    check("固定 16 层路径位（高->低）",
          H.path_bits(0x00A1) == [int(b) for b in f"{0x00A1:016b}"])
    check("空树根为 16 层默认子树摘要",
          H.DEFAULTS[16] == H.GENESIS_ROOT and len(H.GENESIS_ROOT) == 32)
    # 第二原像：叶子与分支域分离，不可能被伪造为彼此
    try:
        H.leaf_digest(1, 9)
        check("非法状态被拒绝", False)
    except ValueError:
        check("非法状态被拒绝", True)


def test_code_level_store(tmpdir: str) -> None:
    print("\n== 代码级批次与并发 ==", flush=True)
    db = os.path.join(tmpdir, "code.db")
    store = Store(db)
    genesis = H.GENESIS_ROOT.hex()

    # 正常批次：3 项吊销
    res = store.apply_batch(genesis, [
        {"serial": "00A1", "status": "revoked"},
        {"serial": "FF00", "status": "revoked"},
        {"serial": "0000", "status": "revoked"},
    ])
    check("批次生成新版本 v1 且根发生变化",
          res["version"] == 1 and res["root"] != genesis)
    check("批次内每项都带可独立复算的有效证明",
          all(p["root_check_ok"] for p in res["proofs"])
          and len(res["proofs"]) == 3)

    # 陈旧根
    stale = False
    try:
        store.apply_batch(genesis, [{"serial": "1234", "status": "revoked"}])
    except StaleRootError:
        stale = True
    check("陈旧期望根抛 StaleRootError 且不生成版本",
          stale and store.latest()["version"] == 1)

    # 批内重复
    dup = False
    try:
        store.apply_batch(res["root"], [
            {"serial": "1234", "status": "revoked"},
            {"serial": 0x1234, "status": "revoked"},
        ])
    except BatchError as exc:
        dup = exc.code == "DUPLICATE_SERIAL"
    check("批内重复序列号被拒绝且不生成版本",
          dup and store.latest()["version"] == 1)

    # 非法状态
    bad = False
    try:
        store.apply_batch(res["root"],
                          [{"serial": "1234", "status": "paused"}])
    except BatchError as exc:
        bad = exc.code == "INVALID_STATUS"
    check("非法状态被拒绝且不生成版本",
          bad and store.latest()["version"] == 1)

    # 超 32 项
    big = False
    try:
        store.apply_batch(res["root"],
                          [{"serial": i, "status": 1} for i in range(33)])
    except BatchError as exc:
        big = exc.code == "BATCH_TOO_LARGE"
    check("超过 32 项的批次被拒绝", big)

    # 非法序列号
    bad_serial = False
    try:
        store.apply_batch(res["root"],
                          [{"serial": "ZZZZ", "status": "revoked"}])
    except BatchError:
        bad_serial = True
    check("非法序列号被拒绝", bad_serial)

    # 确定性：同内容同根
    s2 = Store(":memory:")
    r2 = s2.apply_batch(H.GENESIS_ROOT.hex(), [
        {"serial": "00A1", "status": "revoked"},
        {"serial": "FF00", "status": "revoked"},
        {"serial": "0000", "status": "revoked"},
    ])
    check("相同批次内容产生相同根（确定性）", r2["root"] == res["root"])
    s2.close()

    # 恰好 32 项应接受
    try:
        r32 = store.apply_batch(res["root"],
                                [{"serial": i, "status": 1} for i in range(32)])
        check("恰好 32 项的批次被接受", r32["version"] == 2)
        current_root = r32["root"]
    except BatchError as exc:
        check("恰好 32 项的批次被接受", False, str(exc))
        current_root = res["root"]

    # 持久化：关闭后以新连接重开同一数据库，历史版本与证明必须原样可复算
    store.close()
    reopened = Store(db)
    check("重启后最新版本保持", reopened.latest()["version"] == 2)
    pv = reopened.proof(1, 0x00A1)
    _, pok = verify_proof(pv)
    check("重启后 v1 的 00A1 历史包含证明仍可复算",
          pok and pv.included and pv.root.hex() == res["root"])
    pa = reopened.proof(1, 0x1234)
    _, aok = verify_proof(pa)
    check("重启后 v1 的 1234 历史未包含证明仍可复算",
          aok and not pa.included)
    reopened.close()
    return current_root


# ----------------------------------------------------------------- HTTP 冒烟

def start_http_server(tmpdir: str):
    db = os.path.join(tmpdir, "http.db")
    httpd = build_server("127.0.0.1", 0, db)
    port = httpd.server_address[1]
    import threading
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    # 等服务可用
    for _ in range(50):
        try:
            http("GET", base + "/health")
            break
        except OSError:
            time.sleep(0.05)
    return httpd, base


def test_http_flows(base: str) -> None:
    print("\n== API / HTTP 冒烟（可观察结果） ==", flush=True)

    status, health = http("GET", base + "/health")
    check("GET /health 返回 200/ok 与最新根",
          status == 200 and health["status"] == "ok"
          and health["latest_version"] == 0)

    _, versions = http("GET", base + "/api/versions")
    genesis = versions["latest"]["root"]
    check("初始仅 v0 创世版本，根为 16 层空树根",
          versions["latest"]["version"] == 0
          and genesis == H.GENESIS_ROOT.hex())

    # --- 批次更新：吊销 00A1 / FF00 ---
    status, b1 = http("POST", base + "/api/batches", {
        "expected_root": genesis,
        "items": [
            {"serial": "00A1", "status": "revoked"},
            {"serial": "ff00", "status": "revoked"},
        ],
        "note": "batch-1",
    }, expect_status=201)
    root1 = b1.get("root")
    check("批次返回新版本 v1", b1.get("version") == 1)

    # 逐项独立复算（不信任服务端字段）
    all_ok = True
    for p in b1.get("proofs", []):
        recomputed, ok = independent_recompute(p)
        all_ok &= ok and recomputed.hex() == p["root"]
        check(f"  独立复算 {p['serial']} 的包含证明与 v1 根一致", ok)
    check("批次每项证明均可由叶子+兄弟摘要独立复算", all_ok)

    # v1 上查 00A1：已吊销包含证明
    q = urllib.parse.urlencode({"version": 1, "serial": "00a1"})
    _, p1 = http("GET", f"{base}/api/proof?{q}")
    recomputed, ok = independent_recompute(p1)
    check("v1 查询 00A1：已吊销（包含证明）且 16 层兄弟复算一致",
          p1["status"] == "revoked" and p1["included"] is True
          and len(p1["siblings"]) == 16 and ok
          and recomputed.hex() == root1)
    check("页面返回逐层兄弟摘要（高->低）",
          [l["depth"] for l in p1["levels"]] == list(range(1, 17)))

    # --- 历史未包含证明：v0/v1 上 1234 尚未吊销 ---
    for v in (0, 1):
        q = urllib.parse.urlencode({"version": v, "serial": "1234"})
        _, old = http("GET", f"{base}/api/proof?{q}")
        rec, vok = independent_recompute(old)
        check(f"v{v} 查询 1234：未吊销（未包含证明，空叶）且复算一致",
              old["status"] == "active" and old["included"] is False
              and old["leaf_digest"] == H.EMPTY_LEAF.hex()
              and vok and rec.hex() == old["root"])

    # --- 第二个批次：吊销 1234，解除 FF00 ---
    _, b2 = http("POST", base + "/api/batches", {
        "expected_root": root1,
        "items": [
            {"serial": "1234", "status": "revoked"},
            {"serial": "FF00", "status": "released"},
        ],
    }, expect_status=201)
    root2 = b2["root"]
    check("第二批次生成 v2", b2["version"] == 2 and root2 != root1)

    status, v2detail = http("GET", base + "/api/version/2")
    check("GET /api/version/2 返回该版本批次明细",
          status == 200 and v2detail["batch"]["item_count"] == 2
          and {(i["serial"], i["status"]) for i in v2detail["batch"]["items"]}
          == {("1234", "revoked"), ("FF00", "released")})
    status, v0detail = http("GET", base + "/api/version/0")
    check("GET /api/version/0 创世版本无批次明细",
          status == 200 and v0detail["batch"] is None)

    # 后续批次不得改变旧版本查询结果
    q = urllib.parse.urlencode({"version": 1, "serial": "1234"})
    _, still_absent = http("GET", f"{base}/api/proof?{q}")
    check("v1 历史查询不可变：1234 在 v1 仍未吊销",
          still_absent["included"] is False
          and still_absent["root"] == root1
          and independent_recompute(still_absent)[1])
    q = urllib.parse.urlencode({"version": 2, "serial": "1234"})
    _, now_present = http("GET", f"{base}/api/proof?{q}")
    check("v2 查询 1234：已吊销",
          now_present["included"] is True
          and independent_recompute(now_present)[1])
    q = urllib.parse.urlencode({"version": 2, "serial": "FF00"})
    _, released = http("GET", f"{base}/api/proof?{q}")
    check("v2 查询 FF00：解除后回到未吊销",
          released["included"] is False
          and independent_recompute(released)[1])
    q = urllib.parse.urlencode({"version": 1, "serial": "FF00"})
    _, v1_ff00 = http("GET", f"{base}/api/proof?{q}")
    check("v1 历史查询不可变：FF00 在 v1 仍为已吊销",
          v1_ff00["included"] is True
          and v1_ff00["root"] == root1)

    # --- 陈旧根冲突（通过 HTTP 可观察 409） ---
    status, err = http("POST", base + "/api/batches", {
        "expected_root": genesis,  # 早已不是最新根
        "items": [{"serial": "BEEF", "status": "revoked"}],
    }, expect_status=409)
    check("陈旧根返回 409 STALE_ROOT",
          err.get("error") == "STALE_ROOT")
    _, vs = http("GET", base + "/api/versions")
    check("冲突后未产生新版本（最新仍为 v2）",
          vs["latest"]["version"] == 2 and vs["latest"]["root"] == root2)

    # --- 批内重复 / 非法状态（HTTP 400，无版本） ---
    status, err = http("POST", base + "/api/batches", {
        "expected_root": root2,
        "items": [
            {"serial": "BEEF", "status": "revoked"},
            {"serial": "beef", "status": "revoked"},
        ],
    }, expect_status=400)
    check("批内重复序列号返回 400 DUPLICATE_SERIAL",
          err.get("error") == "DUPLICATE_SERIAL")
    status, err = http("POST", base + "/api/batches", {
        "expected_root": root2,
        "items": [{"serial": "BEEF", "status": "frozen"}],
    }, expect_status=400)
    check("非法状态返回 400 INVALID_STATUS",
          err.get("error") == "INVALID_STATUS")
    _, vs = http("GET", base + "/api/versions")
    check("非法批次均未生成版本（仍为 v2）",
          vs["latest"]["version"] == 2)

    # --- 篡改兄弟摘要：根校验必须失败 ---
    q = urllib.parse.urlencode({"version": 2, "serial": "1234"})
    _, good = http("GET", f"{base}/api/proof?{q}")
    tampered = json.loads(json.dumps(good))
    sib = bytearray(bytes.fromhex(tampered["siblings"][7]))
    sib[0] ^= 0xFF
    tampered["siblings"][7] = sib.hex()
    status, verdict = http("POST", base + "/api/verify", {
        "version": tampered["version"],
        "serial": tampered["serial"],
        "status": tampered["status"],
        "included": tampered["included"],
        "root": tampered["root"],
        "leaf_digest": tampered["leaf_digest"],
        "path_bits": tampered["path_bits"],
        "siblings": tampered["siblings"],
    }, expect_status=422)
    check("篡改任一兄弟摘要后 /api/verify 观察到根校验失败",
          verdict.get("root_check_ok") is False
          and verdict.get("recomputed_root") != verdict.get("expected_root"))

    # 代码级再验一次同一篡改
    proof = Proof(
        version=good["version"], serial=int(good["serial"], 16),
        status=H.STATUS_REVOKED, included=True,
        root=bytes.fromhex(good["root"]),
        leaf=bytes.fromhex(good["leaf_digest"]),
        siblings=[bytes.fromhex(s) for s in good["siblings"]],
        path=good["path_bits"],
    )
    _, valid_before = verify_proof(proof)
    proof.siblings[7] = bytes(sib)
    _, valid_after = verify_proof(proof)
    check("篡改前证明有效、篡改后复算根 != 版本根",
          valid_before and not valid_after)

    # 未篡改的证明经 /api/verify 必须通过
    status, verdict = http("POST", base + "/api/verify", {
        "version": good["version"], "serial": good["serial"],
        "status": good["status"], "included": good["included"],
        "root": good["root"], "leaf_digest": good["leaf_digest"],
        "path_bits": good["path_bits"], "siblings": good["siblings"],
    }, expect_status=200)
    check("未篡改证明 /api/verify 返回 200 校验通过",
          verdict.get("root_check_ok") is True)

    return root2


def test_cross_service() -> None:
    base = os.environ.get("BASE_URL")
    if not base:
        print("\n== 跨服务冒烟：未设置 BASE_URL，跳过 ==", flush=True)
        return
    print(f"\n== 跨服务 HTTP 冒烟 -> {base} ==", flush=True)
    try:
        status, health = http("GET", base + "/health")
        check("对 web 服务 GET /health 可观察",
              status == 200 and health["status"] == "ok",
              f"version={health.get('latest_version')}")
        status, versions = http("GET", base + "/api/versions")
        check("对 web 服务 GET /api/versions 可观察",
              status == 200 and len(versions["versions"]) >= 1)
        status, _ = http("GET", base + "/")
        check("对 web 服务 GET / 页面可观察", status == 200)
    except OSError as exc:
        check("对 web 服务的 HTTP 连通性", False, str(exc))


def test_build_check() -> None:
    print("\n== 构建检查 ==", flush=True)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ok = compileall.compile_dir(os.path.join(root, "app"), quiet=1)
    check("compileall 编译全部 Python 源文件", bool(ok), f"tree={root}")
    check("parse_serial 接受 00A1 / a1 / 整数 41",
          parse_serial("00A1") == 0xA1 and parse_serial("a1") == 0xA1
          and parse_serial(41) == 41)


def main() -> int:
    print("==== 十六层稀疏 Merkle 吊销目录：一次性验收 ====", flush=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        test_build_check()
        test_hashing_contract()
        test_code_level_store(tmpdir)
        httpd, base = start_http_server(tmpdir)
        try:
            test_http_flows(base)
        finally:
            httpd.shutdown()
    test_cross_service()

    print("\n====" , flush=True)
    if FAILED_STEPS:
        print(f"验收失败：{len(FAILED_STEPS)} 项 -- {FAILED_STEPS}", flush=True)
        return 1
    print("验收通过：全部检查项 PASS，退出码 0", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
