"""SQLite 持久化层。

一次批次成功时，新节点、版本根、批次记录与每项的包含/未包含证明
全部在同一个 ``BEGIN IMMEDIATE`` 事务（单一持久化提交）中落盘；
任一校验失败则回滚，不产生版本。

节点按摘要内容寻址且不可变，因此新版本永远无法改动旧版本根下的
任何查询结果。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Iterable, Optional

from . import hashing as H

SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
    version    INTEGER PRIMARY KEY,
    root       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS batches (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    version    INTEGER NOT NULL UNIQUE,
    base_root  TEXT NOT NULL,
    item_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS batch_items (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL REFERENCES batches(id),
    serial   INTEGER NOT NULL,
    status   INTEGER NOT NULL,
    ord      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    digest        TEXT PRIMARY KEY,
    level         INTEGER NOT NULL,           -- 0=叶子, 1..16=分支
    left_digest   TEXT,
    right_digest  TEXT,
    serial        INTEGER,
    first_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS proofs (
    version        INTEGER NOT NULL REFERENCES versions(version),
    serial         INTEGER NOT NULL,
    status         INTEGER NOT NULL,          -- 该版本下序列号的有效状态
    included       INTEGER NOT NULL,          -- 1=包含(已吊销) 0=未包含
    root           TEXT NOT NULL,
    leaf_digest    TEXT NOT NULL,
    siblings       TEXT NOT NULL,             -- JSON: 自顶向下 16 个兄弟摘要
    path_bits      TEXT NOT NULL,             -- JSON: 自顶向下 16 个路径位
    recomputed     TEXT NOT NULL,             -- 按证明本地复算出的根
    valid          INTEGER NOT NULL,
    PRIMARY KEY (version, serial)
);
"""


class StaleRootError(Exception):
    """期望根不是最新根（乐观并发冲突）。"""


class BatchError(ValueError):
    """批次本身非法（过大、重复序列号、非法状态/序列号等）。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Proof:
    version: int
    serial: int
    status: int
    included: bool
    root: bytes
    leaf: bytes
    siblings: list[bytes]   # 自顶向下 16 项
    path: list[int]         # 自顶向下 16 位

    def to_dict(self, recomputed: bytes, valid: bool) -> dict:
        return {
            "version": self.version,
            "serial": f"{self.serial:04X}",
            "serial_int": self.serial,
            "status": "revoked" if self.status == H.STATUS_REVOKED else "active",
            "included": self.included,
            "root": self.root.hex(),
            "leaf_digest": self.leaf.hex(),
            "path_bits": self.path,
            "siblings": [s.hex() for s in self.siblings],
            "recomputed_root": recomputed.hex(),
            "root_check_ok": valid,
        }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_serial(value) -> int:
    """接受 1..4 位十六进制（规范显示为 4 位大写）。"""
    if isinstance(value, bool):
        raise BatchError("INVALID_SERIAL", "serial must be a hex string")
    if isinstance(value, int):
        if 0 <= value <= 0xFFFF:
            return value
        raise BatchError("INVALID_SERIAL", "serial out of range")
    if not isinstance(value, str):
        raise BatchError("INVALID_SERIAL", "serial must be a hex string")
    text = value.strip().lower()
    if not (1 <= len(text) <= 4) or any(c not in "0123456789abcdef" for c in text):
        raise BatchError("INVALID_SERIAL", f"invalid serial: {value!r}")
    return int(text, 16)


def parse_status(value) -> int:
    if value in ("revoked", "revoke", H.STATUS_REVOKED, "1", 1):
        return H.STATUS_REVOKED
    if value in ("released", "release", "active", H.STATUS_ACTIVE, "0", 0):
        return H.STATUS_ACTIVE
    raise BatchError("INVALID_STATUS", f"invalid status: {value!r}")


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._tx_lock = threading.Lock()
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._conn.executescript(SCHEMA)
        self._seed_genesis()

    def close(self) -> None:
        self._conn.close()

    def _seed_genesis(self) -> None:
        row = self._conn.execute("SELECT MAX(version) AS v FROM versions").fetchone()
        if row["v"] is None:
            self._conn.execute(
                "INSERT INTO versions(version, root, created_at, note) "
                "VALUES (0, ?, ?, 'genesis empty directory')",
                (H.GENESIS_ROOT.hex(), _now()),
            )

    # ------------------------------------------------------------------ 读

    def latest(self) -> dict:
        row = self._conn.execute(
            "SELECT version, root, created_at, note FROM versions "
            "ORDER BY version DESC LIMIT 1"
        ).fetchone()
        return dict(row)

    def versions(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT v.version, v.root, v.created_at, v.note, "
            "       b.item_count "
            "FROM versions v LEFT JOIN batches b ON b.version = v.version "
            "ORDER BY v.version"
        ).fetchall()
        return [dict(r) for r in rows]

    def version(self, version: int) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM versions WHERE version = ?", (version,)
        ).fetchone()
        return dict(row) if row else None

    def batch(self, version: int) -> Optional[dict]:
        rows = self._conn.execute(
            "SELECT b.version, b.base_root, b.item_count, b.created_at, "
            "       i.serial, i.status, i.ord "
            "FROM batches b JOIN batch_items i ON i.batch_id = b.id "
            "WHERE b.version = ? ORDER BY i.ord",
            (version,),
        ).fetchall()
        if not rows:
            return None
        items = [
            {"serial": f"{r['serial']:04X}", "serial_int": r["serial"],
             "status": ("revoked" if r["status"] == H.STATUS_REVOKED else "released")}
            for r in rows
        ]
        return {
            "version": rows[0]["version"],
            "base_root": rows[0]["base_root"],
            "item_count": rows[0]["item_count"],
            "created_at": rows[0]["created_at"],
            "items": items,
        }

    # ---------------------------------------------------- 树遍历（不可变视图）

    def _node_children(self, digest: bytes, level: int) -> tuple[bytes, bytes]:
        """取分支节点两个孩子；空子树直接返回对应高度的默认摘要。"""
        default = H.DEFAULTS[level]
        if digest == default:
            return H.DEFAULTS[level - 1], H.DEFAULTS[level - 1]
        row = self._conn.execute(
            "SELECT left_digest, right_digest FROM nodes WHERE digest = ?",
            (digest.hex(),),
        ).fetchone()
        if row is None:  # 理论上不可达：所有非空节点均已持久化
            raise KeyError(f"missing node {digest.hex()} at level {level}")
        return bytes.fromhex(row["left_digest"]), bytes.fromhex(row["right_digest"])

    def proof(self, version: int, serial: int) -> Proof:
        """基于指定版本根，沿不可变节点自顶向下生成包含/未包含证明。"""
        vrow = self.version(version)
        if vrow is None:
            raise BatchError("VERSION_NOT_FOUND", f"version {version} not found")
        root = bytes.fromhex(vrow["root"])
        bits = H.path_bits(serial)
        siblings: list[bytes] = []
        cur = root
        for depth, bit in enumerate(bits):
            level = H.TREE_LEVELS - depth
            left, right = self._node_children(cur, level)
            if bit == 0:
                siblings.append(right)
                cur = left
            else:
                siblings.append(left)
                cur = right
        included = cur != H.EMPTY_LEAF
        leaf = cur if included else H.EMPTY_LEAF
        status = H.STATUS_REVOKED if included else H.STATUS_ACTIVE
        return Proof(version, serial, status, included, root, leaf, siblings, bits)

    # ------------------------------------------------------------------ 写

    def apply_batch(self, expected_root: str, raw_items: list,
                    note: str = "") -> dict:
        """乐观并发提交一个批次，返回新版本与全部证明。"""
        # ---- 纯输入校验（不触碰数据库状态） ----
        if not isinstance(raw_items, list) or len(raw_items) == 0:
            raise BatchError("BATCH_EMPTY", "batch must contain 1..32 items")
        if len(raw_items) > 32:
            raise BatchError("BATCH_TOO_LARGE", "at most 32 items per batch")
        items: list[tuple[int, int]] = []
        seen: set[int] = set()
        for raw in raw_items:
            if not isinstance(raw, dict):
                raise BatchError("INVALID_ITEM", "each item must be an object")
            serial = parse_serial(raw.get("serial"))
            status = parse_status(raw.get("status"))
            if serial in seen:
                raise BatchError(
                    "DUPLICATE_SERIAL",
                    f"duplicate serial in batch: {serial:04X}",
                )
            seen.add(serial)
            items.append((serial, status))
        try:
            expected = H.from_hex(expected_root)
        except ValueError as exc:
            raise BatchError("ROOT_NOT_HEX", str(exc)) from exc

        with self._tx_lock:
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                latest_row = conn.execute(
                    "SELECT version, root FROM versions "
                    "ORDER BY version DESC LIMIT 1"
                ).fetchone()
                latest_root = bytes.fromhex(latest_row["root"])
                base_version = latest_row["version"]
                if expected != latest_root:
                    raise StaleRootError(
                        f"expected root {expected.hex()} is not current root "
                        f"{latest_root.hex()} (latest version v{base_version})"
                    )

                new_leaves = {s: st for s, st in items}
                new_nodes: dict[bytes, tuple] = {}  # digest -> (level,l,r,serial)

                def current_subdigest(prefix: int, depth: int) -> bytes:
                    """旧树在 (prefix,depth) 子树位置的摘要（沿旧根下行）。"""
                    cur = latest_root
                    for i in range(depth):
                        level = H.TREE_LEVELS - i
                        if cur == H.DEFAULTS[level]:
                            return H.DEFAULTS[H.TREE_LEVELS - depth]
                        row = conn.execute(
                            "SELECT left_digest, right_digest FROM nodes "
                            "WHERE digest = ?", (cur.hex(),)
                        ).fetchone()
                        bit = (prefix >> (H.TREE_LEVELS - 1 - i)) & 1
                        cur = bytes.fromhex(
                            row["right_digest"] if bit else row["left_digest"]
                        )
                    return cur

                def build(depth: int, prefix: int) -> bytes:
                    lo = prefix << (H.TREE_LEVELS - depth)
                    hi = (prefix + 1) << (H.TREE_LEVELS - depth)
                    if depth > 0 and not any(lo <= s < hi for s in new_leaves):
                        return current_subdigest(prefix, depth)
                    if depth == H.TREE_LEVELS:
                        status = new_leaves.get(prefix, H.STATUS_ACTIVE)
                        return (H.leaf_digest(prefix, H.STATUS_REVOKED)
                                if status == H.STATUS_REVOKED else H.EMPTY_LEAF)
                    shift = H.TREE_LEVELS - depth - 1
                    left = build(depth + 1, prefix << 1)
                    right = build(depth + 1, (prefix << 1) | 1)
                    if depth == H.TREE_LEVELS - 1:
                        left_serial = (prefix << 1) & 0xFFFF
                        right_serial = ((prefix << 1) | 1) & 0xFFFF
                        if left != H.EMPTY_LEAF:
                            new_nodes[left] = (0, None, None, left_serial)
                        if right != H.EMPTY_LEAF:
                            new_nodes[right] = (0, None, None, right_serial)
                    digest = H.branch_digest(left, right)
                    if digest != H.DEFAULTS[H.TREE_LEVELS - depth]:
                        new_nodes[digest] = (
                            H.TREE_LEVELS - depth, left.hex(), right.hex(), None
                        )
                    return digest

                new_root = build(0, 0)
                new_version = base_version + 1

                # ---- 单一持久化提交：版本根 + 批次 + 节点 + 逐项证明 ----
                conn.execute(
                    "INSERT INTO versions(version, root, created_at, note) "
                    "VALUES (?, ?, ?, ?)",
                    (new_version, new_root.hex(), _now(), note or ""),
                )
                cur = conn.execute(
                    "INSERT INTO batches(version, base_root, item_count, "
                    "created_at) VALUES (?, ?, ?, ?)",
                    (new_version, latest_root.hex(), len(items), _now()),
                )
                batch_id = cur.lastrowid
                for ord_, (serial, status) in enumerate(items):
                    conn.execute(
                        "INSERT INTO batch_items(batch_id, serial, status, ord) "
                        "VALUES (?, ?, ?, ?)",
                        (batch_id, serial, status, ord_),
                    )
                for digest, (level, left, right, serial) in new_nodes.items():
                    conn.execute(
                        "INSERT OR IGNORE INTO nodes(digest, level, "
                        "left_digest, right_digest, serial, first_version) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (digest.hex(), level, left, right, serial, new_version),
                    )

                proofs_out = []
                for serial, _status in items:
                    proof = self._proof_against(conn, new_version, new_root, serial)
                    recomputed, valid = verify_proof(proof)
                    assert valid, "freshly written proof must verify"
                    conn.execute(
                        "INSERT INTO proofs(version, serial, status, included, "
                        "root, leaf_digest, siblings, path_bits, recomputed, "
                        "valid) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (proof.version, proof.serial, proof.status,
                         int(proof.included), proof.root.hex(),
                         proof.leaf.hex(), json.dumps([s.hex() for s in
                                                       proof.siblings]),
                         json.dumps(proof.path), recomputed.hex(), int(valid)),
                    )
                    proofs_out.append(proof.to_dict(recomputed, valid))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

        return {
            "version": new_version,
            "root": new_root.hex(),
            "base_version": base_version,
            "proofs": proofs_out,
        }

    def _proof_against(self, conn, version: int, root: bytes,
                       serial: int) -> Proof:
        bits = H.path_bits(serial)
        siblings: list[bytes] = []
        cur = root
        for depth, bit in enumerate(bits):
            level = H.TREE_LEVELS - depth
            if cur == H.DEFAULTS[level]:
                left = right = H.DEFAULTS[level - 1]
            else:
                row = conn.execute(
                    "SELECT left_digest, right_digest FROM nodes "
                    "WHERE digest = ?", (cur.hex(),)
                ).fetchone()
                left, right = (bytes.fromhex(row["left_digest"]),
                               bytes.fromhex(row["right_digest"]))
            if bit == 0:
                siblings.append(right)
                cur = left
            else:
                siblings.append(left)
                cur = right
        included = cur != H.EMPTY_LEAF
        leaf = cur if included else H.EMPTY_LEAF
        return Proof(
            version=version,
            serial=serial,
            status=H.STATUS_REVOKED if included else H.STATUS_ACTIVE,
            included=included,
            root=root,
            leaf=leaf,
            siblings=siblings,
            path=bits,
        )


def verify_proof(proof: Proof) -> tuple[bytes, bool]:
    """任何人都可独立执行的复算：从叶子与逐层兄弟摘要重建根。"""
    node = proof.leaf
    for i in range(H.TREE_LEVELS - 1, -1, -1):
        sibling = proof.siblings[i]
        if proof.path[i] == 0:
            node = H.branch_digest(node, sibling)
        else:
            node = H.branch_digest(sibling, node)
    return node, node == proof.root
