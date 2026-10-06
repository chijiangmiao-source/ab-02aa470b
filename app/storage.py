"""Persistent storage for the versioned revocation directory.

Layout (SQLite)::

    meta(key TEXT PRIMARY KEY, value)          -- e.g. latest_version
    versions(version INTEGER PRIMARY KEY,
             root BLOB, parent_version, created_at, comment)
    leaf_events(version INTEGER, key BLOB, status INTEGER,
                PRIMARY KEY (key, version))    -- append-only leaf facts
    proofs(version INTEGER, key BLOB, status INTEGER, chain BLOB,
           PRIMARY KEY (version, key))         -- per-batch-item stored proofs
    nodes(digest BLOB PRIMARY KEY, height, lchild, rchild)  -- branch nodes

``nodes`` is content-addressed and append-only: a branch digest is inserted
with ``INSERT OR IGNORE`` and never modified or deleted.  Empty subtrees are
implicit (their digests live in :mod:`app.tree`), so rebuilding a proof only
needs the root digest plus the node table.

Batch submission happens in a single ``BEGIN IMMEDIATE`` transaction: the
latest root is re-read while holding the write lock and compared with the
operator's expected root, so a stale root aborts the whole batch and no
version (nor any node/proof) is committed.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
import threading
from typing import Iterable, Optional

from . import tree

MAX_BATCH_ITEMS = 32

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS versions (
    version        INTEGER PRIMARY KEY,
    root           BLOB NOT NULL,
    parent_version INTEGER,
    created_at     TEXT NOT NULL,
    comment        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS leaf_events (
    version INTEGER NOT NULL,
    key     BLOB NOT NULL,
    status  INTEGER NOT NULL,
    PRIMARY KEY (key, version)
);
CREATE TABLE IF NOT EXISTS proofs (
    version  INTEGER NOT NULL,
    key      BLOB NOT NULL,
    status   INTEGER NOT NULL,
    included INTEGER NOT NULL,
    chain    BLOB NOT NULL,
    PRIMARY KEY (version, key)
);
CREATE TABLE IF NOT EXISTS nodes (
    digest BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    lchild BLOB NOT NULL,
    rchild BLOB NOT NULL
) WITHOUT ROWID;
"""


class StaleRootError(Exception):
    """The expected root is no longer the latest root."""


class InvalidBatchError(Exception):
    """The batch itself is malformed (bad size, serial, status or duplicates)."""


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def normalize_status(value) -> int:
    if isinstance(value, bool):  # bool is a subclass of int; reject for clarity
        raise InvalidBatchError("status must be 0/1 or a status name")
    if isinstance(value, int):
        if value in tree.VALID_STATUS:
            return value
        raise InvalidBatchError("status must be 0 (not_revoked) or 1 (revoked)")
    if isinstance(value, str):
        name = value.strip().lower()
        if name in tree.NAME_STATUS:
            return tree.NAME_STATUS[name]
        if name in ("unrevoked", "unrevoke", "clear", "active"):
            return tree.STATUS_NOT_REVOKED
        if name in ("revoke",):
            return tree.STATUS_REVOKED
        raise InvalidBatchError("unknown status %r" % value)
    raise InvalidBatchError("unsupported status value %r" % (value,))


def _locked(method):
    """Serialize access to the shared sqlite connection (RLock: reentrant)."""

    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    return wrapper


class Storage:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(
            path, timeout=30, isolation_level=None, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        row = self.conn.execute("SELECT value FROM meta WHERE key='latest_version'").fetchone()
        if row is None:
            # Version 0: the empty tree, published before any batch.
            self.conn.execute(
                "INSERT INTO versions(version, root, parent_version, created_at, comment) "
                "VALUES (0, ?, NULL, ?, 'genesis empty directory')",
                (tree.EMPTY[tree.TREE_LEVELS], _now()),
            )
            self.conn.execute("INSERT INTO meta(key, value) VALUES ('latest_version', '0')")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------------------------------------------------------------- read --

    @_locked
    def latest(self) -> tuple[int, bytes]:
        row = self.conn.execute(
            "SELECT v.version, v.root FROM versions v "
            "JOIN meta m ON m.value = v.version WHERE m.key='latest_version'"
        ).fetchone()
        return row["version"], row["root"]

    @_locked
    def get_version(self, version: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM versions WHERE version=?", (version,)
        ).fetchone()

    @_locked
    def list_versions(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM versions ORDER BY version"))

    @_locked
    def state_at(self, key: bytes, version: int) -> int:
        """Status of ``key`` as visible at ``version`` (default: not revoked)."""
        row = self.conn.execute(
            "SELECT status FROM leaf_events WHERE key=? AND version<=? "
            "ORDER BY version DESC LIMIT 1",
            (key, version),
        ).fetchone()
        return tree.STATUS_NOT_REVOKED if row is None else row["status"]

    @_locked
    def exists_at(self, key: bytes, version: int) -> bool:
        """Whether the slot of ``key`` has ever been written at ``version``."""
        return self.conn.execute(
            "SELECT 1 FROM leaf_events WHERE key=? AND version<=? LIMIT 1",
            (key, version),
        ).fetchone() is not None

    @_locked
    def proof_for(self, version: int, key: bytes) -> tree.Proof:
        row = self.get_version(version)
        if row is None:
            raise InvalidBatchError("unknown version %d" % version)
        status = self.state_at(key, version)
        included = self.exists_at(key, version)
        root = row["root"]
        collected: list[bytes] = []  # sibling at levels 16..1 (root -> leaf)
        digest = root
        for level in range(tree.TREE_LEVELS, 0, -1):
            bit = (int.from_bytes(key, "big") >> (level - 1)) & 1
            if digest == tree.EMPTY[level]:
                sibling = tree.EMPTY[level - 1]
                child = tree.EMPTY[level - 1]
            else:
                node = self.conn.execute(
                    "SELECT lchild, rchild FROM nodes WHERE digest=? AND height=?",
                    (digest, level),
                ).fetchone()
                if node is None:  # corrupt store; treat as integrity failure
                    raise RuntimeError(
                        "missing node %s at height %d" % (digest.hex(), level)
                    )
                if bit == 0:
                    sibling, child = node["rchild"], node["lchild"]
                else:
                    sibling, child = node["lchild"], node["rchild"]
            collected.append(sibling)
            digest = child
        # Proof chain is ordered leaf -> root; reverse the descent collection.
        chain = b"".join(reversed(collected))
        expected_slot = tree.leaf_digest(key, status) if included else tree.EMPTY[0]
        if digest != expected_slot:
            raise RuntimeError("tree descent ended at an unexpected slot digest")
        proof = tree.Proof(key, status, bytes(chain), included)
        if not proof.verify(root):
            raise RuntimeError("internally produced proof fails root check")
        return proof

    @_locked
    def stored_proof(self, version: int, key: bytes) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT status, included, chain FROM proofs WHERE version=? AND key=?",
            (version, key),
        ).fetchone()

    # --------------------------------------------------------------- write --

    @_locked
    def submit_batch(
        self,
        expected_root_hex: str,
        items: Iterable[dict],
        comment: str = "",
    ) -> tuple[int, bytes]:
        # ---- Validate everything before touching the database.
        try:
            expected_root = bytes.fromhex(expected_root_hex)
        except (TypeError, ValueError):
            raise InvalidBatchError("expected_root must be a hex string") from None
        if len(expected_root) != 32:
            raise InvalidBatchError("expected_root must be a 32-byte hash")

        normalized: list[tuple[bytes, int, str]] = []
        seen: set[bytes] = set()
        items = list(items)
        if not items:
            raise InvalidBatchError("batch must contain at least one item")
        if len(items) > MAX_BATCH_ITEMS:
            raise InvalidBatchError(
                "batch has %d items; at most %d are allowed" % (len(items), MAX_BATCH_ITEMS)
            )
        for item in items:
            serial = item.get("serial") if isinstance(item, dict) else None
            try:
                key = tree.serial_to_key(serial)
            except ValueError as exc:
                raise InvalidBatchError(str(exc)) from None
            if key in seen:
                raise InvalidBatchError("duplicate serial in batch: %s" % serial.upper())
            seen.add(key)
            status = normalize_status(item.get("status"))
            normalized.append((key, status, serial.upper()))

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            version, current_root = self.latest()
            if current_root != expected_root:
                raise StaleRootError(
                    "expected root %s does not match latest root %s (version %d)"
                    % (expected_root.hex(), current_root.hex(), version)
                )

            root = current_root
            # Apply every leaf update, materialising new branch nodes.
            for key, status, _serial in normalized:
                root = self._apply_leaf(root, key, status)

            new_version = version + 1
            self.conn.execute(
                "INSERT INTO versions(version, root, parent_version, created_at, comment) "
                "VALUES (?, ?, ?, ?, ?)",
                (new_version, root, version, _now(), comment or ""),
            )
            for key, status, _serial in normalized:
                self.conn.execute(
                    "INSERT INTO leaf_events(version, key, status) VALUES (?, ?, ?)",
                    (new_version, key, status),
                )
            # Persist each item's proof against the *final* batch root, so the
            # stored proof stays valid even when two batch keys share prefixes.
            for key, status, _serial in normalized:
                proof = self.proof_for(new_version, key)
                self.conn.execute(
                    "INSERT INTO proofs(version, key, status, included, chain) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (new_version, key, status, int(proof.included), proof.chain),
                )
            self.conn.execute(
                "UPDATE meta SET value=? WHERE key='latest_version'", (str(new_version),)
            )
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        return new_version, root

    @_locked
    def _apply_leaf(self, root: bytes, key: bytes, status: int) -> bytes:
        """Insert/overwrite one leaf and return the new root digest."""
        path = list(tree.path_bits(key))
        # Downward walk: remember each level's path bit and sibling digest.
        frames: list[tuple[int, int, bytes]] = []
        digest = root
        for level, bit in zip(range(tree.TREE_LEVELS, 0, -1), path):
            if digest == tree.EMPTY[level]:
                sibling = tree.EMPTY[level - 1]
                child = tree.EMPTY[level - 1]
            else:
                row = self.conn.execute(
                    "SELECT lchild, rchild FROM nodes WHERE digest=? AND height=?",
                    (digest, level),
                ).fetchone()
                if row is None:
                    raise RuntimeError("missing node %s at height %d" % (digest.hex(), level))
                if bit == 0:
                    sibling, child = row["rchild"], row["lchild"]
                else:
                    sibling, child = row["lchild"], row["rchild"]
            frames.append((level, bit, sibling))
            digest = child

        # Bubble the new leaf back up, persisting every materialised branch.
        new_child = tree.leaf_digest(key, status)
        for level, bit, sibling in reversed(frames):
            if bit == 0:
                left, right = new_child, sibling
            else:
                left, right = sibling, new_child
            parent = tree.branch_digest(left, right)
            # Content-addressed: shared subtrees/prefixes hit an existing row.
            self.conn.execute(
                "INSERT OR IGNORE INTO nodes(digest, height, lchild, rchild) "
                "VALUES (?, ?, ?, ?)",
                (parent, level, left, right),
            )
            new_child = parent
        return new_child
