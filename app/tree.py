"""Fixed 16-level sparse binary Merkle tree over 4-digit hex serial numbers.

Path bits are taken high nibble first, high bit of each nibble first, i.e. the
serial's 16 bits from most significant to least significant.

Digest rules (all digests are SHA-256, 32 bytes)::

    leaf(serial_u16, status) = SHA256(LEAF_PREFIX || serial_be16 || status)
    node(left_digest, right_digest) = SHA256(BRANCH_PREFIX || left || right)

``status`` is a single byte, ``b"\\x00"`` for "not revoked" and ``b"\\x01"`` for
"revoked"; ``LEAF_PREFIX`` is the prescribed prefix byte (0x52 == 'R').

An *empty* subtree at height h contains no leaf.  Empty subtree digests are
precomputed bottom-up::

    empty[0] = SHA256(EMPTY_PREFIX)               # empty leaf level
    empty[h] = SHA256(BRANCH_PREFIX || empty[h-1] || empty[h-1])

so the root of the completely empty tree is ``empty[16]``.
"""

from __future__ import annotations

import hashlib

TREE_LEVELS = 16
KEY_BYTES = TREE_LEVELS // 8  # serial numbers are 16 bits -> 2 bytes

LEAF_PREFIX = b"\x52"   # prescribed prefix byte for leaf preimages
BRANCH_PREFIX = b"\x02"
EMPTY_PREFIX = b"\x00"

STATUS_NOT_REVOKED = 0
STATUS_REVOKED = 1
VALID_STATUS = (STATUS_NOT_REVOKED, STATUS_REVOKED)

STATUS_NAME = {STATUS_NOT_REVOKED: "not_revoked", STATUS_REVOKED: "revoked"}
NAME_STATUS = {v: k for k, v in STATUS_NAME.items()}

#: empty subtree digest for every height 0..16, index = subtree height
EMPTY = []


def _build_empty_digests() -> None:
    EMPTY.append(hashlib.sha256(EMPTY_PREFIX).digest())
    for _ in range(TREE_LEVELS):
        child = EMPTY[-1]
        EMPTY.append(hashlib.sha256(BRANCH_PREFIX + child + child).digest())


_build_empty_digests()


def serial_to_key(serial: str) -> bytes:
    """Validate a 4-digit hex serial and return its 2-byte big-endian key."""
    if not isinstance(serial, str) or len(serial) != 4:
        raise ValueError("serial must be exactly 4 hexadecimal digits")
    try:
        value = int(serial, 16)
    except ValueError:
        raise ValueError("serial must be exactly 4 hexadecimal digits") from None
    return value.to_bytes(KEY_BYTES, "big")


def key_to_serial(key: bytes) -> str:
    return key.hex().upper()


def path_bits(key: bytes):
    """Yield the 16 path bits high-to-low (MSB of key first)."""
    n = int.from_bytes(key, "big")
    for i in range(TREE_LEVELS - 1, -1, -1):
        yield (n >> i) & 1


def leaf_digest(key: bytes, status: int) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + key + bytes([status])).digest()


def branch_digest(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(BRANCH_PREFIX + left + right).digest()


class Proof:
    """An inclusion/non-inclusion proof verifiable purely from the root.

    ``chain`` packs 16 sibling digests in encounter order (leaf -> root).

    * inclusion proof (``included=True``): the slot holds a materialised leaf
      ``SHA256(LEAF_PREFIX || key || status)``; verification starts there.
    * non-inclusion proof (``included=False``): the slot has never been
      written at the queried version, so it is the empty leaf digest
      ``EMPTY[0]``; verification starts there instead.  Missing a status is
      reported as *not revoked* (the directory's default state).
    """

    def __init__(self, key: bytes, status: int, chain: bytes, included: bool = True):
        if status not in VALID_STATUS:
            raise ValueError("invalid status byte")
        if len(chain) != TREE_LEVELS * 32:
            raise ValueError("proof must contain exactly %d sibling digests" % TREE_LEVELS)
        self.key = key
        self.status = status
        self.chain = chain
        self.included = included

    @property
    def serial(self) -> str:
        return key_to_serial(self.key)

    def siblings(self):
        """Yield ``(merge_level, path_bit, sibling_digest)`` leaf -> root.

        Merge step ``i`` (0-based) produces the height ``i+1`` node, combines
        the running digest with a height-``i`` sibling, and uses path bit
        ``b_i`` (bit 0 is the LSB / last nibble's low bit).  The final step
        (``i=15``) produces the root using bit 15.
        """
        n = int.from_bytes(self.key, "big")
        for i in range(TREE_LEVELS):
            yield i + 1, (n >> i) & 1, self.chain[i * 32:(i + 1) * 32]

    def claimed_leaf(self) -> bytes:
        """Starting digest for verification: materialised leaf or empty slot."""
        if self.included:
            return leaf_digest(self.key, self.status)
        return EMPTY[0]

    def compute_root(self) -> bytes:
        current = self.claimed_leaf()
        for _merge_level, bit, sibling in self.siblings():
            if bit == 0:
                current = branch_digest(current, sibling)
            else:
                current = branch_digest(sibling, current)
        return current

    def verify(self, expected_root: bytes) -> bool:
        return self.compute_root() == expected_root

    def to_dict(self) -> dict:
        start = self.claimed_leaf()
        kind = "inclusion" if self.included else "non_inclusion"
        steps = [{
            "merge_level": 0,
            "bit": None,
            "kind": "leaf" if self.included else "empty_slot",
            "digest": start.hex(),
        }]
        current = start
        for merge_level, bit, sibling in self.siblings():
            left, right = (current, sibling) if bit == 0 else (sibling, current)
            current = branch_digest(left, right)
            steps.append({
                "merge_level": merge_level,
                "bit": bit,
                "direction": "right" if bit == 0 else "left",
                "sibling": sibling.hex(),
                "digest": current.hex(),
            })
        return {
            "serial": self.serial,
            "kind": kind,
            "included": self.included,
            "status": STATUS_NAME[self.status],
            "leaf_digest": leaf_digest(self.key, self.status).hex() if self.included else None,
            "empty_slot_digest": EMPTY[0].hex(),
            # sibling digests encountered bottom-up; exactly TREE_LEVELS items
            "siblings": [
                {"merge_level": ml, "bit": bit,
                 "direction": "right" if bit == 0 else "left", "digest": sib.hex()}
                for ml, bit, sib in self.siblings()
            ],
            "steps": steps,
            "computed_root": current.hex(),
        }
