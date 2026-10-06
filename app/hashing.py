"""摘要规范（所有参与方必须遵守的同一套域分离约定）。

序列号为四位十六进制（0x0000..0xFFFF），即 16 比特；树为固定 16 层
二叉稀疏 Merkle 树，路径位自高位向低位依次使用。

* 叶子摘要  leaf   = SHA256(0x00 || serial_be[2] || status[1])
  - 仅“已吊销”(status=1) 才会物化叶子节点；
  - “解除吊销”(status=0) 使该位置回归空叶。
* 分支摘要  branch = SHA256(0x01 || left[32] || right[32])
* 空叶摘要  empty  = SHA256(0x02)

不同前缀字节保证叶子 / 分支 / 空叶三类输入互不歧义（第二原像防护）。
"""

from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
BRANCH_PREFIX = b"\x01"
EMPTY_PREFIX = b"\x02"

STATUS_REVOKED = 1
STATUS_ACTIVE = 0

TREE_LEVELS = 16
DIGEST_LEN = 32

#: 空叶摘要（树最底层的“空”占位）。
EMPTY_LEAF = hashlib.sha256(EMPTY_PREFIX).digest()

#: 各高度空默克尔子树摘要：DEFAULTS[k] 表示还需向上 k 层分支的空子树。
#: DEFAULTS[0] 为空叶，DEFAULTS[16] 为空目录的根。
DEFAULTS: list[bytes] = [EMPTY_LEAF]
for _height in range(TREE_LEVELS):
    DEFAULTS.append(hashlib.sha256(
        BRANCH_PREFIX + DEFAULTS[-1] + DEFAULTS[-1]
    ).digest())

GENESIS_ROOT = DEFAULTS[TREE_LEVELS]


def leaf_digest(serial: int, status: int = STATUS_REVOKED) -> bytes:
    """计算叶子摘要。序列号取 2 字节大端，状态取 1 字节。"""
    if not 0 <= serial <= 0xFFFF:
        raise ValueError("serial out of range")
    if status not in (STATUS_ACTIVE, STATUS_REVOKED):
        raise ValueError("invalid status")
    return hashlib.sha256(
        LEAF_PREFIX + serial.to_bytes(2, "big") + bytes([status])
    ).digest()


def branch_digest(left: bytes, right: bytes) -> bytes:
    if len(left) != DIGEST_LEN or len(right) != DIGEST_LEN:
        raise ValueError("child digest must be 32 bytes")
    return hashlib.sha256(BRANCH_PREFIX + left + right).digest()


def path_bits(serial: int) -> list[int]:
    """返回序列号自高位到低位的 16 个路径位（0=左，1=右）。"""
    if not 0 <= serial <= 0xFFFF:
        raise ValueError("serial out of range")
    return [(serial >> (TREE_LEVELS - 1 - i)) & 1 for i in range(TREE_LEVELS)]


def to_hex(data: bytes) -> str:
    return data.hex()


def from_hex(text: str) -> bytes:
    text = text.strip().lower()
    if len(text) != DIGEST_LEN * 2:
        raise ValueError("digest must be 64 hex chars")
    try:
        data = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("invalid hex digest") from exc
    return data
