"""
哈希引擎 — 6 种哈希方法的纯逻辑实现（无 Qt 依赖）

所有函数签名统一为:
    xxx_hash(data: str, charset: str, **kwargs) -> str

输出均为 Hex 字符串
"""
import hashlib
import struct
from modules.codec._sm_crypto import sm3_hash


def _to_bytes(data: str, charset: str) -> bytes:
    return data.encode(charset, errors="replace")


# ============================================================
#  MD5
# ============================================================

def md5_hash(data: str, charset: str) -> str:
    return hashlib.md5(_to_bytes(data, charset)).hexdigest()


# ============================================================
#  SM3（国密哈希）
# ============================================================

def sm3_hash_func(data: str, charset: str) -> str:
    return sm3_hash(_to_bytes(data, charset)).hex()


# ============================================================
#  SHA1
# ============================================================

def sha1_hash(data: str, charset: str) -> str:
    return hashlib.sha1(_to_bytes(data, charset)).hexdigest()


# ============================================================
#  SHA2
# ============================================================

_SHA2_NAMES = {
    "SHA-224": "sha224",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
}


def sha2_hash(data: str, charset: str, variant: str = "SHA-256") -> str:
    name = _SHA2_NAMES.get(variant, "sha256")
    return hashlib.new(name, _to_bytes(data, charset)).hexdigest()


# ============================================================
#  SHA3
# ============================================================

_SHA3_NAMES = {
    "SHA3-224": "sha3_224",
    "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384",
    "SHA3-512": "sha3_512",
}


def sha3_hash(data: str, charset: str, variant: str = "SHA3-256") -> str:
    name = _SHA3_NAMES.get(variant, "sha3_256")
    return hashlib.new(name, _to_bytes(data, charset)).hexdigest()


# ============================================================
#  NTLM (MD4 of UTF-16LE)
# ============================================================

def ntlm_hash(data: str, charset: str) -> str:
    """NTLM 哈希 = MD4(password.encode('utf-16le'))"""
    password_bytes = data.encode("utf-16le")
    # 纯 Python MD4 实现（OpenSSL 3.0+ 移除了 MD4）
    return _md4(password_bytes).hex()


# ---- 纯 Python MD4 实现 (RFC 1320) ----

def _md4(data: bytes):
    """纯 Python MD4 实现"""

    def _f(x, y, z):
        return (x & y) | (~x & z)

    def _g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def _h(x, y, z):
        return x ^ y ^ z

    def _rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    msg = bytearray(data)
    orig_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    msg += struct.pack("<Q", orig_len)

    for i in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[i:i + 64]))
        aa, bb, cc, dd = a, b, c, d

        for j in range(16):
            k = j
            s = [3, 7, 11, 19][j % 4]
            u = (a + _f(b, c, d) + x[k]) & 0xFFFFFFFF
            a, b, c, d = d, _rotl(u, s), b, c

        for j in range(16):
            k = (j % 4) * 4 + (j // 4)
            s = [3, 5, 9, 13][j % 4]
            u = (a + _g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF
            a, b, c, d = d, _rotl(u, s), b, c

        for j in range(16):
            k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][j]
            s = [3, 9, 11, 15][j % 4]
            u = (a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF
            a, b, c, d = d, _rotl(u, s), b, c

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


class _MD4Hash:
    """MD4 哈希对象，模拟 hashlib 接口"""
    def __init__(self, data: bytes = b""):
        self._data = data

    def hexdigest(self) -> str:
        return _md4(self._data).hex()
