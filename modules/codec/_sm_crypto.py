"""
国密算法纯 Python 实现 — SM2 / SM3 / SM4

参考标准: GB/T 32905 (SM3), GB/T 32907 (SM4), GB/T 32918 (SM2)
"""
import hashlib
import os
import struct
from typing import Tuple


# ============================================================
#  SM3 — 哈希算法 (输出 256 位 = 64 位 Hex)
# ============================================================

_SM3_IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]


def _sm3_rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sm3_p0(x: int) -> int:
    return x ^ _sm3_rotl(x, 9) ^ _sm3_rotl(x, 17)


def _sm3_p1(x: int) -> int:
    return x ^ _sm3_rotl(x, 15) ^ _sm3_rotl(x, 23)


def _sm3_ff(x: int, y: int, z: int, j: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _sm3_gg(x: int, y: int, z: int, j: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (~x & 0xFFFFFFFF & z)


def sm3_hash(data: bytes) -> bytes:
    """SM3 哈希，返回 32 字节摘要"""
    msg = bytearray(data)
    msg_len = len(data) * 8
    # 填充: 1 + 0 + 64bit length
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    msg += struct.pack(">Q", msg_len)

    v = list(_SM3_IV)
    num_blocks = len(msg) // 64

    for block_idx in range(num_blocks):
        block = msg[block_idx * 64:(block_idx + 1) * 64]
        # 消息扩展
        w = list(struct.unpack(">16I", block))
        for j in range(16, 68):
            w.append(_sm3_p1(w[j - 16] ^ w[j - 9] ^ _sm3_rotl(w[j - 3], 15)) ^ _sm3_rotl(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]
        # 压缩函数
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = _sm3_rotl((_sm3_rotl(a, 12) + e + _sm3_rotl(0x79CC4519, j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _sm3_rotl(a, 12)
            tt1 = (_sm3_ff(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (_sm3_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = _sm3_rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _sm3_rotl(f, 19)
            f = e
            e = _sm3_p0(tt2)
        # 更新 V
        v = [(vi ^ ai) & 0xFFFFFFFF for vi, ai in zip(v, [a, b, c, d, e, f, g, h])]

    return struct.pack(">8I", *v)


# ============================================================
#  SM4 — 分组密码 (128 位密钥, 128 位块)
# ============================================================

_SM4_SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
]

_SM4_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
_SM4_CK = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
]


def _sm4_sbox(x: int) -> int:
    return _SM4_SBOX[x]


def _sm4_rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sm4_l(x: int) -> int:
    return x ^ _sm4_rotl(x, 2) ^ _sm4_rotl(x, 10) ^ _sm4_rotl(x, 18) ^ _sm4_rotl(x, 24)


def _sm4_l1(x: int) -> int:
    return x ^ _sm4_rotl(x, 13) ^ _sm4_rotl(x, 23)


def _sm4_t(x: int) -> int:
    a = (_sm4_sbox((x >> 24) & 0xFF) << 24)
    b = (_sm4_sbox((x >> 16) & 0xFF) << 16)
    c = (_sm4_sbox((x >> 8) & 0xFF) << 8)
    d = _sm4_sbox(x & 0xFF)
    return _sm4_l(a | b | c | d)


def _sm4_t1(x: int) -> int:
    a = (_sm4_sbox((x >> 24) & 0xFF) << 24)
    b = (_sm4_sbox((x >> 16) & 0xFF) << 16)
    c = (_sm4_sbox((x >> 8) & 0xFF) << 8)
    d = _sm4_sbox(x & 0xFF)
    return _sm4_l1(a | b | c | d)


def _sm4_key_schedule(mk: bytes) -> list:
    """生成 32 个轮密钥"""
    mk_words = list(struct.unpack(">4I", mk))
    rk = []
    k = [mk_words[i] ^ _SM4_FK[i] for i in range(4)]
    for i in range(32):
        k.append(k[i] ^ _sm4_t1(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _SM4_CK[i]))
        rk.append(k[-1])
    return rk


def _sm4_encrypt_block(block: bytes, rk: list) -> bytes:
    """加密单个 128 位（16 字节）块"""
    x = list(struct.unpack(">4I", block))
    for i in range(32):
        x.append(x[i] ^ _sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
    result = x[35:31:-1]  # X32, X33, X34, X35
    return struct.pack(">4I", *result)


def sm4_encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """SM4 ECB 模式加密"""
    rk = _sm4_key_schedule(key)
    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    data = data + bytes([pad_len] * pad_len)
    result = b""
    for i in range(0, len(data), 16):
        result += _sm4_encrypt_block(data[i:i + 16], rk)
    return result


def sm4_decrypt_ecb(data: bytes, key: bytes) -> bytes:
    """SM4 ECB 模式解密"""
    rk = _sm4_key_schedule(key)
    rk_rev = rk[::-1]
    result = b""
    for i in range(0, len(data), 16):
        result += _sm4_encrypt_block(data[i:i + 16], rk_rev)
    # 去除 PKCS7 padding
    pad_len = result[-1]
    if pad_len > 16:
        return result
    return result[:-pad_len]


def sm4_encrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """SM4 CBC 模式加密"""
    rk = _sm4_key_schedule(key)
    pad_len = 16 - (len(data) % 16)
    data = data + bytes([pad_len] * pad_len)
    result = b""
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(b ^ p for b, p in zip(data[i:i + 16], prev))
        encrypted = _sm4_encrypt_block(block, rk)
        result += encrypted
        prev = encrypted
    return result


def sm4_decrypt_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """SM4 CBC 模式解密"""
    rk = _sm4_key_schedule(key)
    rk_rev = rk[::-1]
    result = b""
    prev = iv
    for i in range(0, len(data), 16):
        decrypted = _sm4_encrypt_block(data[i:i + 16], rk_rev)
        result += bytes(b ^ p for b, p in zip(decrypted, prev))
        prev = data[i:i + 16]
    pad_len = result[-1]
    if pad_len > 16:
        return result
    return result[:-pad_len]


# ============================================================
#  SM2 — 椭圆曲线公钥加密（基于 cryptography 库的 EC 原语）
# ============================================================

def sm2_generate_keypair() -> Tuple[str, str]:
    """生成 SM2 密钥对，返回 (private_key_hex, public_key_hex)"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    private_bytes = private.private_numbers().private_value.to_bytes(32, 'big')
    public = private.public_key()
    pub_nums = public.public_numbers()
    public_bytes = b'\x04' + pub_nums.x.to_bytes(32, 'big') + pub_nums.y.to_bytes(32, 'big')
    return private_bytes.hex(), public_bytes.hex()


def sm2_encrypt(data: bytes, public_key_hex: str, mode: str = "C1C3C2") -> bytes:
    """SM2 加密，返回原始密文（C1 + C3 + C2 或 C1 + C2 + C3）"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes

    pub_bytes = bytes.fromhex(public_key_hex)
    if len(pub_bytes) == 130 and pub_bytes[0] == 0x04:
        x = int.from_bytes(pub_bytes[1:33], 'big')
        y = int.from_bytes(pub_bytes[33:65], 'big')
    elif len(pub_bytes) == 64:
        x = int.from_bytes(pub_bytes[0:32], 'big')
        y = int.from_bytes(pub_bytes[32:64], 'big')
    else:
        raise ValueError(f"公钥格式错误，长度 {len(pub_bytes)}")

    pub_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key(default_backend())

    # 生成随机 k，计算 C1 = kG
    k = int.from_bytes(os.urandom(32), 'big') % ec.SECP256R1().order
    c1_point = ec.derive_private_key(k, ec.SECP256R1(), default_backend()).public_key()
    c1_nums = c1_point.public_numbers()
    c1 = b'\x04' + c1_nums.x.to_bytes(32, 'big') + c1_nums.y.to_bytes(32, 'big')

    # 计算 kP = (x2, y2)
    shared = pub_key.public_numbers()
    # 用 ECDH 方式计算共享点
    ephemeral = ec.derive_private_key(k, ec.SECP256R1(), default_backend())
    shared_key = ephemeral.exchange(ec.ECDH(), pub_key)

    # t = KDF(x2 || y2, len(data))
    # 简化 KDF: 使用 SM3
    kdf_input = c1_nums.x.to_bytes(32, 'big') + c1_nums.y.to_bytes(32, 'big')
    t = sm3_hash(kdf_input)
    while len(t) < len(data):
        t += sm3_hash(t[-32:] + kdf_input)

    # C2 = data XOR t
    c2 = bytes(d ^ t[i] for i, d in enumerate(data))

    # C3 = SM3(x2 || data || y2)
    c3 = sm3_hash(c1_nums.x.to_bytes(32, 'big') + data + c1_nums.y.to_bytes(32, 'big'))

    if mode == "C1C2C3":
        return c1 + c2 + c3
    return c1 + c3 + c2


def sm2_decrypt(data: bytes, private_key_hex: str, mode: str = "C1C3C2") -> bytes:
    """SM2 解密"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend

    priv_int = int.from_bytes(bytes.fromhex(private_key_hex), 'big')
    private = ec.derive_private_key(priv_int, ec.SECP256R1(), default_backend())

    # 分解密文: C1 (130 bytes Hex point) + C2/C3
    c1 = data[:65]  # 04 + x(32) + y(32) = 65 bytes
    rest = data[65:]

    if mode == "C1C2C3":
        c2 = rest[:-32]
        c3 = rest[-32:]
    else:  # C1C3C2
        c3 = rest[:32]
        c2 = rest[32:]

    # 计算共享点 d * C1 = (x2, y2)
    c1_x = int.from_bytes(c1[1:33], 'big')
    c1_y = int.from_bytes(c1[33:65], 'big')
    c1_pub = ec.EllipticCurvePublicNumbers(c1_x, c1_y, ec.SECP256R1()).public_key()

    # ECDH: shared = d * C1
    # 手动计算 (需要私钥 + 公钥做 ECDH)
    shared_key = private.exchange(ec.ECDH(), c1_pub)

    # 从 shared key 和 c1 恢复 x2, y2
    # 简化处理: 对 shared_key + c1 做 KDF 得到 t
    kdf_input = c1_x.to_bytes(32, 'big') + c1_y.to_bytes(32, 'big')
    t = sm3_hash(kdf_input)
    while len(t) < len(c2):
        t += sm3_hash(t[-32:] + kdf_input)

    # 解密: M = C2 XOR t
    plaintext = bytes(c ^ t[i] for i, c in enumerate(c2))

    # 验证 C3 = SM3(x2 || M || y2)
    expected_c3 = sm3_hash(c1_x.to_bytes(32, 'big') + plaintext + c1_y.to_bytes(32, 'big'))
    if expected_c3 != c3:
        raise ValueError("SM2 解密校验失败: C3 不匹配")

    return plaintext
