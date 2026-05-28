"""
加密引擎 — 10 种加密/解密方法的纯逻辑实现（无 Qt 依赖）

基于 cryptography 库实现标准算法，SM2/SM4 基于 _sm_crypto
"""
import base64
import hashlib
import hmac as hmac_mod
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric import ec

from modules.codec._sm_crypto import (
    sm4_encrypt_ecb, sm4_decrypt_ecb,
    sm4_encrypt_cbc, sm4_decrypt_cbc,
    sm2_encrypt, sm2_decrypt, sm2_generate_keypair,
)


# ============================================================
#  工具函数
# ============================================================

def _to_bytes(data: str, charset: str) -> bytes:
    return data.encode(charset, errors="replace")


def _to_str(data: bytes, charset: str) -> str:
    return data.decode(charset, errors="replace")


def _format_output(data: bytes, fmt: str) -> str:
    """将字节按指定格式编码输出"""
    if fmt == "Base64":
        return base64.b64encode(data).decode("ascii")
    return data.hex()


def _parse_input(data: str, fmt: str) -> bytes:
    """将输入字符串按指定格式解析为字节"""
    if fmt == "Base64":
        return base64.b64decode(data.encode("ascii"))
    # hex 格式，去除空白和换行
    clean = data.replace(" ", "").replace("\n", "").replace("\r", "")
    return bytes.fromhex(clean)


def _resolve_key(key: str, key_format: str, charset: str) -> bytes:
    """将密钥字符串转为字节"""
    if key_format == "Hex":
        return bytes.fromhex(key.replace(" ", ""))
    return _to_bytes(key, charset)


# ---- Padding ----

def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len > len(data) or pad_len == 0:
        raise ValueError("PKCS7 填充数据错误")
    return data[:-pad_len]


def _zero_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == block_size:
        return data
    return data + b'\x00' * pad_len


def _zero_unpad(data: bytes) -> bytes:
    return data.rstrip(b'\x00')


def _iso7816_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == block_size:
        return data
    return data + b'\x80' + b'\x00' * (pad_len - 1)


def _iso7816_unpad(data: bytes) -> bytes:
    for i in range(len(data) - 1, -1, -1):
        if data[i] == 0x80:
            return data[:i]
    return data


def _x923_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == block_size:
        return data
    return data + b'\x00' * (pad_len - 1) + bytes([pad_len])


def _x923_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len > len(data):
        raise ValueError("X923 填充数据错误")
    return data[:-pad_len]


_PADDERS = {
    "PKCS7": (_pkcs7_pad, _pkcs7_unpad),
    "ZeroPadding": (_zero_pad, _zero_unpad),
    "ISO7816": (_iso7816_pad, _iso7816_unpad),
    "X923": (_x923_pad, _x923_unpad),
}


# ---- 通用对称加密/解密 ----

def _symmetric_crypt(
    data: bytes,
    key: bytes,
    iv: Optional[bytes],
    mode_name: str,
    algorithm_class,
    block_size: int,
    padding_name: str,
    encrypt: bool,
) -> bytes:
    """通用对称加解密（支持 CBC/ECB/CFB/OFB/CTR/GCM）"""
    # 构建 mode
    if mode_name == "ECB":
        mode = modes.ECB()
    elif mode_name == "CBC":
        if iv is None:
            raise ValueError("CBC 模式需要 IV")
        mode = modes.CBC(iv[:block_size])
    elif mode_name == "CFB":
        if iv is None:
            raise ValueError("CFB 模式需要 IV")
        mode = modes.CFB(iv[:block_size])
    elif mode_name == "OFB":
        if iv is None:
            raise ValueError("OFB 模式需要 IV")
        mode = modes.OFB(iv[:block_size])
    elif mode_name == "CTR":
        # CTR 使用 IV 作为 nonce
        nonce = iv[:block_size] if iv else b'\x00' * block_size
        mode = modes.CTR(nonce)
    elif mode_name == "GCM":
        nonce = iv[:12] if iv else b'\x00' * 12
        if encrypt:
            cipher = Cipher(algorithm_class(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(data) + encryptor.finalize()
            return ct + encryptor.tag  # 追加 16 字节 tag
        else:
            tag_bytes = data[-16:]
            ct = data[:-16]
            cipher = Cipher(algorithm_class(key), modes.GCM(nonce, tag=tag_bytes), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ct) + decryptor.finalize()
    else:
        raise ValueError(f"不支持的加密模式: {mode_name}")

    cipher = Cipher(algorithm_class(key), mode, backend=default_backend())

    if encrypt:
        pad, _ = _PADDERS.get(padding_name, (_pkcs7_pad, _pkcs7_unpad))
        data = pad(data, block_size)
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()
    else:
        decryptor = cipher.decryptor()
        result = decryptor.update(data) + decryptor.finalize()
        _, unpad = _PADDERS.get(padding_name, (_pkcs7_pad, _pkcs7_unpad))
        return unpad(result)


# ============================================================
#  AES
# ============================================================

_AES_KEY_SIZES = {16: 128, 24: 192, 32: 256}

def aes_encrypt(data: str, key: str, iv: str, mode: str, padding: str,
                key_format: str, output_format: str, charset: str) -> str:
    key_bytes = _resolve_key(key, key_format, charset)
    iv_bytes = _resolve_key(iv, key_format, charset) if iv and mode != "ECB" else None
    raw = _to_bytes(data, charset)

    if mode in ("CTR", "GCM"):
        padding = "NoPadding"

    result = _symmetric_crypt(raw, key_bytes, iv_bytes, mode, algorithms.AES, 16, padding, encrypt=True)
    return _format_output(result, output_format)


def aes_decrypt(data: str, key: str, iv: str, mode: str, padding: str,
                key_format: str, output_format: str, charset: str) -> str:
    key_bytes = _resolve_key(key, key_format, charset)
    iv_bytes = _resolve_key(iv, key_format, charset) if iv and mode != "ECB" else None
    raw = _parse_input(data, output_format)

    if mode in ("CTR", "GCM"):
        padding = "NoPadding"

    result = _symmetric_crypt(raw, key_bytes, iv_bytes, mode, algorithms.AES, 16, padding, encrypt=False)
    return _to_str(result, charset)


# ============================================================
#  DES
# ============================================================

def des_encrypt(data: str, key: str, iv: str, mode: str, padding: str,
                output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)[:8]
    # DES 使用 TripleDES 算法，单 DES 密钥重复 3 次
    key_bytes = key_bytes * 3
    iv_bytes = _to_bytes(iv, charset)[:8] if iv and mode != "ECB" else None
    raw = _to_bytes(data, charset)

    result = _symmetric_crypt(raw, key_bytes, iv_bytes, mode, algorithms.TripleDES, 8, padding, encrypt=True)
    return _format_output(result, output_format)


def des_decrypt(data: str, key: str, iv: str, mode: str, padding: str,
                output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)[:8]
    key_bytes = key_bytes * 3
    iv_bytes = _to_bytes(iv, charset)[:8] if iv and mode != "ECB" else None
    raw = _parse_input(data, output_format)

    result = _symmetric_crypt(raw, key_bytes, iv_bytes, mode, algorithms.TripleDES, 8, padding, encrypt=False)
    return _to_str(result, charset)


# ============================================================
#  3DES
# ============================================================

def triple_des_encrypt(data: str, key: str, iv: str, mode: str, padding: str,
                       output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)[:24]
    if len(key_bytes) < 24:
        key_bytes = key_bytes.ljust(24, b'\x00')
    iv_bytes = _to_bytes(iv, charset)[:8] if iv and mode != "ECB" else None
    raw = _to_bytes(data, charset)

    result = _symmetric_crypt(raw, key_bytes, iv_bytes, mode, algorithms.TripleDES, 8, padding, encrypt=True)
    return _format_output(result, output_format)


def triple_des_decrypt(data: str, key: str, iv: str, mode: str, padding: str,
                       output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)[:24]
    if len(key_bytes) < 24:
        key_bytes = key_bytes.ljust(24, b'\x00')
    iv_bytes = _to_bytes(iv, charset)[:8] if iv and mode != "ECB" else None
    raw = _parse_input(data, output_format)

    result = _symmetric_crypt(raw, key_bytes, iv_bytes, mode, algorithms.TripleDES, 8, padding, encrypt=False)
    return _to_str(result, charset)


# ============================================================
#  SM4
# ============================================================

def sm4_encrypt_func(data: str, key: str, iv: str, mode: str, padding: str,
                     output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)[:16].ljust(16, b'\x00')
    raw = _to_bytes(data, charset)

    if mode == "ECB":
        if padding == "ZeroPadding":
            raw = _zero_pad(raw, 16)
        else:
            pad, _ = _PADDERS.get(padding, (_pkcs7_pad, _pkcs7_unpad))
            raw = pad(raw, 16)
        result = sm4_encrypt_ecb(raw, key_bytes)
    else:
        iv_bytes = _to_bytes(iv, charset)[:16].ljust(16, b'\x00')
        if padding == "ZeroPadding":
            raw = _zero_pad(raw, 16)
        else:
            pad, _ = _PADDERS.get(padding, (_pkcs7_pad, _pkcs7_unpad))
            raw = pad(raw, 16)
        result = sm4_encrypt_cbc(raw, key_bytes, iv_bytes)

    return _format_output(result, output_format)


def sm4_decrypt_func(data: str, key: str, iv: str, mode: str, padding: str,
                     output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)[:16].ljust(16, b'\x00')
    raw = _parse_input(data, output_format)

    if mode == "ECB":
        result = sm4_decrypt_ecb(raw, key_bytes)
    else:
        iv_bytes = _to_bytes(iv, charset)[:16].ljust(16, b'\x00')
        result = sm4_decrypt_cbc(raw, key_bytes, iv_bytes)

    # SM4 的 sm4_decrypt_* 内部已做 unpadding (PKCS7)
    try:
        return _to_str(result, charset)
    except (UnicodeDecodeError, UnicodeEncodeError):
        return result.hex()


# ============================================================
#  RSA
# ============================================================

def rsa_generate_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """生成 RSA 密钥对，返回 (private_pem, public_pem)"""
    private = rsa.generate_private_key(65537, key_size, default_backend())
    public = private.public_key()

    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")

    public_pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return private_pem, public_pem


def _load_rsa_public(pem: str):
    if "-----BEGIN PUBLIC KEY-----" in pem:
        return serialization.load_pem_public_key(pem.encode("ascii"), default_backend())
    # 尝试作为 raw base64
    try:
        raw = base64.b64decode(pem)
        return serialization.load_der_public_key(raw, default_backend())
    except Exception:
        pass
    raise ValueError("无法解析 RSA 公钥")


def _load_rsa_private(pem: str):
    if "-----BEGIN" in pem:
        return serialization.load_pem_private_key(pem.encode("ascii"), None, default_backend())
    try:
        raw = base64.b64decode(pem)
        return serialization.load_der_private_key(raw, None, default_backend())
    except Exception:
        pass
    raise ValueError("无法解析 RSA 私钥")


def rsa_encrypt(data: str, public_key: str, padding: str, output_format: str, charset: str) -> str:
    pub = _load_rsa_public(public_key)
    raw = _to_bytes(data, charset)

    pad = rsa_padding.PKCS1v15() if padding == "PKCS1v15" else rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashlib.sha256()),
        algorithm=hashlib.sha256(),
        label=None,
    )

    result = pub.encrypt(raw, pad)
    return _format_output(result, output_format)


def rsa_decrypt(data: str, private_key: str, padding: str, output_format: str, charset: str) -> str:
    priv = _load_rsa_private(private_key)
    raw = _parse_input(data, output_format)

    pad = rsa_padding.PKCS1v15() if padding == "PKCS1v15" else rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashlib.sha256()),
        algorithm=hashlib.sha256(),
        label=None,
    )

    result = priv.decrypt(raw, pad)
    return _to_str(result, charset)


# ============================================================
#  SM2
# ============================================================

def sm2_encrypt_func(data: str, public_key: str, cipher_mode: str, output_format: str, charset: str) -> str:
    raw = _to_bytes(data, charset)
    result = sm2_encrypt(raw, public_key, cipher_mode)
    return _format_output(result, "Hex")


def sm2_decrypt_func(data: str, private_key: str, cipher_mode: str, output_format: str, charset: str) -> str:
    raw = bytes.fromhex(data.replace(" ", ""))
    result = sm2_decrypt(raw, private_key, cipher_mode)
    return _to_str(result, charset)


def sm2_generate_keypair_func() -> Tuple[str, str]:
    return sm2_generate_keypair()


# ============================================================
#  XOR 加密
# ============================================================

def xor_crypto(data: str, key: str, output_format: str, charset: str) -> str:
    """XOR 加密（与 XOR 编解码对称）"""
    return _xor_crypt(data, key, output_format, charset)


def _xor_crypt(data: str, key: str, output_format: str, charset: str) -> str:
    if not key:
        raise ValueError("XOR 密钥不能为空")
    key_bytes = _to_bytes(key, charset)
    if len(key_bytes) == 0:
        raise ValueError("XOR 密钥不能为空")
    raw = _to_bytes(data, charset)
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    return _format_output(result, output_format)


def xor_crypto_decrypt(data: str, key: str, output_format: str, charset: str) -> str:
    """XOR 解密"""
    if not key:
        raise ValueError("XOR 密钥不能为空")
    key_bytes = _to_bytes(key, charset)
    raw = _parse_input(data, output_format)
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    try:
        return _to_str(result, charset)
    except (UnicodeDecodeError, UnicodeEncodeError):
        return result.hex()


# ============================================================
#  RC4
# ============================================================

def _rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 流密码"""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = 0
    j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        result.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(result)


def rc4_encrypt(data: str, key: str, output_format: str, charset: str) -> str:
    raw = _to_bytes(data, charset)
    key_bytes = _to_bytes(key, charset)
    result = _rc4_crypt(raw, key_bytes)
    return _format_output(result, output_format)


def rc4_decrypt(data: str, key: str, output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)
    raw = _parse_input(data, output_format)
    result = _rc4_crypt(raw, key_bytes)
    try:
        return _to_str(result, charset)
    except (UnicodeDecodeError, UnicodeEncodeError):
        return result.hex()


# ============================================================
#  Rabbit (RFC 4503)
# ============================================================

def _rabbit_key_setup(key: bytes):
    """Rabbit 密钥编排"""
    k = list(key[:16].ljust(16, b'\x00'))
    x = []
    c = []
    for j in range(8):
        ka = k[(j + 1) % 8]
        kb = k[(j + 2) % 8]
        kc = k[(j + 5) % 8]
        kd = k[(j + 4) % 8]
        ke = k[(j + 3) % 8]
        x.append(k[j] | (ka << 8) | (kb << 16) | (kc << 24))
        c.append(kd | (ke << 8) | (kd << 16) | (ke << 24))
    return x, c


def _rabbit_rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _rabbit_counter(c, carry):
    for j in range(8):
        temp = (c[j] + (0x4D34D34D if j == 0 else 0xD34D34D3) + carry) & 0xFFFFFFFF
        carry = 1 if (temp < c[j] and j > 0) else 0
        c[j] = temp


def _rabbit_next_state(x, c):
    g = []
    for j in range(8):
        sq = (x[j] + c[j]) & 0xFFFFFFFF
        sq2 = (sq * sq) & 0xFFFFFFFFFFFFFFFF
        g.append(((sq2 >> 32) ^ (sq2 & 0xFFFFFFFF)) & 0xFFFFFFFF)
    new_x = []
    for j in range(8):
        a = g[0] + _rabbit_rotl(g[7], 16) + _rabbit_rotl(g[6], 16)
        b = g[1] + _rabbit_rotl(a, 8) + g[7]
        c2 = g[2] + _rabbit_rotl(b, 16) + _rabbit_rotl(a, 16)
        d = g[3] + _rabbit_rotl(c2, 8) + b
        e = g[4] + _rabbit_rotl(d, 16) + _rabbit_rotl(c2, 16)
        f = g[5] + _rabbit_rotl(e, 8) + d
        g_val = g[6] + _rabbit_rotl(f, 16) + _rabbit_rotl(e, 16)
        h = g[7] + _rabbit_rotl(g_val, 8) + f
        new_x.append((a + x[j]) & 0xFFFFFFFF)
    return new_x


def _rabbit_extract(x):
    s = []
    for j in range(4):
        high = ((x[(j + 1) % 8] << 16) | (x[(j + 2) % 8] & 0xFFFF)) & 0xFFFFFFFF
        low = ((x[(j + 5) % 8] << 16) | (x[(j + 4) % 8] & 0xFFFF)) & 0xFFFFFFFF
        s.append((high ^ low) & 0xFFFFFFFF)
    return s


def _rabbit_keystream(x, c, length):
    s = _rabbit_extract(x)
    result = []
    for i in range(length):
        if i > 0 and i % 16 == 0:
            x = _rabbit_next_state(x, c)
            _rabbit_counter(c, 0)
            s = _rabbit_extract(x)
        idx = (i // 4) % 4
        shift = (i % 4) * 8
        result.append((s[idx] >> shift) & 0xFF)
    return bytes(result)


def _rabbit_iv_setup(iv: bytes, x, c):
    """Rabbit IV Setup"""
    iv = iv[:8].ljust(8, b'\x00')
    iv0 = (iv[0] | (iv[1] << 8) | (iv[2] << 16) | (iv[3] << 24)) & 0xFFFFFFFF
    iv1 = (iv[4] | (iv[5] << 8) | (iv[6] << 16) | (iv[7] << 24)) & 0xFFFFFFFF
    c[0] ^= iv0
    c[1] ^= (iv1 >> 16) | ((iv0 & 0xFFFF) << 16)
    c[2] ^= iv1 & 0xFFFF
    c[3] ^= iv0 & 0xFFFF
    c[4] ^= iv0
    c[5] ^= (iv1 >> 16) | ((iv0 & 0xFFFF) << 16)
    c[6] ^= iv1 & 0xFFFF
    c[7] ^= iv0 & 0xFFFF
    x = _rabbit_next_state(x, c)
    _rabbit_counter(c, 1)
    return x, c


def rabbit_encrypt(data: str, key: str, iv: str, output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)
    raw = _to_bytes(data, charset)

    x, c = _rabbit_key_setup(key_bytes)
    if iv and iv.strip():
        iv_bytes = _to_bytes(iv, charset)
        x, c = _rabbit_iv_setup(iv_bytes, x, c)

    keystream = _rabbit_keystream(x, c, len(raw))
    result = bytes(r ^ k for r, k in zip(raw, keystream))
    return _format_output(result, output_format)


def rabbit_decrypt(data: str, key: str, iv: str, output_format: str, charset: str) -> str:
    key_bytes = _to_bytes(key, charset)
    raw = _parse_input(data, output_format)

    x, c = _rabbit_key_setup(key_bytes)
    if iv and iv.strip():
        iv_bytes = _to_bytes(iv, charset)
        x, c = _rabbit_iv_setup(iv_bytes, x, c)

    keystream = _rabbit_keystream(x, c, len(raw))
    result = bytes(r ^ k for r, k in zip(raw, keystream))
    try:
        return _to_str(result, charset)
    except (UnicodeDecodeError, UnicodeEncodeError):
        return result.hex()


# ============================================================
#  HMAC
# ============================================================

_HMAC_HASHES = {
    "MD5": "md5",
    "SHA1": "sha1",
    "SHA256": "sha256",
    "SHA512": "sha512",
}

def hmac_encrypt(data: str, key: str, hash_algo: str, charset: str) -> str:
    raw = _to_bytes(data, charset)
    key_bytes = _to_bytes(key, charset)

    algo = _HMAC_HASHES.get(hash_algo, "sha256")
    if algo == "SM3":
        digest = hmac_mod.new(key_bytes, raw, hashlib.sha256).digest()
        return digest.hex()
    result = hmac_mod.new(key_bytes, raw, algo).hexdigest()
    return result


def hmac_decrypt(data: str, key: str, hash_algo: str, charset: str) -> str:
    """HMAC 验证：与输入比较，返回验证结果"""
    raw = _to_bytes(data, charset)
    key_bytes = _to_bytes(key, charset)
    algo = _HMAC_HASHES.get(hash_algo, "sha256")
    result = hmac_mod.new(key_bytes, raw, algo).hexdigest()
    return result
