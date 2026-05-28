"""
编码引擎 — 16 种编解码方法的纯逻辑实现（无 Qt 依赖）

所有函数签名统一为:
    xxx_encode(data: str, charset: str, **kwargs) -> str
    xxx_decode(data: str, charset: str, **kwargs) -> str
"""
import base64
import binascii
import html as html_mod
import urllib.parse
import string
from typing import List


# ============================================================
#  工具函数
# ============================================================

def _to_bytes(data: str, charset: str) -> bytes:
    """将字符串按指定字符集编码为字节"""
    return data.encode(charset, errors="replace")


def _to_str(data: bytes, charset: str) -> str:
    """将字节按指定字符集解码为字符串"""
    return data.decode(charset, errors="replace")


# ============================================================
#  Base64
# ============================================================

def base64_encode(data: str, charset: str) -> str:
    return base64.b64encode(_to_bytes(data, charset)).decode("ascii")


def base64_decode(data: str, charset: str) -> str:
    raw = base64.b64decode(data.encode("ascii"))
    return _to_str(raw, charset)


# ============================================================
#  Base16 (Hex)
# ============================================================

def base16_encode(data: str, charset: str) -> str:
    return base64.b16encode(_to_bytes(data, charset)).decode("ascii")


def base16_decode(data: str, charset: str) -> str:
    raw = base64.b16decode(data.encode("ascii"))
    return _to_str(raw, charset)


# ============================================================
#  Base32
# ============================================================

def base32_encode(data: str, charset: str) -> str:
    return base64.b32encode(_to_bytes(data, charset)).decode("ascii")


def base32_decode(data: str, charset: str) -> str:
    raw = base64.b32decode(data.encode("ascii"))
    return _to_str(raw, charset)


# ============================================================
#  Base58 (Bitcoin alphabet)
# ============================================================

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: str, charset: str) -> str:
    raw = _to_bytes(data, charset)
    num = 0
    for byte in raw:
        num = num * 256 + byte
    if num == 0:
        return _BASE58_ALPHABET[0]
    result = []
    while num > 0:
        num, rem = divmod(num, 58)
        result.append(_BASE58_ALPHABET[rem])
    # 处理前导零
    for byte in raw:
        if byte == 0:
            result.append(_BASE58_ALPHABET[0])
        else:
            break
    return "".join(reversed(result))


def base58_decode(data: str, charset: str) -> str:
    num = 0
    for char in data:
        val = _BASE58_ALPHABET.find(char)
        if val == -1:
            raise ValueError(f"非法 Base58 字符: {char}")
        num = num * 58 + val
    result = []
    while num > 0:
        num, rem = divmod(num, 256)
        result.append(rem)
    # 处理前导零（Base58 中的 '1'）
    for char in data:
        if char == _BASE58_ALPHABET[0]:
            result.append(0)
        else:
            break
    return _to_str(bytes(reversed(result)), charset)


# ============================================================
#  Base62 (0-9A-Za-z)
# ============================================================

_BASE62_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase


def base62_encode(data: str, charset: str) -> str:
    raw = _to_bytes(data, charset)
    num = 0
    for byte in raw:
        num = num * 256 + byte
    if num == 0:
        return _BASE62_ALPHABET[0]
    result = []
    while num > 0:
        num, rem = divmod(num, 62)
        result.append(_BASE62_ALPHABET[rem])
    for byte in raw:
        if byte == 0:
            result.append(_BASE62_ALPHABET[0])
        else:
            break
    return "".join(reversed(result))


def base62_decode(data: str, charset: str) -> str:
    num = 0
    for char in data:
        val = _BASE62_ALPHABET.find(char)
        if val == -1:
            raise ValueError(f"非法 Base62 字符: {char}")
        num = num * 62 + val
    result = []
    while num > 0:
        num, rem = divmod(num, 256)
        result.append(rem)
    for char in data:
        if char == _BASE62_ALPHABET[0]:
            result.append(0)
        else:
            break
    return _to_str(bytes(reversed(result)), charset)


# ============================================================
#  Base85 (ASCII85 / Z85)
# ============================================================

def _ascii85_encode(raw: bytes) -> str:
    """Adobe ASCII85 编码"""
    result = []
    i = 0
    while i < len(raw):
        chunk = raw[i:i + 4]
        i += 4
        pad = 4 - len(chunk)
        if pad:
            chunk = chunk + b"\x00" * pad
        val = (chunk[0] << 24) + (chunk[1] << 16) + (chunk[2] << 8) + chunk[3]
        if val == 0 and pad == 0:
            result.append("z")
            continue
        encoded = []
        for j in range(5):
            encoded.append(chr(33 + (val % 85)))
            val //= 85
        result.extend(reversed(encoded[:5 - pad] if pad else encoded))
    return "".join(result)


def _ascii85_decode(data: str) -> bytes:
    """Adobe ASCII85 解码"""
    data = data.replace("z", "!!!!!")
    data = "".join(c for c in data if 33 <= ord(c) <= 117)
    result = []
    i = 0
    while i < len(data):
        chunk = data[i:i + 5]
        i += 5
        pad = 5 - len(chunk)
        if pad:
            chunk = chunk + "u" * pad
        val = 0
        for c in chunk:
            val = val * 85 + (ord(c) - 33)
        decoded = [(val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]
        result.extend(decoded[:4 - pad] if pad else decoded)
    return bytes(result)


_Z85_ALPHABET = (
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ".-:+=^!/*?&<>()[]{}@%$#"
)


def _z85_encode(raw: bytes) -> str:
    """ZeroMQ Z85 编码"""
    result = []
    i = 0
    while i < len(raw):
        chunk = raw[i:i + 4]
        i += 4
        pad = 4 - len(chunk)
        if pad:
            chunk = chunk + b"\x00" * pad
        val = (chunk[0] << 24) + (chunk[1] << 16) + (chunk[2] << 8) + chunk[3]
        encoded = []
        for _ in range(5):
            encoded.append(_Z85_ALPHABET[val % 85])
            val //= 85
        result.extend(reversed(encoded[:5 - pad] if pad else encoded))
    return "".join(result)


def _z85_decode(data: str) -> bytes:
    """ZeroMQ Z85 解码"""
    result = []
    i = 0
    while i < len(data):
        chunk = data[i:i + 5]
        i += 5
        pad = 5 - len(chunk)
        if pad:
            chunk = chunk + "0" * pad
        val = 0
        for c in chunk:
            idx = _Z85_ALPHABET.find(c)
            if idx == -1:
                raise ValueError(f"非法 Z85 字符: {c}")
            val = val * 85 + idx
        decoded = [(val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]
        result.extend(decoded[:4 - pad] if pad else decoded)
    return bytes(result)


def base85_encode(data: str, charset: str, variant: str = "ASCII85") -> str:
    raw = _to_bytes(data, charset)
    if variant == "Z85":
        return _z85_encode(raw)
    return _ascii85_encode(raw)


def base85_decode(data: str, charset: str, variant: str = "ASCII85") -> str:
    if variant == "Z85":
        raw = _z85_decode(data)
    else:
        raw = _ascii85_decode(data)
    return _to_str(raw, charset)


# ============================================================
#  Base91
# ============================================================

_BASE91_ALPHABET = (
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    '0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
)
_BASE91_DECODE_TABLE = {c: i for i, c in enumerate(_BASE91_ALPHABET)}


def base91_encode(data: str, charset: str) -> str:
    raw = _to_bytes(data, charset)
    result = []
    bit_buf = 0
    bit_len = 0
    for byte in raw:
        bit_buf |= byte << bit_len
        bit_len += 8
        if bit_len > 13:
            val = bit_buf & 8191  # 2^13 - 1
            if val > 88:
                bit_buf >>= 13
                bit_len -= 13
            else:
                val = bit_buf & 16383  # 2^14 - 1
                bit_buf >>= 14
                bit_len -= 14
            quotient, remainder = divmod(val, 91)
            result.append(_BASE91_ALPHABET[remainder])
            result.append(_BASE91_ALPHABET[quotient])
    if bit_len:
        quotient, remainder = divmod(bit_buf, 91)
        result.append(_BASE91_ALPHABET[remainder])
        if bit_len > 7 or bit_buf > 90:
            result.append(_BASE91_ALPHABET[quotient])
    return "".join(result)


def base91_decode(data: str, charset: str) -> str:
    raw = []
    bit_buf = 0
    bit_len = 0
    i = 0
    while i < len(data):
        val = _BASE91_DECODE_TABLE.get(data[i], -1)
        if val == -1:
            i += 1
            continue
        i += 1
        if bit_len > 13:
            val2 = _BASE91_DECODE_TABLE.get(data[i], -1) if i < len(data) else -1
            if val2 != -1:
                i += 1
                val += val2 * 91
                bit_buf |= val << bit_len
                bit_len += 13 if (val & 8191) > 88 else 14
            else:
                val2 = 0
                bit_buf |= val << bit_len
                bit_len += 13 if (val & 8191) > 88 else 14
        else:
            val2 = _BASE91_DECODE_TABLE.get(data[i], -1) if i < len(data) else -1
            if val2 != -1:
                i += 1
                val += val2 * 91
                bit_buf |= val << bit_len
                bit_len += 13 if (val & 8191) > 88 else 14
            else:
                bit_buf |= val << bit_len
                bit_len += 13 if (val & 8191) > 88 else 14
        while bit_len >= 8:
            raw.append(bit_buf & 0xFF)
            bit_buf >>= 8
            bit_len -= 8
    if bit_len and (bit_buf & 0xFF) != 0:
        raw.append(bit_buf & 0xFF)
    result = bytes(raw)
    # 去除尾部的空字节（解码端可能多产出一个）
    result = result.rstrip(b'\x00') or result[:1]
    return _to_str(result, charset)


# ============================================================
#  Base92
# ============================================================

_BASE92_ALPHABET = (
    "!#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "[\\]^_abcdefghijklmnopqrstuvwxyz{|}~"
)


def base92_encode(data: str, charset: str) -> str:
    raw = _to_bytes(data, charset)
    result = []
    bit_buf = 0
    bit_len = 0
    for byte in raw:
        bit_buf |= byte << bit_len
        bit_len += 8
        if bit_len > 13:
            val = bit_buf & 8191
            if val <= 88:
                bit_buf >>= 13
                bit_len -= 13
            else:
                val = bit_buf & 16383
                bit_buf >>= 14
                bit_len -= 14
            result.append(_BASE92_ALPHABET[val % 92])
            quotient = val // 92
            if quotient:
                result.append(_BASE92_ALPHABET[quotient])
    if bit_len:
        val = bit_buf & ((1 << bit_len) - 1)
        result.append(_BASE92_ALPHABET[val % 92])
        quotient = val // 92
        if quotient or bit_len > 7:
            result.append(_BASE92_ALPHABET[quotient])
    return "".join(result)


def base92_decode(data: str, charset: str) -> str:
    decode_table = {c: i for i, c in enumerate(_BASE92_ALPHABET)}
    result = []
    bit_buf = 0
    bit_len = 0
    i = 0
    while i < len(data):
        c = data[i]
        if c not in decode_table:
            i += 1
            continue
        val = decode_table[c] + (91 if c == '~' else 0)
        bit_buf |= val << bit_len
        bit_len += 13 if val <= 88 else 14
        while bit_len >= 8:
            result.append(bit_buf & 0xFF)
            bit_buf >>= 8
            bit_len -= 8
        i += 1
    return _to_str(bytes(result), charset)


# ============================================================
#  ASCII 编解码
# ============================================================

_ASCII_SEPARATORS = {"空格": " ", "逗号": ",", "无": ""}


def ascii_encode(data: str, charset: str, separator: str = "空格") -> str:
    sep = _ASCII_SEPARATORS.get(separator, " ")
    nums = [str(ord(c)) for c in data]
    return sep.join(nums)


def ascii_decode(data: str, charset: str, separator: str = "空格") -> str:
    sep = _ASCII_SEPARATORS.get(separator, " ")
    if sep:
        parts = data.split(sep)
    else:
        # 无分隔符时按每2-3位解析
        parts = []
        i = 0
        while i < len(data):
            if i + 3 <= len(data) and 0 <= int(data[i:i + 3]) <= 255:
                parts.append(data[i:i + 3])
                i += 3
            elif i + 2 <= len(data):
                parts.append(data[i:i + 2])
                i += 2
            else:
                i += 1
    chars = []
    for p in parts:
        p = p.strip()
        if p:
            try:
                chars.append(chr(int(p)))
            except (ValueError, OverflowError):
                chars.append("?")
    return "".join(chars)


# ============================================================
#  URL 编解码
# ============================================================

def url_encode(data: str, charset: str) -> str:
    return urllib.parse.quote(data, encoding=charset)


def url_decode(data: str, charset: str) -> str:
    return urllib.parse.unquote(data, encoding=charset)


# ============================================================
#  Brainfuck
# ============================================================

def _brainfuck_execute(code: str, input_str: str = "") -> str:
    """Brainfuck 解释器"""
    code = "".join(c for c in code if c in "+-><.,[]")
    tape = [0] * 30000
    ptr = 0
    code_ptr = 0
    input_ptr = 0
    output: List[str] = []
    loop_stack: List[int] = []

    while code_ptr < len(code):
        cmd = code[code_ptr]
        if cmd == ">":
            ptr = (ptr + 1) % len(tape)
        elif cmd == "<":
            ptr = (ptr - 1) % len(tape)
        elif cmd == "+":
            tape[ptr] = (tape[ptr] + 1) % 256
        elif cmd == "-":
            tape[ptr] = (tape[ptr] - 1) % 256
        elif cmd == ".":
            output.append(chr(tape[ptr]))
        elif cmd == ",":
            if input_ptr < len(input_str):
                tape[ptr] = ord(input_str[input_ptr])
                input_ptr += 1
            else:
                tape[ptr] = 0
        elif cmd == "[":
            if tape[ptr] == 0:
                depth = 1
                while depth:
                    code_ptr += 1
                    if code_ptr >= len(code):
                        raise ValueError("Brainfuck 语法错误: 未匹配的 [")
                    if code[code_ptr] == "[":
                        depth += 1
                    elif code[code_ptr] == "]":
                        depth -= 1
            else:
                loop_stack.append(code_ptr)
        elif cmd == "]":
            if not loop_stack:
                raise ValueError("Brainfuck 语法错误: 未匹配的 ]")
            if tape[ptr] != 0:
                code_ptr = loop_stack[-1]
            else:
                loop_stack.pop()
        code_ptr += 1
    return "".join(output)


def brainfuck_encode(data: str, charset: str) -> str:
    """将文本转换为 Brainfuck 代码"""
    result = []
    prev = 0
    for c in data:
        target = ord(c)
        diff = target - prev
        if diff > 0:
            result.append("+" * diff)
        elif diff < 0:
            result.append("-" * (-diff))
        result.append(".")
        prev = target
    return "".join(result)


def brainfuck_decode(data: str, charset: str) -> str:
    """执行 Brainfuck 代码"""
    return _brainfuck_execute(data)


# ============================================================
#  XOR 编解码（编码模块）
# ============================================================

def xor_encode(data: str, charset: str, key: str = "") -> str:
    """XOR 编码：将输入每个字节与 Key 的字节循环异或"""
    if not key:
        return data
    raw = _to_bytes(data, charset)
    key_bytes = _to_bytes(key, charset)
    if len(key_bytes) == 0:
        return data
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    # 尝试用源字符集解码，失败则返回 Hex
    try:
        return _to_str(result, charset)
    except (UnicodeDecodeError, UnicodeEncodeError):
        return result.hex()


def xor_decode(data: str, charset: str, key: str = "") -> str:
    """XOR 解码（与编码对称）"""
    if not key:
        return data
    # 尝试解析 Hex 输入
    try:
        raw = bytes.fromhex(data.replace(" ", ""))
    except ValueError:
        raw = _to_bytes(data, charset)
    key_bytes = _to_bytes(key, charset)
    if len(key_bytes) == 0:
        return data
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    try:
        return _to_str(result, charset)
    except (UnicodeDecodeError, UnicodeEncodeError):
        return result.hex()


# ============================================================
#  Unicode 编解码
# ============================================================

def unicode_encode(data: str, charset: str, format: str = "\\uXXXX") -> str:
    """将文本转换为 Unicode 转义序列"""
    result: List[str] = []
    for c in data:
        cp = ord(c)
        if format == "\\uXXXX":
            if cp <= 0xFFFF:
                result.append(f"\\u{cp:04X}")
            else:
                result.append(f"\\U{cp:08X}")
        elif format == "&#XXXX;":
            result.append(f"&#{cp};")
        elif format == "U+XXXX":
            result.append(f"U+{cp:04X}")
        elif format == "%uXXXX":
            if cp <= 0xFFFF:
                result.append(f"%u{cp:04X}")
            else:
                result.append(f"%U{cp:08X}")
        else:
            result.append(c)
    return "".join(result)


def unicode_decode(data: str, charset: str, format: str = "\\uXXXX") -> str:
    """将 Unicode 转义序列还原为文本"""
    import re
    result = data
    # 统一处理各种格式
    if "\\u" in result or "\\U" in result:
        def _replace_unicode(m):
            return chr(int(m.group(1), 16))
        result = re.sub(r'\\[uU]([0-9a-fA-F]{4,8})', _replace_unicode, result)
    if "&#" in result and ";" in result:
        def _replace_dec(m):
            return chr(int(m.group(1)))
        def _replace_hex(m):
            return chr(int(m.group(1), 16))
        result = re.sub(r'&#x([0-9a-fA-F]+);', _replace_hex, result)
        result = re.sub(r'&#(\d+);', _replace_dec, result)
    if "U+" in result:
        def _replace_uplus(m):
            return chr(int(m.group(1), 16))
        result = re.sub(r'U\+([0-9a-fA-F]{4,8})', _replace_uplus, result)
    if "%u" in result or "%U" in result:
        def _replace_pct(m):
            return chr(int(m.group(1), 16))
        result = re.sub(r'%[uU]([0-9a-fA-F]{4,8})', _replace_pct, result)
    return result


# ============================================================
#  HTML 编解码
# ============================================================

def html_encode(data: str, charset: str) -> str:
    return html_mod.escape(data)


def html_decode(data: str, charset: str) -> str:
    return html_mod.unescape(data)


# ============================================================
#  摩斯电码
# ============================================================

_MORSE_ENCODE_TABLE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.',
    '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
    '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
    '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
    '$': '...-..-', '@': '.--.-.', ' ': '/',
}
_MORSE_DECODE_TABLE = {v: k for k, v in _MORSE_ENCODE_TABLE.items()}

_DELIMITER_MAP = {"空格": " ", "斜杠": "/", "竖线": "|"}


def morse_encode(data: str, charset: str, delimiter: str = "空格") -> str:
    delim = _DELIMITER_MAP.get(delimiter, " ")
    result: List[str] = []
    for c in data.upper():
        code = _MORSE_ENCODE_TABLE.get(c, c)
        result.append(code)
    return delim.join(result)


def morse_decode(data: str, charset: str, delimiter: str = "空格") -> str:
    delim = _DELIMITER_MAP.get(delimiter, " ")
    # 统一分隔符
    for d in _DELIMITER_MAP.values():
        if d and d != delim:
            data = data.replace(d, delim)
    parts = data.split(delim) if delim else data.split()
    chars: List[str] = []
    for part in parts:
        part = part.strip()
        if part:
            chars.append(_MORSE_DECODE_TABLE.get(part, "?"))
    return "".join(chars)


# ============================================================
#  进制转换
# ============================================================

_RADIX_DIGITS = string.digits + string.ascii_uppercase + string.ascii_lowercase


def radix_convert(data: str, source_base: int, target_base: int) -> str:
    """任意进制互转（2-62）"""
    if not (2 <= source_base <= 62 and 2 <= target_base <= 62):
        raise ValueError("进制范围为 2-62")
    # 处理负数
    negative = data.startswith("-")
    if negative:
        data = data[1:]
    # 转为十进制
    decimal = 0
    for c in data:
        idx = _RADIX_DIGITS.find(c)
        if idx == -1 or idx >= source_base:
            raise ValueError(f"非法字符 '{c}' 在 {source_base} 进制中")
        decimal = decimal * source_base + idx
    if decimal == 0:
        return "0"
    # 十进制转为目标进制
    result: List[str] = []
    while decimal > 0:
        decimal, rem = divmod(decimal, target_base)
        result.append(_RADIX_DIGITS[rem])
    if negative:
        result.append("-")
    return "".join(reversed(result))
