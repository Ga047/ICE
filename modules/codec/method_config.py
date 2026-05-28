"""
编码转换模块 — 32 种方法的声明式配置

每项配置结构:
    id: 唯一标识
    name: 显示名称
    params: 参数列表，每项 {type, name, label, placeholder, default, options?, on_change?}
    hints: {input, output} 输入输出框的 placeholder
    button_type: "encode_decode" | "encrypt_decrypt" | "hash" | "convert"
    category: "codec" | "crypto" | "hash"
"""

# ---- 字符集选项 ----
CHARSET_OPTIONS = [
    "UTF-8", "GBK", "GB2312", "BIG5",
    "UTF-16", "UTF-16LE", "UTF-16BE", "Latin-1", "ASCII",
]

METHODS = {
    "编码转化": [
        {
            "id": "base64", "name": "Base64", "params": [],
            "hints": {"input": "输入待编码/解码的文本或 Base64 字符串", "output": "编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "base16", "name": "Base16 (Hex)", "params": [],
            "hints": {"input": "输入文本或十六进制字符串", "output": "十六进制编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "base32", "name": "Base32", "params": [],
            "hints": {"input": "输入文本或 Base32 字符串", "output": "Base32 编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "base58", "name": "Base58", "params": [],
            "hints": {"input": "输入文本或 Base58 字符串（不含 0/O/I/l）", "output": "Base58 编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "base62", "name": "Base62", "params": [],
            "hints": {"input": "输入文本或 Base62 字符串（0-9a-zA-Z）", "output": "Base62 编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "base85", "name": "Base85", "params": [
                {"type": "combo", "name": "variant", "label": "变体",
                 "options": ["ASCII85", "Z85"], "default": "ASCII85"},
            ],
            "hints": {"input": "输入文本或 Base85 字符串", "output": "Base85 编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "base91", "name": "Base91", "params": [],
            "hints": {"input": "输入文本或 Base91 字符串", "output": "Base91 编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "base92", "name": "Base92", "params": [],
            "hints": {"input": "输入文本或 Base92 字符串", "output": "Base92 编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "ascii_codec", "name": "ASCII", "params": [
                {"type": "combo", "name": "separator", "label": "分隔符",
                 "options": ["空格", "逗号", "无"], "default": "空格"},
            ],
            "hints": {"input": "输入文本或 ASCII 十进制数值（如 72 101 108）", "output": "ASCII 数值 / 文本"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "url", "name": "URL", "params": [],
            "hints": {"input": "输入文本或 URL 编码字符串（%XX）", "output": "URL 编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "brainfuck", "name": "Brainfuck", "params": [],
            "hints": {"input": "输入文本或 Brainfuck 代码（+-><.,[]）", "output": "Brainfuck 代码 / 文本"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "xor_codec", "name": "XOR", "params": [
                {"type": "input", "name": "key", "label": "密钥",
                 "placeholder": "单字节数字 0-255 或任意字符串", "default": ""},
            ],
            "hints": {"input": "输入文本（与密钥进行异或运算）", "output": "XOR 运算结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "unicode", "name": "Unicode", "params": [
                {"type": "combo", "name": "format", "label": "转义格式",
                 "options": ["\\uXXXX", "&#XXXX;", "U+XXXX", "%uXXXX"], "default": "\\uXXXX"},
            ],
            "hints": {"input": "输入文本或 Unicode 转义序列", "output": "Unicode 转义 / 文本"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "html", "name": "HTML", "params": [],
            "hints": {"input": "输入文本或 HTML 实体编码（&amp;lt; &amp;gt; 等）", "output": "HTML 实体编码/解码结果"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "morse", "name": "摩斯电码", "params": [
                {"type": "combo", "name": "delimiter", "label": "分隔符",
                 "options": ["空格", "斜杠", "竖线"], "default": "空格"},
            ],
            "hints": {"input": "输入文本或摩斯电码", "output": "摩斯电码 / 文本"},
            "button_type": "encode_decode", "category": "codec",
        },
        {
            "id": "radix_convert", "name": "进制转换", "params": [
                {"type": "spin", "name": "source_base", "label": "源进制", "min": 2, "max": 62, "default": 10},
                {"type": "spin", "name": "target_base", "label": "目标进制", "min": 2, "max": 62, "default": 16},
            ],
            "hints": {"input": "输入源进制的数值", "output": "目标进制的数值"},
            "button_type": "convert", "category": "codec",
        },
    ],
    "加密解密": [
        {
            "id": "aes", "name": "AES", "params": [
                {"type": "input", "name": "key", "label": "密钥 (Key)",
                 "placeholder": "16/24/32 字节字符串，或对应长度的 Hex", "default": ""},
                {"type": "input", "name": "iv", "label": "IV",
                 "placeholder": "16 字节字符串或 32 位 Hex (GCM: 12 字节 Nonce)", "default": ""},
                {"type": "combo", "name": "mode", "label": "加密模式",
                 "options": ["CBC", "ECB", "CFB", "OFB", "CTR", "GCM"], "default": "CBC",
                 "on_change": {
                     "ECB": {"hide": ["iv"]},
                     "GCM": {"label": {"iv": "Nonce"}, "placeholder": {"iv": "12 字节 Nonce"}, "hide": ["padding"]},
                     "CTR": {"label": {"iv": "Nonce"}, "placeholder": {"iv": "16 字节 Nonce"}, "hide": ["padding"]},
                     "OFB": {"label": {"iv": "IV"}, "placeholder": {"iv": "16 字节字符串或 32 位 Hex"}},
                 }},
                {"type": "combo", "name": "padding", "label": "填充方式",
                 "options": ["PKCS7", "ZeroPadding", "ISO7816", "X923"], "default": "PKCS7"},
                {"type": "combo", "name": "key_format", "label": "密钥格式",
                 "options": ["Text", "Hex"], "default": "Text"},
                {"type": "combo", "name": "output_format", "label": "输出格式",
                 "options": ["Hex", "Base64"], "default": "Hex"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文", "output": "加密/解密结果"},
            "button_type": "encrypt_decrypt", "category": "crypto",
        },
        {
            "id": "des", "name": "DES", "params": [
                {"type": "input", "name": "key", "label": "密钥 (Key)",
                 "placeholder": "8 字节字符串或 16 位 Hex（有效长度 56 位）", "default": ""},
                {"type": "input", "name": "iv", "label": "IV",
                 "placeholder": "8 字节字符串或 16 位 Hex", "default": ""},
                {"type": "combo", "name": "mode", "label": "加密模式",
                 "options": ["CBC", "ECB", "CFB", "OFB"], "default": "CBC",
                 "on_change": {"ECB": {"hide": ["iv"]}}},
                {"type": "combo", "name": "padding", "label": "填充方式",
                 "options": ["PKCS7", "ZeroPadding", "ISO7816"], "default": "PKCS7"},
                {"type": "combo", "name": "output_format", "label": "输出格式",
                 "options": ["Hex", "Base64"], "default": "Hex"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文", "output": "加密/解密结果"},
            "button_type": "encrypt_decrypt", "category": "crypto",
        },
        {
            "id": "triple_des", "name": "3DES", "params": [
                {"type": "input", "name": "key", "label": "密钥 (Key)",
                 "placeholder": "24 字节字符串或 48 位 Hex（也支持 16 字节 2-key 模式）", "default": ""},
                {"type": "input", "name": "iv", "label": "IV",
                 "placeholder": "8 字节字符串或 16 位 Hex", "default": ""},
                {"type": "combo", "name": "mode", "label": "加密模式",
                 "options": ["CBC", "ECB", "CFB", "OFB"], "default": "CBC",
                 "on_change": {"ECB": {"hide": ["iv"]}}},
                {"type": "combo", "name": "padding", "label": "填充方式",
                 "options": ["PKCS7", "ZeroPadding", "ISO7816"], "default": "PKCS7"},
                {"type": "combo", "name": "output_format", "label": "输出格式",
                 "options": ["Hex", "Base64"], "default": "Hex"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文", "output": "加密/解密结果"},
            "button_type": "encrypt_decrypt", "category": "crypto",
        },
        {
            "id": "sm4", "name": "SM4", "params": [
                {"type": "input", "name": "key", "label": "密钥 (Key)",
                 "placeholder": "16 字节字符串或 32 位 Hex（128 位）", "default": ""},
                {"type": "input", "name": "iv", "label": "IV",
                 "placeholder": "16 字节字符串或 32 位 Hex", "default": ""},
                {"type": "combo", "name": "mode", "label": "加密模式",
                 "options": ["CBC", "ECB"], "default": "CBC",
                 "on_change": {"ECB": {"hide": ["iv"]}}},
                {"type": "combo", "name": "padding", "label": "填充方式",
                 "options": ["PKCS7", "ZeroPadding"], "default": "PKCS7"},
                {"type": "combo", "name": "output_format", "label": "输出格式",
                 "options": ["Hex", "Base64"], "default": "Hex"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文", "output": "加密/解密结果"},
            "button_type": "encrypt_decrypt", "category": "crypto",
        },
        {
            "id": "rsa", "name": "RSA", "params": [
                {"type": "input", "name": "public_key", "label": "公钥",
                 "placeholder": "PEM 格式公钥（-----BEGIN PUBLIC KEY-----）", "default": ""},
                {"type": "input", "name": "private_key", "label": "私钥",
                 "placeholder": "PEM 格式私钥（-----BEGIN PRIVATE KEY-----）", "default": ""},
                {"type": "combo", "name": "padding", "label": "填充方式",
                 "options": ["PKCS1v15", "OAEP"], "default": "PKCS1v15"},
                {"type": "combo", "name": "key_size", "label": "密钥长度（生成时）",
                 "options": ["1024", "2048", "4096"], "default": "2048"},
                {"type": "combo", "name": "output_format", "label": "输出格式",
                 "options": ["Hex", "Base64"], "default": "Hex"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文", "output": "加密/解密结果"},
            "button_type": "encrypt_decrypt", "category": "crypto",
            "has_keygen": True,
        },
        {
            "id": "sm2", "name": "SM2", "params": [
                {"type": "input", "name": "public_key", "label": "公钥",
                 "placeholder": "Hex 格式公钥（130 位，04+x+y）", "default": ""},
                {"type": "input", "name": "private_key", "label": "私钥",
                 "placeholder": "Hex 格式私钥（64 位）", "default": ""},
                {"type": "combo", "name": "cipher_mode", "label": "密文模式",
                 "options": ["C1C3C2", "C1C2C3"], "default": "C1C3C2"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文（Hex）", "output": "加密/解密结果（Hex）"},
            "button_type": "encrypt_decrypt", "category": "crypto",
            "has_keygen": True,
        },
        {
            "id": "xor_crypto", "name": "XOR", "params": [
                {"type": "input", "name": "key", "label": "密钥",
                 "placeholder": "单字节数字 0-255 或任意字符串", "default": ""},
                {"type": "combo", "name": "output_format", "label": "输出格式",
                 "options": ["Hex", "Base64"], "default": "Hex"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文（Hex）", "output": "加密/解密结果"},
            "button_type": "encrypt_decrypt", "category": "crypto",
        },
        {
            "id": "rc4", "name": "RC4", "params": [
                {"type": "input", "name": "key", "label": "密钥",
                 "placeholder": "任意长度密钥（建议 8-256 位）", "default": ""},
                {"type": "combo", "name": "output_format", "label": "输出格式",
                 "options": ["Hex", "Base64"], "default": "Hex"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文（Hex）", "output": "加密/解密结果"},
            "button_type": "encrypt_decrypt", "category": "crypto",
        },
        {
            "id": "rabbit", "name": "Rabbit", "params": [
                {"type": "input", "name": "key", "label": "密钥 (Key)",
                 "placeholder": "16 字节字符串或 32 位 Hex（128 位）", "default": ""},
                {"type": "input", "name": "iv", "label": "IV",
                 "placeholder": "8 字节字符串或 16 位 Hex（64 位，可选）", "default": ""},
                {"type": "combo", "name": "output_format", "label": "输出格式",
                 "options": ["Hex", "Base64"], "default": "Hex"},
            ],
            "hints": {"input": "输入待加密/解密的文本或密文", "output": "加密/解密结果"},
            "button_type": "encrypt_decrypt", "category": "crypto",
        },
        {
            "id": "hmac", "name": "HMAC", "params": [
                {"type": "input", "name": "key", "label": "密钥",
                 "placeholder": "任意长度密钥", "default": ""},
                {"type": "combo", "name": "hash_algo", "label": "哈希算法",
                 "options": ["MD5", "SHA1", "SHA256", "SHA512", "SM3"], "default": "SHA256"},
            ],
            "hints": {"input": "输入要计算 HMAC 的文本", "output": "HMAC 计算结果（Hex）"},
            "button_type": "encrypt_decrypt", "category": "crypto",
        },
    ],
    "哈希计算": [
        {
            "id": "md5", "name": "MD5", "params": [],
            "hints": {"input": "输入任意文本，输出 128 位（32 位 Hex）哈希值", "output": "MD5 哈希值（32 位 Hex）"},
            "button_type": "hash", "category": "hash",
        },
        {
            "id": "sm3", "name": "SM3", "params": [],
            "hints": {"input": "国密哈希算法，输出 256 位（64 位 Hex）哈希值", "output": "SM3 哈希值（64 位 Hex）"},
            "button_type": "hash", "category": "hash",
        },
        {
            "id": "sha1", "name": "SHA1", "params": [],
            "hints": {"input": "输出 160 位（40 位 Hex）哈希值", "output": "SHA1 哈希值（40 位 Hex）"},
            "button_type": "hash", "category": "hash",
        },
        {
            "id": "sha2", "name": "SHA2", "params": [
                {"type": "combo", "name": "variant", "label": "变体",
                 "options": ["SHA-224", "SHA-256", "SHA-384", "SHA-512"], "default": "SHA-256"},
            ],
            "hints": {"input": "输入任意文本", "output": "SHA2 哈希值"},
            "button_type": "hash", "category": "hash",
        },
        {
            "id": "sha3", "name": "SHA3", "params": [
                {"type": "combo", "name": "variant", "label": "变体",
                 "options": ["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"], "default": "SHA3-256"},
            ],
            "hints": {"input": "输入任意文本", "output": "SHA3 哈希值"},
            "button_type": "hash", "category": "hash",
        },
        {
            "id": "ntlm", "name": "NTLM", "params": [],
            "hints": {"input": "输入密码文本，输出 128 位（32 位 Hex）NTLM 哈希", "output": "NTLM 哈希值（32 位 Hex）"},
            "button_type": "hash", "category": "hash",
        },
    ],
}
