"""
导出工具 — CSV/XLSX 公式注入防护。

Excel 会将以 =、+、-、@ 开头的单元格内容解释为公式，
攻击者可通过构造特殊 URL 在导出文件中注入恶意公式。
本模块提供 _csv_safe() 对危险前缀进行转义。
"""


def _csv_safe(value: str) -> str:
    """转义 Excel 公式注入危险前缀。

    当单元格值以 =、+、- 或 @ 开头时，Excel 会将其解释为公式。
    在前面添加单引号可强制 Excel 将其视为纯文本。
    """
    if value and value[0] in ("=", "+", "-", "@"):
        return "'" + value
    return value
