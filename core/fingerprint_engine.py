"""
指纹识别核心引擎
"""
import base64
import csv
import io
import json
import os
import re
import time
import threading
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import mmh3
import requests

from core._export_utils import _csv_safe
from core.request_handler import RequestHandler
from core.settings import AppSettings


# ============================================================================
# 数据结构
# ============================================================================

class FingerprintRule:
    """单条指纹规则"""
    __slots__ = ("cms", "method", "location", "keyword", "_compiled")

    def __init__(self, cms: str, method: str, location: str, keyword: List[str]) -> None:
        self.cms = cms
        self.method = method
        self.location = location
        self.keyword = keyword
        self._compiled: Optional[List[re.Pattern]] = None

    def compile_patterns(self) -> None:
        """预编译正则（仅 regular 方法需要）。"""
        if self.method == "regular":
            self._compiled = [re.compile(k, re.IGNORECASE | re.DOTALL) for k in self.keyword]

    def match(self, content_map: Dict[str, str]) -> bool:
        """对提取的响应内容执行匹配。"""
        content = content_map.get(self.location, "")
        if not content:
            return False

        if self.method == "keyword":
            return all(k in content for k in self.keyword)

        if self.method == "regular":
            if self._compiled is None:
                self.compile_patterns()
            return all(pat.search(content) is not None for pat in self._compiled)  # type: ignore[union-attr]

        if self.method == "faviconhash":
            favicon_hash = content_map.get("favicon_hash", "")
            return favicon_hash == self.keyword[0]

        return False


class FingerprintResult:
    """单条识别结果"""
    __slots__ = ("url", "title", "status_code", "length", "cms", "details")

    def __init__(
        self,
        url: str,
        title: str = "",
        status_code: int = 0,
        length: int = 0,
        cms: str = "",
        details: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.url = url
        self.title = title
        self.status_code = status_code
        self.length = length
        self.cms = cms
        self.details: List[Dict[str, Any]] = details or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title,
            "status_code": self.status_code,
            "length": self.length,
            "cms": self.cms,
            "details": self.details,
        }


# ============================================================================
# HTML 标题提取器
# ============================================================================

class _TitleExtractor(HTMLParser):
    """轻量 HTML 解析器，仅提取 <title> 文本。"""

    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag == "title":
            self._in_title = True

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False


def _extract_title(html: str) -> str:
    """从 HTML 中提取 <title> 标签内容。"""
    extractor = _TitleExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    return extractor.title.strip()


# ============================================================================
# 字符编码处理
# ============================================================================

_ENCODING_META_RE = re.compile(
    r'<meta[^>]+charset\s*=\s*["\']?\s*([A-Za-z0-9\-_]+)',
    re.IGNORECASE,
)


def _detect_charset(content: bytes, content_type: str) -> str:
    """多级编码检测：Content-Type → HTML meta charset → 默认 utf-8。"""
    # 1. Content-Type 头
    if content_type:
        ct_lower = content_type.lower()
        if "charset=" in ct_lower:
            _, charset = ct_lower.split("charset=", 1)
            charset = charset.strip().rstrip(";")
            if charset:
                return charset

    # 2. HTML meta 标签
    try:
        head = content[:2048].decode("ascii", errors="ignore")
        m = _ENCODING_META_RE.search(head)
        if m:
            return m.group(1)
    except Exception:
        pass

    return "utf-8"


def _to_utf8(content: bytes, content_type: str) -> str:
    """将响应体转为 UTF-8 字符串。"""
    charset = _detect_charset(content, content_type)
    try:
        return content.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return content.decode("utf-8", errors="replace")


# ============================================================================
# Favicon 哈希计算（照搬 EHole 算法）
# ============================================================================

_FAVICON_HREF_RE = re.compile(r'href\s*=\s*["\'](.*?favicon[^"\']*?)["\']', re.IGNORECASE)


def _compute_mmh3_hash(raw_bytes: bytes) -> str:
    """
    EHole 兼容的 favicon MMH3-32 哈希。
    算法：raw → base64 → 每76字符插入换行 → 末尾追加换行 → mmh3-32 → int32 字符串。
    """
    b64 = base64.b64encode(raw_bytes).decode("ascii")
    buffer_lines = []
    for i in range(0, len(b64), 76):
        buffer_lines.append(b64[i:i + 76])
    formatted = "\n".join(buffer_lines) + "\n"
    hash_val = mmh3.hash(formatted.encode("ascii"))
    return str(hash_val)


# ============================================================================
# 指纹识别引擎
# ============================================================================

class FingerprintEngine:
    """指纹识别核心引擎。"""

    def __init__(
        self,
        rules_path: str,
        request_handler: RequestHandler,
        timeout_ms: int = 3000,
    ) -> None:
        self._rules: List[FingerprintRule] = []
        self._request_handler = request_handler
        self._timeout_ms = timeout_ms
        self._load_rules(rules_path)
        self._precompile_patterns()
        self._favicon_cache: Dict[str, str] = {}

    # -----------------------------------------------------------------------
    # 规则加载
    # -----------------------------------------------------------------------

    def _load_rules(self, path: str) -> None:
        """从 finger.json 加载所有指纹规则（自动过滤低质量规则）。"""
        if not os.path.exists(path):
            raise FileNotFoundError("指纹规则文件不存在: {}".format(path))

        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        raw_rules = data.get("fingerprint", [])
        skipped_empty = 0
        skipped_short = 0
        for item in raw_rules:
            keywords: List[str] = item.get("keyword", [])

            # 过滤含空字符串关键词的规则
            if any(k == "" for k in keywords):
                skipped_empty += 1
                continue

            # 过滤所有 keyword 都 ≤3 字符的规则
            if keywords and all(len(k) <= 3 for k in keywords):
                skipped_short += 1
                continue

            # 过滤单 keyword 且长度 ≤4 的规则
            if len(keywords) == 1 and len(keywords[0]) <= 4:
                skipped_short += 1
                continue

            rule = FingerprintRule(
                cms=item.get("cms", ""),
                method=item.get("method", "keyword"),
                location=item.get("location", "body"),
                keyword=keywords,
            )
            self._rules.append(rule)

        if skipped_empty or skipped_short:
            import sys
            print(
                "[FingerprintEngine] 已过滤 {} 条低质量规则（空关键词 {} 条，超短关键词 {} 条）".format(
                    skipped_empty + skipped_short, skipped_empty, skipped_short
                ),
                file=sys.stderr,
            )

    def _precompile_patterns(self) -> None:
        """预编译所有 regular 方法的正则表达式。"""
        for rule in self._rules:
            if rule.method == "regular":
                rule.compile_patterns()

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    # -----------------------------------------------------------------------
    # 核心识别
    # -----------------------------------------------------------------------

    def identify(
        self,
        url: str,
        stop_event: Optional[threading.Event] = None,
        pause_event: Optional[threading.Event] = None,
    ) -> FingerprintResult:
        """
        对单个 URL 进行指纹识别。

        流程：
        1. HTTP GET 请求
        2. 提取 title / body / headers / favicon hash
        3. 遍历所有规则匹配
        4. 返回去重后的 CMS 列表
        """
        result = FingerprintResult(url=url)

        # 1. 请求
        resp = self._fetch(url, stop_event, pause_event)
        if resp is None:
            return result

        result.status_code = resp.status_code
        body_bytes = resp.content or b""
        result.length = len(body_bytes)

        content_type = resp.headers.get("Content-Type", "")

        # 2. 提取内容
        body_utf8 = _to_utf8(body_bytes, content_type)
        result.title = _extract_title(body_utf8)

        # headers → "key: value" 逐行格式（与 EHole 原始行为一致）
        header_dict = {k.lower(): resp.headers.get(k) for k in resp.headers.keys()}
        header_text = "\n".join("{}: {}".format(k, v) for k, v in header_dict.items())

        # favicon hash（带缓存）
        favicon_hash = self._get_favicon_hash(body_utf8, url, stop_event)

        content_map = {
            "body": body_utf8,
            "header": header_text,
            "title": result.title,
            "url": url,
            "favicon_hash": favicon_hash,
        }

        # 3. 规则匹配 + 置信度评分
        scored: Dict[str, int] = {}  # cms → 最高置信度
        for rule in self._rules:
            if stop_event and stop_event.is_set():
                break
            if rule.match(content_map):
                confidence = self._score_match(rule)
                existing = scored.get(rule.cms, -1)
                if confidence > existing:
                    scored[rule.cms] = confidence

        # 4. 过滤低置信度 + 排序 + 截断
        result.details = [
            {"cms": cms, "confidence": conf}
            for cms, conf in sorted(scored.items(), key=lambda x: x[1], reverse=True)
            if conf >= 20
        ][:20]
        result.cms = ",".join(d["cms"] for d in result.details)
        return result

    # -----------------------------------------------------------------------
    # 置信度评分
    # -----------------------------------------------------------------------

    @staticmethod
    def _score_match(rule: FingerprintRule) -> int:
        """为匹配成功的规则计算置信度（0-100）。"""
        score = 30
        if rule.method == "faviconhash":
            score += 30
        if rule.location == "title":
            score += 10
        kw_count = len(rule.keyword)
        if kw_count > 1:
            score += 10 * (kw_count - 1)
        for kw in rule.keyword:
            kw_len = len(kw)
            if kw_len >= 20:
                score += 10
            elif kw_len >= 10:
                score += 5
        if rule.location == "body" and rule.keyword:
            if all(len(k) <= 6 for k in rule.keyword):
                score -= 20
        return max(0, min(100, score))

    # -----------------------------------------------------------------------
    # HTTP 请求
    # -----------------------------------------------------------------------

    def _fetch(
        self,
        url: str,
        stop_event: Optional[threading.Event] = None,
        pause_event: Optional[threading.Event] = None,
    ) -> Optional[requests.Response]:
        """发送 HTTP GET 请求，返回响应或 None。"""
        if stop_event and stop_event.is_set():
            return None
        self._wait_if_paused(pause_event, stop_event)

        try:
            return self._request_handler.get(url, timeout=self._timeout_ms / 1000.0)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Favicon 处理
    # -----------------------------------------------------------------------

    def _get_favicon_hash(
        self,
        body_html: str,
        base_url: str,
        stop_event: Optional[threading.Event] = None,
    ) -> str:
        """获取 favicon.ico 的 MMH3 哈希（带缓存）。"""
        favicon_url = self._resolve_favicon_url(body_html, base_url)
        if not favicon_url:
            return ""

        if favicon_url in self._favicon_cache:
            return self._favicon_cache[favicon_url]

        try:
            if stop_event and stop_event.is_set():
                return ""
            resp = self._request_handler.get(
                favicon_url,
                timeout=self._timeout_ms / 1000.0,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                favicon_bytes = resp.content
                if favicon_bytes:
                    h = _compute_mmh3_hash(favicon_bytes)
                    self._favicon_cache[favicon_url] = h
                    return h
        except Exception:
            pass

        return ""

    @staticmethod
    def _resolve_favicon_url(body_html: str, base_url: str) -> str:
        """从 HTML 中提取 favicon URL 或使用默认路径。"""
        m = _FAVICON_HREF_RE.search(body_html)
        if m:
            href = m.group(1)
            href = href.replace("&amp;", "&")
            return urljoin(base_url, href)

        # 默认路径
        parsed = urlparse(base_url)
        return "{}://{}/favicon.ico".format(parsed.scheme, parsed.netloc)

    @staticmethod
    def _wait_if_paused(
        pause_event: Optional[threading.Event],
        stop_event: Optional[threading.Event],
    ) -> None:
        """忙等暂停。"""
        if pause_event is None:
            return
        while pause_event.is_set():
            if stop_event and stop_event.is_set():
                return
            time.sleep(0.1)


# ============================================================================
# 导出函数
# ============================================================================

EXPORT_FILTER_TEXT = "CSV 文件 (*.csv);;TXT 文件 (*.txt);;Excel 工作簿 (*.xlsx);;HTML 文件 (*.html)"

_RESULT_COLUMNS = ["URL", "标题", "响应码", "返回长度", "识别结果"]


def _results_as_dicts(results: List[FingerprintResult]) -> List[Dict[str, Any]]:
    return [
        {
            "url": _csv_safe(r.url),
            "title": _csv_safe(r.title),
            "status_code": r.status_code,
            "length": r.length,
            "cms": _csv_safe(r.cms),
        }
        for r in results
    ]


def results_to_csv(results: List[FingerprintResult]) -> str:
    data = _results_as_dicts(results)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["url", "title", "status_code", "length", "cms"])
    writer.writeheader()
    for d in data:
        writer.writerow(d)
    return buf.getvalue()


def results_to_txt(results: List[FingerprintResult]) -> str:
    lines = []
    for i, r in enumerate(results, 1):
        lines.append(
            "[{idx}] {url} | {code} | {length} | {title} | {cms}".format(
                idx=i,
                url=r.url,
                code=r.status_code,
                length=r.length,
                title=r.title,
                cms=r.cms,
            )
        )
    return "\n".join(lines)


def results_to_html(results: List[FingerprintResult]) -> str:
    import html
    rows = ""
    for i, r in enumerate(results, 1):
        status_class = "ok" if 200 <= r.status_code < 300 else "redirect" if 300 <= r.status_code < 400 else "error"
        rows += (
            '<tr>'
            '<td>{idx}</td>'
            '<td class="url">{url}</td>'
            '<td>{title}</td>'
            '<td class="{cls}">{code}</td>'
            '<td>{length}</td>'
            '<td class="cms">{cms}</td>'
            '</tr>'
        ).format(
            idx=i,
            url=html.escape(r.url),
            title=html.escape(r.title),
            code=r.status_code,
            length=r.length,
            cms=html.escape(r.cms),
            cls=status_class,
        )

    return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>ICE 指纹识别结果</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#F5F6FA;padding:24px;color:#1E293B}}
h1{{font-size:20px;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden}}
th{{background:rgba(59,130,246,0.1);color:#1E293B;font-weight:600;padding:10px 12px;text-align:left;font-size:13px}}
td{{padding:8px 12px;font-size:13px;border-top:1px solid rgba(0,0,0,0.06)}}
td.url{{max-width:360px;word-break:break-all}}
td.ok{{color:#22C55E;font-weight:600}}
td.redirect{{color:#F59E0B;font-weight:600}}
td.error{{color:#EF4444;font-weight:600}}
td.cms{{color:#3B82F6;font-weight:500}}
</style>
</head>
<body>
<h1>ICE 指纹识别结果</h1>
<table>
<thead><tr><th>#</th><th>URL</th><th>标题</th><th>响应码</th><th>返回长度</th><th>识别结果</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>""".format(rows=rows)


def results_to_xlsx(results: List[FingerprintResult]) -> bytes:
    """生成 XLSX 字节（最小 OpenXML，无外部依赖）。"""
    import zipfile

    rows_xml = ""
    for r in results:
        rows_xml += (
            '<row>'
            '<c t="inlineStr"><is><t>{url}</t></is></c>'
            '<c t="inlineStr"><is><t>{title}</t></is></c>'
            '<c t="n"><v>{code}</v></c>'
            '<c t="n"><v>{length}</v></c>'
            '<c t="inlineStr"><is><t>{cms}</t></is></c>'
            '</row>'
        ).format(
            url=_xml_escape(r.url),
            title=_xml_escape(r.title),
            code=r.status_code,
            length=r.length,
            cms=_xml_escape(r.cms),
        )

    sheet = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<cols><col min="1" max="1" width="48"/><col min="2" max="2" width="24"/>'
        '<col min="3" max="3" width="12"/><col min="4" max="4" width="14"/><col min="5" max="5" width="24"/></cols>'
        '<sheetData>{rows}</sheetData></worksheet>'
    ).format(rows=rows_xml)

    shared = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="0" uniqueCount="0"/>'
    )

    styles = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '</styleSheet>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '</Types>')
        zf.writestr("_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>')
        zf.writestr("xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Results" sheetId="1" r:id="rId1"/></sheets></workbook>')
        zf.writestr("xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '</Relationships>')
        zf.writestr("xl/sharedStrings.xml", shared)
        zf.writestr("xl/styles.xml", styles)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)

    return buf.getvalue()


def _xml_escape(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
