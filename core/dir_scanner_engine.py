"""目录扫描核心引擎"""
import csv
import html
import io
import os
import threading
import time
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

from core._app_root import get_app_root
from core._export_utils import _csv_safe

import requests
from requests.adapters import HTTPAdapter

from core.request_handler import RequestHandler
from core.settings import AppSettings


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

MAX_WORKERS = 512
WAF_TIMEOUT_THRESHOLD = 20
DICTIONARY_GRID_COLUMNS = 4
EXPORT_FILTER_TEXT = "TXT 文件 (*.txt);;CSV 文件 (*.csv);;Excel 工作簿 (*.xlsx);;HTML 文件 (*.html)"

DICTIONARY_LABELS: Dict[str, str] = {
    "mulu.txt": "目录-大",
    "mulu-small.txt": "目录-小",
    "admindir.txt": "后台",
    "apipath.txt": "api",
    "asp.txt": "asp",
    "aspx.txt": "aspx",
    "Backup.txt": "备份-大",
    "Backup-small.txt": "备份-小",
    "editor.txt": "编辑器",
    "jeecg.txt": "jeecg",
    "jsp.txt": "JSP",
    "log.txt": "日志",
    "php.txt": "PHP",
    "phpmyadmin.txt": "phpmyadmin",
    "ruoyi.txt": "Ruoyi",
    "springblade.txt": "SpringBlade",
    "springboot.txt": "Springboot",
    "wordpress.txt": "Wordpress",
}

DICTIONARY_ORDER: List[str] = [
    "目录-大", "目录-小", "后台", "api", "asp", "aspx",
    "备份-大", "备份-小", "编辑器", "jeecg", "JSP", "日志",
    "PHP", "phpmyadmin", "Ruoyi", "SpringBlade", "Springboot", "Wordpress",
]

STATUS_CODE_OPTIONS = [200, 301, 302, 401, 403, 404, 500, 502]

# Bypass403 常量（与 pass403.py 完全一致）
BYPASS_PATH_PAIRS = [["/", "//"], ["/.", "/./"]]
BYPASS_LEADINGS = ["/%2e"]
BYPASS_TRAILINGS = ["/", "..;/", "/..;/", "%20", "%09", "%00",
                    ".json", ".css", ".html", "?", "??", "???",
                    "?testparam", "#", "#test", "/."]
BYPASS_IP_HEADERS = ["X-Custom-IP-Authorization", "X-Forwarded-For",
                     "X-Forward-For", "X-Remote-IP", "X-Originating-IP",
                     "X-Remote-Addr", "X-Client-IP", "X-Real-IP"]
BYPASS_IP_VALUES = ["localhost", "localhost:80", "localhost:443",
                    "127.0.0.1", "127.0.0.1:80", "127.0.0.1:443",
                    "2130706433", "0x7F000001", "0177.0000.0000.0001",
                    "0", "127.1", "10.0.0.0", "10.0.0.1",
                    "172.16.0.0", "172.16.0.1", "192.168.1.0", "192.168.1.1"]
BYPASS_REWRITE_HEADERS = ["X-Original-URL", "X-Rewrite-URL"]


# ---------------------------------------------------------------------------
# 数据类
# ---------------------------------------------------------------------------

@dataclass
class DirScanOptions:
    """目录扫描配置"""
    base_urls: Sequence[str]
    dictionary_paths: Sequence[str]
    thread_count: int = 20
    timeout_ms: int = 3000
    status_codes: Set[int] = field(default_factory=set)
    keyword_exclude: str = ""
    length_exclude: int = 0
    waf_enabled: bool = False
    bypass_403: bool = False
    retry_count: int = 3


@dataclass
class DirScanResult:
    """单条目录扫描结果"""
    url: str
    status_code: int
    length: int
    redirect: str = ""


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _project_root() -> str:
    """返回项目根目录的绝对路径"""
    return get_app_root()


def _dictionary_dir() -> str:
    """返回目录扫描字典目录"""
    return os.path.join(_project_root(), "resources", "dir", "path")


def discover_dictionary_options(base_dir: str) -> List[Tuple[str, str]]:
    """扫描字典目录，返回按 DICTIONARY_ORDER 排序的 [(label, path), ...] 列表"""
    options: List[Tuple[str, str]] = []
    if not os.path.isdir(base_dir):
        return options
    for filename in os.listdir(base_dir):
        if not filename.endswith(".txt"):
            continue
        if filename in ("400_blacklist.txt", "403_blacklist.txt", "500_blacklist.txt"):
            continue
        label = DICTIONARY_LABELS.get(filename, filename)
        options.append((label, os.path.join(base_dir, filename)))
    order_map = {name: i for i, name in enumerate(DICTIONARY_ORDER)}
    options.sort(key=lambda item: order_map.get(item[0], 9999))
    return options


def parse_urls(text: str) -> List[str]:
    """解析多行 URL 输入，自动补全协议头，去重并校验格式"""
    urls: List[str] = []
    seen: Set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not line.startswith(("http://", "https://")):
            line = "http://" + line
        parsed = urlparse(line)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("URL 格式无效：%s" % raw_line.strip())
        base = line if not line.endswith("/") or parsed.path == "/" else line.rstrip("/")
        if base not in seen:
            urls.append(base)
            seen.add(base)
    if not urls:
        raise ValueError("请输入至少一个目标 URL")
    return urls


def load_dictionary(path: str) -> List[str]:
    """逐行读取字典文件，去空行和注释行"""
    words: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            words.append(word)
    return words


# ---------------------------------------------------------------------------
# 扫描引擎
# ---------------------------------------------------------------------------

class DirScannerEngine:
    """目录扫描引擎 —— 纯逻辑，无 Qt 依赖"""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings
        self._request_handler = RequestHandler(settings)
        self._session: requests.Session = requests.Session()
        # 默认启用 TLS 证书验证；扫描内网自签名证书目标时可按需关闭
        self._session.verify = True
        self._stop_event: Optional[threading.Event] = None
        self._result_callback: Optional[Callable[[DirScanResult], None]] = None
        self._status_callback: Optional[Callable[[str], None]] = None
        self._progress_callback: Optional[Callable[[int], None]] = None
        self._pause_event: Optional[threading.Event] = None
        self._waf_timeout_counters: Dict[str, int] = {}
        self._waf_blocked_urls: Set[str] = set()

    def _setup_session(self, thread_count: int) -> None:
        """配置 Session 的代理、UA、连接池"""
        proxies = self._request_handler.proxy_manager.get_proxy_dict()
        if proxies:
            self._session.proxies.update(proxies)
        headers: Dict[str, str] = {}
        ua = self._request_handler.ua_manager.get_ua()
        if ua:
            headers["User-Agent"] = ua
        custom_headers: Dict[str, str] = self._settings.get("custom_headers", {})
        headers.update(custom_headers)
        if headers:
            self._session.headers.update(headers)
        adapter = HTTPAdapter(
            pool_maxsize=thread_count,
            pool_connections=thread_count,
            max_retries=0,
        )
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    # ---- HTTP 请求 ----

    def _session_get(self, url: str, timeout: float,
                     allow_redirects: bool = False) -> requests.Response:
        """使用 Session 发送 GET 请求（stream=True）"""
        return self._session.get(url, timeout=timeout, allow_redirects=allow_redirects, stream=True)

    def _session_post(self, url: str, timeout: float,
                      allow_redirects: bool = False) -> requests.Response:
        """使用 Session 发送 POST 请求（stream=True）"""
        return self._session.post(url, timeout=timeout, allow_redirects=allow_redirects, stream=True)

    def _request_with_retry(self, url: str, timeout: float,
                            options: DirScanOptions) -> Optional[requests.Response]:
        """带重试的单次请求（最多 retry_count 次，指数退避）"""
        for attempt in range(options.retry_count + 1):
            if self._stop_event and self._stop_event.is_set():
                return None
            try:
                return self._session_get(url, timeout)
            except requests.RequestException:
                if attempt < options.retry_count:
                    time.sleep(0.5 * (attempt + 1))
        return None

    # ---- 过滤逻辑 ----

    @staticmethod
    def _passes_filters(status_code: int, length: int, response_text: str,
                        options: DirScanOptions) -> bool:
        """黑名单过滤：关键词排除 / 长度排除"""
        if options.status_codes and status_code not in options.status_codes:
            return False
        if options.keyword_exclude:
            try:
                if options.keyword_exclude in (response_text or ""):
                    return False
            except Exception:
                pass
        if options.length_exclude > 0 and length > options.length_exclude:
            return False
        return True

    # ---- Bypass403 ----

    def _try_bypass_403(self, base_url: str, word: str, options: DirScanOptions,
                        timeout: float) -> Optional[DirScanResult]:
        """尝试绕过 403 限制（与 pass403.py 逻辑完全一致）"""
        path = word if word.startswith("/") else "/" + word
        full_url = base_url + path

        # Phase 1 — POST 请求（pass403.py: manipulateRequest）
        if self._stop_event and self._stop_event.is_set():
            return None
        try:
            resp = self._session_post(full_url, timeout)
        except requests.RequestException:
            resp = None
        result = self._response_to_result(resp, full_url, options)
        if result is not None and result.status_code != 403:
            return result

        # Phase 2 — 路径变体（pass403.py: manipulatePath）

        # 2a — 路径对
        for pair in BYPASS_PATH_PAIRS:
            if self._stop_event and self._stop_event.is_set():
                return None
            variant_url = base_url + pair[0] + path + pair[1]
            try:
                resp = self._session_get(variant_url, timeout)
            except requests.RequestException:
                resp = None
            result = self._response_to_result(resp, variant_url, options)
            if result is not None and result.status_code != 403:
                return result

        # 2b — 前导
        for leading in BYPASS_LEADINGS:
            if self._stop_event and self._stop_event.is_set():
                return None
            variant_url = base_url + leading + path
            try:
                resp = self._session_get(variant_url, timeout)
            except requests.RequestException:
                resp = None
            result = self._response_to_result(resp, variant_url, options)
            if result is not None and result.status_code != 403:
                return result

        # 2c — 后缀
        for trailing in BYPASS_TRAILINGS:
            if self._stop_event and self._stop_event.is_set():
                return None
            variant_url = base_url + path + trailing
            try:
                resp = self._session_get(variant_url, timeout)
            except requests.RequestException:
                resp = None
            result = self._response_to_result(resp, variant_url, options)
            if result is not None and result.status_code != 403:
                return result

        # Phase 3 — IP 头欺骗（pass403.py: manipulateHeaders）
        for header_name in BYPASS_IP_HEADERS:
            for ip_value in BYPASS_IP_VALUES:
                if self._stop_event and self._stop_event.is_set():
                    return None
                try:
                    resp = self._session.get(full_url, timeout=timeout,
                                             allow_redirects=False, stream=True,
                                             headers={header_name: ip_value})
                except requests.RequestException:
                    resp = None
                result = self._response_to_result(resp, full_url, options)
                if result is not None and result.status_code != 403:
                    return result

        # Phase 4 — 重写头（pass403.py: manipulateHeaders 后半）
        for header_name in BYPASS_REWRITE_HEADERS:
            if self._stop_event and self._stop_event.is_set():
                return None
            try:
                resp = self._session.get(base_url, timeout=timeout,
                                         allow_redirects=False, stream=True,
                                         headers={header_name: path})
            except requests.RequestException:
                resp = None
            result = self._response_to_result(resp, base_url, options)
            if result is not None and result.status_code != 403:
                return result

        return None

    def _response_to_result(self, response: Optional[requests.Response],
                            url: str, options: DirScanOptions) -> Optional[DirScanResult]:
        """将 HTTP 响应转换为 DirScanResult（None 安全）"""
        if response is None:
            return None
        status_code = response.status_code
        cl = response.headers.get("Content-Length")
        if cl is not None and cl.isdigit():
            length = int(cl)
        else:
            length = 0
            try:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        length += len(chunk)
                        if length > 102400:
                            break
            except Exception:
                pass
        redirect = response.headers.get("Location", "") if status_code in (301, 302, 307, 308) else ""
        response_text = ""
        if options.keyword_exclude:
            try:
                response_text = response.text or ""
            except Exception:
                response_text = ""
        if not self._passes_filters(status_code, length, response_text, options):
            return None
        return DirScanResult(url=url, status_code=status_code, length=length, redirect=redirect)

    # ---- 单个探测 ----

    def _probe_url(self, base_url: str, word: str, options: DirScanOptions,
                   timeout: float) -> Optional[DirScanResult]:
        """探测单个 URL 路径"""
        if self._stop_event and self._stop_event.is_set():
            return None
        if options.waf_enabled and base_url in self._waf_blocked_urls:
            return None

        path = word if word.startswith("/") else "/" + word
        full_url = base_url + path

        try:
            response = self._request_with_retry(full_url, timeout, options)
        except Exception:
            response = None

        if response is None:
            if options.waf_enabled:
                count = self._waf_timeout_counters.get(base_url, 0) + 1
                self._waf_timeout_counters[base_url] = count
                if count >= WAF_TIMEOUT_THRESHOLD:
                    self._waf_blocked_urls.add(base_url)
                    self._report_status("WAF 检测: %s 连续超时 %d 次，已跳过该目标" % (base_url, count))
            return None

        if options.waf_enabled and base_url in self._waf_timeout_counters:
            self._waf_timeout_counters[base_url] = 0

        result = self._response_to_result(response, full_url, options)
        if result is not None and result.status_code == 403 and options.bypass_403:
            bypass_result = self._try_bypass_403(base_url, word, options, timeout)
            if bypass_result is not None:
                return bypass_result
        return result

    # ---- 主扫描循环 ----

    def scan(
        self,
        options: DirScanOptions,
        stop_event: threading.Event,
        result_callback: Callable[[DirScanResult], None],
        status_callback: Callable[[str], None],
        pause_event: Optional[threading.Event] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> List[DirScanResult]:
        """执行目录扫描"""
        self._stop_event = stop_event
        self._result_callback = result_callback
        self._status_callback = status_callback
        self._pause_event = pause_event
        self._progress_callback = progress_callback
        self._waf_timeout_counters = {}
        self._waf_blocked_urls = set()

        results: List[DirScanResult] = []

        self._setup_session(options.thread_count)

        base_urls = [url.rstrip("/") for url in options.base_urls]
        timeout = max(options.timeout_ms, 100) / 1000.0
        max_workers = min(max(1, options.thread_count), MAX_WORKERS)

        # 加载多字典并合并去重
        self._report_status("加载字典...")
        all_words: List[str] = []
        seen_words: Set[str] = set()
        for dict_path in options.dictionary_paths:
            try:
                words = load_dictionary(dict_path)
                added = 0
                for w in words:
                    if w not in seen_words:
                        all_words.append(w)
                        seen_words.add(w)
                        added += 1
                self._report_status("已加载字典 %s (%d 条)" % (os.path.basename(dict_path), added))
            except IOError as error:
                self._report_status("字典加载失败 %s: %s" % (dict_path, error))
        if not all_words:
            self._report_status("没有可用的字典内容")
            return results

        # 生成任务列表
        tasks: List[Tuple[str, str]] = []
        for base_url in base_urls:
            for word in all_words:
                tasks.append((base_url, word))
        total_tasks = len(tasks)
        self._report_status("共 %d 个目标, %d 条路径, %d 个任务, 开始扫描..." % (len(base_urls), len(all_words), total_tasks))

        progress = progress_callback or (lambda _value: None)
        progress(0)

        completed = 0

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            future_map: Dict[Any, Tuple[str, str]] = {}
            task_iter = iter(tasks)
            exhausted = [False]

            def submit_next() -> bool:
                if exhausted[0] or stop_event.is_set():
                    return False
                if self._wait_if_paused(pause_event, stop_event):
                    try:
                        base_url, word = next(task_iter)
                    except StopIteration:
                        exhausted[0] = True
                        return False
                    future = executor.submit(self._probe_url, base_url, word, options, timeout)
                    future_map[future] = (base_url, word)
                    return True
                return False

            while len(future_map) < max_workers and submit_next():
                pass

            while future_map and not stop_event.is_set():
                done_futures, _pending = wait(
                    future_map.keys(),
                    timeout=0.05,
                    return_when=FIRST_COMPLETED,
                )
                if not done_futures:
                    if self._wait_if_paused(pause_event, stop_event):
                        continue
                    break
                for future in done_futures:
                    future_map.pop(future)
                    completed += 1
                    try:
                        result = future.result()
                    except Exception:
                        result = None
                    if result is not None:
                        results.append(result)
                        if result_callback:
                            result_callback(result)
                    if completed == total_tasks or completed % max(1, total_tasks // 100) == 0:
                        progress(int(completed * 100 / total_tasks))
                while len(future_map) < max_workers and submit_next():
                    pass

            if stop_event.is_set():
                for future in future_map:
                    future.cancel()
                self._report_status("扫描已停止")
            else:
                progress(100)
                self._report_status("扫描完成，共发现 %d 条结果" % len(results))
        finally:
            executor.shutdown(wait=False)
            self._session.close()

        return results

    def _wait_if_paused(self, pause_event: Optional[threading.Event],
                        stop_event: threading.Event) -> bool:
        """暂停等待，返回 True 表示可以继续，False 表示已停止"""
        if pause_event is None:
            return True
        while pause_event.is_set():
            if stop_event.is_set():
                return False
            time.sleep(0.1)
        return True

    def _report_status(self, message: str) -> None:
        """向 UI 报告状态（线程安全）"""
        if self._status_callback:
            self._status_callback(message)


# ---------------------------------------------------------------------------
# 导出函数
# ---------------------------------------------------------------------------

def results_to_txt(results: Sequence[DirScanResult]) -> str:
    """将结果格式化为纯文本"""
    lines: List[str] = []
    for i, r in enumerate(results, 1):
        redirect = " -> %s" % r.redirect if r.redirect else ""
        lines.append("[%d] %d %s (%d bytes)%s" % (i, r.status_code, r.url, r.length, redirect))
    return "\n".join(lines)


def results_to_csv(results: Sequence[DirScanResult]) -> str:
    """将结果格式化为 CSV 字符串"""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["序号", "状态码", "URL", "长度", "重定向"])
    for i, r in enumerate(results, 1):
        writer.writerow([str(i), str(r.status_code), _csv_safe(r.url), str(r.length), _csv_safe(r.redirect)])
    return output.getvalue()


def results_to_html(results: Sequence[DirScanResult]) -> str:
    """将结果格式化为 HTML 表格"""
    rows: List[str] = []
    for i, r in enumerate(results, 1):
        if 200 <= r.status_code < 300:
            status_class = "ok"
        elif 300 <= r.status_code < 400:
            status_class = "redirect"
        else:
            status_class = "error"
        redirect_html = ' <span style="color:#64748B;">&rarr; %s</span>' % html.escape(r.redirect) if r.redirect else ""
        rows.append(
            '<tr><td>%d</td><td class="%s">%d</td><td>%s</td><td>%d</td><td>%s</td></tr>'
            % (i, status_class, r.status_code, html.escape(r.url), r.length, redirect_html)
        )
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>目录扫描结果</title>"
        "<style>body{font-family:Inter,-apple-system,sans-serif;background:#F5F6FA;padding:24px;}"
        "table{border-collapse:collapse;width:100%%;background:rgba(255,255,255,0.9);border-radius:12px;overflow:hidden;}"
        "th{background:rgba(59,130,246,0.08);color:#1E293B;padding:10px 12px;text-align:left;font-weight:600;}"
        "td{padding:8px 12px;color:#1E293B;border-bottom:1px solid rgba(0,0,0,0.04);}"
        ".ok{color:#22C55E;font-weight:500;}.redirect{color:#F59E0B;font-weight:500;}.error{color:#EF4444;font-weight:500;}"
        "</style></head><body><h2>目录扫描结果</h2><table><tr><th>序号</th><th>状态码</th><th>URL</th><th>长度</th><th>重定向</th></tr>"
        + "".join(rows)
        + "</table></body></html>"
    )


def _xlsx_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def results_to_xlsx(results: Sequence[DirScanResult]) -> bytes:
    """将结果格式化为 XLSX 工作簿（纯标准库 zipfile）"""
    headers = ["序号", "状态码", "URL", "长度", "重定向"]
    column_letters = ["A", "B", "C", "D", "E"]

    rows_xml: List[str] = []
    header_cells = ""
    for letter, h in zip(column_letters, headers):
        header_cells += '<c r="%s1" t="inlineStr"><is><t>%s</t></is></c>' % (letter, _xlsx_escape(h))
    rows_xml.append('<row r="1">%s</row>' % header_cells)

    for i, r in enumerate(results, 1):
        values = [str(i), str(r.status_code), _xlsx_escape(_csv_safe(r.url)), str(r.length),
                  _xlsx_escape(_csv_safe(r.redirect))]
        cells = ""
        for letter, val in zip(column_letters, values):
            cells += '<c r="%s%d" t="inlineStr"><is><t>%s</t></is></c>' % (letter, i + 1, val)
        rows_xml.append('<row r="%d">%s</row>' % (i + 1, cells))

    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData>' + "".join(rows_xml) + "</sheetData></worksheet>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                    '<Default Extension="xml" ContentType="application/xml"/>'
                    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                    '</Types>')
        zf.writestr("_rels/.rels",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                    '</Relationships>')
        zf.writestr("xl/workbook.xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                    '<sheets><sheet name="目录扫描结果" sheetId="1" r:id="rId1"/></sheets></workbook>')
        zf.writestr("xl/_rels/workbook.xml.rels",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
                    '</Relationships>')
        zf.writestr("xl/sharedStrings.xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="0" uniqueCount="0"/>')
        zf.writestr("xl/styles.xml",
                    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>')
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()
