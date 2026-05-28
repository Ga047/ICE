"""JSFinder 扫描引擎"""
import csv
import html as html_module
import io
import os
import re
import threading
import time
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from core._export_utils import _csv_safe
from core.request_handler import RequestHandler
from core.settings import AppSettings


# ============================================================================
# 常量
# ============================================================================

MAX_WORKERS = 512
EXPORT_FILTER_TEXT = "CSV 文件 (*.csv);;TXT 文件 (*.txt);;Excel 工作簿 (*.xlsx);;HTML 文件 (*.html)"

# 默认状态码选项（不包含 500）
STATUS_CODE_OPTIONS = [200, 301, 302, 401, 403, 404, 500, 502]

# 静态资源后缀黑名单
STATIC_EXTENSIONS = {
    ".css", ".scss", ".sass", ".less",
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".webm", ".ogg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".tar", ".gz", ".7z",
    ".vue", ".ts", ".tsx", ".scss", ".map",
}

# JS 黑名单域名
JS_BLACKLIST_DOMAINS = ["www.w3.org", "example.com"]

# 知名公网 DNS/服务 IP（不视为敏感内网 IP）
PUBLIC_IPS = {
    "1.1.1.1", "8.8.8.8", "8.8.4.4", "114.114.114.114", "223.5.5.5",
    "208.67.222.222", "208.67.220.220", "9.9.9.9", "149.112.112.112",
}

# 密码占位符（不视为真实密码）
PASSWORD_PLACEHOLDERS = {
    "your_password", "your_pass", "yourpassword", "password123", "123456",
    "test", "example", "xxxxxx", "******", "****", "***", "...",
    "changeme", "admin123", "root", "guest", "user",
}


# ============================================================================
# 正则规则（翻译自 URLFinder config/config.go）
# ============================================================================

# -- JS 提取正则（JsFind）--
_JS_PATTERNS = [
    re.compile(r"(https?://[^\s\"'{}\]<>]*\.js)"),
    re.compile(r"""["'][^"']*\.js(?:\?[^"']*)?["']"""),
    re.compile(r"""=\s*["']?([^"'\s><]*\.js(?:\?[^"'\s><]*)?)"""),
]

# -- URL 提取正则（UrlFind）--
_URL_PATTERNS = [
    re.compile(r"(https?://[^\s\"'<>\)\]\}]+)"),
    re.compile(r"""=\s*["']?(https?://[^\s\"'<>]+)"""),
    re.compile(r"""["']([^"']*?)["']"""),
    re.compile(r"""(?:href|action)\s*=\s*["']([^"']+)["']"""),
    re.compile(r"(/\w[\w./_-]+)"),
]

# -- JS 过滤器（JsFiler）--
_JS_FILTER_PATTERNS = [
    re.compile(r"www\.w3\.org"),
    re.compile(r"example\.com"),
]

# -- URL 过滤器（UrlFiler）--
_URL_FILTER_PATTERNS = [
    re.compile(r"[?&]?\.(?:js|css|jpg|jpeg|png|gif|ico|svg|woff2?|ttf|vue|tsx?|scss|less|map)\b"),
    re.compile(r"(?:javascript:|mailto:|tel:|data:)"),
]

# URL 必须包含至少一个字母或数字
_URL_VALID_CHAR_RE = re.compile(r"[a-zA-Z0-9]")

# Base 标签提取
_BASE_HREF_RE = re.compile(r"""<base\s[^>]*href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# Title 标签提取
_TITLE_RE = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE)

# -- 敏感信息正则（InfoFind）--
_SENSITIVE_PATTERNS: Dict[str, Tuple[re.Pattern, str]] = {
    "phone": (
        re.compile(r"\b1[3-9]\d{9}\b"),
        "手机号",
    ),
    "email": (
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "邮箱",
    ),
    "idcard": (
        re.compile(r"\b\d{15}\b|\b\d{17}[\dXx]\b"),
        "身份证",
    ),
    "jwt": (
        re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)?"),
        "JWT Token",
    ),
    "cloud_key": (
        re.compile(
            r"AKID[A-Za-z0-9]{32,48}"                 # 腾讯云
            r"|AKIA[A-Z0-9]{16}"                      # AWS
            r"|LTAI[A-Za-z0-9]{16,24}"                 # 阿里云
        ),
        "云服务密钥",
    ),
    "password": (
        re.compile(
            r"""(?:password|passwd|pwd|pass|userpass|passcode|secret|secret_key|secretKey"""
            r"""|app_secret|appSecret|private_key|privateKey|encrypt_key|encryptKey"""
            r"""|sign_key|signKey|salt_key|saltKey|master_key|masterKey"""
            r"""|admin_pass|adminPass|db_pass|dbPass|db_password|dbPassword"""
            r"""|database_password|mysql_pass|redis_pass|ftp_pass|smtp_pass"""
            r""")\s*[:=]\s*["']([^"']{6,})["']""",
            re.IGNORECASE,
        ),
        "密码/凭据",
    ),
    "api_key": (
        re.compile(
            r"""(?:api_key|apiKey|apikey|api_secret|apiSecret|apisecret"""
            r"""|app_key|appKey|appkey|access_key|accessKey|accesskey"""
            r"""|access_token|accessToken|accesstoken|refresh_token|refreshToken"""
            r"""|auth_token|authToken|authtoken|bearer_token|bearerToken"""
            r"""|client_id|clientId|client_secret|clientSecret|oauth_token|oauthToken"""
            r"""|authorization|auth_key|authKey|authentication"""
            r""")\s*[:=]\s*["']([^"']{8,})["']""",
            re.IGNORECASE,
        ),
        "API Key/Token",
    ),
    "db_conn": (
        re.compile(
            r"""(?:mysql|postgresql|postgres|mongodb|redis|sqlite|oracle|mssql|jdbc)://[^\s"'<>]+"""
            r"""|(?:DATABASE_URL|DB_URL|MONGO_URI|REDIS_URL|SQLALCHEMY_DATABASE_URI)\s*[:=]\s*["']([^"']+)["']""",
            re.IGNORECASE,
        ),
        "数据库连接串",
    ),
    "ssh_key": (
        re.compile(
            r"-----BEGIN\s*(?:RSA\s*)?PRIVATE\s*KEY-----\s*"
            r"(?:[a-zA-Z0-9+/=\s]+?)"
            r"\s*-----END\s*(?:RSA\s*)?PRIVATE\s*KEY-----"
            r"|-----BEGIN\s*OPENSSH\s*PRIVATE\s*KEY-----"
            r"(?:[a-zA-Z0-9+/=\s]+?)"
            r"-----END\s*OPENSSH\s*PRIVATE\s*KEY-----"
            r"|-----BEGIN\s*DSA\s*PRIVATE\s*KEY-----"
            r"(?:[a-zA-Z0-9+/=\s]+?)"
            r"-----END\s*DSA\s*PRIVATE\s*KEY-----"
        ),
        "SSH私钥",
    ),
    "internal_ip": (
        re.compile(
            r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
            r"|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"
            r"|\b192\.168\.\d{1,3}\.\d{1,3}\b"
            r"|\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        ),
        "内网IP地址",
    ),
}

# 通用敏感信息匹配（宽松模式）
_GENERIC_SENSITIVE_RE = re.compile(
    r"""[a-zA-Z_][a-zA-Z0-9_]*(?:_key|_secret|_token|_pass|_pwd"""
    r"""|Key|Secret|Token|Pass|Pwd)\s*[:=]\s*["']([^"']{6,})["']"""
)

# 敏感标签映射
SENSITIVE_LABELS: Dict[str, str] = {k: v[1] for k, v in _SENSITIVE_PATTERNS.items()}


# ============================================================================
# 数据类
# ============================================================================

@dataclass
class JsFindOptions:
    """JSFinder 扫描配置"""
    base_urls: Sequence[str]
    mode: str = "normal"                         # "normal" | "deep"
    js_depth: int = 3                             # JS 递归层数（深入模式）
    thread_count: int = 50                        # 线程数
    timeout_ms: int = 3000                        # 超时(毫秒)
    status_codes: Set[int] = field(default_factory=set)  # 状态码过滤
    retry_count: int = 3                          # 重试次数


@dataclass
class JsFindResult:
    """单条 JSFinder 扫描结果"""
    target: str                                   # 来源目标 URL
    url: str                                      # 发现的 URL/JS
    status_code: int                              # HTTP 状态码
    length: int                                   # 响应长度(字节)
    title: str = ""                               # 页面 <title>
    sensitive: Dict[str, List[str]] = field(default_factory=dict)  # 敏感信息分组


# ============================================================================
# 工具函数
# ============================================================================

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


def _extract_host(url: str) -> str:
    """提取 URL 的 scheme + host"""
    parsed = urlparse(url)
    return "%s://%s" % (parsed.scheme, parsed.netloc)


def _extract_path_dir(url: str) -> str:
    """提取 URL 的目录部分（不含文件名）"""
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return parsed.scheme + "://" + parsed.netloc + "/"
    if "/" in path:
        return parsed.scheme + "://" + parsed.netloc + path[:path.rfind("/") + 1]
    return parsed.scheme + "://" + parsed.netloc + "/"


def _get_extension(url: str) -> str:
    """获取 URL 的文件扩展名（小写）"""
    path = urlparse(url).path
    ext = os.path.splitext(path)[1].lower()
    return ext


def _xlsx_escape(value: str) -> str:
    """XML 转义"""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ============================================================================
# 扫描引擎
# ============================================================================

class JsFindEngine:
    """JSFinder 扫描引擎 — 照搬 URLFinder 的扫描管道"""

    def __init__(self, settings: AppSettings) -> None:
        self._settings = settings
        self._request_handler = RequestHandler(settings)
        self._session: Optional[requests.Session] = None
        self._stop_event: Optional[threading.Event] = None
        self._pause_event: Optional[threading.Event] = None
        self._result_callback: Optional[Callable[[JsFindResult], None]] = None
        self._status_callback: Optional[Callable[[str], None]] = None
        self._progress_callback: Optional[Callable[[int], None]] = None

        # 结果收集
        self._lock = threading.Lock()
        self._js_results: Dict[str, Dict[str, Any]] = {}
        self._url_results: Dict[str, Dict[str, Any]] = {}
        self._seen_js: Set[str] = set()
        self._seen_url: Set[str] = set()
        self._crawled_pages: Set[str] = set()
        self._info_results: Dict[str, Dict[str, List[str]]] = {}

    # ---- Session 管理 ----

    def _setup_session(self, thread_count: int) -> None:
        """配置 HTTP Session"""
        self._session = requests.Session()
        # 默认启用 TLS 证书验证；扫描内网自签名证书目标时可按需关闭
        self._session.verify = True
        self._session.max_redirects = 10

        proxies = self._request_handler.proxy_manager.get_proxy_dict()
        if proxies:
            self._session.proxies.update(proxies)

        headers: Dict[str, str] = {"Accept-Encoding": "gzip, deflate"}
        ua = self._request_handler.ua_manager.get_ua()
        if ua:
            headers["User-Agent"] = ua
        custom_headers: Dict[str, str] = self._settings.get("custom_headers", {})
        headers.update(custom_headers)
        self._session.headers.update(headers)

        adapter = HTTPAdapter(
            pool_maxsize=thread_count,
            pool_connections=thread_count,
            max_retries=0,
        )
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    # ---- HTTP 请求 ----

    def _fetch(self, url: str, timeout: float) -> Optional[requests.Response]:
        """发送 GET 请求，支持 gzip 解压和重定向跟踪"""
        if self._stop_event and self._stop_event.is_set():
            return None
        try:
            response = self._session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            return response
        except requests.RequestException:
            return None

    # ---- URL 规范化 ----

    @staticmethod
    def _normalize_url(url: str, host: str, scheme: str, path_dir: str) -> str:
        """规范化 JS/URL 路径为完整 URL（照搬 URLFinder 的拼接策略）"""
        url = url.strip().strip("'").strip('"')

        if url.startswith(("https://", "http://")):
            return url
        if url.startswith("//"):
            return scheme + ":" + url
        if url.startswith("/"):
            return "%s://%s%s" % (scheme, host, url)
        return path_dir + url

    # ---- JS 提取与过滤 ----

    def _js_find(self, content: str, host: str, scheme: str, path_dir: str) -> List[str]:
        """从内容中提取 JS 链接"""
        results: List[str] = []
        for pattern in _JS_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                js_url = self._normalize_url(match, host, scheme, path_dir)
                if self._js_filter(js_url):
                    results.append(js_url)
        return results

    def _js_filter(self, url: str) -> bool:
        """JS 链接过滤器"""
        # 必须以 .js 结尾或包含 .js?
        if not (url.endswith(".js") or ".js?" in url):
            return False
        # 黑名单域名
        for pattern in _JS_FILTER_PATTERNS:
            if pattern.search(url):
                return False
        return True

    # ---- URL 提取与过滤 ----

    def _url_find(self, content: str, host: str, scheme: str, path_dir: str, source: str) -> List[str]:
        """从内容中提取 URL"""
        results: List[str] = []
        for pattern in _URL_PATTERNS:
            matches = pattern.findall(content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                url = self._normalize_url(match, host, scheme, path_dir)
                if self._url_filter(url, source):
                    results.append(url)
        return results

    def _url_filter(self, url: str, source: str) -> bool:
        """URL 链接过滤器"""
        # 必须包含至少一个字母或数字
        if not _URL_VALID_CHAR_RE.search(url):
            return False
        # 过滤静态资源后缀
        ext = _get_extension(url)
        if ext in STATIC_EXTENSIONS:
            return False
        # 过滤 JS 代码中常见的误提取模式
        for pattern in _URL_FILTER_PATTERNS:
            if pattern.search(url):
                return False
        return True

    # ---- 敏感信息提取 ----

    def _info_find(self, content: str, source: str) -> Dict[str, List[str]]:
        """从内容中提取所有类别敏感信息"""
        result: Dict[str, List[str]] = {}
        for key, (pattern, _label) in _SENSITIVE_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                cleaned: List[str] = []
                for m in matches:
                    if isinstance(m, tuple):
                        m = m[0] if m[0] else m[-1]
                    m = m.strip()
                    if not m:
                        continue
                    if key == "password":
                        m_lower = m.lower()
                        if m_lower in PASSWORD_PLACEHOLDERS:
                            continue
                        if re.match(r"<[^>]+>", m):
                            continue
                    if key == "internal_ip" and m in PUBLIC_IPS:
                        continue
                    if key == "ssh_key":
                        m = m.strip()[:200] + "..." if len(m) > 200 else m.strip()
                    cleaned.append(m)
                if cleaned:
                    # 去重
                    seen: Set[str] = set()
                    unique: List[str] = []
                    for item in cleaned:
                        if item not in seen:
                            unique.append(item)
                            seen.add(item)
                    result[key] = unique

        # 通用敏感信息匹配（宽松模式）
        generic_matches = _GENERIC_SENSITIVE_RE.findall(content)
        if generic_matches:
            generic_cleaned: List[str] = []
            for m in generic_matches:
                if isinstance(m, tuple):
                    m = m[0] if m[0] else m[-1]
                m = m.strip()
                if m and m.lower() not in PASSWORD_PLACEHOLDERS and len(m) >= 6:
                    generic_cleaned.append(m)
            if generic_cleaned:
                existing = result.get("api_key", [])
                seen_gen: Set[str] = set(existing)
                for item in generic_cleaned:
                    if item not in seen_gen:
                        existing.append(item)
                        seen_gen.add(item)
                if existing:
                    result["api_key"] = existing

        return result

    # ---- Spider（核心爬取函数，照搬 URLFinder crawler/crawler.go）----

    def _spider(self, url: str, depth: int, options: JsFindOptions, timeout: float, target: str) -> None:
        """爬取单个页面，提取 JS/URL/敏感信息，并决定是否递归"""
        if self._stop_event and self._stop_event.is_set():
            return

        # 暂停等待
        self._wait_if_paused()

        # 去重：已抓取过的页面跳过
        with self._lock:
            if url in self._crawled_pages:
                return
            self._crawled_pages.add(url)

        response = self._fetch(url, timeout)
        if response is None:
            return

        try:
            content = response.text or ""
        except Exception:
            content = ""

        if not content:
            return

        # 解析当前 URL 的各部分
        parsed = urlparse(url)
        host = parsed.netloc
        scheme = parsed.scheme
        path_dir = _extract_path_dir(url)

        # 检查 <base> 标签
        base_match = _BASE_HREF_RE.search(content)
        if base_match:
            base_url = base_match.group(1)
            base_parsed = urlparse(base_url)
            host = base_parsed.netloc or host
            scheme = base_parsed.scheme or scheme
            path_dir = _extract_path_dir(base_url) if base_url else path_dir

        # 提取
        js_links = self._js_find(content, host, scheme, path_dir)
        url_links = self._url_find(content, host, scheme, path_dir, url)
        info = self._info_find(content, url)

        # 记录敏感信息到对应来源
        with self._lock:
            for key, values in info.items():
                if url not in self._info_results:
                    self._info_results[url] = {}
                if key not in self._info_results[url]:
                    self._info_results[url][key] = []
                existing_set = set(self._info_results[url][key])
                for v in values:
                    if v not in existing_set:
                        self._info_results[url][key].append(v)
                        existing_set.add(v)

        # 记录 JS 和 URL 发现
        with self._lock:
            for js_url in js_links:
                if js_url not in self._seen_js:
                    self._seen_js.add(js_url)
                    self._js_results[js_url] = {"url": js_url, "source": url, "target": target}

            for found_url in url_links:
                if found_url not in self._seen_url:
                    self._seen_url.add(found_url)
                    self._url_results[found_url] = {"url": found_url, "source": url, "target": target}

        # 深入模式：递归抓取 JS
        if options.mode == "deep" and depth < options.js_depth:
            for js_url in js_links:
                if self._stop_event and self._stop_event.is_set():
                    return
                self._wait_if_paused()
                self._spider(js_url, depth + 1, options, timeout, target)

    # ---- 状态码验证 ----

    def _verify_links(
        self,
        options: JsFindOptions,
        timeout: float,
    ) -> None:
        """并发验证所有发现的链接状态码"""
        all_links: List[Dict[str, Any]] = []
        all_links.extend(self._js_results.values())
        all_links.extend(self._url_results.values())

        total = len(all_links)
        if total == 0:
            return

        self._report_status("开始验证 %d 个链接的状态码..." % total)

        completed = 0
        max_workers = min(max(1, options.thread_count), MAX_WORKERS)

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            future_map: Dict[Any, Dict[str, Any]] = {}
            link_iter = iter(all_links)
            exhausted = [False]

            def submit_next() -> bool:
                if exhausted[0] or (self._stop_event and self._stop_event.is_set()):
                    return False
                if self._wait_if_paused():
                    try:
                        link = next(link_iter)
                    except StopIteration:
                        exhausted[0] = True
                        return False
                    future = executor.submit(self._verify_single, link, timeout)
                    future_map[future] = link
                    return True
                return False

            while len(future_map) < max_workers and submit_next():
                pass

            while future_map:
                if self._stop_event and self._stop_event.is_set():
                    for future in future_map:
                        future.cancel()
                    break

                done_futures, _pending = wait(
                    future_map.keys(),
                    timeout=0.05,
                    return_when=FIRST_COMPLETED,
                )

                if not done_futures:
                    if self._wait_if_paused():
                        continue
                    break

                for future in done_futures:
                    link = future_map.pop(future)
                    completed += 1
                    try:
                        result = future.result()
                    except Exception:
                        result = None
                    if result is not None:
                        if self._result_callback:
                            self._result_callback(result)

                    # 进度回调
                    if completed == total or completed % max(1, total // 100) == 0:
                        if self._progress_callback:
                            self._progress_callback(int(completed * 100 / total))

                while len(future_map) < max_workers and submit_next():
                    pass

            if not (self._stop_event and self._stop_event.is_set()):
                if self._progress_callback:
                    self._progress_callback(100)
                self._report_status("扫描完成")
        finally:
            executor.shutdown(wait=False)

    def _verify_single(self, link: Dict[str, Any], timeout: float) -> Optional[JsFindResult]:
        """验证单个链接的状态码、长度、标题"""
        url = link["url"]
        target = link.get("target", "")
        source = link.get("source", "")

        if self._stop_event and self._stop_event.is_set():
            return None

        try:
            response = self._session.get(url, timeout=timeout, allow_redirects=True, stream=True)
        except requests.RequestException:
            return None

        status_code = response.status_code

        # 获取响应长度
        cl = response.headers.get("Content-Length")
        if cl is not None and cl.isdigit():
            response_length = int(cl)
        else:
            response_length = 0
            try:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        response_length += len(chunk)
                        if response_length > 102400:
                            break
            except Exception:
                pass

        # 提取标题
        title = ""
        try:
            content_type = response.headers.get("Content-Type", "").lower()
            if "html" in content_type and response_length < 102400:
                text = response.text or ""
                title_match = _TITLE_RE.search(text)
                if title_match:
                    title = title_match.group(1).strip()
        except Exception:
            pass

        # 敏感信息
        sensitive = self._info_results.get(url, self._info_results.get(source, {}))

        return JsFindResult(
            target=target,
            url=url,
            status_code=status_code,
            length=response_length,
            title=title,
            sensitive=sensitive,
        )

    # ---- 主扫描入口 ----

    def scan(
        self,
        options: JsFindOptions,
        stop_event: threading.Event,
        result_callback: Callable[[JsFindResult], None],
        status_callback: Callable[[str], None],
        pause_event: Optional[threading.Event] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> List[JsFindResult]:
        """执行 JSFinder 扫描"""
        self._stop_event = stop_event
        self._pause_event = pause_event
        self._result_callback = result_callback
        self._status_callback = status_callback
        self._progress_callback = progress_callback

        # 重置状态
        with self._lock:
            self._js_results.clear()
            self._url_results.clear()
            self._seen_js.clear()
            self._seen_url.clear()
            self._crawled_pages.clear()
            self._info_results.clear()

        timeout = max(options.timeout_ms, 100) / 1000.0
        self._setup_session(options.thread_count)

        base_urls = [url.rstrip("/") for url in options.base_urls]
        total_targets = len(base_urls)

        # ---- 阶段 1：爬取 ----
        self._report_status("开始爬取 %d 个目标..." % total_targets)

        for idx, base_url in enumerate(base_urls):
            if self._stop_event.is_set():
                break
            self._report_status("正在爬取 [%d/%d] %s" % (idx + 1, total_targets, base_url))
            self._spider(base_url, depth=1, options=options, timeout=timeout, target=base_url)

        if self._stop_event.is_set():
            self._report_status("扫描已停止")
            return []

        total_discovered = len(self._js_results) + len(self._url_results)
        self._report_status("爬取完成，发现 %d 个 JS、%d 个 URL，共 %d 个链接" % (
            len(self._js_results), len(self._url_results), total_discovered,
        ))

        # ---- 阶段 2：状态码验证 ----
        if total_discovered == 0:
            self._report_status("未发现任何链接，扫描结束")
            if self._progress_callback:
                self._progress_callback(100)
            return []

        self._verify_links(options, timeout)

        return []

    # ---- 内部辅助 ----

    def _wait_if_paused(self) -> bool:
        """暂停等待，返回 True 表示可继续，False 表示已停止"""
        if self._pause_event is None:
            return True
        while self._pause_event.is_set():
            if self._stop_event and self._stop_event.is_set():
                return False
            time.sleep(0.1)
        return True

    def _report_status(self, message: str) -> None:
        """向 UI 报告状态"""
        if self._status_callback:
            self._status_callback(message)


# ============================================================================
# 导出函数
# ============================================================================

def results_to_txt(results: Sequence[JsFindResult]) -> str:
    """将结果格式化为纯文本"""
    lines: List[str] = []
    for i, r in enumerate(results, 1):
        sensitive_str = _format_sensitive_summary(r.sensitive)
        lines.append(
            "[%d] %s | %d | %s | %d bytes | %s | %s" % (
                i, r.url, r.status_code, r.target, r.length, r.title, sensitive_str,
            )
        )
    return "\n".join(lines)


def results_to_csv(results: Sequence[JsFindResult]) -> str:
    """将结果格式化为 CSV"""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["序号", "目标", "URL", "状态码", "返回长度", "标题", "敏感信息"])
    for i, r in enumerate(results, 1):
        writer.writerow([
            str(i), _csv_safe(r.target), _csv_safe(r.url), str(r.status_code), str(r.length),
            _csv_safe(r.title), _format_sensitive_summary(r.sensitive),
        ])
    return output.getvalue()


def results_to_html(results: Sequence[JsFindResult]) -> str:
    """将结果格式化为 HTML 表格"""
    rows: List[str] = []
    for i, r in enumerate(results, 1):
        if 200 <= r.status_code < 300:
            status_class = "ok"
        elif 300 <= r.status_code < 400:
            status_class = "redirect"
        else:
            status_class = "error"
        sensitive_str = html_module.escape(_format_sensitive_summary(r.sensitive))
        rows.append(
            '<tr><td>%d</td><td>%s</td><td>%s</td><td class="%s">%d</td>'
            '<td>%d</td><td>%s</td><td>%s</td></tr>'
            % (i, html_module.escape(r.target), html_module.escape(r.url),
               status_class, r.status_code, r.length,
               html_module.escape(r.title), sensitive_str)
        )
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><title>JSFinder 结果</title>'
        '<style>body{font-family:Inter,-apple-system,sans-serif;background:#F5F6FA;padding:24px;}'
        'table{border-collapse:collapse;width:100%;background:rgba(255,255,255,0.9);border-radius:12px;overflow:hidden;}'
        'th{background:rgba(59,130,246,0.08);color:#1E293B;padding:10px 12px;text-align:left;font-weight:600;}'
        'td{padding:8px 12px;color:#1E293B;border-bottom:1px solid rgba(0,0,0,0.04);font-size:13px;}'
        '.ok{color:#22C55E;font-weight:500;}.redirect{color:#F59E0B;font-weight:500;}.error{color:#EF4444;font-weight:500;}'
        '</style></head><body><h2>JSFinder 扫描结果</h2><table>'
        '<tr><th>序号</th><th>目标</th><th>URL</th><th>状态码</th><th>返回长度</th><th>标题</th><th>敏感信息</th></tr>'
        + "".join(rows)
        + "</table></body></html>"
    )


def results_to_xlsx(results: Sequence[JsFindResult]) -> bytes:
    """将结果格式化为 XLSX 工作簿"""
    headers = ["序号", "目标", "URL", "状态码", "返回长度", "标题", "敏感信息"]
    column_letters = ["A", "B", "C", "D", "E", "F", "G"]

    rows_xml: List[str] = []
    header_cells = ""
    for letter, h in zip(column_letters, headers):
        header_cells += '<c r="%s1" t="inlineStr"><is><t>%s</t></is></c>' % (letter, _xlsx_escape(h))
    rows_xml.append('<row r="1">%s</row>' % header_cells)

    for i, r in enumerate(results, 1):
        values = [
            str(i), _xlsx_escape(_csv_safe(r.target)), _xlsx_escape(_csv_safe(r.url)),
            str(r.status_code), str(r.length),
            _xlsx_escape(_csv_safe(r.title)), _xlsx_escape(_format_sensitive_summary(r.sensitive)),
        ]
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
                    '<sheets><sheet name="JSFinder结果" sheetId="1" r:id="rId1"/></sheets></workbook>')
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


def _format_sensitive_summary(sensitive: Dict[str, List[str]]) -> str:
    """格式化敏感信息摘要"""
    if not sensitive:
        return ""
    parts: List[str] = []
    for key, label in SENSITIVE_LABELS.items():
        if key in sensitive and sensitive[key]:
            parts.append("%s:%d" % (label, len(sensitive[key])))
    return ", ".join(parts) if parts else ""
