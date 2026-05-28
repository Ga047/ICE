"""子域名挖掘核心引擎"""
import csv
import html
import ipaddress
import os
import random
import re
import socket
import struct
import threading
import time
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from io import BytesIO, StringIO
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import requests

from core._export_utils import _csv_safe
from core.request_handler import RequestHandler
from core.settings import AppSettings


DNS_SERVER_OPTIONS = [
    "随机DNS",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "9.9.9.10",
    "149.112.112.112",
    "4.2.2.1",
    "4.2.2.2",
    "4.2.2.3",
    "4.2.2.4",
    "4.2.2.5",
    "4.2.2.6",
    "1.1.1.1",
    "1.0.0.1",
    "1.0.0.2",
    "1.0.0.3",
    "1.0.0.19",
    "208.67.222.222",
    "208.67.220.220",
    "8.26.56.26",
    "8.20.247.20",
    "84.200.69.80",
    "84.200.70.40",
    "185.228.168.9",
    "185.228.169.9",
    "64.6.64.6",
    "64.6.65.6",
    "198.101.242.72",
    "23.253.163.53",
    "176.103.130.130",
    "176.103.130.131",
    "223.5.5.5",
    "223.6.6.6",
    "114.114.114.114",
    "114.114.115.115",
    "180.76.76.76",
    "119.29.29.29",
    "182.254.116.116",
]

DICTIONARY_LABELS = {
    "subdomains-100.txt": "Top100",
    "subdomains-500.txt": "Top500",
    "subdomains-1000.txt": "Top1000",
    "subdomains-10000.txt": "Top10000",
    "subnames.txt": "标准",
    "subnames_medium.txt": "中型",
    "subnames_big.txt": "大型",
}

DICTIONARY_ORDER = [
    "Top100",
    "Top500",
    "Top1000",
    "Top10000",
    "标准",
    "中型",
    "大型",
]

HTTPS_PORTS = set([443, 8443, 9443, 10443, 4433, 4443])
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
SUBNAME_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RESULT_FLUSH_INTERVAL = 0.05
MAX_WORKERS = 512
WILDCARD_SAMPLE_COUNT = 3


@dataclass
class DNSResolution:
    """DNS A 记录解析结果"""

    ips: List[str]
    ttl: int
    resolver: str


@dataclass
class SubdomainScanOptions:
    """子域名爆破配置"""

    domains: Sequence[str]
    dictionary_paths: Sequence[str]
    thread_count: int = 200
    timeout_ms: int = 3000
    depth: int = 1
    dns_provider: str = "223.5.5.5"
    ports: Sequence[int] = (80, 443)
    filtered_ips: Sequence[str] = ("127.0.0.1",)
    ip_appear_limit: int = 100


@dataclass
class SubdomainScanResult:
    """单个子域名扫描结果"""

    main_domain: str
    subdomain: str
    ips: List[str]
    open_ports: List[int]
    banner: str
    title: str


def parse_domains(text: str) -> List[str]:
    """解析多行域名输入，去重并统一小写"""
    domains = []
    seen = set()
    for raw_line in text.splitlines():
        domain = _normalize_domain(raw_line)
        if not domain:
            continue
        if not DOMAIN_PATTERN.match(domain):
            raise ValueError("域名格式无效：%s" % raw_line.strip())
        if domain not in seen:
            domains.append(domain)
            seen.add(domain)
    if not domains:
        raise ValueError("请输入至少一个域名")
    return domains


def parse_ports(text: str) -> List[int]:
    """解析端口表达式，支持逗号、空白、分号和范围"""
    ports = set()
    normalized_text = re.sub(r"[\s;]+", ",", text.strip())
    for raw_part in normalized_text.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = [value.strip() for value in part.split("-", 1)]
            _validate_port_text(start_text, "端口范围格式无效：%s" % part)
            _validate_port_text(end_text, "端口范围格式无效：%s" % part)
            start_port = int(start_text)
            end_port = int(end_text)
            if start_port > end_port:
                raise ValueError("端口范围起始值不能大于结束值：%s" % part)
            for port in range(start_port, end_port + 1):
                _validate_port(port)
                ports.add(port)
        else:
            _validate_port_text(part, "端口必须为数字：%s" % part)
            port = int(part)
            _validate_port(port)
            ports.add(port)
    if not ports:
        raise ValueError("请输入至少一个端口")
    return sorted(ports)


def parse_filter_ips(text: str) -> List[str]:
    """解析需要过滤的 IP 列表"""
    ips = []
    seen = set()
    normalized_text = re.sub(r"[\s;]+", ",", text.strip())
    for raw_part in normalized_text.split(","):
        ip_text = raw_part.strip()
        if not ip_text:
            continue
        try:
            normalized_ip = str(ipaddress.ip_address(ip_text))
        except ValueError:
            raise ValueError("过滤 IP 格式无效：%s" % ip_text)
        if normalized_ip not in seen:
            ips.append(normalized_ip)
            seen.add(normalized_ip)
    return ips


def load_dictionary(path: str) -> List[str]:
    """读取子域名字典，过滤空行、重复项和非法片段"""
    words = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as dict_file:
        for raw_line in dict_file:
            word = raw_line.strip().lower().strip(".")
            if not word or not _is_valid_subname(word):
                continue
            if word not in seen:
                words.append(word)
                seen.add(word)
    if not words:
        raise ValueError("字典内容为空或无有效子域名片段：%s" % path)
    return words


def discover_dictionary_options(base_dir: str) -> List[Tuple[str, str]]:
    """发现资源目录里的内置子域名字典"""
    if not os.path.isdir(base_dir):
        return []
    options = []
    for filename in os.listdir(base_dir):
        path = os.path.join(base_dir, filename)
        if not os.path.isfile(path) or not filename.lower().endswith(".txt"):
            continue
        if filename not in DICTIONARY_LABELS:
            continue
        label = DICTIONARY_LABELS[filename]
        options.append((label, path))
    order_map = {label: index for index, label in enumerate(DICTIONARY_ORDER)}
    return sorted(options, key=lambda item: (order_map.get(item[0], 999), item[0]))


def results_to_csv(results: Sequence[SubdomainScanResult]) -> str:
    """把子域名结果序列化为 CSV 文本"""
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["主域名", "子域名", "IP", "开放端口", "Banner", "标题"])
    for result in results:
        writer.writerow(_result_values(result))
    return buffer.getvalue()


def results_to_txt(results: Sequence[SubdomainScanResult]) -> str:
    """把子域名结果序列化为纯文本列表"""
    return "\n".join(result.subdomain for result in results) + ("\n" if results else "")


def results_to_html(results: Sequence[SubdomainScanResult]) -> str:
    """把子域名结果序列化为 HTML 表格"""
    headers = ["主域名", "子域名", "IP", "开放端口", "Banner", "标题"]
    rows = []
    for result in results:
        cells = "".join("<td>%s</td>" % html.escape(str(value)) for value in _result_values(result))
        rows.append("<tr>%s</tr>" % cells)
    header_cells = "".join("<th>%s</th>" % html.escape(header) for header in headers)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>子域名挖掘结果</title>"
        "<style>body{font-family:Segoe UI,Microsoft YaHei,sans-serif;color:#1E293B;}"
        "table{border-collapse:collapse;width:100%%;}th,td{border:1px solid #CBD5E1;"
        "padding:8px;text-align:left;}th{background:#E2E8F0;}</style></head><body>"
        "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></body></html>"
        % (header_cells, "".join(rows))
    )


def results_to_xlsx(results: Sequence[SubdomainScanResult]) -> bytes:
    """使用标准库生成最小 XLSX 工作簿字节"""
    workbook = BytesIO()
    rows = [["主域名", "子域名", "IP", "开放端口", "Banner", "标题"]]
    rows.extend(_result_values(result) for result in results)
    with zipfile.ZipFile(workbook, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _xlsx_content_types())
        archive.writestr("_rels/.rels", _xlsx_root_relationships())
        archive.writestr("xl/workbook.xml", _xlsx_workbook())
        archive.writestr("xl/_rels/workbook.xml.rels", _xlsx_workbook_relationships())
        archive.writestr("xl/worksheets/sheet1.xml", _xlsx_sheet(rows))
    return workbook.getvalue()


class SubdomainScannerEngine:
    """子域名爆破引擎，负责生成、解析、过滤和端口探测"""

    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._request_handler = RequestHandler(settings)

    def scan(
        self,
        options: SubdomainScanOptions,
        stop_event: threading.Event,
        result_callback: Callable[[SubdomainScanResult], None],
        status_callback: Callable[[str], None],
        pause_event: Optional[threading.Event] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> List[SubdomainScanResult]:
        """执行子域名字典爆破"""
        domains = [domain.lower() for domain in options.domains]
        dictionary = self._load_dictionaries(options.dictionary_paths)
        timeout = max(options.timeout_ms, 100) / 1000.0
        nameservers = nameservers_for_server(options.dns_provider)
        results_by_subdomain: Dict[str, SubdomainScanResult] = {}
        max_workers = self._effective_worker_count(options.thread_count)
        progress = progress_callback or (lambda _value: None)
        progress(0)

        for domain in domains:
            if stop_event.is_set():
                break
            status_callback("开始爆破：%s" % domain)
            wildcard_ips, wildcard_ttl = self._collect_wildcard_baseline(domain, nameservers, timeout)
            parents = [domain]
            seen_candidates: Set[str] = set()
            for layer_index in range(max(1, min(options.depth, 3))):
                if stop_event.is_set():
                    break
                candidates = self._build_candidates(parents, dictionary, seen_candidates)
                if not candidates:
                    break
                status_callback(
                    "第 %s 层候选：%s 个" % (layer_index + 1, len(candidates))
                )
                resolutions = self._resolve_candidates(
                    candidates,
                    nameservers,
                    timeout,
                    max_workers,
                    stop_event,
                    pause_event,
                    status_callback,
                    progress,
                )
                ip_counts = self._count_ips(resolutions.values())
                next_parents = []
                valid_results = []
                for candidate in candidates:
                    resolution = resolutions.get(candidate)
                    if resolution is None:
                        continue
                    if not self._is_resolution_allowed(
                        resolution,
                        set(options.filtered_ips),
                        wildcard_ips,
                        wildcard_ttl,
                        ip_counts,
                        options.ip_appear_limit,
                    ):
                        continue
                    result = SubdomainScanResult(
                        main_domain=domain,
                        subdomain=candidate,
                        ips=resolution.ips,
                        open_ports=[],
                        banner="",
                        title="",
                    )
                    results_by_subdomain[candidate] = result
                    valid_results.append(result)
                    next_parents.append(candidate)
                    result_callback(result)
                self._enrich_results(
                    valid_results,
                    options.ports,
                    timeout,
                    max_workers,
                    stop_event,
                    pause_event,
                    result_callback,
                    results_by_subdomain,
                )
                parents = next_parents
                if not parents:
                    break
        if stop_event.is_set():
            status_callback("爆破已停止")
        else:
            progress(100)
            status_callback("爆破完成")
        return list(results_by_subdomain.values())

    def _load_dictionaries(self, paths: Sequence[str]) -> List[str]:
        words = []
        seen = set()
        for path in paths:
            for word in load_dictionary(path):
                if word not in seen:
                    words.append(word)
                    seen.add(word)
        if not words:
            raise ValueError("请选择至少一个有效字典")
        return words

    def _build_candidates(
        self,
        parents: Sequence[str],
        words: Sequence[str],
        seen_candidates: Set[str],
    ) -> List[str]:
        candidates = []
        for parent in parents:
            for word in words:
                candidate = "%s.%s" % (word, parent)
                if candidate not in seen_candidates:
                    candidates.append(candidate)
                    seen_candidates.add(candidate)
        return candidates

    def _resolve_candidates(
        self,
        candidates: Sequence[str],
        nameservers: Sequence[str],
        timeout: float,
        max_workers: int,
        stop_event: threading.Event,
        pause_event: Optional[threading.Event],
        status_callback: Callable[[str], None],
        progress_callback: Callable[[int], None],
    ) -> Dict[str, DNSResolution]:
        resolutions: Dict[str, DNSResolution] = {}
        total = len(candidates)
        finished = 0
        progress_step = max(1, total // 100)

        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            future_map = {}
            candidate_iter = iter(candidates)
            exhausted = [False]

            def submit_next() -> bool:
                if exhausted[0] or stop_event.is_set():
                    return False
                if not self._wait_if_paused(pause_event, stop_event):
                    return False
                try:
                    candidate = next(candidate_iter)
                except StopIteration:
                    exhausted[0] = True
                    return False
                future = executor.submit(self._query_a_records, candidate, nameservers, timeout)
                future_map[future] = candidate
                return True

            while len(future_map) < max_workers and submit_next():
                pass

            while future_map and not stop_event.is_set():
                done_futures, _pending = wait(
                    future_map.keys(),
                    timeout=RESULT_FLUSH_INTERVAL,
                    return_when=FIRST_COMPLETED,
                )
                if not done_futures:
                    continue
                for future in done_futures:
                    candidate = future_map.pop(future)
                    finished += 1
                    try:
                        resolution = future.result()
                    except Exception as error:
                        status_callback("%s 解析异常：%s" % (candidate, error))
                        resolution = None
                    if resolution is not None:
                        resolutions[candidate] = resolution
                    if finished == total or finished % progress_step == 0:
                        progress_callback(int(finished * 100 / total))
                while len(future_map) < max_workers and submit_next():
                    pass
            if stop_event.is_set():
                for future in future_map:
                    future.cancel()
        finally:
            executor.shutdown(wait=False)
        return resolutions

    def _enrich_results(
        self,
        results: Sequence[SubdomainScanResult],
        ports: Sequence[int],
        timeout: float,
        max_workers: int,
        stop_event: threading.Event,
        pause_event: Optional[threading.Event],
        result_callback: Callable[[SubdomainScanResult], None],
        results_by_subdomain: Dict[str, SubdomainScanResult],
    ) -> None:
        if not results or not ports or stop_event.is_set():
            return
        jobs = []
        for result in results:
            for port in ports:
                jobs.append((result, port))
        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            future_map = {}
            job_iter = iter(jobs)
            exhausted = [False]

            def submit_next() -> bool:
                if exhausted[0] or stop_event.is_set():
                    return False
                if not self._wait_if_paused(pause_event, stop_event):
                    return False
                try:
                    result, port = next(job_iter)
                except StopIteration:
                    exhausted[0] = True
                    return False
                future = executor.submit(self._probe_http_port, result.subdomain, port, timeout)
                future_map[future] = (result, port)
                return True

            while len(future_map) < max_workers and submit_next():
                pass
            while future_map and not stop_event.is_set():
                done_futures, _pending = wait(
                    future_map.keys(),
                    timeout=RESULT_FLUSH_INTERVAL,
                    return_when=FIRST_COMPLETED,
                )
                if not done_futures:
                    continue
                for future in done_futures:
                    result, port = future_map.pop(future)
                    try:
                        probe_result = future.result()
                    except Exception:
                        probe_result = None
                    if probe_result is not None:
                        banner, title = probe_result
                        self._merge_port_result(result, port, banner, title)
                        results_by_subdomain[result.subdomain] = result
                        result_callback(result)
                while len(future_map) < max_workers and submit_next():
                    pass
            if stop_event.is_set():
                for future in future_map:
                    future.cancel()
        finally:
            executor.shutdown(wait=False)

    def _merge_port_result(
        self,
        result: SubdomainScanResult,
        port: int,
        banner: str,
        title: str,
    ) -> None:
        if port not in result.open_ports:
            result.open_ports.append(port)
            result.open_ports.sort()
        if banner and not result.banner:
            result.banner = banner
        if title and not result.title:
            result.title = title

    def _collect_wildcard_baseline(
        self,
        domain: str,
        nameservers: Sequence[str],
        timeout: float,
    ) -> Tuple[Set[str], Optional[int]]:
        wildcard_ips = set()
        wildcard_ttl = None
        for _index in range(WILDCARD_SAMPLE_COUNT):
            token = "%08x" % random.getrandbits(32)
            qname = "%s.%s" % (token, domain)
            resolution = self._query_a_records(qname, nameservers, timeout)
            if resolution is None:
                continue
            wildcard_ips.update(resolution.ips)
            wildcard_ttl = resolution.ttl
        return wildcard_ips, wildcard_ttl

    def _query_a_records(
        self,
        qname: str,
        nameservers: Sequence[str],
        timeout: float,
    ) -> Optional[DNSResolution]:
        query_id = random.randint(0, 65535)
        payload = _build_dns_query(qname, query_id)
        shuffled_nameservers = list(nameservers)
        random.shuffle(shuffled_nameservers)
        for nameserver in shuffled_nameservers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(payload, (nameserver, 53))
                data, _remote = sock.recvfrom(4096)
            except OSError:
                continue
            finally:
                try:
                    sock.close()
                except UnboundLocalError:
                    pass
            parsed = _parse_dns_a_response(data, query_id)
            if parsed is None:
                continue
            ips, ttl = parsed
            if ips:
                return DNSResolution(ips=ips, ttl=ttl, resolver=nameserver)
        return None

    def _probe_http_port(
        self,
        subdomain: str,
        port: int,
        timeout: float,
    ) -> Optional[Tuple[str, str]]:
        if not self._scan_tcp_port_open(subdomain, port, timeout):
            return None
        scheme = "https" if port in HTTPS_PORTS else "http"
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            url = "%s://%s/" % (scheme, subdomain)
        else:
            url = "%s://%s:%s/" % (scheme, subdomain, port)
        try:
            response = self._request_handler.get(
                url,
                timeout=(timeout, timeout),
                allow_redirects=True,
                verify=False,
            )
        except requests.RequestException:
            return "", ""
        response.encoding = response.apparent_encoding
        banner = _extract_banner(response.headers)
        title = _extract_title(response.text)
        return banner, title

    def _scan_tcp_port_open(self, host: str, port: int, timeout: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _count_ips(self, resolutions: Iterable[DNSResolution]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for resolution in resolutions:
            for ip_text in resolution.ips:
                counts[ip_text] = counts.get(ip_text, 0) + 1
        return counts

    def _is_resolution_allowed(
        self,
        resolution: DNSResolution,
        filtered_ips: Set[str],
        wildcard_ips: Set[str],
        wildcard_ttl: Optional[int],
        ip_counts: Dict[str, int],
        ip_appear_limit: int,
    ) -> bool:
        if not resolution.ips:
            return False
        for ip_text in resolution.ips:
            if ip_text in filtered_ips:
                return False
            if ip_counts.get(ip_text, 0) > ip_appear_limit:
                return False
        if wildcard_ips and wildcard_ttl is not None:
            if all(ip_text in wildcard_ips for ip_text in resolution.ips) and resolution.ttl == wildcard_ttl:
                return False
        return True

    def _effective_worker_count(self, thread_count: int) -> int:
        return max(1, min(thread_count, MAX_WORKERS))

    def _wait_if_paused(
        self,
        pause_event: Optional[threading.Event],
        stop_event: threading.Event,
    ) -> bool:
        while pause_event is not None and pause_event.is_set():
            if stop_event.is_set():
                return False
            time.sleep(0.05)
        return not stop_event.is_set()


def nameservers_for_server(server: str) -> List[str]:
    """根据选中的 DNS 服务器 IP 返回解析器列表"""
    if server == "随机DNS":
        valid_servers = []
        for entry in DNS_SERVER_OPTIONS:
            if entry == "随机DNS":
                continue
            try:
                ipaddress.ip_address(entry)
                valid_servers.append(entry)
            except ValueError:
                pass
        if not valid_servers:
            return ["223.5.5.5"]
        return random.sample(valid_servers, min(5, len(valid_servers)))
    try:
        normalized_server = str(ipaddress.ip_address(server.strip()))
    except ValueError:
        return ["223.5.5.5"]
    return [normalized_server]


def nameservers_for_provider(provider: str) -> List[str]:
    """兼容旧调用：直接按 DNS 服务器 IP 处理"""
    return nameservers_for_server(provider)


def _normalize_domain(raw_text: str) -> str:
    text = raw_text.strip().lower()
    if not text:
        return ""
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0]
    if ":" in text:
        text = text.split(":", 1)[0]
    return text.strip(".")


def _validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError("端口超出范围：%s" % port)


def _validate_port_text(port_text: str, message: str) -> None:
    if not port_text.isdigit():
        raise ValueError(message)
    if len(port_text) > 1 and port_text[0] == "0":
        raise ValueError("端口 \"%s\" 含多余前导零，请改为 \"%s\"。" % (port_text, port_text.lstrip("0")))


def _is_valid_subname(word: str) -> bool:
    labels = word.split(".")
    for label in labels:
        if not SUBNAME_LABEL_PATTERN.match(label):
            return False
    return True


def _result_values(result: SubdomainScanResult) -> List[str]:
    return [
        _csv_safe(result.main_domain),
        _csv_safe(result.subdomain),
        ",".join(result.ips),
        ",".join(str(port) for port in result.open_ports),
        _csv_safe(result.banner),
        _csv_safe(result.title),
    ]


def _xlsx_content_types() -> str:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
        "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
        "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
        "<Override PartName=\"/xl/workbook.xml\" "
        "ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>"
        "<Override PartName=\"/xl/worksheets/sheet1.xml\" "
        "ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"
        "</Types>"
    )


def _xlsx_root_relationships() -> str:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        "<Relationship Id=\"rId1\" "
        "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" "
        "Target=\"xl/workbook.xml\"/>"
        "</Relationships>"
    )


def _xlsx_workbook() -> str:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" "
        "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">"
        "<sheets><sheet name=\"Results\" sheetId=\"1\" r:id=\"rId1\"/></sheets>"
        "</workbook>"
    )


def _xlsx_workbook_relationships() -> str:
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        "<Relationship Id=\"rId1\" "
        "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" "
        "Target=\"worksheets/sheet1.xml\"/>"
        "</Relationships>"
    )


def _xlsx_sheet(rows: Sequence[Sequence[str]]) -> str:
    sheet_rows = []
    for row_index, row in enumerate(rows, start=1):
        cells = []
        for column_index, value in enumerate(row):
            cell_ref = "%s%s" % (chr(ord("A") + column_index), row_index)
            cells.append(
                "<c r=\"%s\" t=\"inlineStr\"><is><t>%s</t></is></c>"
                % (cell_ref, html.escape(str(value)))
            )
        sheet_rows.append("<row r=\"%s\">%s</row>" % (row_index, "".join(cells)))
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
        "<sheetData>%s</sheetData>"
        "</worksheet>"
    ) % "".join(sheet_rows)


def _build_dns_query(qname: str, query_id: int) -> bytes:
    labels = qname.strip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return header + question + struct.pack("!HH", 1, 1)


def _parse_dns_a_response(data: bytes, query_id: int) -> Optional[Tuple[List[str], int]]:
    if len(data) < 12:
        return None
    response_id, flags, question_count, answer_count, _ns_count, _ar_count = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if response_id != query_id or flags & 0x000F != 0:
        return None
    offset = 12
    try:
        for _index in range(question_count):
            offset = _skip_dns_name(data, offset)
            offset += 4
        ips = []
        ttls = []
        for _index in range(answer_count):
            offset = _skip_dns_name(data, offset)
            record_type, record_class, ttl, length = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            record_data = data[offset:offset + length]
            offset += length
            if record_type == 1 and record_class == 1 and length == 4:
                ips.append(socket.inet_ntoa(record_data))
                ttls.append(ttl)
    except (struct.error, IndexError):
        return None
    if not ips:
        return None
    return ips, min(ttls) if ttls else 0


def _skip_dns_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def _extract_title(html_text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


def _extract_banner(headers: Dict[str, str]) -> str:
    values = []
    for key in ["Server", "Via", "X-Powered-By"]:
        value = headers.get(key)
        if value:
            values.append(value)
    return ",".join(values)[:120]
