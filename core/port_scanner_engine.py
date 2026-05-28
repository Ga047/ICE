"""端口扫描核心引擎"""
import csv
import html
import ipaddress
import logging
import re
import socket
import threading
import time
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from io import BytesIO, StringIO
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import requests

from core._export_utils import _csv_safe
from core.request_handler import RequestHandler
from core.settings import AppSettings


TOP_100_PORT_TEXT = (
    "80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,5900,"
    "8888,81,10000,514,5060,2000,8443,8000,32768,554,1433,49152,2001,8008,"
    "49154,5666,5000,5631,49153,8081,2049,88,79,5800,2121,1110,49155,6000,"
    "513,990,5357,543,544,5101,389,8009,444,9999,5009,7070,5190,3000,5432,"
    "3986,1900,6646,5051,49157,873,1755,2717,4899,9100,82,83,85,888,1521,"
    "3443,4430,4433,4443,5443,5985,6379,7001,8001,8002,8003,8010,8082,8086,"
    "8088,8089,8090,9000,9043,9200,9443,10443,11211,27017"
)

TOP_1000_PORT_TEXT = (
    "21,22,23,25,53,69,80,81,88,89,110,135,161,445,139,137,143,389,443,512,"
    "513,514,548,873,1433,1521,2181,3306,3389,3690,4848,5000,5001,5432,5632,"
    "5900,5901,5902,6379,7000,7001,7002,8000,8001,8007,8008,8009,8069,8080,"
    "8081,8088,8089,8090,8091,9060,9090,9091,9200,9300,10000,11211,27017,"
    "27018,50000,1080,888,1158,2100,2424,2601,2604,3128,5984,7080,8010,8082,"
    "8083,8084,8085,8086,8087,8222,8443,8686,8888,9000,9001,9002,9003,9004,"
    "9005,9006,9007,9008,9009,9010,9043,9080,9081,9418,9999,50030,50060,50070,"
    "82,83,84,85,86,87,7003,7004,7005,7006,7007,7008,7009,7010,7070,7071,"
    "7072,7073,7074,7075,7076,7077,7078,7079,8002,8003,8004,8005,8006,8200,"
    "90,801,8011,8100,8012,8070,99,7777,8028,808,38888,8181,800,18080,8099,"
    "8899,8360,8300,8800,8180,3505,8053,1000,8989,28017,49166,3000,41516,"
    "880,8484,6677,8016,7200,9085,5555,8280,1980,8161,7890,8060,6080,8880,"
    "8020,889,8881,38501,1010,93,6666,100,6789,7060,8018,8022,3050,8787,"
    "2000,10001,8013,6888,8040,10021,2011,6006,4000,8055,4430,1723,6060,"
    "7788,8066,9898,6001,8801,10040,9998,803,6688,10080,8050,7011,40310,"
    "18090,802,10003,8014,2080,7288,8044,9992,8889,5644,8886,9500,58031,"
    "9020,8015,8887,8021,8700,91,9900,9191,3312,8186,8735,8380,1234,38080,"
    "9088,9988,2110,21245,3333,2046,9061,2375,9011,8061,8093,9876,8030,8282,"
    "60465,2222,98,1100,18081,70,8383,5155,92,8188,2517,8062,11324,2008,"
    "9231,999,28214,16080,8092,8987,8038,809,2010,8983,7700,3535,7921,9093,"
    "11080,6778,805,9083,8073,10002,114,2012,701,8810,8400,9099,8098,8808,"
    "20000,8065,8822,15000,9901,11158,1107,28099,12345,2006,9527,51106,688,"
    "25006,8045,8023,8029,9997,7048,8580,8585,2001,8035,10088,20022,4001,"
    "2013,20808,8095,106,3580,7742,8119,6868,32766,50075,7272,3380,3220,"
    "7801,5256,5255,10086,1300,5200,8096,6198,6889,3503,6088,9991,806,5050,"
    "8183,8688,1001,58080,1182,9025,8112,7776,7321,235,8077,8500,11347,7081,"
    "8877,8480,9182,58000,8026,11001,10089,5888,8196,8078,9995,2014,5656,"
    "8019,5003,8481,6002,9889,9015,8866,8182,8057,8399,10010,8308,511,12881,"
    "4016,8042,1039,28080,5678,7500,8051,18801,15018,15888,38443,8123,8144,"
    "94,9070,1800,9112,8990,3456,2051,9098,444,9131,97,7100,7711,7180,11000,"
    "8037,6988,122,8885,14007,8184,7012,8079,9888,9301,59999,49705,1979,"
    "8900,5080,5013,1550,8844,4850,206,5156,8813,3030,1790,8802,9012,5544,"
    "3721,8980,10009,8043,8390,7943,8381,8056,7111,1500,7088,5881,9437,5655,"
    "8102,6000,65486,4443,10025,8024,8333,8666,103,8,9666,8999,9111,8071,"
    "9092,522,11381,20806,8041,1085,8864,7900,1700,8036,8032,8033,8111,60022,"
    "955,3080,8788,7443,8192,6969,9909,5002,9990,188,8910,9022,10004,866,"
    "8582,4300,9101,6879,8891,4567,4440,10051,10068,50080,8341,30001,6890,"
    "8168,8955,16788,8190,18060,7041,42424,8848,15693,2521,19010,18103,6010,"
    "8898,9910,9190,9082,8260,8445,1680,8890,8649,30082,3013,30000,2480,"
    "7202,9704,5233,8991,11366,7888,8780,7129,6600,9443,47088,7791,18888,"
    "50045,15672,9089,2585,60,9494,31945,2060,8610,8860,58060,6118,2348,"
    "8097,38000,18880,13382,6611,8064,7101,5081,7380,7942,10016,8027,2093,"
    "403,9014,8133,6886,95,8058,9201,6443,5966,27000,7017,6680,8401,9036,"
    "8988,8806,6180,421,423,57880,7778,18881,812,15004,9110,8213,8868,1213,"
    "8193,8956,1108,778,65000,7020,1122,9031,17000,8039,8600,50090,1863,"
    "8191,65,6587,8136,9507,132,200,2070,308,5811,3465,8680,7999,7084,"
    "18082,3938,18001,9595,442,4433,7171,9084,7567,811,1128,6003,2125,6090,"
    "10007,7022,1949,6565,65001,1301,19244,10087,8025,5098,21080,1200,15801,"
    "1005,22343,7086,8601,6259,7102,10333,211,10082,18085,180,40000,7021,"
    "7702,66,38086,666,6603,1212,65493,96,9053,7031,23454,30088,6226,8660,"
    "6170,8972,9981,48080,9086,10118,40069,28780,20153,20021,20151,58898,"
    "10066,1818,9914,55351,8343,18000,6546,3880,8902,22222,19045,5561,7979,"
    "5203,8879,50240,49960,2007,1722,8913,8912,9504,8103,8567,1666,8720,"
    "8197,3012,8220,9039,5898,925,38517,8382,6842,8895,2808,447,3600,3606,"
    "9095,45177,19101,171,133,8189,7108,10154,47078,6800,8122,381,1443,"
    "15580,23352,3443,1180,268,2382,43651,10099,65533,7018,60010,60101,6699,"
    "2005,18002,2009,59777,591,1933,9013,8477,9696,9030,2015,7925,6510,"
    "18803,280,5601,2901,2301,5201,302,610,8031,5552,8809,6869,9212,17095,"
    "20001,8781,25024,5280,7909,17003,1088,7117,20052,1900,10038,30551,"
    "9980,9180,59009,28280,7028,61999,7915,8384,9918,9919,55858,7215,77,"
    "9845,20140,8288,7856,1982,1123,17777,8839,208,2886,877,6101,5100,804,"
    "983,5600,8402,5887,8322,770,13333,7330,3216,31188,47583,8710,22580,"
    "1042,2020,34440,20,7703,65055,8997,6543,6388,8283,7201,4040,61081,"
    "12001,3588,7123,2490,4389,1313,19080,9050,6920,299,20046,8892,9302,"
    "7899,30058,7094,6801,321,1356,12333,11362,11372,6602,7709,45149,3668,"
    "517,9912,9096,8130,7050,7713,40080,8104,13988,18264,8799,55070,23458,"
    "8176,9517,9541,9542,9512,8905,11660,1025,44445,44401,17173,436,560,"
    "733,968,602,3133,3398,16580,8488,8901,8512,10443,9113,9119,6606,22080,"
    "5560,7,5757,1600,8250,10024,10200,333,73,7547,8054,6372,223,3737,"
    "9800,9019,8067,45692,15400,15698,9038,37006,2086,1002,9188,8094,8201,"
    "8202,30030,2663,9105,10017,4503,1104,8893,40001,27779,3010,7083,5010,"
    "5501,309,1389,10070,10069,10056,3094,10057,10078,10050,10060,10098,"
    "4180,10777,270,6365,9801,1046,7140,1004,9198,8465,8548,108,30015,8153,"
    "1020,50100,8391,34899,7090,6100,8777,8298,8281,7023,3377,9100"
)

COMMON_WEB_PORTS = [
    80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9090, 5000, 3000, 7001,
    7002, 5601, 9200, 9443, 10443,
]

COMMON_DATABASE_PORTS = [
    1433, 1521, 3306, 5432, 6379, 27017, 27018, 9200, 9300, 11211, 50000, 9042,
]

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 139, 143,
    161, 389, 443, 445, 465, 514, 587, 631, 993, 995, 1080, 1433, 1521, 1723,
    2049, 3306, 3389, 5432, 5900, 5985, 6379, 7001, 8000, 8008, 8080, 8081,
    8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
]

TOP_100_PORTS = []
TOP_1000_PORTS = []

HTTP_PORTS = set([80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 800, 801, 802, 803, 804, 805, 806, 808, 8000, 8001, 8002, 8003, 8008, 8010, 8080, 8081, 8082, 8086, 8088, 8089, 8090, 8091, 8092, 8093, 8095, 8096, 8097, 8098, 8099, 8180, 8181, 8200, 8280, 8888, 9000, 9080, 9090, 9200])
HTTPS_PORTS = set([443, 444, 8443, 9443, 10443, 3443, 4430, 4433, 4443, 5443, 9043])
COMMON_UDP_PORTS = set([53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 1900, 5353])
MAX_SCAN_WORKERS = 256
MAX_APPLICATION_TIMEOUT = 1.5
SCAN_WAIT_INTERVAL = 0.05
MIN_PROGRESS_REPORT_STEP = 10
MAX_PROGRESS_REPORTS = 100

TCP_PROTOCOLS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    8080: "http",
    8443: "https",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

UDP_PROTOCOLS = {
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    161: "snmp",
    162: "snmptrap",
    500: "isakmp",
    1900: "ssdp",
    5353: "mdns",
}

BANNER_KEYWORDS = [
    ("openssh", "OpenSSH", "ssh"),
    ("ssh-", "SSH", "ssh"),
    ("nginx", "nginx", "http"),
    ("apache", "Apache", "http"),
    ("microsoft-iis", "Microsoft-IIS", "http"),
    ("redis", "Redis", "redis"),
    ("mysql", "MySQL", "mysql"),
    ("postgresql", "PostgreSQL", "postgresql"),
    ("mongodb", "MongoDB", "mongodb"),
    ("memcached", "Memcached", "memcached"),
    ("smtp", "SMTP", "smtp"),
    ("ftp", "FTP", "ftp"),
    ("dns", "DNS", "dns"),
]

TCP_PROBES = {
    "redis": b"PING\r\n",
    "memcached": b"version\r\n",
    "mongodb": b"\x3a\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",
    "smtp": b"\r\n",
    "pop3": b"\r\n",
    "imap": b"\r\n",
}

UDP_PROBES = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01",
    69: b"\x00\x01test\x00octet\x00",
    123: b"\x1b" + (b"\x00" * 47),
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x69\x6e\x67\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_local\x00\x00\x0c\x00\x01",
}


@dataclass
class PortScanResult:
    """单个开放端口扫描结果"""

    target: str
    host: str
    port: int
    transport: str
    protocol: str
    status_code: str
    web_title: str
    banner: str


PORT_SCAN_EXPORT_HEADERS = ["Target", "Host", "端口", "传输", "协议", "响应码", "Web标题", "Banner"]


def _unique_ports_from_text(port_text: str) -> List[int]:
    ports = []
    seen = set()
    for raw_part in port_text.split(","):
        raw_part = raw_part.strip()
        if not raw_part:
            continue
        port = int(raw_part)
        if 1 <= port <= 65535 and port not in seen:
            ports.append(port)
            seen.add(port)
    return ports


TOP_100_PORTS = _unique_ports_from_text(TOP_100_PORT_TEXT)
TOP_1000_PORTS = _unique_ports_from_text(TOP_1000_PORT_TEXT)


def parse_targets(text: str) -> List[str]:
    """解析目标地址，支持单 IP、域名、CIDR、IPv4 范围和多行输入"""
    targets = []
    seen = set()
    for raw_line in text.splitlines():
        target_text = raw_line.strip()
        if not target_text:
            continue
        expanded_targets = _expand_target(target_text)
        for target in expanded_targets:
            if target not in seen:
                targets.append(target)
                seen.add(target)
    if not targets:
        raise ValueError("请输入至少一个目标地址")
    return targets


def _expand_target(target_text: str) -> List[str]:
    if "/" in target_text:
        try:
            network = ipaddress.ip_network(target_text, strict=False)
        except ValueError:
            raise ValueError("CIDR 地址格式无效：%s" % target_text)
        return [str(host) for host in network.hosts()]

    if "-" in target_text and _looks_like_ipv4_range(target_text):
        return _expand_ipv4_range(target_text)

    if _is_ip_address(target_text) or _is_domain_name(target_text):
        return [target_text]

    raise ValueError("目标地址格式无效：%s" % target_text)


def _looks_like_ipv4_range(target_text: str) -> bool:
    parts = target_text.split("-", 1)
    return len(parts) == 2 and "." in parts[0] and "." in parts[1]


def _expand_ipv4_range(target_text: str) -> List[str]:
    start_text, end_text = [part.strip() for part in target_text.split("-", 1)]
    try:
        start_ip = ipaddress.IPv4Address(start_text)
        end_ip = ipaddress.IPv4Address(end_text)
    except ValueError:
        raise ValueError("IPv4 范围格式无效：%s" % target_text)
    if int(start_ip) > int(end_ip):
        raise ValueError("IPv4 范围起始地址不能大于结束地址：%s" % target_text)
    return [str(ipaddress.IPv4Address(value)) for value in range(int(start_ip), int(end_ip) + 1)]


def _is_ip_address(target_text: str) -> bool:
    try:
        ipaddress.ip_address(target_text)
        return True
    except ValueError:
        return False


def _is_domain_name(target_text: str) -> bool:
    if len(target_text) > 253 or " " in target_text:
        return False
    domain_pattern = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return bool(domain_pattern.match(target_text))


def parse_ports(text: str) -> List[int]:
    """解析端口表达式，支持逗号和范围"""
    ports = set()
    normalized_text = re.sub(r"[\s;]+", ",", text.strip())
    for raw_part in normalized_text.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = [value.strip() for value in part.split("-", 1)]
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError("端口范围格式无效：%s" % part)
            start_port = int(start_text)
            end_port = int(end_text)
            if start_port > end_port:
                raise ValueError("端口范围起始值不能大于结束值：%s" % part)
            for port in range(start_port, end_port + 1):
                _validate_port(port)
                ports.add(port)
        else:
            if not part.isdigit():
                raise ValueError("端口必须为数字：%s" % part)
            port = int(part)
            _validate_port(port)
            ports.add(port)
    if not ports:
        raise ValueError("请输入至少一个端口")
    return sorted(ports)


def ports_to_text(ports: Sequence[int]) -> str:
    """把端口列表转成输入框展示文本"""
    return ",".join(str(port) for port in ports)


def results_to_csv(results: Sequence[PortScanResult]) -> str:
    """把扫描结果序列化为 CSV 文本"""
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["Target", "Host", "端口", "传输", "协议", "响应码", "Web标题", "Banner"])
    for result in results:
        writer.writerow([
            result.target,
            result.host,
            result.port,
            result.transport,
            result.protocol,
            result.status_code,
            result.web_title,
            result.banner,
        ])
    return buffer.getvalue()


def _result_export_rows(results: Sequence[PortScanResult]) -> List[List[str]]:
    """把扫描结果转换为各导出格式共用的表格行"""
    rows = []
    for result in results:
        rows.append([
            _csv_safe(result.target),
            _csv_safe(result.host),
            str(result.port),
            result.transport,
            result.protocol,
            result.status_code,
            _csv_safe(result.web_title),
            _csv_safe(result.banner),
        ])
    return rows


def results_to_csv(results: Sequence[PortScanResult]) -> str:
    """把扫描结果序列化为 CSV 文本"""
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(PORT_SCAN_EXPORT_HEADERS)
    writer.writerows(_result_export_rows(results))
    return buffer.getvalue()


def results_to_txt(results: Sequence[PortScanResult]) -> str:
    """把扫描结果序列化为制表符分隔文本"""
    lines = ["\t".join(PORT_SCAN_EXPORT_HEADERS)]
    lines.extend("\t".join(row) for row in _result_export_rows(results))
    return "\n".join(lines) + "\n"


def results_to_html(results: Sequence[PortScanResult]) -> str:
    """把扫描结果序列化为 HTML 表格"""
    header_cells = "".join("<th>%s</th>" % html.escape(header) for header in PORT_SCAN_EXPORT_HEADERS)
    body_rows = []
    for row in _result_export_rows(results):
        cells = "".join("<td>%s</td>" % html.escape(value) for value in row)
        body_rows.append("<tr>%s</tr>" % cells)
    return (
        "<!doctype html>\n"
        "<html>\n"
        "<head><meta charset=\"utf-8\"><title>Port Scan Results</title></head>\n"
        "<body>\n"
        "<table>\n"
        "<thead><tr>%s</tr></thead>\n"
        "<tbody>\n%s\n</tbody>\n"
        "</table>\n"
        "</body>\n"
        "</html>\n"
    ) % (header_cells, "\n".join(body_rows))


def results_to_xlsx(results: Sequence[PortScanResult]) -> bytes:
    """使用标准库生成最小 XLSX 工作簿字节"""
    workbook = BytesIO()
    rows = [PORT_SCAN_EXPORT_HEADERS] + _result_export_rows(results)
    with zipfile.ZipFile(workbook, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _xlsx_content_types())
        archive.writestr("_rels/.rels", _xlsx_root_relationships())
        archive.writestr("xl/workbook.xml", _xlsx_workbook())
        archive.writestr("xl/_rels/workbook.xml.rels", _xlsx_workbook_relationships())
        archive.writestr("xl/worksheets/sheet1.xml", _xlsx_sheet(rows))
    return workbook.getvalue()


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
                % (cell_ref, html.escape(value))
            )
        sheet_rows.append("<row r=\"%s\">%s</row>" % (row_index, "".join(cells)))
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">"
        "<sheetData>%s</sheetData>"
        "</worksheet>"
    ) % "".join(sheet_rows)


def _validate_port(port: int):
    if port < 1 or port > 65535:
        raise ValueError("端口超出范围：%s" % port)


class PortScannerEngine:
    """端口扫描引擎，负责探活、端口扫描和结果增强"""

    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._request_handler = RequestHandler(settings)
        self._ttl_cache: Dict[str, Optional[int]] = {}
        self._scapy_available: Optional[bool] = None

    def scan(
        self,
        targets: Sequence[str],
        ports: Sequence[int],
        thread_count: int,
        timeout_ms: int,
        ping_enabled: bool,
        stop_event: threading.Event,
        result_callback: Callable[[PortScanResult], None],
        status_callback: Callable[[str], None],
        pause_event: Optional[threading.Event] = None,
    ) -> None:
        """按主机探活、TCP/UDP 探测、协议识别的顺序扫描目标"""
        timeout = max(timeout_ms, 100) / 1000.0
        udp_ports = [port for port in ports if port in COMMON_UDP_PORTS]
        jobs_per_target = len(ports) + len(udp_ports)
        total_jobs = len(targets) * jobs_per_target
        finished_jobs = 0
        status_callback(
            "准备扫描：%s 个目标，TCP %s 个端口，UDP %s 个常见端口"
            % (len(targets), len(ports), len(udp_ports))
        )

        scan_timeout = timeout
        application_timeout = min(timeout, MAX_APPLICATION_TIMEOUT)
        max_workers = self._effective_worker_count(thread_count)
        progress_step = self._progress_report_step(total_jobs)
        last_reported_progress = [0]

        with self._create_executor(max_workers) as executor:
            future_map = {}
            skipped_jobs = [0]
            exhausted_jobs = [False]

            def iter_jobs():
                for target in targets:
                    if stop_event.is_set():
                        return
                    if not self._wait_if_paused(pause_event, stop_event):
                        return
                    addresses = self._resolve_target(target)
                    if not addresses:
                        status_callback("目标解析失败，已跳过：%s" % target)
                        skipped_jobs[0] += jobs_per_target
                        continue
                    if ping_enabled and not self.is_host_alive(target, timeout, addresses):
                        status_callback("目标不存活，已跳过：%s" % target)
                        skipped_jobs[0] += jobs_per_target
                        continue
                    for port in ports:
                        if stop_event.is_set():
                            return
                        if not self._wait_if_paused(pause_event, stop_event):
                            return
                        yield target, addresses, port, "tcp"
                    for port in udp_ports:
                        if stop_event.is_set():
                            return
                        if not self._wait_if_paused(pause_event, stop_event):
                            return
                        yield target, addresses, port, "udp"

            job_iterator = iter_jobs()

            def submit_next_job() -> bool:
                if exhausted_jobs[0] or stop_event.is_set():
                    return False
                try:
                    target, addresses, port, transport = next(job_iterator)
                except StopIteration:
                    exhausted_jobs[0] = True
                    return False
                future = executor.submit(
                    self._scan_port,
                    target,
                    addresses,
                    port,
                    transport,
                    scan_timeout,
                    application_timeout,
                    stop_event,
                    result_callback,
                    status_callback,
                )
                future_map[future] = (target, port, transport)
                return True

            def report_progress(force: bool = False) -> None:
                if total_jobs <= 0:
                    return
                if (
                    force
                    or finished_jobs >= total_jobs
                    or finished_jobs - last_reported_progress[0] >= progress_step
                ):
                    last_reported_progress[0] = finished_jobs
                    status_callback("扫描进度：%s/%s" % (finished_jobs, total_jobs))

            while len(future_map) < max_workers and submit_next_job():
                pass
            finished_jobs += skipped_jobs[0]

            while future_map and not stop_event.is_set():
                done_futures, _pending_futures = wait(
                    future_map.keys(),
                    timeout=SCAN_WAIT_INTERVAL,
                    return_when=FIRST_COMPLETED,
                )
                if not done_futures:
                    continue

                for future in done_futures:
                    target, port, transport = future_map.pop(future)
                    finished_jobs += 1
                    try:
                        future.result()
                    except Exception as error:
                        status_callback("%s/%s:%s 扫描异常：%s" % (transport, target, port, error))
                    report_progress()

                previous_skipped_jobs = skipped_jobs[0]
                while len(future_map) < max_workers and submit_next_job():
                    pass
                if skipped_jobs[0] > previous_skipped_jobs:
                    finished_jobs += skipped_jobs[0] - previous_skipped_jobs
                    report_progress()

        if stop_event.is_set():
            status_callback("扫描已停止")
        else:
            report_progress(force=True)
            status_callback("扫描完成")

    def _wait_if_paused(
        self,
        pause_event: Optional[threading.Event],
        stop_event: threading.Event,
    ) -> bool:
        """暂停时等待，停止时立刻退出提交后续任务"""
        while pause_event is not None and pause_event.is_set():
            if stop_event.is_set():
                return False
            time.sleep(0.05)
        return not stop_event.is_set()

    def _effective_worker_count(self, thread_count: int) -> int:
        """限制有效线程数，避免过高并发拖慢系统和 UI"""
        return max(1, min(thread_count, MAX_SCAN_WORKERS))

    def _progress_report_step(self, total_jobs: int) -> int:
        """降低大批量扫描的进度回调频率，避免 UI 事件队列拥堵"""
        if total_jobs <= MIN_PROGRESS_REPORT_STEP:
            return 1
        return max(MIN_PROGRESS_REPORT_STEP, total_jobs // MAX_PROGRESS_REPORTS)

    def _create_executor(self, max_workers: int) -> ThreadPoolExecutor:
        """创建扫描线程池，便于测试调度参数"""
        return ThreadPoolExecutor(max_workers=max_workers)

    def _is_host_alive(
        self,
        host: str,
        timeout: float,
        addresses: Optional[Sequence[str]],
    ) -> bool:
        scan_addresses = list(addresses) if addresses is not None else self._resolve_target(host)
        for address in scan_addresses:
            ttl = self._probe_ttl(address, timeout)
            if ttl is not None:
                return True
        for port in [80, 443, 22, 3389, 445]:
            if self._tcp_connect_scan(host, port, timeout):
                return True
        return False

    def is_host_alive(
        self,
        host: str,
        timeout: float,
        addresses: Optional[Sequence[str]] = None,
    ) -> bool:
        """轻量探活，域名先解析，再用 ICMP/TCP ping 判定存活"""
        return self._is_host_alive(host, timeout, addresses)

    def estimate_os(self, host: str) -> str:
        """根据 TTL 做轻量 OS 估算"""
        addresses = self._resolve_target(host)
        ttl = self._probe_ttl(addresses[0], 1.0) if addresses else None
        if ttl is None:
            return "Unknown"
        if ttl <= 64:
            return "Linux/Unix"
        if ttl <= 128:
            return "Windows"
        return "Network Device"

    def _scan_port(
        self,
        host: str,
        addresses: Sequence[str],
        port: int,
        transport: str,
        scan_timeout: float,
        application_timeout: float,
        stop_event: threading.Event,
        result_callback: Callable[[PortScanResult], None],
        status_callback: Callable[[str], None],
    ) -> Optional[PortScanResult]:
        if stop_event.is_set():
            return None

        udp_payload = None
        if transport == "udp":
            udp_payload = self._scan_udp_port(host, addresses, port, scan_timeout)
            if udp_payload is None:
                return None
        elif not self._scan_tcp_port_open(host, addresses, port, scan_timeout):
            return None

        protocol_hint = self._default_protocol(port, transport)
        initial_result = PortScanResult(
            target=self._build_target(host, port, protocol_hint),
            host=host,
            port=port,
            transport=transport,
            protocol=protocol_hint,
            status_code="",
            web_title="",
            banner="",
        )
        result_callback(initial_result)

        protocol, status_code, web_title, banner = self._identify_application(
            host,
            port,
            transport,
            application_timeout,
            udp_payload,
        )
        final_result = PortScanResult(
            target=self._build_target(host, port, protocol),
            host=host,
            port=port,
            transport=transport,
            protocol=protocol,
            status_code=status_code,
            web_title=web_title,
            banner=banner,
        )
        result_callback(final_result)
        return final_result

    def _scan_tcp_port_open(
        self,
        host: str,
        addresses: Sequence[str],
        port: int,
        timeout: float,
    ) -> bool:
        syn_answer_seen = False
        for address in addresses:
            is_open = self._syn_scan(address, port, timeout)
            if is_open is True:
                return True
            if is_open is not None:
                syn_answer_seen = True
        if syn_answer_seen:
            return False
        return self._tcp_connect_scan(host, port, timeout)

    def _identify_application(
        self,
        host: str,
        port: int,
        transport: str,
        timeout: float,
        udp_payload: Optional[bytes],
    ) -> Tuple[str, str, str, str]:
        protocol_hint = self._default_protocol(port, transport)
        if transport == "udp":
            banner_text = _decode_banner(udp_payload or b"")
            banner_name, banner_protocol = _match_banner(banner_text)
            protocol = banner_protocol or protocol_hint
            banner = banner_name or _clean_banner(banner_text)
            return protocol, "", "", banner

        if protocol_hint in ["http", "https"] or port in HTTP_PORTS or port in HTTPS_PORTS:
            scheme, web_title, status_code, web_banner = self._probe_web(host, port, timeout)
            if scheme:
                return scheme, status_code, web_title, _normalize_banner(web_banner)

        banner_text = self._grab_tcp_banner(host, port, timeout, protocol_hint)
        banner_name, banner_protocol = _match_banner(banner_text)
        if not banner_protocol and protocol_hint == "unknown":
            scheme, web_title, status_code, web_banner = self._probe_web(host, port, timeout)
            if scheme:
                return scheme, status_code, web_title, _normalize_banner(web_banner)
        protocol = banner_protocol or protocol_hint
        banner = banner_name or _clean_banner(banner_text)
        return protocol, "", "", banner

    def _default_protocol(self, port: int, transport: str) -> str:
        if transport == "udp":
            if port in UDP_PROTOCOLS:
                return UDP_PROTOCOLS[port]
        elif port in TCP_PROTOCOLS:
            return TCP_PROTOCOLS[port]
        if port in HTTPS_PORTS:
            return "https"
        if port in HTTP_PORTS:
            return "http"
        try:
            return socket.getservbyport(port, transport)
        except OSError:
            return "unknown"

    def _detect_service(self, port: int) -> str:
        return self._default_protocol(port, "tcp")

    def _build_target(self, host: str, port: int, protocol: str) -> str:
        host_text = _format_url_host(host)
        if protocol in ["http", "https"]:
            return "%s://%s:%s" % (protocol, host_text, port)
        return "%s:%s" % (host_text, port)

    def _probe_web(self, host: str, port: int, timeout: float) -> Tuple[str, str, str, str]:
        if port in HTTPS_PORTS:
            schemes = ["https", "http"]
        else:
            schemes = ["http", "https"]
        for scheme in schemes:
            url = "%s://%s:%s/" % (scheme, _format_url_host(host), port)
            try:
                response = self._request_handler.get(
                    url,
                    timeout=(timeout, timeout),
                    allow_redirects=True,
                    verify=False,
                )
            except requests.RequestException:
                continue
            server_header = response.headers.get("Server", "")
            return scheme, _extract_title(response.text), str(response.status_code), server_header
        return "", "", "", ""

    def _grab_tcp_banner(
        self,
        host: str,
        port: int,
        timeout: float,
        protocol_hint: str,
    ) -> str:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                probe = TCP_PROBES.get(protocol_hint, b"")
                if probe:
                    sock.sendall(probe)
                try:
                    data = sock.recv(512)
                except socket.timeout:
                    return ""
        except OSError:
            return ""
        return _decode_banner(data)

    def _scan_udp_port(
        self,
        host: str,
        addresses: Sequence[str],
        port: int,
        timeout: float,
    ) -> Optional[bytes]:
        probe = UDP_PROBES.get(port, b"\x00")
        for address in addresses:
            family = socket.AF_INET6 if _detect_ip_version(address) == 6 else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            try:
                sock.settimeout(timeout)
                sock.sendto(probe, (address, port))
                data, _remote = sock.recvfrom(1024)
                if data:
                    return data
            except (OSError, socket.timeout):
                continue
            finally:
                sock.close()
        return None

    def _tcp_connect_scan(self, host: str, port: int, timeout: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def _syn_scan(self, host: str, port: int, timeout: float) -> Optional[bool]:
        if not self._can_use_scapy():
            return None
        try:
            from scapy.all import IP, IPv6, TCP, sr1  # type: ignore

            ip_version = _detect_ip_version(host)
            packet_ip = IPv6(dst=host) if ip_version == 6 else IP(dst=host)
            response = sr1(packet_ip / TCP(dport=port, flags="S"), timeout=timeout, verbose=False)
            if response is None:
                return None
            if not response.haslayer(TCP):
                return False
            tcp_layer = response.getlayer(TCP)
            flags = int(tcp_layer.flags)
            if flags & 0x12 == 0x12:
                return True
            if flags & 0x14 == 0x14:
                return False
            return False
        except Exception:
            self._scapy_available = False
            return None

    def _probe_ttl(self, host: str, timeout: float) -> Optional[int]:
        if host in self._ttl_cache:
            return self._ttl_cache[host]
        if not self._can_use_scapy():
            self._ttl_cache[host] = None
            return None
        try:
            from scapy.all import ICMP, ICMPv6EchoRequest, IP, IPv6, sr1  # type: ignore

            if _detect_ip_version(host) == 6:
                response = sr1(IPv6(dst=host) / ICMPv6EchoRequest(), timeout=timeout, verbose=False)
                ttl = int(response.hlim) if response is not None and hasattr(response, "hlim") else None
            else:
                response = sr1(IP(dst=host) / ICMP(), timeout=timeout, verbose=False)
                ttl = int(response.ttl) if response is not None and hasattr(response, "ttl") else None
        except Exception:
            self._scapy_available = False
            ttl = None
        self._ttl_cache[host] = ttl
        return ttl

    def _resolve_target(self, host: str) -> List[str]:
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass

        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []

        addresses = []
        seen = set()
        for record in records:
            address = record[4][0]
            if address not in seen:
                addresses.append(address)
                seen.add(address)
        return addresses

    def _can_use_scapy(self) -> bool:
        _quiet_scapy_runtime_warnings()
        if self._scapy_available is not None:
            return self._scapy_available
        try:
            from scapy.all import conf  # type: ignore

            conf.verb = 0

            self._scapy_available = True
        except Exception:
            self._scapy_available = False
        return self._scapy_available


def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


def _quiet_scapy_runtime_warnings() -> None:
    """静默 Scapy 找不到 MAC 时的运行时告警，避免污染界面/控制台输出。"""
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)


def _decode_banner(raw_data: bytes) -> str:
    """把协议响应转成适合展示和识别的短文本"""
    if not raw_data:
        return ""
    return raw_data.decode("utf-8", errors="ignore").replace("\x00", " ").strip()


def _match_banner(banner_text: str) -> Tuple[str, str]:
    """根据 banner 关键字识别产品名和应用层协议"""
    lowered_text = banner_text.lower()
    for keyword, banner_name, protocol in BANNER_KEYWORDS:
        if keyword in lowered_text:
            return banner_name, protocol
    return "", ""


def _clean_banner(banner_text: str) -> str:
    """清理 banner，避免表格中出现过长或多行内容"""
    if not banner_text:
        return ""
    return re.sub(r"\s+", " ", banner_text).strip()[:120]


def _normalize_banner(banner_text: str) -> str:
    banner_name, _protocol = _match_banner(banner_text)
    if banner_name:
        return banner_name
    return _clean_banner(banner_text)


def _format_url_host(host: str) -> str:
    try:
        ip_address = ipaddress.ip_address(host)
        if ip_address.version == 6:
            return "[%s]" % host
    except ValueError:
        pass
    return host


def _detect_ip_version(host: str) -> int:
    try:
        return ipaddress.ip_address(host).version
    except ValueError:
        return 4
