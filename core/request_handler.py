"""
统一请求处理器 — 应用代理、UA、Header 配置
"""
import requests
from typing import Optional

from core.proxy import ProxyManager
from core.useragent import UserAgentManager
from core.settings import AppSettings


class RequestHandler:
    """统一 HTTP 请求处理器"""

    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._proxy = ProxyManager(settings)
        self._ua = UserAgentManager(settings)

    def _build_kwargs(self) -> dict:
        kwargs = {"timeout": self._build_timeout()}

        # 代理
        proxies = self._proxy.get_proxy_dict()
        if proxies:
            kwargs["proxies"] = proxies

        # Header — 模拟 Chrome 120 浏览器请求头，避免被服务器拒绝
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        }
        ua = self._ua.get_ua()
        if ua:
            headers["User-Agent"] = ua  # 用户配置的 UA 覆盖默认值
        custom_headers = self._settings.get("custom_headers", {})
        headers.update(custom_headers)  # 用户自定义 Header 可覆盖默认值
        kwargs["headers"] = headers

        return kwargs

    def _build_timeout(self) -> tuple:
        connect = self._settings.get("connect_timeout", 2000) / 1000.0
        read = self._settings.get("timeout", 3000) / 1000.0
        return (connect, read)

    def get(self, url: str, **extra) -> requests.Response:
        kwargs = self._build_kwargs()
        kwargs.update(extra)
        return requests.get(url, **kwargs)

    def post(self, url: str, data=None, json=None, **extra) -> requests.Response:
        kwargs = self._build_kwargs()
        kwargs.update(extra)
        return requests.post(url, data=data, json=json, **kwargs)

    @property
    def proxy_manager(self) -> ProxyManager:
        return self._proxy

    @property
    def ua_manager(self) -> UserAgentManager:
        return self._ua
