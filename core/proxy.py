"""
代理管理器 - 支持 HTTP / SOCKS4 / SOCKS5
"""
from typing import Dict, Optional, Tuple
from urllib.parse import quote


class ProxyManager:
    """统一代理配置管理"""

    _SCHEME_MAP = {
        "http": "http",
        "socks4": "socks4a",
        "socks5": "socks5h",
    }

    def __init__(self, settings):
        from core.settings import AppSettings
        self._settings: AppSettings = settings

    def is_enabled(self) -> bool:
        return self._settings.get("proxy_enabled", False)

    @classmethod
    def build_proxy_url(
        cls,
        proxy_type: str,
        host: str,
        port: int,
        proxy_auth: bool = False,
        proxy_user: str = "",
        proxy_pass: str = "",
    ) -> Optional[str]:
        """根据参数构造代理 URL。SOCKS4/5 使用远端 DNS 解析。"""
        host_text = (host or "").strip()
        if not host_text:
            return None

        scheme = cls._SCHEME_MAP.get((proxy_type or "http").lower(), "http")
        auth = ""
        if proxy_auth:
            user_encoded = quote(proxy_user or "", safe="")
            pass_encoded = quote(proxy_pass or "", safe="")
            auth = "{0}:{1}@".format(user_encoded, pass_encoded)

        return "{0}://{1}{2}:{3}".format(scheme, auth, host_text, port)

    @classmethod
    def build_proxy_dict(
        cls,
        proxy_type: str,
        host: str,
        port: int,
        proxy_auth: bool = False,
        proxy_user: str = "",
        proxy_pass: str = "",
    ) -> Optional[Dict[str, str]]:
        """返回 requests 兼容的代理字典。"""
        url = cls.build_proxy_url(
            proxy_type=proxy_type,
            host=host,
            port=port,
            proxy_auth=proxy_auth,
            proxy_user=proxy_user,
            proxy_pass=proxy_pass,
        )
        if not url:
            return None
        return {"http": url, "https": url}

    def get_proxy_dict(self) -> Optional[Dict[str, str]]:
        """返回 requests 库兼容的代理字典。"""
        if not self.is_enabled():
            return None

        return self.build_proxy_dict(
            proxy_type=self._settings.get("proxy_type", "HTTP"),
            host=self._settings.get("proxy_host", ""),
            port=self._settings.get("proxy_port", 1080),
            proxy_auth=self._settings.get("proxy_auth", False),
            proxy_user=self._settings.get("proxy_user", ""),
            proxy_pass=self._settings.get("proxy_pass", ""),
        )

    def get_socks_proxy(self) -> Optional[Tuple[int, str, int]]:
        """返回 PySocks 兼容的代理配置。"""
        if not self.is_enabled():
            return None

        host = self._settings.get("proxy_host", "")
        port = self._settings.get("proxy_port", 1080)
        if not host:
            return None

        proxy_type = self._settings.get("proxy_type", "HTTP").lower()
        type_map = {"socks4": 1, "socks5": 2, "http": 3}
        proxy_type_code = type_map.get(proxy_type, 2)

        return (proxy_type_code, host, port)
