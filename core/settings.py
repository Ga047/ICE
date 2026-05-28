"""
全局设置管理器 — JSON 持久化
"""
import json
import os
from typing import Any, Dict

from core._app_root import get_app_root


class AppSettings:
    """应用全局设置，支持 JSON 文件持久化"""

    _DEFAULTS = {
        "timeout": 3000,
        "connect_timeout": 2000,
        "retry_count": 3,
        "proxy_enabled": False,
        "proxy_type": "HTTP",
        "proxy_host": "",
        "proxy_port": 1080,
        "proxy_auth": False,
        "proxy_user": "",
        "proxy_pass": "",
        "proxy_test_url": "https://www.google.com",
        "custom_headers": {},
        "ua_random": False,
        "ua_custom": "",
    }

    def __init__(self, filepath: str = None):
        if filepath is None:
            filepath = os.path.join(get_app_root(), "config.json")
        self._filepath = filepath
        self._data: Dict[str, Any] = dict(self._DEFAULTS)
        self.load()

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any):
        self._data[key] = value

    def load(self):
        """从 JSON 文件加载设置"""
        try:
            if os.path.exists(self._filepath):
                with open(self._filepath, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                    for k, v in saved.items():
                        if k in self._DEFAULTS:
                            self._data[k] = v
        except (json.JSONDecodeError, IOError):
            pass

    def save(self):
        """保存设置到 JSON 文件"""
        try:
            with open(self._filepath, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    @property
    def filepath(self) -> str:
        return self._filepath
