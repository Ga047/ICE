"""
底部全局设置栏 + 设置面板弹窗
"""
import ipaddress
import re

import requests

from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QSizePolicy,
)

from app.widgets.glass_button import GlassButton
from core.proxy import ProxyManager
from core.settings import AppSettings


def _parse_validated_int(text: str, min_val: int, max_val: int) -> int:
    """安全解析整数字符串：去前导零并限制范围。"""
    cleaned = text.strip().lstrip("0") or "0"
    try:
        value = int(cleaned)
    except ValueError:
        value = min_val
    return max(min_val, min(value, max_val))


def _check_timeout_input(text: str, min_val: int, max_val: int, field_name: str) -> str:
    """校验超时字段输入，返回错误信息（空字符串表示合法）。"""
    text_value = text.strip()
    if not text_value:
        return "【{0}】不能为空，请填写 {1}-{2} 之间的整数".format(field_name, min_val, max_val)

    if not text_value.isdigit():
        return "【{0}】请输入纯数字，范围 {1}-{2}".format(field_name, min_val, max_val)

    if len(text_value) > 1 and text_value[0] == "0":
        return "【{0}】输入“{1}”含多余前导零，请改为“{2}”".format(
            field_name,
            text_value,
            text_value.lstrip("0"),
        )

    value = int(text_value)
    if value < min_val or value > max_val:
        return "【{0}】值 {1} 超出范围，应为 {2}-{3}".format(field_name, value, min_val, max_val)

    return ""


def _validate_proxy_address(host: str) -> bool:
    """校验代理地址是否为合法 IP 或域名。"""
    if not host or not host.strip():
        return True

    host_text = host.strip()
    try:
        ipaddress.ip_address(host_text)
        return True
    except ValueError:
        pass

    return bool(
        re.match(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$",
            host_text,
        )
    )


def _validate_http_url(url: str) -> bool:
    """校验测试地址是否为 HTTP/HTTPS。"""
    text = (url or "").strip()
    return text.startswith("http://") or text.startswith("https://")


class SettingsDialog(QDialog):
    """全局设置弹窗面板。"""

    settingsChanged = Signal()
    proxyTestFinished = Signal(bool, str)

    PROXY_TYPES = ["HTTP", "SOCKS4", "SOCKS5"]

    UA_PRESETS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/132.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 Version/18.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/132.0.0.0 Safari/537.36",
    ]

    _TIMEOUT_RANGE = (100, 300000)
    _CONNECT_RANGE = (100, 120000)
    _RETRY_RANGE = (0, 10)

    def __init__(self, settings: AppSettings, parent=None):
        super().__init__(parent)
        self._settings = settings
        self.proxyTestFinished.connect(self._on_proxy_test_done)

        self.setWindowTitle("ICE 设置")
        self.setFixedSize(680, 620)
        self.setObjectName("settingsPanel")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setModal(True)

        self._setup_ui()
        self._load_values()

    def _make_timeout_input(self, min_val: int, max_val: int, suffix: str) -> QWidget:
        """创建带 QIntValidator 的输入框与后缀标签。"""
        container = QWidget()
        row_layout = QHBoxLayout()
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(4)
        container.setLayout(row_layout)

        edit = QLineEdit()
        edit.setObjectName("glassInput")
        edit.setValidator(QIntValidator(min_val, max_val))
        edit.setPlaceholderText(str(min_val))
        row_layout.addWidget(edit, stretch=1)

        suffix_label = QLabel(suffix)
        suffix_label.setStyleSheet("color: #64748B; font-size: 12px; background: transparent;")
        row_layout.addWidget(suffix_label)

        container._edit = edit  # type: ignore[attr-defined]
        return container

    def _apply_proxy_control_size_guard(self):
        """为代理页控件增加最小高度，避免文本下沿被布局压缩裁切。"""
        line_edits = [
            self._proxy_host,
            self._proxy_port,
            self._proxy_user,
            self._proxy_pass,
            self._proxy_test_url,
        ]
        for edit in line_edits:
            edit.setFixedHeight(40)
            edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        field_containers = [
            self._proxy_port_container,
            self._proxy_password_container,
        ]
        for container in field_containers:
            container.setMinimumHeight(40)
            container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self._proxy_enable.setMinimumHeight(28)
        self._proxy_enable.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._proxy_auth.setMinimumHeight(28)
        self._proxy_auth.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)
        self.setLayout(layout)

        title_bar = QHBoxLayout()
        title_label = QLabel("全局设置")
        title_label.setObjectName("settingsTitle")
        title_bar.addWidget(title_label)
        title_bar.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(28, 28)
        close_btn.setStyleSheet(
            "QPushButton { background: rgba(0,0,0,0.04); border: 1px solid rgba(0,0,0,0.08);"
            "border-radius: 6px; color: #64748B; font-size: 14px; }"
            "QPushButton:hover { background: rgba(239,68,68,0.1); color: #EF4444; }"
        )
        close_btn.clicked.connect(self.reject)
        title_bar.addWidget(close_btn)
        layout.addLayout(title_bar)

        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            "QTabWidget::pane { border: none; background: transparent; }"
            "QTabBar::tab { background: transparent; border: none; border-radius: 6px;"
            "padding: 8px 18px; color: #64748B; font-size: 12px; font-weight: 500; margin-right: 4px; }"
            "QTabBar::tab:selected { background: rgba(59,130,246,0.08); color: #3B82F6; }"
            "QTabBar::tab:hover { color: #475569; }"
        )

        timeout_page = QWidget()
        timeout_layout = QFormLayout()
        timeout_layout.setSpacing(16)
        timeout_layout.setContentsMargins(16, 20, 16, 20)

        self._timeout_container = self._make_timeout_input(*self._TIMEOUT_RANGE, "毫秒")
        timeout_layout.addRow("请求超时:", self._timeout_container)

        self._connect_timeout_container = self._make_timeout_input(*self._CONNECT_RANGE, "毫秒")
        timeout_layout.addRow("连接超时:", self._connect_timeout_container)

        self._retry_container = self._make_timeout_input(*self._RETRY_RANGE, "次")
        timeout_layout.addRow("重试次数:", self._retry_container)

        timeout_page.setLayout(timeout_layout)
        self._tabs.addTab(timeout_page, "超时设置")

        proxy_page = QWidget()
        proxy_layout = QVBoxLayout()
        proxy_layout.setSpacing(16)
        proxy_layout.setContentsMargins(16, 20, 16, 20)

        self._proxy_enable = QCheckBox("启用代理")
        self._proxy_enable.setObjectName("glassCheckbox")
        proxy_layout.addWidget(self._proxy_enable)

        proxy_form = QFormLayout()
        proxy_form.setSpacing(14)
        proxy_form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        self._proxy_type = QComboBox()
        self._proxy_type.setObjectName("glassCombo")
        self._proxy_type.addItems(self.PROXY_TYPES)
        proxy_form.addRow("代理类型:", self._proxy_type)

        self._proxy_host = QLineEdit()
        self._proxy_host.setObjectName("glassInput")
        self._proxy_host.setPlaceholderText("127.0.0.1")
        self._proxy_host.editingFinished.connect(self._on_proxy_host_changed)
        proxy_form.addRow("代理地址:", self._proxy_host)

        self._proxy_port_container = QWidget()
        port_layout = QHBoxLayout()
        port_layout.setContentsMargins(0, 0, 0, 0)
        port_layout.setSpacing(0)
        self._proxy_port_container.setLayout(port_layout)

        self._proxy_port = QLineEdit()
        self._proxy_port.setObjectName("glassInput")
        self._proxy_port.setValidator(QIntValidator(0, 65535))
        self._proxy_port.setPlaceholderText("1080")
        self._proxy_port.editingFinished.connect(self._on_proxy_port_changed)
        port_layout.addWidget(self._proxy_port, stretch=1)
        proxy_form.addRow("代理端口:", self._proxy_port_container)

        self._proxy_auth = QCheckBox("需要认证")
        self._proxy_auth.setObjectName("glassCheckbox")
        proxy_form.addRow("", self._proxy_auth)

        self._proxy_user = QLineEdit()
        self._proxy_user.setObjectName("glassInput")
        self._proxy_user.setPlaceholderText("用户名")
        proxy_form.addRow("用户名:", self._proxy_user)

        self._proxy_password_container = QWidget()
        password_layout = QHBoxLayout()
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.setSpacing(4)
        self._proxy_password_container.setLayout(password_layout)

        self._proxy_pass = QLineEdit()
        self._proxy_pass.setObjectName("glassInput")
        self._proxy_pass.setPlaceholderText("密码")
        self._proxy_pass.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self._proxy_pass, stretch=1)

        self._pwd_toggle_btn = QPushButton("👁")
        self._pwd_toggle_btn.setFixedSize(32, 32)
        self._pwd_toggle_btn.setCursor(Qt.PointingHandCursor)
        self._pwd_toggle_btn.setCheckable(True)
        self._pwd_toggle_btn.setToolTip("显示/隐藏密码")
        self._pwd_toggle_btn.setStyleSheet(
            "QPushButton { background: transparent; border: 1px solid rgba(0,0,0,0.08);"
            "border-radius: 6px; font-size: 14px; color: #64748B; }"
            "QPushButton:hover { background: rgba(0,0,0,0.06); border: 1px solid rgba(0,0,0,0.14); }"
            "QPushButton:checked { background: rgba(59,130,246,0.1); border: 1px solid rgba(59,130,246,0.25); color: #3B82F6; }"
        )
        self._pwd_toggle_btn.clicked.connect(self._toggle_password_visibility)
        password_layout.addWidget(self._pwd_toggle_btn)
        proxy_form.addRow("密码:", self._proxy_password_container)

        self._proxy_test_url = QLineEdit()
        self._proxy_test_url.setObjectName("glassInput")
        self._proxy_test_url.setPlaceholderText("https://www.google.com")
        proxy_form.addRow("测试地址:", self._proxy_test_url)

        self._apply_proxy_control_size_guard()

        proxy_layout.addLayout(proxy_form)

        test_row = QHBoxLayout()
        test_row.setSpacing(12)

        self._test_btn = QPushButton("测试代理")
        self._test_btn.setObjectName("glassButton")
        self._test_btn.setCursor(Qt.PointingHandCursor)
        self._test_btn.setStyleSheet(
            "QPushButton { background: rgba(59,130,246,0.08); border: 1px solid rgba(59,130,246,0.18);"
            "border-radius: 6px; padding: 6px 16px; color: #3B82F6; font-size: 12px; font-weight: 500; }"
            "QPushButton:hover { background: rgba(59,130,246,0.14); }"
            "QPushButton:disabled { color: #94A3B8; background: rgba(0,0,0,0.03); border: 1px solid rgba(0,0,0,0.06); }"
        )
        self._test_btn.clicked.connect(self._test_proxy)
        test_row.addWidget(self._test_btn)

        self._test_result = QLabel("")
        self._test_result.setStyleSheet("font-size: 12px;")
        test_row.addWidget(self._test_result, stretch=1)

        proxy_layout.addLayout(test_row)
        proxy_page.setLayout(proxy_layout)
        self._tabs.addTab(proxy_page, "代理设置")

        header_page = QWidget()
        header_layout = QVBoxLayout()
        header_layout.setSpacing(12)
        header_layout.setContentsMargins(16, 20, 16, 20)

        header_hint = QLabel("每行一个自定义 Header，格式：Key: Value")
        header_hint.setStyleSheet("color: #64748B; font-size: 11px;")
        header_layout.addWidget(header_hint)

        self._headers_edit = QTextEdit()
        self._headers_edit.setObjectName("terminalOutput")
        self._headers_edit.setPlaceholderText("X-Custom-Token: abc123\nReferer: https://example.com")
        self._headers_edit.setMinimumHeight(200)
        header_layout.addWidget(self._headers_edit)

        header_page.setLayout(header_layout)
        self._tabs.addTab(header_page, "请求头 Header")

        ua_page = QWidget()
        ua_layout = QVBoxLayout()
        ua_layout.setSpacing(16)
        ua_layout.setContentsMargins(16, 20, 16, 20)

        self._ua_random = QCheckBox("随机 User-Agent")
        self._ua_random.setObjectName("glassCheckbox")
        ua_layout.addWidget(self._ua_random)

        ua_preset_label = QLabel("预设 User-Agent:")
        ua_preset_label.setObjectName("inputLabel")
        ua_layout.addWidget(ua_preset_label)

        self._ua_preset = QComboBox()
        self._ua_preset.setObjectName("glassCombo")
        self._ua_preset.addItem("— 选择预设 —")
        for ua in self.UA_PRESETS:
            self._ua_preset.addItem(ua[:80] + "...", ua)
        ua_layout.addWidget(self._ua_preset)

        ua_custom_label = QLabel("自定义 User-Agent:")
        ua_custom_label.setObjectName("inputLabel")
        ua_layout.addWidget(ua_custom_label)

        self._ua_custom = QTextEdit()
        self._ua_custom.setObjectName("glassInput")
        self._ua_custom.setMaximumHeight(80)
        self._ua_custom.setPlaceholderText("输入自定义 User-Agent 字符串...")
        ua_layout.addWidget(self._ua_custom)

        ua_page.setLayout(ua_layout)
        self._tabs.addTab(ua_page, "UA 设置")

        layout.addWidget(self._tabs)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = GlassButton("取消", GlassButton.STYLE_PRIMARY)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        save_btn = GlassButton("保存设置", GlassButton.STYLE_PRIMARY)
        save_btn.clicked.connect(self._save_and_close)
        btn_layout.addWidget(save_btn)

        layout.addLayout(btn_layout)

    def _toggle_password_visibility(self):
        """切换密码可见状态。"""
        show_password = self._pwd_toggle_btn.isChecked()
        self._proxy_pass.setEchoMode(QLineEdit.Normal if show_password else QLineEdit.Password)
        self._pwd_toggle_btn.setText("🙈" if show_password else "👁")

    def _on_proxy_host_changed(self):
        """代理地址失焦时即时校验。"""
        host = self._proxy_host.text().strip()
        if host and not _validate_proxy_address(host):
            self._show_styled_warning(
                "地址格式无效",
                "代理地址 “{0}” 不是合法的 IP 地址或域名格式，请检查后重试。".format(host),
            )
            self._proxy_host.setFocus()

    def _on_proxy_port_changed(self):
        """代理端口失焦时即时校验（0 与 >65535 均非法）。"""
        port_text = self._proxy_port.text().strip()
        if not port_text:
            return

        if not port_text.isdigit():
            self._show_styled_warning(
                "端口格式无效",
                "代理端口 “{0}” 不是合法数字，请输入 1-65535 之间的整数。".format(port_text),
            )
            self._proxy_port.setFocus()
            return

        if len(port_text) > 1 and port_text[0] == "0":
            self._show_styled_warning(
                "端口格式无效",
                "代理端口 “{0}” 含多余前导零，请改为 “{1}”。".format(port_text, port_text.lstrip("0")),
            )
            self._proxy_port.setFocus()
            return

        port = int(port_text)
        if port == 0:
            self._show_styled_warning("端口无效", "代理端口不能为 0，请输入 1-65535 之间的整数。")
            self._proxy_port.setFocus()
            return

        if port > 65535:
            self._show_styled_warning(
                "端口超出范围",
                "代理端口 {0} 超出最大 65535，请输入 1-65535 之间的整数。".format(port),
            )
            self._proxy_port.setFocus()

    def _show_styled_warning(self, title: str, message: str):
        """显示与界面风格一致的警告弹窗。"""
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(message)
        box.setIcon(QMessageBox.Warning)
        box.setStandardButtons(QMessageBox.Ok)
        box.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        box.setAttribute(Qt.WA_StyledBackground, True)
        box.setObjectName("settingsPanel")
        box.setStyleSheet(
            "#settingsPanel {"
            "  background-color: rgba(255,255,255,0.95);"
            "  border: 1px solid rgba(0,0,0,0.08);"
            "  border-radius: 14px;"
            "}"
            "QLabel {"
            "  color: #1E293B;"
            "  font-size: 13px;"
            "  padding: 12px 8px;"
            "}"
            "QPushButton {"
            "  background: rgba(59,130,246,0.08);"
            "  border: 1px solid rgba(59,130,246,0.18);"
            "  border-radius: 6px;"
            "  padding: 6px 24px;"
            "  color: #3B82F6;"
            "  font-size: 12px;"
            "  font-weight: 500;"
            "}"
            "QPushButton:hover {"
            "  background: rgba(59,130,246,0.14);"
            "}"
        )
        return box.exec()

    def _load_values(self):
        settings = self._settings
        # 迁移旧版秒单位配置（< 100 视为秒，乘以 1000 转换为毫秒）
        timeout_val = settings.get("timeout", 3000)
        if timeout_val < self._TIMEOUT_RANGE[0]:
            timeout_val *= 1000
        connect_val = settings.get("connect_timeout", 2000)
        if connect_val < self._CONNECT_RANGE[0]:
            connect_val *= 1000
        self._timeout_container._edit.setText(str(timeout_val))
        self._connect_timeout_container._edit.setText(str(connect_val))
        self._retry_container._edit.setText(str(settings.get("retry_count", 3)))

        self._proxy_enable.setChecked(settings.get("proxy_enabled", False))

        proxy_type = settings.get("proxy_type", "HTTP")
        if proxy_type in self.PROXY_TYPES:
            self._proxy_type.setCurrentText(proxy_type)

        self._proxy_host.setText(settings.get("proxy_host", ""))
        self._proxy_port.setText(str(settings.get("proxy_port", 1080)))
        self._proxy_auth.setChecked(settings.get("proxy_auth", False))
        self._proxy_user.setText(settings.get("proxy_user", ""))
        self._proxy_pass.setText(settings.get("proxy_pass", ""))
        self._proxy_test_url.setText(settings.get("proxy_test_url", "https://www.google.com"))

        headers = settings.get("custom_headers", {})
        self._headers_edit.setPlainText("\n".join("{0}: {1}".format(k, v) for k, v in headers.items()))

        self._ua_random.setChecked(settings.get("ua_random", False))
        self._ua_custom.setPlainText(settings.get("ua_custom", ""))

    def _save_and_close(self):
        settings = self._settings

        timeout_fields = [
            (self._timeout_container._edit, self._TIMEOUT_RANGE[0], self._TIMEOUT_RANGE[1], "请求超时"),
            (self._connect_timeout_container._edit, self._CONNECT_RANGE[0], self._CONNECT_RANGE[1], "连接超时"),
            (self._retry_container._edit, self._RETRY_RANGE[0], self._RETRY_RANGE[1], "重试次数"),
        ]
        for edit, min_val, max_val, field_name in timeout_fields:
            error_msg = _check_timeout_input(edit.text(), min_val, max_val, field_name)
            if error_msg:
                self._show_styled_warning("输入校验失败", error_msg)
                return

        settings.set("timeout", _parse_validated_int(self._timeout_container._edit.text(), *self._TIMEOUT_RANGE))
        settings.set(
            "connect_timeout",
            _parse_validated_int(self._connect_timeout_container._edit.text(), *self._CONNECT_RANGE),
        )
        settings.set("retry_count", _parse_validated_int(self._retry_container._edit.text(), *self._RETRY_RANGE))

        proxy_host = self._proxy_host.text().strip()
        if self._proxy_enable.isChecked() and proxy_host and not _validate_proxy_address(proxy_host):
            self._show_styled_warning(
                "地址格式无效",
                "代理地址 “{0}” 不是合法的 IP 地址或域名格式，请检查后重试。".format(proxy_host),
            )
            return

        proxy_test_url = self._proxy_test_url.text().strip() or "https://www.google.com"
        if not _validate_http_url(proxy_test_url):
            self._show_styled_warning("测试地址无效", "测试地址必须以 http:// 或 https:// 开头。")
            return

        settings.set("proxy_enabled", self._proxy_enable.isChecked())
        settings.set("proxy_type", self._proxy_type.currentText())
        settings.set("proxy_host", proxy_host)
        settings.set("proxy_port", _parse_validated_int(self._proxy_port.text(), 1, 65535))
        settings.set("proxy_auth", self._proxy_auth.isChecked())
        settings.set("proxy_user", self._proxy_user.text())
        settings.set("proxy_pass", self._proxy_pass.text())
        settings.set("proxy_test_url", proxy_test_url)

        headers = {}
        for line in self._headers_edit.toPlainText().strip().split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        settings.set("custom_headers", headers)

        settings.set("ua_random", self._ua_random.isChecked())
        settings.set("ua_custom", self._ua_custom.toPlainText().strip())
        if self._ua_preset.currentIndex() > 0:
            settings.set("ua_custom", self._ua_preset.currentData())

        settings.save()
        self.settingsChanged.emit()
        self.accept()

    def _test_proxy(self):
        """使用当前表单配置测试代理是否可用。"""
        host = self._proxy_host.text().strip()
        port = _parse_validated_int(self._proxy_port.text().strip(), 1, 65535)
        proxy_type = self._proxy_type.currentText()
        probe_url = self._proxy_test_url.text().strip() or "https://www.google.com"

        if not host:
            self._show_test_result("请先填写代理地址", "#EF4444")
            return

        if not _validate_http_url(probe_url):
            self._show_test_result("测试地址无效：仅支持 http/https", "#EF4444")
            return

        proxies = ProxyManager.build_proxy_dict(
            proxy_type=proxy_type,
            host=host,
            port=port,
            proxy_auth=self._proxy_auth.isChecked(),
            proxy_user=self._proxy_user.text(),
            proxy_pass=self._proxy_pass.text(),
        )
        if not proxies:
            self._show_test_result("代理配置无效", "#EF4444")
            return

        self._test_btn.setEnabled(False)
        self._test_btn.setText("测试中...")
        self._test_result.setText("")

        import threading

        def do_test():
            try:
                response = requests.get(probe_url, proxies=proxies, timeout=8)
                if response.status_code < 400:
                    return True, "代理连接成功"
                return False, "连接失败: HTTP {0}".format(response.status_code)
            except requests.exceptions.ProxyError:
                return False, "连接失败: 代理拒绝连接"
            except requests.exceptions.ConnectTimeout:
                return False, "连接失败: 连接超时"
            except requests.exceptions.ReadTimeout:
                return False, "连接失败: 读取超时"
            except requests.exceptions.SSLError:
                return False, "连接失败: SSL 错误"
            except requests.exceptions.ConnectionError as error:
                error_text = str(error)
                if "NameResolutionError" in error_text or "getaddrinfo" in error_text:
                    return False, "连接失败: DNS 解析错误"
                return False, "连接失败: 网络连接错误"
            except Exception as error:
                return False, "连接失败: {0}".format(str(error)[:80])

        def run():
            success, message = do_test()
            self.proxyTestFinished.emit(success, message)

        threading.Thread(target=run, daemon=True).start()

    def _on_proxy_test_done(self, success: bool, message: str):
        color = "#22C55E" if success else "#EF4444"
        self._show_test_result(message, color)
        self._test_btn.setEnabled(True)
        self._test_btn.setText("测试代理")

    def _show_test_result(self, message: str, color: str):
        self._test_result.setText(message)
        self._test_result.setStyleSheet("font-size: 12px; color: {0};".format(color))
        QTimer.singleShot(4000, lambda: self._test_result.setText(""))


class SettingsBar(QWidget):
    """底部全局设置栏（仅保留设置入口按钮）。"""

    def __init__(self, settings: AppSettings, parent=None):
        super().__init__(parent)
        self._settings = settings
        self.setObjectName("settingsBar")
        self.setFixedHeight(48)

        layout = QHBoxLayout()
        layout.setContentsMargins(20, 0, 20, 0)
        layout.setSpacing(16)
        self.setLayout(layout)

        status_label = QLabel()
        status_label.setStyleSheet(
            "background-color: #22C55E; border-radius: 5px;"
            "min-width: 10px; max-width: 10px; min-height: 10px; max-height: 10px;"
        )
        layout.addWidget(status_label)

        ready_label = QLabel("就绪")
        ready_label.setStyleSheet("color: #64748B; font-size: 12px;")
        layout.addWidget(ready_label)

        layout.addStretch()

        self._all_settings_btn = QPushButton("⚙ 设置")
        self._all_settings_btn.setStyleSheet(
            "QPushButton { background: rgba(59,130,246,0.08); border: 1px solid rgba(59,130,246,0.18);"
            "border-radius: 6px; padding: 5px 16px; color: #3B82F6; font-size: 11px; font-weight: 500; }"
            "QPushButton:hover { background: rgba(59,130,246,0.15); border: 1px solid rgba(59,130,246,0.3); }"
        )
        self._all_settings_btn.setCursor(Qt.PointingHandCursor)
        self._all_settings_btn.clicked.connect(self.open_settings_dialog)
        layout.addWidget(self._all_settings_btn)

    def open_settings_dialog(self):
        """打开全局设置弹窗。"""
        dialog = SettingsDialog(self._settings, self.window())
        dialog.settingsChanged.connect(lambda: None)
        dialog.exec()
