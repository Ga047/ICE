"""反弹 Shell 模块 

生成各类反弹 Shell / 绑定 Shell / MSFVenom / HoaxShell / 汇编 Shellcode 命令，
支持 URL 编码、Base64 编码、多监听器类型、OS 筛选、搜索过滤等功能。
"""
import base64
import urllib.parse
from typing import Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSizePolicy,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.content_area import ModulePage
from app.widgets.glass_button import GlassButton
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassCombo, GlassInput, GlassSpinBox, GlassTextEdit
from core.settings import AppSettings

from modules.weapon_arsenal.reverse_shell_data import (
    ASSEMBLED_COMMANDS,
    BIND_SHELL_COMMANDS,
    CLEANUP_COMMANDS,
    CommandType,
    HOAXSHELL_COMMANDS,
    HOAXSHELL_LISTENER_TYPES,
    LISTENER_COMMANDS,
    MSFVENOM_COMMANDS,
    PROXY_COMMANDS,
    REVERSE_SHELL_COMMANDS,
    SHELLS,
    SPECIAL_COMMANDS,
    UDP_PAYLOADS,
)


# ============================================================================
# 编码辅助函数
# ============================================================================

def _fixed_encode_uri_component(text: str) -> str:
    """模拟 JS fixedEncodeURIComponent：编码 !'()* 等特殊字符"""
    return urllib.parse.quote(text, safe='')


def _b64_encode_unicode(text: str) -> str:
    """UTF-8 编码后 Base64（匹配 Web 版 b64EncodeUnicode 行为）"""
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


def _ip_to_hex_bytes(ip: str) -> str:
    """IP 地址 → \\xNN\\xNN\\xNN\\xNN 十六进制字节格式"""
    parts = ip.split('.')
    return ''.join('\\x{:02x}'.format(int(p)) for p in parts)


def _port_to_hex_bytes(port: int) -> str:
    """端口 → \\xNN\\xNN 大端十六进制字节格式"""
    return '\\x{:02x}\\x{:02x}'.format((port >> 8) & 0xFF, port & 0xFF)


# ============================================================================
# UI 常量
# ============================================================================

_TAB_NAMES = {
    CommandType.ReverseShell: "Reverse",
    CommandType.BindShell: "Bind",
    CommandType.MSFVenom: "MSFVenom",
    CommandType.HoaxShell: "HoaxShell",
    CommandType.Assembled: "Assembled",
    CommandType.Proxy: "内网代理",
    CommandType.Cleanup: "痕迹清理",
}

_TAB_COMMANDS: Dict[str, List[dict]] = {
    CommandType.ReverseShell: REVERSE_SHELL_COMMANDS,
    CommandType.BindShell: BIND_SHELL_COMMANDS,
    CommandType.MSFVenom: MSFVENOM_COMMANDS,
    CommandType.HoaxShell: HOAXSHELL_COMMANDS,
    CommandType.Assembled: ASSEMBLED_COMMANDS,
    CommandType.Proxy: PROXY_COMMANDS,
    CommandType.Cleanup: CLEANUP_COMMANDS,
}

_ENCODING_OPTIONS = ["None", "encodeURL", "encodeURLDouble", "Base64"]
_OS_FILTERS = ["All", "Windows", "Linux", "Mac"]

_LISTENER_NAMES = [name for name, _cmd in LISTENER_COMMANDS]
_LISTENER_MAP = {name: cmd for name, cmd in LISTENER_COMMANDS}

# 不支持 UDP 的监听器
_LISTENERS_NO_UDP = ["msfconsole", "powercat", "hoaxshell", "windows ConPty"]


# ============================================================================
# 页面类
# ============================================================================

class ReverseShellPage(ModulePage):
    """反弹 Shell 生成器页面"""

    def __init__(
        self,
        settings: Optional[AppSettings] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(
            "反弹Shell",
            "生成各类反弹 Shell / 绑定 Shell / MSFVenom / HoaxShell / 汇编 Shellcode 命令",
            parent,
        )
        if settings is None:
            settings = AppSettings()
        self._settings = settings

        # ---- 状态 ----
        self._ip = "10.10.10.10"
        self._port = 9001
        self._shell = "/bin/sh"
        self._listener = "nc"
        self._encoding = "None"
        self._command_type = CommandType.ReverseShell
        self._filter_os = "All"
        self._filter_text = ""
        self._selected_values: Dict[str, str] = {}  # tab_title → 选中的命令名

        # ---- UI 引用 ----
        self._tab_widget: Optional[QTabWidget] = None
        self._selection_lists: Dict[str, QListWidget] = {}
        self._command_displays: Dict[str, GlassTextEdit] = {}
        self._shell_combo: Optional[GlassCombo] = None
        self._encoding_combo: Optional[GlassCombo] = None

        # ---- 构建 UI ----
        self.layout().setSpacing(8)
        self.content_layout.setSpacing(8)
        self._setup_ui()
        self._connect_signals()

        # ---- 初始化默认选中 ----
        for tab_title in _TAB_NAMES.values():
            self._selected_values[tab_title] = ""
        self._full_update()

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        """构建完整页面布局"""
        self._setup_top_row()
        self._setup_payload_card()

    def _setup_top_row(self) -> None:
        """顶部并排卡片行：连接配置（左） + 监听器配置（右）"""
        row = QWidget()
        row_layout = QHBoxLayout()
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(12)
        row.setLayout(row_layout)
        row.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        # ---- 左侧：连接配置 ----
        conn_card = GlassCard(padding=12)
        conn_card.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        conn_card.layout().setSpacing(8)

        conn_title = QLabel("连接配置")
        conn_title.setObjectName("sectionTitle")
        conn_card.layout().addWidget(conn_title)

        # IP 输入（紧凑）
        ip_row = QWidget()
        ip_layout = QHBoxLayout()
        ip_layout.setContentsMargins(0, 0, 0, 0)
        ip_layout.setSpacing(8)
        ip_row.setLayout(ip_layout)

        self._ip_input = GlassInput("监听 IP", "10.10.10.10")
        self._ip_input.setText(self._ip)
        self._ip_input.setFixedWidth(160)
        ip_layout.addWidget(self._ip_input)

        # 端口 SpinBox（带上下小箭头）
        self._port_spin = GlassSpinBox("监听端口", 1, 65535, self._port)
        self._port_spin.setFixedWidth(100)
        ip_layout.addWidget(self._port_spin)

        conn_card.layout().addWidget(ip_row)

        # Port < 1024 警告标签
        self._port_warning = QLabel("端口 < 1024 可能需要 root/管理员权限")
        self._port_warning.setStyleSheet(
            "color: #EF4444; font-size: 11px; padding: 2px 0;"
        )
        self._port_warning.setVisible(self._port < 1024)
        conn_card.layout().addWidget(self._port_warning)

        row_layout.addWidget(conn_card)

        # ---- 右侧：监听器配置 ----
        listen_card = GlassCard(padding=12)
        listen_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        listen_card.layout().setSpacing(8)

        listen_title = QLabel("监听器配置")
        listen_title.setObjectName("sectionTitle")
        listen_card.layout().addWidget(listen_title)

        # 监听器类型下拉框
        self._listener_combo = GlassCombo("监听器类型", _LISTENER_NAMES)
        self._listener_combo.combo.setCurrentText(self._listener)
        listen_card.layout().addWidget(self._listener_combo)

        # 监听器命令显示区
        self._listener_display = GlassTextEdit("生成的监听器命令", readonly=True)
        self._listener_display.edit.setMaximumHeight(60)
        font = self._listener_display.edit.font()
        font.setFamily("JetBrains Mono")
        self._listener_display.edit.setFont(font)
        listen_card.layout().addWidget(self._listener_display)

        # 复制按钮
        self._copy_listener_btn = GlassButton("复制监听器命令")
        listen_card.add_button_row(self._copy_listener_btn)

        row_layout.addWidget(listen_card, stretch=1)
        self.content_layout.addWidget(row)

    def _setup_payload_card(self) -> None:
        """Payload 区域（含 5 标签页）"""
        card = GlassCard(padding=16)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        title = QLabel("Payload 生成")
        title.setObjectName("sectionTitle")
        card.layout().addWidget(title)

        # ---- 顶部筛选栏 ----
        filter_row = QWidget()
        filter_layout = QHBoxLayout()
        filter_layout.setContentsMargins(0, 0, 0, 0)
        filter_layout.setSpacing(12)
        filter_row.setLayout(filter_layout)

        os_label = QLabel("OS:")
        os_label.setObjectName("inputLabel")
        filter_layout.addWidget(os_label)

        self._os_combo = GlassCombo("", _OS_FILTERS)
        self._os_combo.setFixedWidth(120)
        filter_layout.addWidget(self._os_combo)

        filter_layout.addStretch()

        search_label = QLabel("搜索:")
        search_label.setObjectName("inputLabel")
        filter_layout.addWidget(search_label)

        self._search_input = GlassInput("", "输入关键词筛选...")
        self._search_input.setFixedWidth(200)
        filter_layout.addWidget(self._search_input)

        card.layout().addWidget(filter_row)

        # ---- 高级选项行 ----
        adv_row = QWidget()
        adv_layout = QHBoxLayout()
        adv_layout.setContentsMargins(0, 0, 0, 0)
        adv_layout.setSpacing(12)
        adv_row.setLayout(adv_layout)

        self._shell_combo = GlassCombo("Shell 类型", SHELLS)
        self._shell_combo.combo.setCurrentText(self._shell)
        self._shell_combo.setFixedWidth(160)
        adv_layout.addWidget(self._shell_combo)

        self._encoding_combo = GlassCombo("编码方式", _ENCODING_OPTIONS)
        self._encoding_combo.combo.setCurrentText(self._encoding)
        adv_layout.addWidget(self._encoding_combo)

        adv_layout.addStretch()

        self._copy_btn = GlassButton("复制")
        adv_layout.addWidget(self._copy_btn)

        card.layout().addWidget(adv_row)

        # ---- 5 标签页 ----
        self._tab_widget = QTabWidget()
        self._tab_widget.setObjectName("glassTabWidget")
        self._tab_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        for cmd_type, tab_title in _TAB_NAMES.items():
            tab_content = self._build_tab_content(cmd_type, tab_title)
            self._tab_widget.addTab(tab_content, tab_title)

        card.layout().addWidget(self._tab_widget, stretch=1)
        self.content_layout.addWidget(card, stretch=1)

    def _build_tab_content(self, cmd_type: str, tab_title: str) -> QWidget:
        """构建单个标签页：左侧命令列表 + 右侧命令显示区"""
        container = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        container.setLayout(layout)

        # 左侧 — 命令列表
        list_widget = QListWidget()
        list_widget.setObjectName("shellCommandList")
        list_widget.setFixedWidth(250)
        list_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        list_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        layout.addWidget(list_widget)
        self._selection_lists[tab_title] = list_widget

        # 右侧 — 命令显示区
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        right_panel.setLayout(right_layout)

        cmd_display = GlassTextEdit("生成的命令", readonly=True)
        font = cmd_display.edit.font()
        font.setFamily("JetBrains Mono")
        font.setPointSize(10)
        cmd_display.edit.setFont(font)
        right_layout.addWidget(cmd_display, stretch=1)
        self._command_displays[tab_title] = cmd_display

        layout.addWidget(right_panel, stretch=1)
        return container

    # ------------------------------------------------------------------
    # 信号连接
    # ------------------------------------------------------------------

    def _connect_signals(self) -> None:
        """连接所有信号/槽"""
        # IP / 端口变更
        self._ip_input.input.textChanged.connect(self._on_ip_changed)
        self._port_spin.spin.valueChanged.connect(self._on_port_changed)

        # 监听器类型变更
        self._listener_combo.combo.currentTextChanged.connect(
            self._on_listener_changed
        )
        # 复制监听器
        self._copy_listener_btn.clicked.connect(self._on_copy_listener)

        # 标签页切换
        self._tab_widget.currentChanged.connect(self._on_tab_changed)

        # OS 筛选 / 搜索
        self._os_combo.combo.currentTextChanged.connect(self._on_filter_changed)
        self._search_input.input.textChanged.connect(self._on_filter_changed)

        # Shell 类型 / 编码方式
        self._shell_combo.combo.currentTextChanged.connect(
            self._on_shell_or_encoding_changed
        )
        self._encoding_combo.combo.currentTextChanged.connect(
            self._on_shell_or_encoding_changed
        )

        # 复制命令
        self._copy_btn.clicked.connect(self._on_copy_command)

        # 命令列表选择
        for tab_title, list_widget in self._selection_lists.items():
            list_widget.currentItemChanged.connect(
                lambda current, _previous, tt=tab_title: self._on_list_selection_changed(tt, current)
            )

    # ------------------------------------------------------------------
    # 槽函数
    # ------------------------------------------------------------------

    def _on_ip_changed(self, text: str) -> None:
        """IP 输入变更"""
        self._ip = text.strip() or "10.10.10.10"
        self._full_update()

    def _on_port_changed(self, value: int) -> None:
        """端口变更（SpinBox）"""
        self._port = value
        self._port_warning.setVisible(self._port < 1024)
        self._full_update()

    def _on_listener_changed(self, listener_name: str) -> None:
        """监听器类型变更"""
        self._listener = listener_name
        self._update_listener_command()

    def _on_copy_listener(self) -> None:
        """复制监听器命令到剪贴板"""
        text = self._listener_display.text()
        if text.strip():
            QApplication.clipboard().setText(text)
            self._show_styled_message("已复制", "监听器命令已复制到剪贴板", QMessageBox.Information)

    def _on_tab_changed(self, index: int) -> None:
        """标签页切换"""
        tab_titles = list(_TAB_NAMES.values())
        cmd_types = list(_TAB_NAMES.keys())
        if index < 0 or index >= len(tab_titles):
            return
        self._command_type = cmd_types[index]
        # Bind / MSFVenom / HoaxShell / Assembled / Proxy / Cleanup 重置编码为 None
        if self._command_type in (
            CommandType.BindShell,
            CommandType.MSFVenom,
            CommandType.HoaxShell,
            CommandType.Assembled,
            CommandType.Proxy,
            CommandType.Cleanup,
        ):
            self._encoding_combo.combo.setCurrentText("None")
        self._full_update()

    def _on_filter_changed(self, _text: str) -> None:
        """OS 筛选或搜索变更"""
        self._filter_os = self._os_combo.current_text()
        self._filter_text = self._search_input.text().strip().lower()
        self._full_update()

    def _on_shell_or_encoding_changed(self, _text: str) -> None:
        """Shell 类型或编码方式变更"""
        self._shell = self._shell_combo.current_text()
        self._encoding = self._encoding_combo.current_text()
        self._update_command_display()

    def _on_list_selection_changed(self, tab_title: str, current: QListWidgetItem) -> None:
        """命令列表选中项变更"""
        if current is None:
            return
        self._selected_values[tab_title] = current.text()
        self._update_command_display()

    def _on_copy_command(self) -> None:
        """复制当前命令到剪贴板"""
        current_tab_title = self._get_current_tab_title()
        if current_tab_title is None:
            return
        display = self._command_displays.get(current_tab_title)
        if display is None:
            return
        text = display.text()
        if text.strip():
            QApplication.clipboard().setText(text)
            self._show_styled_message("已复制", "命令已复制到剪贴板", QMessageBox.Information)

    # ------------------------------------------------------------------
    # 全量刷新
    # ------------------------------------------------------------------

    def _full_update(self) -> None:
        """触发监听器 + 列表 + 命令显示全部刷新"""
        self._update_listener_command()
        self._update_selection_list()
        self._update_command_display()

    # ------------------------------------------------------------------
    # 监听器命令生成
    # ------------------------------------------------------------------

    def _update_listener_command(self) -> None:
        """生成监听器命令（含 UDP 检测、sudo 警告）"""
        template = _LISTENER_MAP.get(self._listener, "")
        if not template:
            self._listener_display.setText("")
            return

        # 检测 UDP payload
        current_cmd = self._get_selected_command()
        is_udp = False
        if current_cmd:
            cmd_name = current_cmd.get("name", "")
            if cmd_name in UDP_PAYLOADS:
                is_udp = True

        command = template.replace("{ip}", self._ip).replace("{port}", str(self._port))

        # HoaxShell 特殊处理
        if self._listener == "hoaxshell":
            hoax_type = HOAXSHELL_LISTENER_TYPES.get(
                self._selected_values.get(self._get_current_tab_title() or "", ""), ""
            )
            command = command.replace("{type}", hoax_type)

        # MSFConsole 特殊处理
        if self._listener == "msfconsole":
            payload_map = {
                "linux": "linux/x64/meterpreter/reverse_tcp",
                "windows": "windows/x64/meterpreter/reverse_tcp",
                "mac": "osx/x64/meterpreter/reverse_tcp",
            }
            payload = payload_map.get(self._filter_os.lower(), "linux/x64/meterpreter/reverse_tcp")
            command = command.replace("{payload}", payload)

        # UDP 检测：自动添加 -u 标志
        if is_udp:
            udp_listeners = ["nc", "ncat", "busybox nc", "rustcat", "pwncat", "socat"]
            if self._listener in udp_listeners or self._listener in ["ncat.exe", "pwncat (windows)"]:
                command = command.replace("-lvnp", "-lvnup").replace("-lvp", "-lvup")
                if "-lvnup" not in command and "-lvup" not in command:
                    command = command.replace("-lp ", "-lup ").replace("-lvnp ", "-lvnup ")

        # sudo 前缀检测（端口 < 1024 且非 root）
        sudo_listeners = [
            "nc", "nc freebsd", "busybox nc", "ncat", "rlwrap + nc",
            "rustcat", "socat", "socat (TTY)", "windows ConPty",
        ]
        prefix = ""
        if self._port < 1024 and self._listener in sudo_listeners:
            prefix = "sudo "

        # 不支持 UDP 的监听器警告
        if is_udp and self._listener in _LISTENERS_NO_UDP:
            command = "⚠ 该监听器不支持 UDP Payload"

        self._listener_display.setText(prefix + command)

    # ------------------------------------------------------------------
    # 命令列表筛选与填充
    # ------------------------------------------------------------------

    def _update_selection_list(self) -> None:
        """根据当前筛选条件重建命令列表"""
        commands = _TAB_COMMANDS.get(self._command_type, [])
        filtered = self._filter_data(commands)

        for tab_title, list_widget in self._selection_lists.items():
            list_widget.blockSignals(True)
            list_widget.clear()

        current_tab_title = self._get_current_tab_title()
        target_list = self._selection_lists.get(current_tab_title or "")
        if target_list is None:
            return

        previous_selection = self._selected_values.get(current_tab_title or "", "")
        found_previous = False

        for cmd in filtered:
            name = cmd.get("name", "")
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, cmd)
            item.setToolTip(name)
            target_list.addItem(item)
            if name == previous_selection:
                found_previous = True
                target_list.setCurrentItem(item)

        if not found_previous and target_list.count() > 0:
            target_list.setCurrentRow(0)
            first_item = target_list.item(0)
            if first_item:
                self._selected_values[current_tab_title or ""] = first_item.text()

        for tab_title, list_widget in self._selection_lists.items():
            list_widget.blockSignals(False)

    def _filter_data(self, commands: List[dict]) -> List[dict]:
        """按 OS + 搜索文本筛选命令"""
        result: List[dict] = []
        for cmd in commands:
            meta = cmd.get("meta", [])
            name = cmd.get("name", "")

            # OS 筛选
            if self._filter_os != "All":
                os_lower = self._filter_os.lower()
                if os_lower not in [m.lower() for m in meta]:
                    continue

            # 搜索文本筛选
            if self._filter_text:
                if self._filter_text not in name.lower():
                    # 也检查命令内容
                    cmd_text = cmd.get("command", "").lower()
                    if self._filter_text not in cmd_text:
                        continue

            result.append(cmd)
        return result

    # ------------------------------------------------------------------
    # 命令生成核心逻辑
    # ------------------------------------------------------------------

    def _get_current_tab_title(self) -> Optional[str]:
        """获取当前标签页标题"""
        idx = self._tab_widget.currentIndex()
        tab_titles = list(_TAB_NAMES.values())
        if 0 <= idx < len(tab_titles):
            return tab_titles[idx]
        return None

    def _get_selected_command(self) -> Optional[dict]:
        """获取当前选中命令的数据"""
        current_tab_title = self._get_current_tab_title()
        if current_tab_title is None:
            return None
        selected_name = self._selected_values.get(current_tab_title, "")
        if not selected_name:
            return None
        commands = _TAB_COMMANDS.get(self._command_type, [])
        for cmd in commands:
            if cmd.get("name") == selected_name:
                return cmd
        return None

    def _update_command_display(self) -> None:
        """生成并显示当前选中命令"""
        current_tab_title = self._get_current_tab_title()
        if current_tab_title is None:
            return

        display = self._command_displays.get(current_tab_title)
        if display is None:
            return

        command = self._generate_command()
        display.setText(command)

        # 更新监听器（UDP 检测依赖当前选中命令）
        self._update_listener_command()

    def _generate_command(self) -> str:
        """核心：参数替换 + 编码 + PowerShell / Assembled 特殊处理"""
        cmd_data = self._get_selected_command()
        if cmd_data is None:
            return ""

        command_template = cmd_data.get("command", "")
        encoding = self._encoding

        # ---- PowerShell Base64 特殊处理 ----
        if command_template == "__POWERSHELL_BASE64_3__":
            return self._generate_powershell_base64("PowerShell payload")
        if command_template == "__POWERSHELL_BASE64_5__":
            return self._generate_powershell_base64("PowerShell +stderr payload")

        # ---- Assembled Shellcode 特殊处理 ----
        if self._command_type == CommandType.Assembled:
            hex_ip = _ip_to_hex_bytes(self._ip)
            hex_port = _port_to_hex_bytes(self._port)
            command = command_template.replace("{ip}", hex_ip).replace(
                "{port}", hex_port
            ).replace("{shell}", self._shell)
            return command

        # ---- 常规命令生成 ----
        if encoding == "None":
            return self._insert_parameters(command_template)

        if encoding == "encodeURL":
            return self._apply_url_encoding(command_template, double=False)

        if encoding == "encodeURLDouble":
            return self._apply_url_encoding(command_template, double=True)

        if encoding == "Base64":
            command = self._insert_parameters(command_template)
            return _b64_encode_unicode(command)

        return ""

    def _insert_parameters(self, template: str) -> str:
        """替换 {ip} / {port} / {shell} 占位符"""
        return template.replace("{ip}", self._ip).replace(
            "{port}", str(self._port)
        ).replace("{shell}", self._shell)

    def _apply_url_encoding(self, template: str, double: bool = False) -> str:
        """URL 编码管线：先编码模板，再替换已编码占位符为已编码实际值"""
        encoded_template = _fixed_encode_uri_component(template)
        encoded_ip = _fixed_encode_uri_component(self._ip)
        encoded_port = _fixed_encode_uri_component(str(self._port))
        encoded_shell = _fixed_encode_uri_component(self._shell)

        if double:
            encoded_template = _fixed_encode_uri_component(encoded_template)
            encoded_ip = _fixed_encode_uri_component(encoded_ip)
            encoded_port = _fixed_encode_uri_component(encoded_port)
            encoded_shell = _fixed_encode_uri_component(encoded_shell)

        encoded_placeholder_ip = _fixed_encode_uri_component("{ip}")
        encoded_placeholder_port = _fixed_encode_uri_component("{port}")
        encoded_placeholder_shell = _fixed_encode_uri_component("{shell}")

        if double:
            encoded_placeholder_ip = _fixed_encode_uri_component(encoded_placeholder_ip)
            encoded_placeholder_port = _fixed_encode_uri_component(encoded_placeholder_port)
            encoded_placeholder_shell = _fixed_encode_uri_component(encoded_placeholder_shell)

        result = encoded_template.replace(encoded_placeholder_ip, encoded_ip)
        result = result.replace(encoded_placeholder_port, encoded_port)
        result = result.replace(encoded_placeholder_shell, encoded_shell)
        return result

    def _generate_powershell_base64(self, payload_key: str) -> str:
        """PowerShell Base64 特殊编码：参数替换 → UTF-8 → Base64 → powershell -e 前缀"""
        payload = SPECIAL_COMMANDS.get(payload_key, "")
        if not payload:
            return ""
        command = self._insert_parameters(payload)
        encoded = _b64_encode_unicode(command)
        return "powershell -e " + encoded

    # ------------------------------------------------------------------
    # 弹窗
    # ------------------------------------------------------------------

    def _show_styled_message(
        self, title: str, message: str, icon: QMessageBox.Icon
    ) -> int:
        """显示毛玻璃风格提示弹窗"""
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(message)
        box.setIcon(icon)
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

    def _show_styled_warning(self, title: str, message: str) -> int:
        """显示毛玻璃风格警告弹窗"""
        return self._show_styled_message(title, message, QMessageBox.Warning)


# ============================================================================
# 工厂函数
# ============================================================================

def create_page(settings: Optional[AppSettings] = None) -> ModulePage:
    """创建反弹 Shell 页面"""
    if settings is None:
        settings = AppSettings()
    return ReverseShellPage(settings)
