"""文件下载模块

提供跨平台文件下载命令生成，支持多种下载方式（wget/curl/certutil/Bitsadmin/PowerShell 等）
和文件服务搭建命令。支持 URL 编码、Base64 编码、OS 筛选、搜索过滤等功能。
"""
import base64
import json
import os
import urllib.parse
from typing import Dict, List, Optional, Tuple

from core._app_root import get_app_root

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
from app.widgets.glass_input import GlassCombo, GlassInput, GlassTextEdit
from core.settings import AppSettings


# ============================================================================
# 编码辅助函数
# ============================================================================

def _fixed_encode_uri_component(text: str) -> str:
    """模拟 JS fixedEncodeURIComponent：编码 !'()* 等特殊字符"""
    return urllib.parse.quote(text, safe='')


def _b64_encode_unicode(text: str) -> str:
    """UTF-8 编码后 Base64"""
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


# ============================================================================
# 加载命令数据
# ============================================================================

def _load_commands() -> List[dict]:
    """从 JSON 文件加载命令数据并转换为模板格式"""
    json_path = os.path.join(
        get_app_root(),
        "resources", "dir", "filedown", "filedown.json"
    )
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    download_entries: List[dict] = []
    server_entries: List[dict] = []

    for entry in data:
        name = entry.get("name", "")
        cmd = entry.get("command", "")
        meta: List[str] = entry.get("meta", [])

        # 判断是服务端还是下载类
        server_keywords = [
            "Server", "server", "busybox", "PHP 5.4",
            "NC下载", "SCP下载", "Rsync", "TFTP",
            "Window文件共享", "Python3 SMB",
        ]
        is_server = any(kw in name for kw in server_keywords)
        if is_server:
            server_entries.append({
                "name": name,
                "command": cmd,
                "meta": meta,
            })
        else:
            # 下载类命令 —— 替换 URL 和文件名占位符
            cmd = cmd.replace("http://127.0.0.1/shellcode.exe", "{url}")
            cmd = cmd.replace("shellcode.exe", "{file}")
            cmd = cmd.replace("exploit.exe", "{file}")
            # 修正错误的替换 —— 如果 {url} 出现在不应该出现的地方
            # msiexec 特殊处理
            if "msiexec" in cmd and "{file}" in name:
                pass
            download_entries.append({
                "name": name,
                "command": cmd,
                "meta": meta,
            })

    return download_entries, server_entries


_DOWNLOAD_ENTRIES, _SERVER_ENTRIES = _load_commands()

# 分类标签
_TAB_DOWNLOAD = "下载执行"
_TAB_SERVER = "文件服务"

_TAB_COMMANDS: Dict[str, List[dict]] = {
    _TAB_DOWNLOAD: _DOWNLOAD_ENTRIES,
    _TAB_SERVER: _SERVER_ENTRIES,
}

_ENCODING_OPTIONS = ["None", "encodeURL", "encodeURLDouble", "Base64"]
_OS_FILTERS = ["All", "Windows", "Linux"]


# ============================================================================
# 页面类
# ============================================================================

class FileDownloadPage(ModulePage):
    """文件下载模块页面"""

    def __init__(
        self,
        settings: Optional[AppSettings] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(
            "文件下载",
            "生成各类文件下载命令与文件服务搭建命令",
            parent,
        )
        if settings is None:
            settings = AppSettings()
        self._settings = settings

        # ---- 状态 ----
        self._url = "http://127.0.0.1/shellcode.exe"
        self._file = "shellcode.exe"
        self._encoding = "None"
        self._command_type = _TAB_DOWNLOAD
        self._filter_os = "All"
        self._filter_text = ""
        self._selected_values: Dict[str, str] = {
            _TAB_DOWNLOAD: "",
            _TAB_SERVER: "",
        }

        # ---- UI 引用 ----
        self._tab_widget: Optional[QTabWidget] = None
        self._selection_lists: Dict[str, QListWidget] = {}
        self._command_displays: Dict[str, GlassTextEdit] = {}
        self._encoding_combo: Optional[GlassCombo] = None

        # ---- 构建 UI ----
        self.layout().setSpacing(8)
        self.content_layout.setSpacing(8)
        self._setup_ui()
        self._connect_signals()

        # ---- 初始化 ----
        self._full_update()

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        """构建完整页面布局"""
        self._setup_config_card()
        self._setup_command_card()

    def _setup_config_card(self) -> None:
        """顶部配置卡片：URL + 文件名"""
        card = GlassCard(padding=12)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        card.layout().setSpacing(8)

        title = QLabel("下载配置")
        title.setObjectName("sectionTitle")
        card.layout().addWidget(title)

        row = QWidget()
        row_layout = QHBoxLayout()
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(12)
        row.setLayout(row_layout)

        self._url_input = GlassInput("远程 URL 地址", "http://127.0.0.1/shellcode.exe")
        self._url_input.setText(self._url)
        self._url_input.setMinimumWidth(280)
        row_layout.addWidget(self._url_input)

        self._file_input = GlassInput("目标文件名", "shellcode.exe")
        self._file_input.setText(self._file)
        self._file_input.setFixedWidth(180)
        row_layout.addWidget(self._file_input)

        row_layout.addStretch()
        card.layout().addWidget(row)
        self.content_layout.addWidget(card)

    def _setup_command_card(self) -> None:
        """命令区域（含 2 标签页）"""
        card = GlassCard(padding=16)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        title = QLabel("命令生成")
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

        self._encoding_combo = GlassCombo("编码方式", _ENCODING_OPTIONS)
        self._encoding_combo.combo.setCurrentText(self._encoding)
        adv_layout.addWidget(self._encoding_combo)

        adv_layout.addStretch()

        self._copy_btn = GlassButton("复制")
        adv_layout.addWidget(self._copy_btn)

        card.layout().addWidget(adv_row)

        # ---- 2 标签页 ----
        self._tab_widget = QTabWidget()
        self._tab_widget.setObjectName("glassTabWidget")
        self._tab_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        for tab_title in [_TAB_DOWNLOAD, _TAB_SERVER]:
            tab_content = self._build_tab_content(tab_title)
            self._tab_widget.addTab(tab_content, tab_title)

        card.layout().addWidget(self._tab_widget, stretch=1)
        self.content_layout.addWidget(card, stretch=1)

    def _build_tab_content(self, tab_title: str) -> QWidget:
        """构建单个标签页：左侧命令列表 + 右侧命令显示区"""
        container = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        container.setLayout(layout)

        # 左侧 — 命令列表
        list_widget = QListWidget()
        list_widget.setObjectName("shellCommandList")
        list_widget.setFixedWidth(280)
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
        # URL / 文件名变更
        self._url_input.input.textChanged.connect(self._on_url_changed)
        self._file_input.input.textChanged.connect(self._on_file_changed)

        # 标签页切换
        self._tab_widget.currentChanged.connect(self._on_tab_changed)

        # OS 筛选 / 搜索
        self._os_combo.combo.currentTextChanged.connect(self._on_filter_changed)
        self._search_input.input.textChanged.connect(self._on_filter_changed)

        # 编码方式
        self._encoding_combo.combo.currentTextChanged.connect(
            self._on_encoding_changed
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

    def _on_url_changed(self, text: str) -> None:
        """URL 输入变更"""
        self._url = text.strip() or "http://127.0.0.1/shellcode.exe"
        self._full_update()

    def _on_file_changed(self, text: str) -> None:
        """文件名变更"""
        self._file = text.strip() or "shellcode.exe"
        self._full_update()

    def _on_tab_changed(self, index: int) -> None:
        """标签页切换"""
        tab_titles = [_TAB_DOWNLOAD, _TAB_SERVER]
        if index < 0 or index >= len(tab_titles):
            return
        self._command_type = tab_titles[index]
        self._encoding_combo.combo.setCurrentText("None")
        self._full_update()

    def _on_filter_changed(self, _text: str) -> None:
        """OS 筛选或搜索变更"""
        self._filter_os = self._os_combo.current_text()
        self._filter_text = self._search_input.text().strip().lower()
        self._full_update()

    def _on_encoding_changed(self, _text: str) -> None:
        """编码方式变更"""
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
        current_tab_title = self._command_type
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
        """触发列表 + 命令显示全部刷新"""
        self._update_selection_list()
        self._update_command_display()

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

        target_list = self._selection_lists.get(self._command_type)
        if target_list is None:
            return

        previous_selection = self._selected_values.get(self._command_type, "")
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
                self._selected_values[self._command_type] = first_item.text()

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
                # meta 可能包含 "All" 表示全平台
                if os_lower not in [m.lower() for m in meta] and "all" not in [m.lower() for m in meta]:
                    continue

            # 搜索文本筛选
            if self._filter_text:
                if self._filter_text not in name.lower():
                    cmd_text = cmd.get("command", "").lower()
                    if self._filter_text not in cmd_text:
                        continue

            result.append(cmd)
        return result

    # ------------------------------------------------------------------
    # 命令生成核心逻辑
    # ------------------------------------------------------------------

    def _get_selected_command(self) -> Optional[dict]:
        """获取当前选中命令的数据"""
        selected_name = self._selected_values.get(self._command_type, "")
        if not selected_name:
            return None
        commands = _TAB_COMMANDS.get(self._command_type, [])
        for cmd in commands:
            if cmd.get("name") == selected_name:
                return cmd
        return None

    def _update_command_display(self) -> None:
        """生成并显示当前选中命令"""
        display = self._command_displays.get(self._command_type)
        if display is None:
            return

        command = self._generate_command()
        display.setText(command)

    def _generate_command(self) -> str:
        """核心：参数替换 + 编码"""
        cmd_data = self._get_selected_command()
        if cmd_data is None:
            return ""

        command_template = cmd_data.get("command", "")
        encoding = self._encoding

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
        """替换 {url} / {file} 占位符"""
        return template.replace("{url}", self._url).replace("{file}", self._file)

    def _apply_url_encoding(self, template: str, double: bool = False) -> str:
        """URL 编码管线：先编码模板，再替换已编码占位符"""
        encoded_template = _fixed_encode_uri_component(template)
        encoded_url = _fixed_encode_uri_component(self._url)
        encoded_file = _fixed_encode_uri_component(self._file)

        if double:
            encoded_template = _fixed_encode_uri_component(encoded_template)
            encoded_url = _fixed_encode_uri_component(encoded_url)
            encoded_file = _fixed_encode_uri_component(encoded_file)

        encoded_placeholder_url = _fixed_encode_uri_component("{url}")
        encoded_placeholder_file = _fixed_encode_uri_component("{file}")

        if double:
            encoded_placeholder_url = _fixed_encode_uri_component(encoded_placeholder_url)
            encoded_placeholder_file = _fixed_encode_uri_component(encoded_placeholder_file)

        result = encoded_template.replace(encoded_placeholder_url, encoded_url)
        result = result.replace(encoded_placeholder_file, encoded_file)
        return result

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


# ============================================================================
# 工厂函数
# ============================================================================

def create_page(settings: Optional[AppSettings] = None) -> ModulePage:
    """创建文件下载页面"""
    if settings is None:
        settings = AppSettings()
    return FileDownloadPage(settings)
