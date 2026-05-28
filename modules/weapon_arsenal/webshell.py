"""WebShell 集合模块 — 按编程语言分类的 WebShell 脚本速查"""
import json
import os
from typing import List, Optional

from core._app_root import get_app_root

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSizePolicy,
    QWidget,
)

from app.content_area import ModulePage
from app.widgets.glass_button import GlassButton
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassCombo, GlassInput, GlassTextEdit


def _load_commands() -> List[dict]:
    """从 resources/dir/webshell/webshell.json 加载 WebShell 数据"""
    json_path = os.path.join(
        get_app_root(),
        "resources", "dir", "webshell", "webshell.json"
    )
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


class WebshellPage(ModulePage):
    """WebShell 集合页面 — 左右分栏布局"""

    def __init__(self, webshell_data: List[dict], parent: Optional[QWidget] = None) -> None:
        super().__init__("WebShell 集合", "常用 WebShell 脚本速查，支持多种编程语言", parent)

        self._all_commands: List[dict] = webshell_data
        self._filtered_indices: List[int] = []
        self._selected_index: int = -1
        self._edit_mode: bool = False
        self._filter_lang: str = "全部"
        self._filter_text: str = ""

        self._setup_ui()
        self._connect_signals()
        self._apply_filters()

    # ---- UI 构建 ----

    def _setup_ui(self) -> None:
        """构建左右分栏布局"""
        split_widget = QWidget()
        split_row = QHBoxLayout()
        split_row.setContentsMargins(0, 0, 0, 0)
        split_row.setSpacing(12)
        split_widget.setLayout(split_row)
        split_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # ---- 左侧面板 ----
        left_card = GlassCard(padding=16)
        left_card.setFixedWidth(280)
        left_layout = left_card.layout()

        left_title = QLabel("WebShell 列表")
        left_title.setObjectName("sectionTitle")
        left_layout.addWidget(left_title)

        self._list_widget = QListWidget()
        self._list_widget.setObjectName("shellCommandList")
        self._list_widget.setCursor(Qt.PointingHandCursor)
        self._list_widget.setMinimumHeight(400)
        left_layout.addWidget(self._list_widget, stretch=1)

        self._edit_btn = GlassButton("编辑代码", GlassButton.STYLE_PRIMARY)
        left_card.add_button_row(self._edit_btn)

        split_row.addWidget(left_card)

        # ---- 右侧面板 ----
        right_card = GlassCard(padding=16)
        right_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_layout = right_card.layout()

        # 顶部工具栏（语言选择 + 搜索）
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(8)
        toolbar.setLayout(toolbar_layout)

        lang_label = QLabel("语言:")
        lang_label.setObjectName("inputLabel")
        toolbar_layout.addWidget(lang_label)

        self._lang_combo = GlassCombo(
            "", ["全部", "PHP", "JSP", "ASP", "ASPX", "JSPX", "Python", "Perl", "Node.js"]
        )
        toolbar_layout.addWidget(self._lang_combo)

        toolbar_layout.addSpacing(16)

        search_label = QLabel("搜索:")
        search_label.setObjectName("inputLabel")
        toolbar_layout.addWidget(search_label)

        self._search_input = GlassInput("", "输入关键词筛选...")
        self._search_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        toolbar_layout.addWidget(self._search_input, stretch=1)

        right_layout.addWidget(toolbar)

        # 代码展示区
        self._command_display = GlassTextEdit("代码", readonly=True)
        font = self._command_display.edit.font()
        font.setFamily("JetBrains Mono")
        font.setPointSize(11)
        self._command_display.edit.setFont(font)
        right_layout.addWidget(self._command_display, stretch=1)
        self._command_display.edit.setMinimumHeight(400)

        # 编辑模式工具栏（默认隐藏）
        self._save_toolbar = QWidget()
        save_toolbar_layout = QHBoxLayout()
        save_toolbar_layout.setContentsMargins(0, 0, 0, 0)
        save_toolbar_layout.setSpacing(8)
        self._save_toolbar.setLayout(save_toolbar_layout)
        save_toolbar_layout.addStretch()

        self._save_btn = GlassButton("保存修改", GlassButton.STYLE_PRIMARY)
        self._cancel_btn = GlassButton("取消编辑", GlassButton.STYLE_PRIMARY)
        save_toolbar_layout.addWidget(self._save_btn)
        save_toolbar_layout.addWidget(self._cancel_btn)
        self._save_toolbar.setVisible(False)

        right_layout.addWidget(self._save_toolbar)

        split_row.addWidget(right_card, stretch=1)
        self.content_layout.addWidget(split_widget, stretch=1)

    # ---- 信号连接 ----

    def _connect_signals(self) -> None:
        self._lang_combo.combo.currentTextChanged.connect(self._on_filter_changed)
        self._search_input.input.textChanged.connect(self._on_filter_changed)
        self._list_widget.currentItemChanged.connect(self._on_selection_changed)
        self._edit_btn.clicked.connect(self._on_edit_clicked)
        self._save_btn.clicked.connect(self._on_save_clicked)
        self._cancel_btn.clicked.connect(self._on_cancel_clicked)

    # ---- 筛选逻辑 ----

    def _on_filter_changed(self, _text: str = "") -> None:
        self._filter_lang = self._lang_combo.current_text()
        self._filter_text = self._search_input.input.text().strip().lower()
        self._apply_filters()

    def _apply_filters(self) -> None:
        self._filtered_indices = []

        for i, cmd in enumerate(self._all_commands):
            meta: List[str] = cmd.get("meta", [])
            name: str = cmd.get("name", "")

            # 语言筛选
            if self._filter_lang != "全部":
                target_lang = self._filter_lang.lower()
                if target_lang not in [m.lower() for m in meta]:
                    continue

            # 搜索文本筛选
            if self._filter_text:
                cmd_text = cmd.get("cmd", "").lower()
                if self._filter_text not in name.lower() and self._filter_text not in cmd_text:
                    continue

            self._filtered_indices.append(i)

        self._rebuild_list()

    # ---- 列表重建 ----

    def _rebuild_list(self) -> None:
        self._list_widget.blockSignals(True)
        self._list_widget.clear()

        previous_name = ""
        if self._selected_index >= 0 and self._selected_index < len(self._filtered_indices):
            real_idx = self._filtered_indices[self._selected_index]
            previous_name = self._all_commands[real_idx].get("name", "")

        found = False
        for filtered_pos, real_idx in enumerate(self._filtered_indices):
            name = self._all_commands[real_idx].get("name", "")
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, filtered_pos)
            item.setToolTip(name)
            self._list_widget.addItem(item)
            if name == previous_name:
                self._list_widget.setCurrentItem(item)
                found = True

        if not found and self._list_widget.count() > 0:
            self._list_widget.setCurrentRow(0)

        self._list_widget.blockSignals(False)

        # 筛选变更时退出编辑模式（丢弃未保存修改）
        if self._edit_mode:
            self._exit_edit_mode(discard=True)

        # 列表为空时清空显示区
        if self._list_widget.count() == 0:
            self._selected_index = -1
            self._command_display.setText("")

    # ---- 选择变更 ----

    def _on_selection_changed(self, current: QListWidgetItem, _previous: QListWidgetItem) -> None:
        if current is None:
            self._command_display.setText("")
            return
        self._selected_index = current.data(Qt.UserRole)
        self._update_command_display()

    def _update_command_display(self) -> None:
        if self._selected_index < 0 or self._selected_index >= len(self._filtered_indices):
            self._command_display.setText("")
            return
        real_idx = self._filtered_indices[self._selected_index]
        cmd_text = self._all_commands[real_idx].get("cmd", "")
        self._command_display.setText(cmd_text)

    # ---- 编辑模式 ----

    def _on_edit_clicked(self) -> None:
        if self._selected_index < 0 or self._selected_index >= len(self._filtered_indices):
            self._show_message("提示", "请先选择一个 WebShell", QMessageBox.Warning)
            return
        self._enter_edit_mode()

    def _enter_edit_mode(self) -> None:
        self._edit_mode = True
        self._command_display.edit.setReadOnly(False)
        self._command_display.edit.setStyleSheet(
            "QTextEdit { border: 2px solid #F59E0B; }"
        )
        self._edit_btn.setVisible(False)
        self._save_toolbar.setVisible(True)

    def _exit_edit_mode(self, discard: bool = True) -> None:
        self._edit_mode = False
        self._command_display.edit.setReadOnly(True)
        self._command_display.edit.setStyleSheet("")
        self._edit_btn.setVisible(True)
        self._save_toolbar.setVisible(False)
        if discard:
            self._update_command_display()

    def _on_save_clicked(self) -> None:
        new_text = self._command_display.text()
        real_idx = self._filtered_indices[self._selected_index]
        self._all_commands[real_idx]["cmd"] = new_text
        self._save_to_json()
        self._exit_edit_mode(discard=False)
        self._show_message("保存成功", "WebShell 代码已保存", QMessageBox.Information)

    def _on_cancel_clicked(self) -> None:
        self._exit_edit_mode(discard=True)

    # ---- JSON 持久化 ----

    def _save_to_json(self) -> None:
        json_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "resources", "dir", "webshell", "webshell.json"
        )
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self._all_commands, f, ensure_ascii=False, indent=2)

    # ---- 消息弹窗 ----

    def _show_message(self, title: str, message: str, icon: QMessageBox.Icon) -> None:
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
            "QLabel { color: #1E293B; font-size: 13px; padding: 12px 8px; }"
            "QPushButton {"
            "  background: rgba(59,130,246,0.08);"
            "  border: 1px solid rgba(59,130,246,0.18);"
            "  border-radius: 6px;"
            "  padding: 6px 24px;"
            "  color: #3B82F6;"
            "  font-size: 12px;"
            "  font-weight: 500;"
            "}"
            "QPushButton:hover { background: rgba(59,130,246,0.14); }"
        )
        box.exec()


def create_page() -> ModulePage:
    """创建 WebShell 集合页面（工厂函数，供 main_window.py 注册使用）"""
    webshell_data = _load_commands()
    return WebshellPage(webshell_data)
