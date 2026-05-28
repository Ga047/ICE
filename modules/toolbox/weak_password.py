"""弱密码查询模块 — 查询常见弱密码、默认密码、设备默认口令"""
import json
import os
from typing import List, Optional

from core._app_root import get_app_root

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.content_area import ModulePage
from app.widgets.glass_button import GlassButton
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassInput, GlassTextEdit


def _load_passwords() -> List[dict]:
    """从 weakpass.json 加载弱密码数据"""
    json_path = os.path.join(
        get_app_root(),
        "resources", "dir", "weakpass", "weakpass.json"
    )
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


class _AddPasswordDialog(QDialog):
    """添加自定义密码弹窗"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("添加自定义密码")
        self.setFixedSize(580, 480)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setObjectName("settingsPanel")
        self.setStyleSheet(
            "#settingsPanel {"
            "  background-color: rgba(255,255,255,0.95);"
            "  border: 1px solid rgba(0,0,0,0.08);"
            "  border-radius: 14px;"
            "}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(20)

        title = QLabel("添加自定义密码")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        self._name_input = GlassInput("设备名称", "例如: 某品牌-路由器")
        self._username_input = GlassInput("用户名", "例如: admin")
        self._password_input = GlassInput("密码", "例如: admin123")

        input_style = (
            "QLineEdit {"
            "  background-color: rgba(255, 255, 255, 0.9);"
            "  border: 1px solid rgba(0, 0, 0, 0.08);"
            "  border-radius: 8px;"
            "  padding: 4px 12px;"
            "  min-height: 28px;"
            "  max-height: 28px;"
            "  color: #1E293B;"
            "  font-size: 13px;"
            "}"
        )
        self._name_input.input.setStyleSheet(input_style)
        self._username_input.input.setStyleSheet(input_style)
        self._password_input.input.setStyleSheet(input_style)
        layout.addWidget(self._name_input)
        layout.addWidget(self._username_input)
        layout.addWidget(self._password_input)

        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.addStretch()

        cancel_btn = GlassButton("取消", GlassButton.STYLE_PRIMARY)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        ok_btn = GlassButton("确定", GlassButton.STYLE_PRIMARY)
        ok_btn.clicked.connect(self._on_ok)
        btn_row.addWidget(ok_btn)

        layout.addLayout(btn_row)

    def _on_ok(self) -> None:
        """校验非空后接受"""
        name = self._name_input.text().strip()
        username = self._username_input.text().strip()
        password = self._password_input.text().strip()

        if not name or not username or not password:
            box = QMessageBox(self)
            box.setWindowTitle("提示")
            box.setText("设备名称、用户名和密码均不能为空")
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
            return

        self._result_name = name
        self._result_username = username
        self._result_password = password
        self.accept()

    def get_result(self):
        """返回 (name, username, password) 元组"""
        return (
            getattr(self, "_result_name", ""),
            getattr(self, "_result_username", ""),
            getattr(self, "_result_password", ""),
        )


class WeakPasswordPage(ModulePage):
    """弱密码查询页面 — 左右分栏布局"""

    def __init__(self, passwords_data: List[dict], parent: Optional[QWidget] = None) -> None:
        super().__init__("弱密码查询", "查询常见弱密码、默认密码、设备默认口令", parent)

        self._all_passwords: List[dict] = passwords_data
        self._filtered_indices: List[int] = []
        self._selected_index: int = -1
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

        left_title = QLabel("密码列表")
        left_title.setObjectName("sectionTitle")
        left_layout.addWidget(left_title)

        self._list_widget = QListWidget()
        self._list_widget.setObjectName("shellCommandList")
        self._list_widget.setCursor(Qt.PointingHandCursor)
        self._list_widget.setMinimumHeight(400)
        left_layout.addWidget(self._list_widget, stretch=1)

        # 添加密码按钮
        self._add_btn = GlassButton("添加密码", GlassButton.STYLE_PRIMARY)
        left_card.add_button_row(self._add_btn)

        split_row.addWidget(left_card)

        # ---- 右侧面板 ----
        right_card = GlassCard(padding=16)
        right_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_layout = right_card.layout()

        # 搜索工具栏
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(8)
        toolbar.setLayout(toolbar_layout)

        search_label = QLabel("搜索:")
        search_label.setObjectName("inputLabel")
        toolbar_layout.addWidget(search_label)

        self._search_input = GlassInput("", "输入设备名称或用户名搜索...")
        self._search_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        toolbar_layout.addWidget(self._search_input, stretch=1)

        right_layout.addWidget(toolbar)

        # 密码详情展示区
        self._detail_display = GlassTextEdit("密码详情", readonly=True)
        font = self._detail_display.edit.font()
        font.setFamily("JetBrains Mono")
        font.setPointSize(11)
        self._detail_display.edit.setFont(font)
        right_layout.addWidget(self._detail_display, stretch=1)
        self._detail_display.edit.setMinimumHeight(400)

        split_row.addWidget(right_card, stretch=1)
        self.content_layout.addWidget(split_widget, stretch=1)

    # ---- 信号连接 ----

    def _connect_signals(self) -> None:
        self._search_input.input.textChanged.connect(self._on_filter_changed)
        self._list_widget.currentItemChanged.connect(self._on_selection_changed)
        self._add_btn.clicked.connect(self._on_add_clicked)

    # ---- 筛选逻辑 ----

    def _on_filter_changed(self, _text: str = "") -> None:
        self._filter_text = self._search_input.input.text().strip().lower()
        self._apply_filters()

    def _apply_filters(self) -> None:
        self._filtered_indices = []

        for i, entry in enumerate(self._all_passwords):
            if self._filter_text:
                name = entry.get("name", "").lower()
                username = entry.get("username", "").lower()
                if self._filter_text not in name and self._filter_text not in username:
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
            previous_name = self._all_passwords[real_idx].get("name", "")

        found = False
        for filtered_pos, real_idx in enumerate(self._filtered_indices):
            entry = self._all_passwords[real_idx]
            name = entry.get("name", "")
            username = entry.get("username", "")
            display = "{} | {}".format(name, username)
            item = QListWidgetItem(display)
            item.setData(Qt.UserRole, filtered_pos)
            item.setToolTip(display)
            self._list_widget.addItem(item)
            if name == previous_name:
                self._list_widget.setCurrentItem(item)
                found = True

        if not found and self._list_widget.count() > 0:
            self._list_widget.setCurrentRow(0)

        self._list_widget.blockSignals(False)

        if self._list_widget.count() == 0:
            self._selected_index = -1
            self._detail_display.setText("")

    # ---- 选择变更 ----

    def _on_selection_changed(self, current: QListWidgetItem, _previous: QListWidgetItem) -> None:
        if current is None:
            self._detail_display.setText("")
            return
        self._selected_index = current.data(Qt.UserRole)
        self._update_detail_display()

    def _update_detail_display(self) -> None:
        if self._selected_index < 0 or self._selected_index >= len(self._filtered_indices):
            self._detail_display.setText("")
            return
        real_idx = self._filtered_indices[self._selected_index]
        entry = self._all_passwords[real_idx]
        text = "设备名称: {}\n用户名:   {}\n密码:     {}".format(
            entry.get("name", ""),
            entry.get("username", ""),
            entry.get("password", ""),
        )
        self._detail_display.setText(text)

    # ---- 添加密码 ----

    def _on_add_clicked(self) -> None:
        dialog = _AddPasswordDialog(self)
        if dialog.exec() == QDialog.Accepted:
            name, username, password = dialog.get_result()
            self._add_password(name, username, password)

    def _add_password(self, name: str, username: str, password: str) -> None:
        """添加新条目到列表并持久化"""
        entry = {"name": name, "username": username, "password": password}
        self._all_passwords.append(entry)
        self._save_to_json()
        self._apply_filters()

        # 选中刚添加的条目（最后一个在过滤结果中的位置）
        for i in range(self._list_widget.count()):
            item = self._list_widget.item(i)
            if item and item.data(Qt.UserRole) == len(self._filtered_indices) - 1:
                self._list_widget.setCurrentItem(item)
                break

    # ---- JSON 持久化 ----

    def _save_to_json(self) -> None:
        json_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "resources", "dir", "weakpass", "weakpass.json"
        )
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self._all_passwords, f, ensure_ascii=False, indent=2)

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
    """创建弱密码查询页面（工厂函数，供 main_window.py 注册使用）"""
    passwords = _load_passwords()
    return WeakPasswordPage(passwords)
