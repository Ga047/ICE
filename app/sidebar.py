"""
左侧导航栏组件 — 手风琴式折叠菜单，浅色毛玻璃背景
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QScrollArea, QFrame
)
from typing import List, Dict

from PySide6.QtCore import Qt, Signal


class SidebarGroup(QWidget):
    """可折叠的导航分组（手风琴模式：点击标题展开/收起子项）"""

    collapsedChanged = Signal()

    def __init__(self, title: str, items: List[Dict], parent=None):
        """
        items: [{"id": str, "text": str}, ...]
        """
        super().__init__(parent)
        self.setObjectName("sidebarGroup")
        self._collapsed = True  # 默认折叠

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(1)
        self.setLayout(layout)

        # 分组标题按钮（可点击折叠/展开）
        self._header_btn = QPushButton(f"▸  {title}")
        self._header_btn.setObjectName("groupHeader")
        self._header_btn.setCursor(Qt.PointingHandCursor)
        self._header_btn.clicked.connect(self._toggle)
        layout.addWidget(self._header_btn)

        # 子项容器
        self._items_widget = QWidget()
        self._items_layout = QVBoxLayout()
        self._items_layout.setContentsMargins(0, 0, 0, 0)
        self._items_layout.setSpacing(1)
        self._items_widget.setLayout(self._items_layout)
        self._items_widget.setVisible(False)  # 默认隐藏
        layout.addWidget(self._items_widget)

        self._buttons: Dict[str, QPushButton] = {}
        for item in items:
            btn = self._create_nav_item(item["id"], item["text"])
            self._buttons[item["id"]] = btn
            self._items_layout.addWidget(btn)

        # 分隔线
        divider = QFrame()
        divider.setObjectName("divider")
        layout.addWidget(divider)

    def _create_nav_item(self, item_id: str, text: str) -> QPushButton:
        btn = QPushButton(f"  {text}")
        btn.setObjectName("navItem")
        btn.setCursor(Qt.PointingHandCursor)
        btn.setProperty("active", "false")
        btn.setStyleSheet("text-align: left;")
        return btn

    def _toggle(self):
        """切换折叠/展开状态"""
        self.set_collapsed(not self._collapsed)

    def set_collapsed(self, collapsed: bool):
        """设置为折叠状态"""
        self._collapsed = collapsed
        self._items_widget.setVisible(not collapsed)
        # 更新箭头
        self._header_btn.setText(
            f"{'▸' if collapsed else '▾'}  {self._header_btn.text()[3:]}"
        )
        if not collapsed:
            self.collapsedChanged.emit()

    @property
    def collapsed(self) -> bool:
        return self._collapsed

    def set_active(self, item_id: str):
        for bid, btn in self._buttons.items():
            should_be_active = bid == item_id
            current = btn.property("active")
            if current != should_be_active:
                btn.setProperty("active", "true" if should_be_active else "false")
                btn.style().unpolish(btn)
                btn.style().polish(btn)

    def get_buttons(self) -> Dict[str, QPushButton]:
        return self._buttons


class Sidebar(QWidget):
    """浅色风格左侧导航栏（手风琴菜单）"""
    itemClicked = Signal(str)  # item_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(188)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setLayout(layout)

        # Logo 区域
        logo = QLabel("ICE")
        logo.setObjectName("logoText")
        layout.addWidget(logo)

        # 首页按钮
        self._home_btn = QPushButton("  🏠  首页")
        self._home_btn.setObjectName("homeNavItem")
        self._home_btn.setCursor(Qt.PointingHandCursor)
        self._home_btn.clicked.connect(lambda: self._on_item_clicked("home"))
        self._home_btn.setProperty("active", "false")
        layout.addWidget(self._home_btn)

        # 可滚动的导航区域
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea { background: transparent; border: none; }"
            "QWidget#qt_scrollarea_viewport { background: transparent; }"
        )

        nav_widget = QWidget()
        nav_widget.setStyleSheet("background: transparent;")
        nav_layout = QVBoxLayout()
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(4)
        nav_widget.setLayout(nav_layout)

        # 定义导航菜单结构
        self._groups_data = [
            ("信息收集", [
                {"id": "port_scanner", "text": "端口扫描"},
                {"id": "subdomain", "text": "子域名挖掘"},
                {"id": "dir_scanner", "text": "目录扫描"},
                {"id": "jsfinder", "text": "JSFinder"},
                {"id": "fingerprint", "text": "指纹识别"},
                {"id": "weight_query", "text": "权重查询"},
            ]),
            ("武器库", [
                {"id": "jwt_crack", "text": "JwtCrack"},
                {"id": "ip_lookup", "text": "IP归属地查询"},
                {"id": "codec", "text": "编码转换"},
                {"id": "reverse_shell", "text": "反弹 Shell"},
                {"id": "os_commands", "text": "常用命令"},
                {"id": "webshell", "text": "WebShell 集合"},
                {"id": "file_download", "text": "文件下载"},
            ]),
            ("工具箱", [
                {"id": "data_processing", "text": "数据处理"},
                {"id": "dict_generator", "text": "社工字典生成"},
                {"id": "weak_password", "text": "弱密码查询"},
                {"id": "av_detection", "text": "杀软识别"},
            ]),
        ]

        self._groups: List[SidebarGroup] = []
        self._all_buttons: Dict[str, QPushButton] = {}
        self._active_id: str = ""

        for title, items in self._groups_data:
            group = SidebarGroup(title, items)
            self._groups.append(group)
            nav_layout.addWidget(group)

            # 分组展开时折叠其他分组（手风琴）
            group.collapsedChanged.connect(
                lambda g=group: self._on_group_expanded(g)
            )

            for bid, btn in group.get_buttons().items():
                self._all_buttons[bid] = btn
                btn.clicked.connect(lambda checked=False, i=bid: self._on_item_clicked(i))

        nav_layout.addStretch()
        scroll.setWidget(nav_widget)
        layout.addWidget(scroll, stretch=1)

    def _on_group_expanded(self, expanded_group: SidebarGroup):
        """手风琴逻辑：同一时间只允许一个分组展开"""
        for group in self._groups:
            if group is not expanded_group and not group.collapsed:
                group.set_collapsed(True)

    def _on_item_clicked(self, item_id: str):
        self.set_active(item_id)
        self.itemClicked.emit(item_id)

    def set_active(self, item_id: str):
        self._active_id = item_id
        # 更新首页按钮状态
        is_home = (item_id == "home")
        self._home_btn.setProperty("active", "true" if is_home else "false")
        self._home_btn.style().unpolish(self._home_btn)
        self._home_btn.style().polish(self._home_btn)
        # 更新分组按钮状态
        for group in self._groups:
            group.set_active(item_id)

    @property
    def active_id(self) -> str:
        return self._active_id
