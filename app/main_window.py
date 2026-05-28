"""
主窗口 — 组合侧边栏、内容区、底部设置栏
"""
import os

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QApplication
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon

from app.sidebar import Sidebar
from app.content_area import ContentArea
from app.settings_bar import SettingsBar
from core.settings import AppSettings
from core._app_root import get_app_root


class MainWindow(QMainWindow):
    """ICE 主窗口"""

    WINDOW_WIDTH = 1280
    WINDOW_HEIGHT = 920
    MIN_WIDTH = 960
    MIN_HEIGHT = 680

    def __init__(self):
        super().__init__()
        self._settings = AppSettings()

        self.setWindowTitle("ICE V1.0 by Ga0Y1u")
        self.setMinimumSize(self.MIN_WIDTH, self.MIN_HEIGHT)
        self.resize(self.WINDOW_WIDTH, self.WINDOW_HEIGHT)

        # 窗口居中
        screen = QApplication.primaryScreen().availableGeometry()
        x = (screen.width() - self.WINDOW_WIDTH) // 2
        y = (screen.height() - self.WINDOW_HEIGHT) // 2
        self.move(x, y)

        # 加载窗口图标
        base = get_app_root()
        icon_path = os.path.join(base, "resources", "icons", "Ice.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self.setStyleSheet("QMainWindow { background-color: #F5F6FA; }")

        self._setup_ui()
        self._register_pages()
        self._connect_signals()

        # 启动时默认显示首页，高亮首页按钮
        self._sidebar.set_active("home")

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        # 主水平布局：侧边栏 + 内容区
        main_h = QHBoxLayout()
        main_h.setContentsMargins(0, 0, 0, 0)
        main_h.setSpacing(0)

        self._sidebar = Sidebar()
        main_h.addWidget(self._sidebar)

        # 右侧：内容区 + 底部设置栏
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_widget.setLayout(right_layout)

        self._content_area = ContentArea()
        right_layout.addWidget(self._content_area, stretch=1)

        self._settings_bar = SettingsBar(self._settings)
        right_layout.addWidget(self._settings_bar)

        main_h.addWidget(right_widget, stretch=1)

        central.setLayout(main_h)

    def _register_pages(self):
        """注册所有模块页面到内容区"""
        from modules import info_gathering, weapon_arsenal, toolbox, codec

        # 信息收集
        self._content_area.register_page(
            "port_scanner",
            lambda: info_gathering.port_scanner.create_page(self._settings)
        )
        self._content_area.register_page(
            "subdomain",
            lambda: info_gathering.subdomain.create_page(self._settings)
        )
        self._content_area.register_page(
            "dir_scanner",
            lambda: info_gathering.dir_scanner.create_page(self._settings)
        )
        self._content_area.register_page(
            "jsfinder",
            lambda: info_gathering.jsfinder.create_page(self._settings)
        )
        self._content_area.register_page(
            "fingerprint",
            lambda: info_gathering.fingerprint.create_page(self._settings)
        )
        self._content_area.register_page(
            "weight_query",
            lambda: info_gathering.weight_query.create_page(self._settings)
        )

        # 武器库
        self._content_area.register_page(
            "jwt_crack",
            weapon_arsenal.jwt_crack.create_page
        )
        self._content_area.register_page(
            "ip_lookup",
            weapon_arsenal.ip_lookup.create_page
        )
        self._content_area.register_page(
            "codec",
            codec.create_page
        )
        self._content_area.register_page(
            "reverse_shell",
            weapon_arsenal.reverse_shell.create_page
        )
        self._content_area.register_page(
            "os_commands",
            weapon_arsenal.os_commands.create_page
        )
        self._content_area.register_page(
            "webshell",
            weapon_arsenal.webshell.create_page
        )
        self._content_area.register_page(
            "file_download",
            weapon_arsenal.file_download.create_page
        )

        # 工具箱
        self._content_area.register_page(
            "data_processing",
            toolbox.data_processing.create_page
        )
        self._content_area.register_page(
            "dict_generator",
            toolbox.dict_generator.create_page
        )
        self._content_area.register_page(
            "weak_password",
            toolbox.weak_password.create_page
        )
        self._content_area.register_page(
            "av_detection",
            toolbox.av_detection.create_page
        )

    def _show_welcome(self) -> None:
        """返回首页介绍页"""
        self._content_area.show_welcome()
        self._sidebar.set_active("")

    def _connect_signals(self):
        self._sidebar.itemClicked.connect(self._on_nav_item_clicked)

    def _on_nav_item_clicked(self, page_id: str) -> None:
        if page_id == "home":
            self._show_welcome()
        else:
            self._content_area.switch_to(page_id)
        if page_id == "dict_generator":
            self.showMaximized()

    @property
    def settings(self) -> AppSettings:
        return self._settings
