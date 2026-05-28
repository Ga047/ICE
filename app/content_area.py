"""
右侧内容区 — QStackedWidget 管理所有模块页面（懒加载）
"""
from typing import Callable, Dict

from PySide6.QtWidgets import QStackedWidget, QWidget, QVBoxLayout, QLabel, QFrame
from PySide6.QtCore import Qt


_DISCLAIMER_TEXT = (
    "免责声明：本工具仅面向合法授权的企业安全建设行为，在使用本工具进行检测时，"
    "您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。"
    "如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，"
    "我们将不承担任何法律及连带责任。"
    "在使用本工具前，请您务必审慎阅读、充分理解各条款内容。"
    "除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。"
    "您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，"
    "即视为您已阅读并同意本协议的约束。"
)


class ModulePage(QWidget):
    """所有模块页面的基类"""

    def __init__(self, title: str, description: str, parent=None):
        super().__init__(parent)
        self._title = title
        self._description = description

        layout = QVBoxLayout()
        layout.setContentsMargins(8, 24, 32, 24)
        layout.setSpacing(16)
        self.setLayout(layout)

        title_lbl = QLabel(title)
        title_lbl.setObjectName("pageTitle")
        layout.addWidget(title_lbl)

        desc_lbl = QLabel(description)
        desc_lbl.setObjectName("pageDescription")
        layout.addWidget(desc_lbl)

        divider = QFrame()
        divider.setObjectName("divider")
        layout.addWidget(divider)

        self._content_layout = QVBoxLayout()
        self._content_layout.setSpacing(16)
        layout.addLayout(self._content_layout)

        layout.addStretch()

    @property
    def content_layout(self) -> QVBoxLayout:
        return self._content_layout

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description


class ContentArea(QWidget):
    """右侧内容区管理器 — 按需懒加载模块页面"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("contentArea")

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setLayout(layout)

        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: transparent;")
        layout.addWidget(self._stack)

        self._factories: Dict[str, Callable[[], ModulePage]] = {}
        self._pages: Dict[str, ModulePage] = {}

        self._welcome_page = ModulePage(
            "ICE V1.0",
            "一款为了渗透小子的集成工具，减少不同工具的切换，提高渗透测试的效率。\n"
            "主要功能：信息收集、端口探测、URL指纹识别、目录扫描等。"
        )

        # 在欢迎页底部添加免责声明
        disclaimer_frame = QFrame()
        disclaimer_frame.setObjectName("disclaimerBox")
        disc_layout = QVBoxLayout()
        disc_layout.setContentsMargins(16, 16, 16, 16)
        disclaimer_frame.setLayout(disc_layout)

        disc_title = QLabel("免责声明")
        disc_title.setObjectName("disclaimerTitle")
        disc_layout.addWidget(disc_title)

        disc_text = QLabel(_DISCLAIMER_TEXT)
        disc_text.setObjectName("disclaimerText")
        disc_text.setWordWrap(True)
        disc_layout.addWidget(disc_text)

        # 追加到 stretch 之后，使免责声明保持在欢迎页底部
        welcome_layout = self._welcome_page.layout()
        welcome_layout.addWidget(disclaimer_frame)

        self._stack.addWidget(self._welcome_page)
        self._stack.setCurrentWidget(self._welcome_page)

    def register_page(self, page_id: str, factory: Callable[[], ModulePage]):
        """注册页面工厂函数（不立即创建页面）"""
        self._factories[page_id] = factory

    def switch_to(self, page_id: str):
        """切换到指定页面，首次访问时懒加载创建"""
        if page_id not in self._factories:
            return
        if page_id not in self._pages:
            page = self._factories[page_id]()
            self._pages[page_id] = page
            self._stack.addWidget(page)
        self._stack.setCurrentWidget(self._pages[page_id])

    def show_welcome(self):
        self._stack.setCurrentWidget(self._welcome_page)
