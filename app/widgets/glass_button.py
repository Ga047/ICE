"""
毛玻璃按钮组件
"""
from PySide6.QtWidgets import QPushButton
from PySide6.QtCore import Qt


class GlassButton(QPushButton):
    """毛玻璃风格按钮，支持 primary / accent / danger 三种样式"""

    STYLE_PRIMARY = "primary"
    STYLE_ACCENT = "accent"
    STYLE_DANGER = "danger"

    def __init__(self, text: str = "", btn_type: str = STYLE_PRIMARY, parent=None):
        super().__init__(text, parent)
        self.setObjectName("glassButton")
        self.setCursor(Qt.PointingHandCursor)
        self._btn_type = btn_type
        self._apply_type()

    def _apply_type(self):
        if self._btn_type == self.STYLE_ACCENT:
            self.setProperty("class", "accentButton")
            self.setObjectName("accentButton")
        elif self._btn_type == self.STYLE_DANGER:
            self.setProperty("class", "dangerButton")
            self.setObjectName("dangerButton")
        else:
            self.setObjectName("glassButton")

        self.style().unpolish(self)
        self.style().polish(self)

    @property
    def btn_type(self) -> str:
        return self._btn_type

    @btn_type.setter
    def btn_type(self, value: str):
        self._btn_type = value
        self._apply_type()
