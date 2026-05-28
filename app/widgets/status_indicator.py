"""
状态指示器组件
"""
from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel
from PySide6.QtCore import Qt


class StatusIndicator(QWidget):
    """状态指示器，显示空闲/运行中/错误三种状态"""

    STATUS_IDLE = "idle"
    STATUS_RUNNING = "running"
    STATUS_ERROR = "error"

    STATUS_TEXT = {
        STATUS_IDLE: "就绪",
        STATUS_RUNNING: "运行中",
        STATUS_ERROR: "错误",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.setLayout(layout)

        self._dot = QLabel()
        self._dot.setObjectName("statusDot")
        self._dot.setProperty("status", self.STATUS_IDLE)
        self._dot.setFixedSize(10, 10)

        self._label = QLabel(self.STATUS_TEXT[self.STATUS_IDLE])
        self._label.setStyleSheet("font-size: 12px; color: #64748B;")

        layout.addWidget(self._dot)
        layout.addWidget(self._label)
        layout.addStretch()

        self._status = self.STATUS_IDLE

    def set_status(self, status: str, text: str = None):
        self._status = status
        self._dot.setProperty("status", status)
        self._dot.style().unpolish(self._dot)
        self._dot.style().polish(self._dot)

        if text is None:
            text = self.STATUS_TEXT.get(status, status)
        self._label.setText(text)

    @property
    def status(self) -> str:
        return self._status
