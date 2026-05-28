"""
毛玻璃卡片基类组件
"""
from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QPushButton
from PySide6.QtCore import Qt


class GlassCard(QFrame):
    """毛玻璃风格卡片，用于包裹模块内容"""

    def __init__(self, parent=None, padding: int = 24):
        super().__init__(parent)
        self.setObjectName("glassCard")
        self.setLayout(QVBoxLayout())
        self.layout().setContentsMargins(padding, padding, padding, padding)
        self.layout().setSpacing(16)

    def add_button_row(self, button: QPushButton):
        """添加右对齐按钮行"""
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(button)
        self.layout().addLayout(row)
