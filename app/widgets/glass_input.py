"""
毛玻璃输入框组件
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QComboBox, QSpinBox, QCheckBox,
    QTextEdit
)
from typing import List

from PySide6.QtCore import Qt


class GlassInput(QWidget):
    """带标签的毛玻璃输入框"""

    def __init__(
        self,
        label: str = "",
        placeholder: str = "",
        parent=None
    ):
        super().__init__(parent)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.setLayout(layout)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("inputLabel")
            layout.addWidget(lbl)

        self._input = QLineEdit()
        self._input.setObjectName("glassInput")
        self._input.setPlaceholderText(placeholder)
        layout.addWidget(self._input)

    @property
    def input(self) -> QLineEdit:
        return self._input

    def text(self) -> str:
        return self._input.text()

    def setText(self, value: str):
        self._input.setText(value)


# 下拉框弹出列表统一样式（白底 + 34px 行高 + 蓝色选中态）
COMBO_POPUP_STYLE = (
    "QComboBox QAbstractItemView {"
    "  background-color: #FFFFFF;"
    "  color: #1E293B;"
    "  border: 1px solid rgba(0, 0, 0, 0.08);"
    "  border-radius: 8px;"
    "  outline: 0;"
    "  font-size: 13px;"
    "}"
    "QComboBox QAbstractItemView::item {"
    "  min-height: 34px;"
    "  padding: 8px 10px;"
    "}"
    "QComboBox QAbstractItemView::item:selected {"
    "  background-color: rgba(59, 130, 246, 0.14);"
    "  color: #1E293B;"
    "}"
)


class GlassCombo(QWidget):
    """带标签的毛玻璃下拉框（弹出列表自动应用 COMBO_POPUP_STYLE）"""

    def __init__(self, label: str = "", items: List[str] = None, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.setLayout(layout)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("inputLabel")
            layout.addWidget(lbl)

        self._combo = QComboBox()
        self._combo.setObjectName("glassCombo")
        self._combo.setStyleSheet(COMBO_POPUP_STYLE)
        if items:
            self._combo.addItems(items)
        layout.addWidget(self._combo)

    @property
    def combo(self) -> QComboBox:
        return self._combo

    def current_text(self) -> str:
        return self._combo.currentText()


class GlassSpinBox(QWidget):
    """带标签的毛玻璃数字输入"""

    def __init__(
        self,
        label: str = "",
        minimum: int = 0,
        maximum: int = 99999,
        value: int = 0,
        parent=None
    ):
        super().__init__(parent)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.setLayout(layout)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("inputLabel")
            layout.addWidget(lbl)

        self._spin = QSpinBox()
        self._spin.setObjectName("glassSpinBox")
        self._spin.setRange(minimum, maximum)
        self._spin.setValue(value)
        layout.addWidget(self._spin)

    @property
    def spin(self) -> QSpinBox:
        return self._spin

    def value(self) -> int:
        return self._spin.value()


class GlassCheckBox(QWidget):
    """毛玻璃复选框"""

    def __init__(self, label: str = "", checked: bool = False, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

        self._check = QCheckBox(label)
        self._check.setObjectName("glassCheckbox")
        self._check.setChecked(checked)
        layout.addWidget(self._check)

    @property
    def check(self) -> QCheckBox:
        return self._check

    def is_checked(self) -> bool:
        return self._check.isChecked()


class GlassTextEdit(QWidget):
    """带标签的毛玻璃文本编辑区（终端输出用）"""

    def __init__(self, label: str = "", readonly: bool = True, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.setLayout(layout)

        if label:
            lbl = QLabel(label)
            lbl.setObjectName("inputLabel")
            layout.addWidget(lbl)

        self._edit = QTextEdit()
        self._edit.setObjectName("terminalOutput")
        # 只接收纯文本，避免粘贴网页链接时带入蓝色下划线等富文本样式。
        self._edit.setAcceptRichText(False)
        self._edit.setReadOnly(readonly)
        layout.addWidget(self._edit)

    @property
    def edit(self) -> QTextEdit:
        return self._edit

    def text(self) -> str:
        return self._edit.toPlainText()

    def setText(self, value: str):
        self._edit.setPlainText(value)

    def append(self, value: str):
        self._edit.append(value)
