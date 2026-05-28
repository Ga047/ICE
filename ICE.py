"""
ICE V1.0 — 综合安全工具集
主入口
"""
import sys
import os
from typing import Optional

from PySide6.QtWidgets import QApplication, QLineEdit, QMenu, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QWidget
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QIcon, QAction, QColor, QPalette

from core._app_root import get_app_root
from app.main_window import MainWindow


# ============================================================================
# 全局右键菜单 —— 通过 CustomContextMenu 策略 + 递归控件树实现
# ============================================================================

_WIDGET_TYPES_WITH_EDIT_MENU = (
    QLineEdit, QTextEdit, QPlainTextEdit,
    QSpinBox, QDoubleSpinBox,
)

_PATCHED_PROPERTY = "__ice_menu_patched__"


def _build_light_palette() -> QPalette:
    p = QPalette()
    p.setColor(QPalette.Window, QColor(255, 255, 255))
    p.setColor(QPalette.Base, QColor(255, 255, 255))
    p.setColor(QPalette.Button, QColor(255, 255, 255))
    p.setColor(QPalette.Text, QColor(30, 41, 59))
    p.setColor(QPalette.Highlight, QColor(59, 130, 246, 30))
    p.setColor(QPalette.HighlightedText, QColor(30, 41, 59))
    return p


_LIGHT_PALETTE: Optional[QPalette] = None


def _get_light_palette() -> QPalette:
    global _LIGHT_PALETTE
    if _LIGHT_PALETTE is None:
        _LIGHT_PALETTE = _build_light_palette()
    return _LIGHT_PALETTE


def _show_context_menu(widget, global_pos) -> None:
    try:
        menu = QMenu()
        menu.setAutoFillBackground(True)
        menu.setPalette(_get_light_palette())
        menu.setStyleSheet("""
            QMenu {
                background-color: #FFFFFF;
                border: 1px solid rgba(0, 0, 0, 0.10);
                border-radius: 10px;
                padding: 6px;
            }
            QMenu::item {
                padding: 7px 32px 7px 14px;
                border-radius: 6px;
                color: #1E293B;
                font-size: 13px;
                background-color: transparent;
            }
            QMenu::item:selected {
                background-color: rgba(59, 130, 246, 0.12);
                color: #1E293B;
            }
            QMenu::item:disabled {
                color: #94A3B8;
                background-color: transparent;
            }
            QMenu::separator {
                height: 1px;
                background-color: rgba(0, 0, 0, 0.08);
                margin: 4px 10px;
            }
        """)

        is_readonly = False
        if isinstance(widget, QLineEdit):
            is_readonly = widget.isReadOnly()
        elif isinstance(widget, (QTextEdit, QPlainTextEdit)):
            is_readonly = widget.isReadOnly()
        elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
            is_readonly = widget.isReadOnly()

        has_selection = False
        if isinstance(widget, QLineEdit):
            has_selection = widget.hasSelectedText()
        elif isinstance(widget, (QTextEdit, QPlainTextEdit)):
            has_selection = widget.textCursor().hasSelection()
        elif isinstance(widget, (QSpinBox, QDoubleSpinBox)):
            has_selection = widget.hasSelectedText() if hasattr(widget, 'hasSelectedText') else False

        clipboard = QApplication.clipboard()
        has_clipboard = bool(clipboard.text())

        if not is_readonly:
            has_undo = widget.isUndoAvailable() if hasattr(widget, 'isUndoAvailable') else False
            ua = QAction("撤销(&U)", menu)
            ua.setEnabled(has_undo)
            if hasattr(widget, 'undo'):
                ua.triggered.connect(widget.undo)
            menu.addAction(ua)
            menu.addSeparator()

        ca = QAction("剪切(&X)", menu)
        ca.setEnabled(not is_readonly and has_selection)
        if hasattr(widget, 'cut'):
            ca.triggered.connect(widget.cut)
        menu.addAction(ca)

        cpa = QAction("复制(&C)", menu)
        cpa.setEnabled(has_selection)
        if hasattr(widget, 'copy'):
            cpa.triggered.connect(widget.copy)
        menu.addAction(cpa)

        pa = QAction("粘贴(&V)", menu)
        pa.setEnabled(not is_readonly and has_clipboard)
        if hasattr(widget, 'paste'):
            pa.triggered.connect(widget.paste)
        menu.addAction(pa)

        if not is_readonly:
            menu.addSeparator()
            da = QAction("删除(&D)", menu)
            da.setEnabled(has_selection)
            if hasattr(widget, 'del_'):
                da.triggered.connect(widget.del_)
            menu.addAction(da)

        menu.addSeparator()
        saa = QAction("全选(&A)", menu)
        if hasattr(widget, 'selectAll'):
            saa.triggered.connect(widget.selectAll)
        menu.addAction(saa)

        menu.exec_(global_pos)
    except Exception:
        pass


def _patch_one_widget(widget: QWidget) -> None:
    """对单个控件安装自定义右键菜单（通过 CustomContextMenu 策略）。"""
    if not isinstance(widget, _WIDGET_TYPES_WITH_EDIT_MENU):
        return
    if widget.property(_PATCHED_PROPERTY) is True:
        return
    # 已设置 CustomContextMenu 的控件（如子域名结果表格）会自行处理，跳过
    if widget.contextMenuPolicy() == Qt.CustomContextMenu:
        return

    widget.setProperty(_PATCHED_PROPERTY, True)
    widget.setContextMenuPolicy(Qt.CustomContextMenu)
    widget.customContextMenuRequested.connect(
        lambda pos, w=widget: _show_context_menu(w, w.mapToGlobal(pos))
    )


def patch_all_children(root: QWidget) -> None:
    """递归遍历控件树，对所有可编辑控件安装自定义右键菜单。"""
    for child in root.findChildren(QWidget):
        _patch_one_widget(child)
    _patch_one_widget(root)


# ============================================================================
# IceApplication
# ============================================================================

class IceApplication(QApplication):
    """自定义 QApplication：在窗口创建后持续扫描并 patch 新控件。"""

    def __init__(self, argv):
        super().__init__(argv)
        self._patch_timer = QTimer(self)
        self._patch_timer.setInterval(400)
        self._patch_timer.timeout.connect(self._scan_new_widgets)
        self._patch_timer.start()

    def _scan_new_widgets(self) -> None:
        """扫描所有顶层窗口的控件树，patch 未处理的可编辑控件。"""
        for top in self.topLevelWidgets():
            patch_all_children(top)


def load_stylesheet(app: QApplication) -> str:
    """加载 QSS 样式表"""
    style_path = os.path.join(
        get_app_root(),
        "resources", "styles", "apple_dark.qss"
    )
    if os.path.exists(style_path):
        with open(style_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


def setup_fonts(app: QApplication):
    """设置默认字体"""
    font = QFont()
    font.setFamilies(["Inter", "Microsoft YaHei", "Segoe UI", "sans-serif"])
    font.setPointSize(10)
    app.setFont(font)


def load_app_icon(app: QApplication):
    """加载应用图标"""
    base = get_app_root()
    icon_path = os.path.join(base, "resources", "icons", "Ice.ico")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))


def main():
    # 启用高 DPI 支持
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = IceApplication(sys.argv)
    app.setApplicationName("ICE")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("ICE")

    # 加载图标
    load_app_icon(app)

    # 加载样式
    stylesheet = load_stylesheet(app)
    if stylesheet:
        app.setStyleSheet(stylesheet)

    # 设置字体
    setup_fonts(app)

    # 创建并显示主窗口
    window = MainWindow()
    window.show()

    # 主窗口显示后立即 patch 所有已有控件的右键菜单
    patch_all_children(window)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
