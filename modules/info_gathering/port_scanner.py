"""端口扫描模块"""
import os
import re
import threading
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QApplication,
    QVBoxLayout,
    QWidget,
)

from app.content_area import ModulePage
from app.widgets.glass_button import GlassButton
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassCheckBox, GlassSpinBox, GlassTextEdit
from core.port_scanner_engine import (
    COMMON_DATABASE_PORTS,
    COMMON_PORTS,
    COMMON_WEB_PORTS,
    TOP_1000_PORTS,
    TOP_100_PORTS,
    PortScanResult,
    PortScannerEngine,
    parse_ports,
    parse_targets,
    ports_to_text,
    results_to_csv,
    results_to_html,
    results_to_txt,
    results_to_xlsx,
)
from core.settings import AppSettings


PORT_MODE_PRESETS = {
    "常见Web端口": COMMON_WEB_PORTS,
    "常见端口": COMMON_PORTS,
    "Top100": TOP_100_PORTS,
    "Top1000": TOP_1000_PORTS,
    "常见数据库": COMMON_DATABASE_PORTS,
    "自定义端口": [],
    "全端口": [],
}

RESULT_FLUSH_BATCH_SIZE = 80
EXPORT_FILTER_TEXT = "CSV 文件 (*.csv);;文本文件 (*.txt);;HTML 文件 (*.html);;Excel 工作簿 (*.xlsx)"
EXPORT_FILTER_EXTENSIONS = {
    ".csv": "CSV 文件 (*.csv)",
    ".txt": "文本文件 (*.txt)",
    ".html": "HTML 文件 (*.html)",
    ".xlsx": "Excel 工作簿 (*.xlsx)",
}


class PortScanWorker(QThread):
    """后台扫描线程"""

    resultFound = Signal(object)
    statusChanged = Signal(str)
    scanFinished = Signal()

    def __init__(
        self,
        settings: AppSettings,
        targets: List[str],
        ports: List[int],
        thread_count: int,
        timeout_ms: int,
        ping_enabled: bool,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._settings = settings
        self._targets = targets
        self._ports = ports
        self._thread_count = thread_count
        self._timeout_ms = timeout_ms
        self._ping_enabled = ping_enabled
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()

    def stop(self) -> None:
        """请求完全停止扫描"""
        self._stop_event.set()
        self._pause_event.clear()

    def pause(self) -> None:
        """暂停提交后续扫描任务"""
        self._pause_event.set()

    def resume(self) -> None:
        """继续提交后续扫描任务"""
        self._pause_event.clear()

    def is_paused(self) -> bool:
        """返回当前是否处于暂停状态"""
        return self._pause_event.is_set()

    def run(self) -> None:
        """执行扫描任务"""
        try:
            engine = PortScannerEngine(self._settings)
            engine.scan(
                targets=self._targets,
                ports=self._ports,
                thread_count=self._thread_count,
                timeout_ms=self._timeout_ms,
                ping_enabled=self._ping_enabled,
                stop_event=self._stop_event,
                pause_event=self._pause_event,
                result_callback=self.resultFound.emit,
                status_callback=self.statusChanged.emit,
            )
        finally:
            self.scanFinished.emit()


class PortScannerPage(ModulePage):
    """端口扫描页面"""

    TABLE_HEADERS = ["Target", "Host", "端口", "传输", "协议", "响应码", "Web标题", "Banner"]

    def __init__(self, settings: AppSettings, parent: Optional[QWidget] = None):
        super().__init__(
            "端口扫描",
            "对目标主机进行端口开放情况探测，支持批量目标、端口预设、服务识别和 Web 标题探测",
            parent,
        )
        self._settings = settings
        self._worker: Optional[PortScanWorker] = None
        self._results: List[PortScanResult] = []
        self._result_rows: Dict[Tuple[str, int, str], int] = {}
        self._results_by_key: Dict[Tuple[str, int, str], PortScanResult] = {}
        self._pending_results_by_key: Dict[Tuple[str, int, str], PortScanResult] = {}
        self._pending_status_message: Optional[str] = None
        self._mode_buttons: Dict[str, GlassButton] = {}
        self._last_target_count = 0
        self._last_port_count = 0

        self.layout().setSpacing(8)
        self.content_layout.setSpacing(8)
        self._setup_ui()
        self._apply_port_mode("常见Web端口")
        self._update_config_summary()

    def _setup_ui(self) -> None:
        self._config_card = GlassCard(padding=12)
        self._config_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        header_widget = QWidget()
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)
        header_widget.setLayout(header_layout)

        config_title = QLabel("扫描配置")
        config_title.setObjectName("sectionTitle")
        header_layout.addWidget(config_title)

        self._config_summary = QLabel("")
        self._config_summary.setObjectName("configSummary")
        self._config_summary.setWordWrap(True)
        header_layout.addWidget(self._config_summary, stretch=1)

        self._status_label = QLabel("")
        self._status_label.setObjectName("scanStatus")
        header_layout.addWidget(self._status_label)

        self._config_card.layout().addWidget(header_widget)

        self._config_body = QWidget()
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(12)
        self._config_body.setLayout(body_layout)

        self._target_input = GlassTextEdit("目标地址", readonly=False)
        self._target_input.setFixedWidth(210)
        self._target_input.edit.setPlaceholderText(
            "IPv4 / IPv6 / 域名(支持换行分割)\n192.168.1.1/24\n192.168.1.2-192.168.1.15"
        )
        self._target_input.edit.setObjectName("targetAddressInput")
        self._target_input.edit.setMinimumHeight(100)
        self._target_input.edit.setMaximumHeight(130)
        self._target_input.edit.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._target_input.edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        body_layout.addWidget(self._target_input)
        body_layout.setAlignment(self._target_input, Qt.AlignBottom)

        middle_panel = QWidget()
        middle_layout = QVBoxLayout()
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(8)
        middle_panel.setLayout(middle_layout)
        body_layout.addWidget(middle_panel, stretch=1)
        body_layout.setAlignment(middle_panel, Qt.AlignBottom)

        mode_label = QLabel("端口选择模式")
        mode_label.setObjectName("inputLabel")
        middle_layout.addWidget(mode_label)

        mode_widget = QWidget()
        mode_layout = QGridLayout()
        mode_layout.setContentsMargins(0, 0, 0, 0)
        mode_layout.setHorizontalSpacing(6)
        mode_layout.setVerticalSpacing(6)
        mode_widget.setLayout(mode_layout)

        self._mode_group = QButtonGroup(self)
        self._mode_group.setExclusive(True)
        for index, mode_name in enumerate(PORT_MODE_PRESETS.keys()):
            button = GlassButton(mode_name)
            button.setCheckable(True)
            button.setObjectName("compactModeButton")
            button.setMinimumWidth(92)
            button.setFixedHeight(28)
            self._mode_buttons[mode_name] = button
            self._mode_group.addButton(button)
            mode_layout.addWidget(button, index // 4, index % 4)
        self._mode_group.buttonClicked.connect(
            lambda button: self._apply_port_mode(button.text())
        )
        middle_layout.addWidget(mode_widget)

        self._port_input = GlassTextEdit("端口范围", readonly=True)
        self._port_input.edit.setObjectName("portRangeInput")
        self._port_input.edit.setPlaceholderText("例如：80,443,8000-8100")
        self._port_input.edit.setMinimumHeight(60)
        self._port_input.edit.setMaximumHeight(80)
        self._port_input.edit.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._port_input.edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        middle_layout.addWidget(self._port_input)

        control_panel = QWidget()
        control_layout = QVBoxLayout()
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(8)
        control_panel.setLayout(control_layout)
        body_layout.addWidget(control_panel)

        self._thread_input = GlassSpinBox("线程数", 1, 200, 200)
        self._thread_input.setFixedWidth(160)
        control_layout.addWidget(self._thread_input)

        self._timeout_input = GlassSpinBox("超时时间（毫秒）", 3000, 60000, self._settings.get("timeout", 3000))
        self._timeout_input.setFixedWidth(160)
        control_layout.addWidget(self._timeout_input)

        self._ping_check = GlassCheckBox("IP 探活", True)
        self._ping_check.check.stateChanged.connect(lambda _state: self._update_config_summary())
        control_layout.addWidget(self._ping_check)
        control_layout.addStretch()

        self._scan_btn = GlassButton("开始扫描")
        self._scan_btn.clicked.connect(self._start_scan)

        self._pause_btn = GlassButton("暂停扫描")
        self._pause_btn.setEnabled(False)
        self._pause_btn.clicked.connect(self._toggle_pause)

        self._stop_btn = GlassButton("停止扫描")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_scan)

        self._export_btn = GlassButton("导出结果")
        self._export_btn.clicked.connect(self._export_results)

        self._clear_btn = GlassButton("清空结果")
        self._clear_btn.clicked.connect(self._clear_results)

        button_panel = QWidget()
        button_layout = QVBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(6)
        for btn in [self._scan_btn, self._pause_btn, self._stop_btn,
                    self._export_btn, self._clear_btn]:
            btn.setMinimumWidth(88)
            button_layout.addWidget(btn)
        button_layout.addStretch()
        button_panel.setLayout(button_layout)
        body_layout.addWidget(button_panel)

        self._config_card.layout().addWidget(self._config_body)

        self._target_input.edit.textChanged.connect(self._update_config_summary)
        self._port_input.edit.textChanged.connect(self._update_config_summary)
        self._thread_input.spin.valueChanged.connect(lambda _value: self._update_config_summary())
        self._timeout_input.spin.valueChanged.connect(lambda _value: self._update_config_summary())

        self._target_timer = QTimer(self)
        self._target_timer.setSingleShot(True)
        self._target_timer.setInterval(600)
        self._target_timer.timeout.connect(self._validate_target)
        self._target_input.edit.textChanged.connect(self._target_timer.start)

        self._port_timer = QTimer(self)
        self._port_timer.setSingleShot(True)
        self._port_timer.setInterval(600)
        self._port_timer.timeout.connect(self._validate_port_range)
        self._port_input.edit.textChanged.connect(self._port_timer.start)

        self._thread_input.spin.lineEdit().editingFinished.connect(
            lambda: self._validate_spin_no_leading_zero(self._thread_input.spin, "线程数")
        )
        self._timeout_input.spin.lineEdit().editingFinished.connect(
            lambda: self._validate_spin_no_leading_zero(self._timeout_input.spin, "超时时间")
        )

        self._result_flush_timer = QTimer(self)
        self._result_flush_timer.setSingleShot(True)
        self._result_flush_timer.setInterval(100)
        self._result_flush_timer.timeout.connect(self._flush_pending_results)

        self._status_timer = QTimer(self)
        self._status_timer.setSingleShot(True)
        self._status_timer.setInterval(250)
        self._status_timer.timeout.connect(self._flush_status)

        result_card = GlassCard(padding=16)
        result_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self._result_table = QTableWidget(0, len(self.TABLE_HEADERS))
        self._result_table.setHorizontalHeaderLabels(self.TABLE_HEADERS)
        self._result_table.setObjectName("portResultTable")
        self._result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._result_table.setAlternatingRowColors(True)
        self._result_table.setSortingEnabled(True)
        self._result_table.verticalHeader().setVisible(False)
        self._result_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._result_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._result_table.horizontalHeader().setStretchLastSection(False)
        self._result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._result_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self._result_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self._result_table.setColumnWidth(0, 220)
        self._result_table.setColumnWidth(1, 150)
        self._result_table.setColumnWidth(2, 70)
        self._result_table.setColumnWidth(3, 70)
        self._result_table.setColumnWidth(4, 90)
        self._result_table.setColumnWidth(5, 70)
        self._result_table.setColumnWidth(6, 280)
        self._result_table.setColumnWidth(7, 180)
        self._result_table.setMinimumHeight(430)
        self._result_table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        self._result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._result_table.customContextMenuRequested.connect(self._on_context_menu)
        result_card.layout().addWidget(self._result_table)

        self.content_layout.addWidget(self._config_card)
        self.content_layout.addWidget(result_card, stretch=1)

    def _update_config_summary(self) -> None:
        target_count = self._last_target_count or self._count_targets_for_summary()
        port_count = self._last_port_count or self._count_ports_for_summary()
        ping_text = "开启探活" if self._ping_check.is_checked() else "关闭探活"
        self._config_summary.setText(
            "目标 %s 个 · 端口 %s 个 · 线程 %s · 超时 %sms · %s"
            % (
                target_count,
                port_count,
                self._thread_input.value(),
                self._timeout_input.value(),
                ping_text,
            )
        )

    def _count_targets_for_summary(self) -> int:
        return len([line for line in self._target_input.text().splitlines() if line.strip()])

    def _count_ports_for_summary(self) -> int:
        try:
            return len(parse_ports(self._port_input.text()))
        except ValueError:
            return 0

    def _on_cell_double_clicked(self, row: int, col: int) -> None:
        """双击单元格弹出完整内容"""
        item = self._result_table.item(row, col)
        if item is None or not item.text().strip():
            return
        header = self.TABLE_HEADERS[col] if col < len(self.TABLE_HEADERS) else "内容"
        self._show_styled_message(header, item.text(), QMessageBox.Information)

    def _on_context_menu(self, pos) -> None:
        """右键菜单 — 毛玻璃风格"""
        item = self._result_table.itemAt(pos)
        if item is None or not item.text().strip():
            return
        menu = QMenu(self)
        menu.setObjectName("styledMenu")
        menu.setStyleSheet(
            "QMenu {"
            "  background-color: rgba(255,255,255,0.95);"
            "  border: 1px solid rgba(0,0,0,0.08);"
            "  border-radius: 10px;"
            "  padding: 6px 4px;"
            "}"
            "QMenu::item {"
            "  padding: 8px 32px 8px 16px;"
            "  color: #1E293B;"
            "  font-size: 13px;"
            "  border-radius: 6px;"
            "}"
            "QMenu::item:selected {"
            "  background-color: rgba(59,130,246,0.12);"
            "  color: #3B82F6;"
            "}"
        )
        copy_action = menu.addAction("复制")
        copy_action.triggered.connect(lambda _checked=False, i=item: self._perform_copy(i))
        menu.exec_(self._result_table.viewport().mapToGlobal(pos))

    def _perform_copy(self, item: QTableWidgetItem) -> None:
        """执行复制并弹窗提示"""
        QApplication.clipboard().setText(item.text())
        self._show_styled_message("已复制", "已复制到剪贴板", QMessageBox.Information)

    def _show_styled_message(self, title: str, message: str, icon):
        """显示与全局设置一致的毛玻璃提示弹窗。"""
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
            "QLabel {"
            "  color: #1E293B;"
            "  font-size: 13px;"
            "  padding: 12px 8px;"
            "}"
            "QPushButton {"
            "  background: rgba(59,130,246,0.08);"
            "  border: 1px solid rgba(59,130,246,0.18);"
            "  border-radius: 6px;"
            "  padding: 6px 24px;"
            "  color: #3B82F6;"
            "  font-size: 12px;"
            "  font-weight: 500;"
            "}"
            "QPushButton:hover {"
            "  background: rgba(59,130,246,0.14);"
            "}"
        )
        return box.exec()

    def _show_styled_warning(self, title: str, message: str):
        """显示与全局设置一致的警告弹窗"""
        return self._show_styled_message(title, message, QMessageBox.Warning)

    def _validate_target(self):
        """校验目标地址输入"""
        text = self._target_input.text().strip()
        if not text:
            return
        try:
            parse_targets(text)
        except ValueError as error:
            self._show_styled_warning("目标地址无效", str(error))

    def _validate_port_range(self):
        """校验端口范围输入（含前导零检测）"""
        text = self._port_input.text().strip()
        if not text:
            return
        normalized = re.sub(r"[\s;]+", ",", text.replace("\n", ","))
        for part in normalized.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                for sub in part.split("-"):
                    sub = sub.strip()
                    if len(sub) > 1 and sub[0] == "0":
                        self._show_styled_warning(
                            "端口格式无效",
                            "端口 \"%s\" 含多余前导零，请改为 \"%s\"。" % (sub, sub.lstrip("0")),
                        )
                        return
            else:
                if len(part) > 1 and part[0] == "0":
                    self._show_styled_warning(
                        "端口格式无效",
                        "端口 \"%s\" 含多余前导零，请改为 \"%s\"。" % (part, part.lstrip("0")),
                    )
                    return
        try:
            parse_ports(text)
        except ValueError as error:
            self._show_styled_warning("端口无效", str(error))

    def _validate_spin_no_leading_zero(self, spin, field_name: str):
        """校验 SpinBox 输入无前导零"""
        text = spin.lineEdit().text().strip()
        if len(text) > 1 and text[0] == "0":
            self._show_styled_warning(
                "数值格式无效",
                "%s \"%s\" 含多余前导零，请改为 \"%s\"。" % (field_name, text, text.lstrip("0")),
            )
            spin.lineEdit().setText(text.lstrip("0"))

    def _apply_port_mode(self, mode_name: str) -> None:
        if mode_name in self._mode_buttons:
            self._mode_buttons[mode_name].setChecked(True)

        if mode_name == "全端口":
            self._port_input.setText("1-65535")
            self._set_port_input_editable(False)
        elif mode_name == "自定义端口":
            self._set_port_input_editable(True)
            if not self._port_input.text().strip():
                self._port_input.setText("80,443,8080")
        else:
            self._port_input.setText(ports_to_text(PORT_MODE_PRESETS[mode_name]))
            self._set_port_input_editable(False)
        self._last_port_count = 0
        self._update_config_summary()

    def _set_port_input_editable(self, editable: bool) -> None:
        self._port_input.edit.setReadOnly(not editable)
        self._port_input.edit.setProperty("editable", "true" if editable else "false")
        self._port_input.edit.style().unpolish(self._port_input.edit)
        self._port_input.edit.style().polish(self._port_input.edit)

    def _start_scan(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return

        self._stop_validation_timers()
        try:
            targets = parse_targets(self._target_input.text())
            ports = parse_ports(self._port_input.text())
        except ValueError as error:
            self._show_styled_warning("输入错误", str(error))
            return

        self._last_target_count = len(targets)
        self._last_port_count = len(ports)
        self._update_config_summary()

        self._results = []
        self._result_rows = {}
        self._results_by_key = {}
        self._prepare_result_table_for_scan()
        self._result_table.setRowCount(0)
        self._scan_btn.setEnabled(False)
        self._pause_btn.setText("暂停扫描")
        self._pause_btn.setEnabled(True)
        self._stop_btn.setEnabled(True)
        self._clear_btn.setEnabled(False)
        self._set_inputs_enabled(False)
        self._set_status("扫描启动中...")

        self._worker = PortScanWorker(
            settings=self._settings,
            targets=targets,
            ports=ports,
            thread_count=self._thread_input.value(),
            timeout_ms=self._timeout_input.value(),
            ping_enabled=self._ping_check.is_checked(),
            parent=self,
        )
        self._worker.resultFound.connect(self._add_result)
        self._worker.statusChanged.connect(self._queue_status)
        self._worker.scanFinished.connect(self._finish_scan)
        self._worker.start()

    def _toggle_pause(self) -> None:
        if self._worker is None or not self._worker.isRunning():
            return
        if self._worker.is_paused():
            self._worker.resume()
            self._pause_btn.setText("暂停扫描")
            self._set_status("扫描继续中...")
        else:
            self._worker.pause()
            self._pause_btn.setText("继续扫描")
            self._set_status("扫描已暂停，当前连接完成后不再提交新任务")

    def _stop_scan(self) -> None:
        if self._worker is None or not self._worker.isRunning():
            return
        self._worker.stop()
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._set_status("正在停止扫描...")

    def _finish_scan(self) -> None:
        self._scan_btn.setEnabled(True)
        self._pause_btn.setText("暂停扫描")
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._clear_btn.setEnabled(True)
        self._set_inputs_enabled(True)
        self._restore_result_table_after_scan()
        self._flush_status()
        self._worker = None

    def _set_inputs_enabled(self, enabled: bool) -> None:
        self._target_input.setEnabled(enabled)
        self._port_input.setEnabled(enabled)
        self._thread_input.setEnabled(enabled)
        self._timeout_input.setEnabled(enabled)
        self._ping_check.setEnabled(enabled)
        for button in self._mode_buttons.values():
            button.setEnabled(enabled)

    def _add_result(self, result: PortScanResult) -> None:
        key = self._result_key(result)
        self._pending_results_by_key[key] = result
        if not self._result_flush_timer.isActive():
            self._result_flush_timer.start()

    def _flush_pending_results(self, flush_all: bool = False) -> None:
        """分片刷新扫描结果，避免大量行更新阻塞滚动和折叠交互"""
        if not self._pending_results_by_key:
            self._result_flush_timer.stop()
            return

        pending_keys = list(self._pending_results_by_key.keys())
        if not flush_all:
            pending_keys = pending_keys[:RESULT_FLUSH_BATCH_SIZE]
        pending_results = [
            self._pending_results_by_key.pop(key)
            for key in pending_keys
        ]
        self._result_flush_timer.stop()
        should_scroll = self._should_auto_scroll_results()
        has_new_row = False
        self._result_table.setUpdatesEnabled(False)
        try:
            for result in pending_results:
                if self._upsert_result_row(result):
                    has_new_row = True
        finally:
            self._result_table.setUpdatesEnabled(True)
        self._results = list(self._results_by_key.values())
        if has_new_row and should_scroll:
            self._result_table.scrollToBottom()
        if self._pending_results_by_key:
            self._result_flush_timer.start()

    def _upsert_result_row(self, result: PortScanResult) -> bool:
        key = self._result_key(result)
        is_new_row = key not in self._result_rows
        if is_new_row:
            row = self._result_table.rowCount()
            self._result_table.insertRow(row)
            self._result_rows[key] = row
        else:
            row = self._result_rows[key]

        self._results_by_key[key] = result
        values = [
            result.target,
            result.host,
            str(result.port),
            result.transport,
            result.protocol,
            result.status_code,
            result.web_title,
            result.banner,
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            self._result_table.setItem(row, column, item)
        return is_new_row

    def _should_auto_scroll_results(self) -> bool:
        """仅在用户本来就在底部时自动跟随新结果，避免滚动时被强制拉回"""
        scroll_bar = self._result_table.verticalScrollBar()
        return scroll_bar.value() >= scroll_bar.maximum() - 2

    def _result_key(self, result: PortScanResult) -> Tuple[str, int, str]:
        """生成同一端口结果的稳定更新键"""
        return (result.host, result.port, result.transport)

    def _prepare_result_table_for_scan(self) -> None:
        """扫描期间关闭排序，保证实时更新行号稳定"""
        self._stop_validation_timers()
        self._pending_results_by_key = {}
        self._result_flush_timer.stop()
        self._result_table.setSortingEnabled(False)

    def _restore_result_table_after_scan(self) -> None:
        """扫描结束后恢复结果表排序能力"""
        self._flush_pending_results(flush_all=True)
        self._result_table.setSortingEnabled(True)

    def _set_status(self, message: str) -> None:
        self._status_label.setText(message)

    def _queue_status(self, message: str) -> None:
        """延迟刷新状态栏，合并短时间内的大量进度消息"""
        self._pending_status_message = message
        if not self._status_timer.isActive():
            self._status_timer.start()

    def _flush_status(self) -> None:
        if self._pending_status_message is None:
            self._status_timer.stop()
            return
        self._status_label.setText(self._pending_status_message)
        self._pending_status_message = None
        self._status_timer.stop()

    def _stop_validation_timers(self) -> None:
        """扫描启动前停止输入校验定时器，避免扫描中弹出阻塞提示"""
        self._target_timer.stop()
        self._port_timer.stop()

    def _clear_results(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self._results = []
        self._result_rows = {}
        self._results_by_key = {}
        self._pending_results_by_key = {}
        self._result_flush_timer.stop()
        self._result_table.setRowCount(0)
        self._set_status("结果已清空")

    def _export_results(self) -> None:
        self._flush_pending_results(flush_all=True)
        if not self._results:
            self._show_styled_warning("导出结果", "当前没有可导出的扫描结果")
            return

        filepath, selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出扫描结果",
            "port_scan_results.csv",
            EXPORT_FILTER_TEXT,
        )
        if not filepath:
            return
        try:
            filepath, extension = self._normalize_export_filepath(filepath, selected_filter)
        except ValueError as error:
            self._show_styled_warning("导出失败", str(error))
            return

        try:
            self._write_export_file(filepath, extension)
        except IOError as error:
            self._show_styled_warning("导出失败", "写入文件失败：%s" % error)
            return
        self._show_styled_message("导出完成", "扫描结果已导出", QMessageBox.Information)

    def _normalize_export_filepath(self, filepath: str, selected_filter: str) -> Tuple[str, str]:
        """根据文件名和过滤器确定导出扩展名"""
        root, extension = os.path.splitext(filepath)
        extension = extension.lower()
        if not extension:
            extension = self._extension_from_filter(selected_filter)
            filepath = root + extension
        if extension not in EXPORT_FILTER_EXTENSIONS:
            raise ValueError("不支持的导出格式：%s" % extension)
        return filepath, extension

    def _extension_from_filter(self, selected_filter: str) -> str:
        """从 QFileDialog 过滤器文本中提取默认扩展名"""
        for extension in EXPORT_FILTER_EXTENSIONS:
            if "*%s" % extension in selected_filter:
                return extension
        return ".csv"

    def _write_export_file(self, filepath: str, extension: str) -> None:
        """按扩展名写入对应导出内容"""
        if extension == ".xlsx":
            with open(filepath, "wb") as output_file:
                output_file.write(results_to_xlsx(self._results))
            return

        if extension == ".csv":
            content = results_to_csv(self._results)
            encoding = "utf-8-sig"
        elif extension == ".txt":
            content = results_to_txt(self._results)
            encoding = "utf-8"
        elif extension == ".html":
            content = results_to_html(self._results)
            encoding = "utf-8"
        else:
            raise ValueError("不支持的导出格式：%s" % extension)

        with open(filepath, "w", encoding=encoding, newline="") as output_file:
            output_file.write(content)


def create_page(settings: Optional[AppSettings] = None) -> ModulePage:
    """创建端口扫描页面"""
    if settings is None:
        settings = AppSettings()
    return PortScannerPage(settings)
