"""子域名挖掘模块"""
import os
import queue
import threading
from typing import Dict, List, Optional

from core._app_root import get_app_root

from PySide6.QtCore import QEvent, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QProgressBar,
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
from app.widgets.glass_input import GlassCombo, GlassSpinBox, GlassTextEdit
from core.settings import AppSettings
from core.subdomain_engine import (
    DNS_SERVER_OPTIONS,
    SubdomainScanOptions,
    SubdomainScanResult,
    SubdomainScannerEngine,
    discover_dictionary_options,
    parse_domains,
    parse_filter_ips,
    parse_ports,
    results_to_csv,
    results_to_html,
    results_to_txt,
    results_to_xlsx,
)


RESULT_FLUSH_BATCH_SIZE = 80
EXPORT_FILTER_TEXT = "TXT 文件 (*.txt);;CSV 文件 (*.csv);;Excel 工作簿 (*.xlsx);;HTML 文件 (*.html)"
DICTIONARY_GRID_COLUMNS = 4
NUMERIC_CONTROL_WIDTH = 142
PORT_FILTER_COLUMN_WIDTH = 128
DEPTH_CONTROL_WIDTH = 96
DNS_CONTROL_WIDTH = 162
ACTION_BUTTON_MIN_WIDTH = 104
COMBO_DNS_POPUP_STYLE = (
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


class SubdomainScanWorker(QThread):
    """后台子域名爆破线程"""

    statusChanged = Signal(str)
    progressChanged = Signal(int)
    scanFinished = Signal()

    def __init__(
        self,
        settings: AppSettings,
        options: SubdomainScanOptions,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._settings = settings
        self._options = options
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._result_queue: queue.Queue = queue.Queue()

    def stop(self) -> None:
        """请求完全停止爆破"""
        self._stop_event.set()
        self._pause_event.clear()

    def pause(self) -> None:
        """暂停提交后续任务"""
        self._pause_event.set()

    def resume(self) -> None:
        """继续提交任务"""
        self._pause_event.clear()

    def is_paused(self) -> bool:
        """返回当前是否处于暂停状态"""
        return self._pause_event.is_set()

    def run(self) -> None:
        """执行爆破任务"""
        try:
            engine = SubdomainScannerEngine(self._settings)
            engine.scan(
                options=self._options,
                stop_event=self._stop_event,
                pause_event=self._pause_event,
                result_callback=self._result_queue.put,
                status_callback=self.statusChanged.emit,
                progress_callback=self.progressChanged.emit,
            )
        finally:
            self.scanFinished.emit()


class SubdomainPage(ModulePage):
    """子域名挖掘页面"""

    TABLE_HEADERS = ["主域名", "子域名", "IP", "开放端口", "Banner", "标题"]

    def __init__(self, settings: AppSettings, parent: Optional[QWidget] = None):
        super().__init__(
            "子域名挖掘",
            "基于内置字典爆破模式发现子域名，并对解析结果进行端口、Banner 和标题探测",
            parent,
        )
        self._settings = settings
        self._worker: Optional[SubdomainScanWorker] = None
        self._dictionary_options = discover_dictionary_options(_dictionary_dir())
        self._dictionary_buttons: Dict[str, GlassButton] = {}
        self._custom_dictionary_path: Optional[str] = None
        self._results: List[SubdomainScanResult] = []
        self._results_by_key: Dict[str, SubdomainScanResult] = {}
        self._result_rows: Dict[str, int] = {}
        self._pending_status_message: Optional[str] = None
        self._last_validated_domain_text: str = ""
        self._last_validated_port_text: str = ""
        self._last_validated_filter_ip_text: str = ""

        self.layout().setSpacing(8)
        self.content_layout.setSpacing(8)
        self._setup_ui()
        self._select_default_dictionary()
        self._update_config_summary()

    def eventFilter(self, watched, event):
        """处理多行输入框失焦校验"""
        if event.type() == QEvent.FocusOut:
            # 弹出菜单/对话框期间跳过校验，避免嵌套模态导致崩溃
            if QApplication.activePopupWidget() is not None:
                return super().eventFilter(watched, event)
            if watched is self._domain_input.edit:
                self._validate_domain_input()
            elif watched is self._port_input.edit:
                self._validate_port_input()
            elif watched is self._filter_ip_input.edit:
                self._validate_filter_ip_input()
        return super().eventFilter(watched, event)

    def _setup_ui(self) -> None:
        self._config_card = GlassCard(padding=12)
        self._config_card.setMinimumHeight(340)
        self._config_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        header_widget = QWidget()
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)
        header_widget.setLayout(header_layout)

        config_title = QLabel("爆破配置")
        config_title.setObjectName("sectionTitle")
        header_layout.addWidget(config_title)

        self._config_summary = QLabel("")
        self._config_summary.setObjectName("configSummary")
        self._config_summary.setWordWrap(True)
        header_layout.addWidget(self._config_summary, stretch=1)

        self._progress_bar = QProgressBar()
        self._progress_bar.setObjectName("scanProgressBar")
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFixedWidth(150)
        self._progress_bar.setTextVisible(True)
        header_layout.addWidget(self._progress_bar)

        self._status_label = QLabel("")
        self._status_label.setObjectName("scanStatus")
        header_layout.addWidget(self._status_label)
        self._config_card.layout().addWidget(header_widget)

        self._config_body = QWidget()
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(12)
        self._config_body.setLayout(body_layout)

        domain_panel = QWidget()
        domain_layout = QVBoxLayout()
        domain_layout.setContentsMargins(0, 0, 0, 0)
        domain_layout.setSpacing(8)
        domain_panel.setLayout(domain_layout)
        body_layout.addWidget(domain_panel)

        self._domain_input = GlassTextEdit("目标域名", readonly=False)
        self._domain_input.setFixedWidth(210)
        self._domain_input.edit.setPlaceholderText("example.com\nexample.org")
        self._domain_input.edit.setMinimumHeight(100)
        self._domain_input.edit.setMaximumHeight(130)
        self._domain_input.edit.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._domain_input.edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        domain_layout.addWidget(self._domain_input)

        self._import_btn = GlassButton("导入域名")
        self._import_btn.clicked.connect(self._import_domains)
        domain_layout.addWidget(self._import_btn)
        domain_layout.addStretch()

        middle_panel = QWidget()
        middle_layout = QVBoxLayout()
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(8)
        middle_panel.setLayout(middle_layout)
        body_layout.addWidget(middle_panel, stretch=1)

        dict_label = QLabel("字典选择")
        dict_label.setObjectName("inputLabel")
        middle_layout.addWidget(dict_label)

        dict_widget = QWidget()
        dict_layout = QGridLayout()
        dict_layout.setContentsMargins(0, 0, 0, 0)
        dict_layout.setHorizontalSpacing(6)
        dict_layout.setVerticalSpacing(6)
        dict_widget.setLayout(dict_layout)

        self._dictionary_group = QButtonGroup(self)
        self._dictionary_group.setExclusive(True)
        for index, item in enumerate(self._dictionary_options):
            label, path = item
            button = GlassButton(label)
            button.setCheckable(True)
            button.setObjectName("compactModeButton")
            button.setMinimumWidth(92)
            button.setFixedHeight(28)
            button.setProperty("path", path)
            self._refresh_widget_style(button)
            button.clicked.connect(lambda _checked=False, name=label: self._select_builtin_dictionary(name))
            self._dictionary_buttons[label] = button
            self._dictionary_group.addButton(button)
            dict_layout.addWidget(button, index // DICTIONARY_GRID_COLUMNS, index % DICTIONARY_GRID_COLUMNS)

        self._custom_dict_btn = GlassButton("自定义字典")
        self._custom_dict_btn.setCheckable(True)
        self._custom_dict_btn.setObjectName("compactModeButton")
        self._custom_dict_btn.setMinimumWidth(92)
        self._custom_dict_btn.setFixedHeight(28)
        self._refresh_widget_style(self._custom_dict_btn)
        self._custom_dict_btn.clicked.connect(self._choose_custom_dictionary)
        self._dictionary_group.addButton(self._custom_dict_btn)
        custom_index = len(self._dictionary_options)
        dict_layout.addWidget(
            self._custom_dict_btn,
            custom_index // DICTIONARY_GRID_COLUMNS,
            custom_index % DICTIONARY_GRID_COLUMNS,
        )
        middle_layout.addWidget(dict_widget)

        dictionary_numeric_panel = QWidget()
        dictionary_numeric_panel.setObjectName("dictionaryNumericControls")
        dictionary_numeric_layout = QHBoxLayout()
        dictionary_numeric_layout.setContentsMargins(0, 0, 0, 0)
        dictionary_numeric_layout.setSpacing(8)
        dictionary_numeric_panel.setLayout(dictionary_numeric_layout)
        middle_layout.addWidget(dictionary_numeric_panel)

        self._thread_input = GlassSpinBox("线程数", 1, 200, 200)
        self._thread_input.setFixedWidth(NUMERIC_CONTROL_WIDTH)
        dictionary_numeric_layout.addWidget(self._thread_input)

        self._timeout_input = GlassSpinBox("超时(ms)", 3000, 60000, self._settings.get("timeout", 3000))
        self._timeout_input.setFixedWidth(NUMERIC_CONTROL_WIDTH)
        dictionary_numeric_layout.addWidget(self._timeout_input)
        self._port_input = GlassTextEdit("探测端口", readonly=False)
        self._port_input.setFixedWidth(NUMERIC_CONTROL_WIDTH)
        self._port_input.setText("80,443")
        self._port_input.edit.setMinimumHeight(56)
        self._port_input.edit.setMaximumHeight(64)
        self._port_input.edit.setPlaceholderText("80,443,8080")
        self._port_input.edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._port_input.edit.installEventFilter(self)
        dictionary_numeric_layout.addWidget(self._port_input)
        dictionary_numeric_layout.addStretch()

        middle_layout.addStretch()

        depth_dns_panel = QWidget()
        depth_dns_panel.setObjectName("depthDnsColumn")
        depth_dns_panel.setFixedWidth(DNS_CONTROL_WIDTH)
        depth_dns_layout = QVBoxLayout()
        depth_dns_layout.setContentsMargins(0, 0, 0, 0)
        depth_dns_layout.setSpacing(8)
        depth_dns_panel.setLayout(depth_dns_layout)
        body_layout.addWidget(depth_dns_panel)

        self._depth_input = GlassSpinBox("深度", 1, 3, 1)
        self._depth_input.setFixedWidth(DEPTH_CONTROL_WIDTH)
        depth_dns_layout.addWidget(self._depth_input)

        self._dns_combo = GlassCombo("DNS", DNS_SERVER_OPTIONS)
        self._dns_combo.setFixedWidth(DNS_CONTROL_WIDTH)
        self._dns_combo.combo.setMaxVisibleItems(12)
        self._dns_combo.combo.view().setMinimumWidth(DNS_CONTROL_WIDTH)
        self._apply_dns_popup_style()
        depth_dns_layout.addWidget(self._dns_combo)

        self._filter_ip_input = GlassTextEdit("过滤 IP", readonly=False)
        self._filter_ip_input.setFixedWidth(DNS_CONTROL_WIDTH)
        self._filter_ip_input.setText("127.0.0.1")
        self._filter_ip_input.edit.setMinimumHeight(56)
        self._filter_ip_input.edit.setMaximumHeight(64)
        self._filter_ip_input.edit.setPlaceholderText("127.0.0.1")
        self._filter_ip_input.edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._filter_ip_input.edit.installEventFilter(self)
        depth_dns_layout.addWidget(self._filter_ip_input)
        depth_dns_layout.addStretch()

        button_panel = QWidget()
        button_layout = QVBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(6)
        button_panel.setLayout(button_layout)

        self._scan_btn = GlassButton("开始爆破")
        self._scan_btn.clicked.connect(self._start_scan)

        self._pause_btn = GlassButton("暂停爆破")
        self._pause_btn.setEnabled(False)
        self._pause_btn.clicked.connect(self._toggle_pause)

        self._stop_btn = GlassButton("停止爆破")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_scan)

        self._export_btn = GlassButton("导出结果")
        self._export_btn.clicked.connect(self._export_results)

        self._clear_btn = GlassButton("清空结果")
        self._clear_btn.clicked.connect(self._clear_results)

        for button in [
            self._scan_btn,
            self._pause_btn,
            self._stop_btn,
            self._export_btn,
            self._clear_btn,
        ]:
            button.setMinimumWidth(ACTION_BUTTON_MIN_WIDTH)
            button_layout.addWidget(button)
        button_layout.addStretch()
        body_layout.addWidget(button_panel)

        self._config_card.layout().addWidget(self._config_body)

        self._domain_input.edit.installEventFilter(self)
        self._domain_input.edit.textChanged.connect(self._update_config_summary)
        self._port_input.edit.textChanged.connect(self._update_config_summary)
        self._filter_ip_input.edit.textChanged.connect(self._update_config_summary)
        self._thread_input.spin.valueChanged.connect(lambda _value: self._update_config_summary())
        self._timeout_input.spin.valueChanged.connect(lambda _value: self._update_config_summary())
        self._depth_input.spin.valueChanged.connect(lambda _value: self._update_config_summary())
        self._dns_combo.combo.currentTextChanged.connect(lambda _text: self._update_config_summary())

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
        self._result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._result_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self._result_table.setColumnWidth(0, 150)
        self._result_table.setColumnWidth(1, 260)
        self._result_table.setColumnWidth(2, 170)
        self._result_table.setColumnWidth(3, 90)
        self._result_table.setColumnWidth(4, 170)
        self._result_table.setColumnWidth(5, 260)
        self._result_table.setMinimumHeight(300)
        self._result_table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        self._result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._result_table.customContextMenuRequested.connect(self._on_context_menu)
        result_card.layout().addWidget(self._result_table)

        self.content_layout.addWidget(self._config_card)
        self.content_layout.addWidget(result_card, stretch=1)

    def _select_default_dictionary(self) -> None:
        if "Top1000" in self._dictionary_buttons:
            self._dictionary_buttons["Top1000"].setChecked(True)
            return
        if "标准" in self._dictionary_buttons:
            self._dictionary_buttons["标准"].setChecked(True)
            return
        if self._dictionary_buttons:
            first_button = list(self._dictionary_buttons.values())[0]
            first_button.setChecked(True)

    def _refresh_widget_style(self, widget: QWidget) -> None:
        """切换 objectName 后刷新 Qt 样式，避免按钮退回系统默认外观。"""
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def _apply_dns_popup_style(self) -> None:
        """确保 DNS 下拉列表在不同平台都保持浅色样式。"""
        self._dns_combo.combo.setStyleSheet(COMBO_DNS_POPUP_STYLE)

    def _select_builtin_dictionary(self, _label: str) -> None:
        self._custom_dictionary_path = None
        self._update_config_summary()

    def _update_config_summary(self) -> None:
        domain_count = len([line for line in self._domain_input.text().splitlines() if line.strip()])
        dict_label = self._current_dictionary_label()
        self._config_summary.setText(
            "域名 %s 个 · 字典 %s · 深度 %s · 线程 %s · 超时 %sms · DNS %s"
            % (
                domain_count,
                dict_label,
                self._depth_input.value(),
                self._thread_input.value(),
                self._timeout_input.value(),
                self._dns_combo.current_text(),
            )
        )

    def _current_dictionary_label(self) -> str:
        if self._custom_dictionary_path:
            return os.path.basename(self._custom_dictionary_path)
        for label, button in self._dictionary_buttons.items():
            if button.isChecked():
                return label
        return "未选择"

    def _selected_dictionary_paths(self) -> List[str]:
        if self._custom_dictionary_path:
            return [self._custom_dictionary_path]
        for _label, button in self._dictionary_buttons.items():
            if button.isChecked():
                return [button.property("path")]
        return []

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
        """显示与全局设置一致的警告弹窗。"""
        return self._show_styled_message(title, message, QMessageBox.Warning)

    def _validate_domain_input(self) -> bool:
        """目标域名失焦校验（同一文本只弹一次错误，允许切换模块）"""
        text = self._domain_input.text().strip()
        if not text:
            self._last_validated_domain_text = ""
            return True
        if text == self._last_validated_domain_text:
            return True  # 已提示过，不再反复弹窗
        try:
            parse_domains(text)
            self._last_validated_domain_text = text
        except ValueError as error:
            self._last_validated_domain_text = text
            self._show_styled_warning("域名格式无效", str(error))
            QTimer.singleShot(0, self._domain_input.edit.setFocus)
            return False
        return True

    def _validate_port_input(self) -> bool:
        """探测端口失焦校验（同一文本只弹一次错误）"""
        text = self._port_input.text().strip()
        if not text:
            self._last_validated_port_text = ""
            return True
        if text == self._last_validated_port_text:
            return True
        try:
            parse_ports(text)
            self._last_validated_port_text = text
        except ValueError as error:
            self._last_validated_port_text = text
            self._show_styled_warning("端口格式无效", str(error))
            QTimer.singleShot(0, self._port_input.edit.setFocus)
            return False
        return True

    def _validate_filter_ip_input(self) -> bool:
        """过滤 IP 失焦校验（同一文本只弹一次错误）"""
        text = self._filter_ip_input.text().strip()
        if not text:
            self._last_validated_filter_ip_text = ""
            return True
        if text == self._last_validated_filter_ip_text:
            return True
        try:
            parse_filter_ips(text)
            self._last_validated_filter_ip_text = text
        except ValueError as error:
            self._last_validated_filter_ip_text = text
            self._show_styled_warning("过滤 IP 格式无效", str(error))
            QTimer.singleShot(0, self._filter_ip_input.edit.setFocus)
            return False
        return True

    def _import_domains(self) -> None:
        filepath, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "导入域名列表",
            "",
            "TXT 文件 (*.txt)",
        )
        if not filepath:
            return
        if os.path.splitext(filepath)[1].lower() != ".txt":
            self._show_styled_warning("导入失败", "域名列表只支持 txt 文件")
            return
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as input_file:
                imported_domains = parse_domains(input_file.read())
        except (IOError, ValueError) as error:
            self._show_styled_warning("导入失败", str(error))
            return
        current_domains = []
        try:
            current_domains = parse_domains(self._domain_input.text())
        except ValueError:
            current_domains = []
        merged = []
        seen = set()
        for domain in current_domains + imported_domains:
            if domain not in seen:
                merged.append(domain)
                seen.add(domain)
        self._domain_input.setText("\n".join(merged))

    def _choose_custom_dictionary(self) -> None:
        filepath, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "选择子域名字典",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)",
        )
        if not filepath:
            return
        self._custom_dictionary_path = filepath
        for button in self._dictionary_buttons.values():
            button.setChecked(False)
        self._update_config_summary()

    def _start_scan(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        try:
            domains = parse_domains(self._domain_input.text())
            ports = parse_ports(self._port_input.text())
            filtered_ips = parse_filter_ips(self._filter_ip_input.text())
        except ValueError as error:
            self._show_styled_warning("输入错误", str(error))
            return

        dictionary_paths = self._selected_dictionary_paths()
        if not dictionary_paths:
            self._show_styled_warning("字典未选择", "请选择一个内置字典或自定义字典文件")
            return

        options = SubdomainScanOptions(
            domains=domains,
            dictionary_paths=dictionary_paths,
            thread_count=self._thread_input.value(),
            timeout_ms=self._timeout_input.value(),
            depth=self._depth_input.value(),
            dns_provider=self._dns_combo.current_text(),
            ports=ports,
            filtered_ips=filtered_ips,
        )

        self._results = []
        self._results_by_key = {}
        self._result_rows = {}
        self._result_table.setRowCount(0)
        self._result_table.setSortingEnabled(False)
        self._progress_bar.setValue(0)
        self._scan_btn.setEnabled(False)
        self._pause_btn.setText("暂停爆破")
        self._pause_btn.setEnabled(True)
        self._stop_btn.setEnabled(True)
        self._clear_btn.setEnabled(False)
        self._set_inputs_enabled(False)
        self._set_status("爆破启动中...")

        self._worker = SubdomainScanWorker(self._settings, options, self)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(30)
        self._poll_timer.timeout.connect(self._drain_results)
        self._poll_timer.start()
        self._worker.statusChanged.connect(self._queue_status)
        self._worker.progressChanged.connect(self._progress_bar.setValue)
        self._worker.scanFinished.connect(self._finish_scan)
        self._worker.start()

    def _toggle_pause(self) -> None:
        if self._worker is None or not self._worker.isRunning():
            return
        if self._worker.is_paused():
            self._worker.resume()
            self._pause_btn.setText("暂停爆破")
            self._set_status("爆破继续中...")
        else:
            self._worker.pause()
            self._pause_btn.setText("继续爆破")
            self._set_status("爆破已暂停，当前任务完成后不再提交新任务")

    def _stop_scan(self) -> None:
        if self._worker is None or not self._worker.isRunning():
            return
        self._worker.stop()
        if hasattr(self, '_poll_timer') and self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._set_status("正在停止爆破...")

    def _finish_scan(self) -> None:
        if hasattr(self, '_poll_timer') and self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        self._drain_results()
        self._scan_btn.setEnabled(True)
        self._pause_btn.setText("暂停爆破")
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._clear_btn.setEnabled(True)
        self._set_inputs_enabled(True)
        self._result_table.setSortingEnabled(True)
        self._flush_status()
        self._worker = None

    def _set_inputs_enabled(self, enabled: bool) -> None:
        self._domain_input.setEnabled(enabled)
        self._import_btn.setEnabled(enabled)
        self._custom_dict_btn.setEnabled(enabled)
        self._port_input.setEnabled(enabled)
        self._filter_ip_input.setEnabled(enabled)
        self._thread_input.setEnabled(enabled)
        self._timeout_input.setEnabled(enabled)
        self._depth_input.setEnabled(enabled)
        self._dns_combo.setEnabled(enabled)
        for button in self._dictionary_buttons.values():
            button.setEnabled(enabled)

    def _drain_results(self) -> None:
        """从工作线程结果队列取出所有结果并刷新表格"""
        if self._worker is None:
            return
        result_queue = self._worker._result_queue
        drained = False
        while True:
            try:
                result = result_queue.get_nowait()
            except queue.Empty:
                break
            self._add_result(result)
            drained = True
        if drained:
            self._result_table.repaint()

    def _add_result(self, result: SubdomainScanResult) -> None:
        self._results_by_key[result.subdomain] = result
        self._upsert_result_row(result)
        if self._should_auto_scroll_results():
            self._result_table.scrollToBottom()

    def _upsert_result_row(self, result: SubdomainScanResult) -> bool:
        key = result.subdomain
        is_new_row = key not in self._result_rows
        if is_new_row:
            row = self._result_table.rowCount()
            self._result_table.insertRow(row)
            self._result_rows[key] = row
        else:
            row = self._result_rows[key]
        self._results_by_key[key] = result
        values = [
            result.main_domain,
            result.subdomain,
            ",".join(result.ips),
            ",".join(str(port) for port in result.open_ports),
            result.banner,
            result.title,
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            self._result_table.setItem(row, column, item)
        return is_new_row

    def _should_auto_scroll_results(self) -> bool:
        scroll_bar = self._result_table.verticalScrollBar()
        return scroll_bar.value() >= scroll_bar.maximum() - 2

    def _set_status(self, message: str) -> None:
        self._status_label.setText(message)

    def _queue_status(self, message: str) -> None:
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

    def _clear_results(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self._results = []
        self._results_by_key = {}
        self._result_rows = {}
        self._result_table.setRowCount(0)
        self._progress_bar.setValue(0)
        self._set_status("结果已清空")

    def _export_results(self) -> None:
        results = list(self._results_by_key.values())
        if not results:
            self._show_styled_warning("导出结果", "当前没有可导出的子域名结果")
            return
        filepath, selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出子域名结果",
            "subdomain_results.csv",
            EXPORT_FILTER_TEXT,
        )
        if not filepath:
            return
        filepath = self._normalize_export_path(filepath, selected_filter)
        if filepath is None:
            self._show_styled_warning("导出失败", "仅支持 csv、txt、html 格式")
            return
        extension = os.path.splitext(filepath)[1].lower()
        try:
            if extension == ".xlsx":
                with open(filepath, "wb") as output_file:
                    output_file.write(results_to_xlsx(results))
                self._show_styled_message("导出完成", "子域名结果已导出", QMessageBox.Information)
                return
            if extension == ".csv":
                content = results_to_csv(results)
                encoding = "utf-8-sig"
            elif extension == ".txt":
                content = results_to_txt(results)
                encoding = "utf-8"
            else:
                content = results_to_html(results)
                encoding = "utf-8"
            with open(filepath, "w", encoding=encoding, newline="") as output_file:
                output_file.write(content)
        except IOError as error:
            self._show_styled_warning("导出失败", "写入文件失败：%s" % error)
            return
        self._show_styled_message("导出完成", "子域名结果已导出", QMessageBox.Information)

    def _normalize_export_path(self, filepath: str, selected_filter: str) -> Optional[str]:
        extension = os.path.splitext(filepath)[1].lower()
        if not extension:
            if "*.txt" in selected_filter:
                return filepath + ".txt"
            if "*.xlsx" in selected_filter:
                return filepath + ".xlsx"
            if "*.html" in selected_filter:
                return filepath + ".html"
            return filepath + ".csv"
        if extension not in [".csv", ".txt", ".xlsx", ".html"]:
            return None
        return filepath


def _dictionary_dir() -> str:
    root = get_app_root()
    return os.path.join(root, "resources", "dir", "subdomains")


def create_page(settings: Optional[AppSettings] = None) -> ModulePage:
    """创建子域名挖掘页面"""
    if settings is None:
        settings = AppSettings()
    return SubdomainPage(settings)
