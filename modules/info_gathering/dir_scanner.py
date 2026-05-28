"""目录扫描模块"""
import os
import queue
import threading
from typing import Dict, List, Optional, Set

from PySide6.QtCore import QEvent, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QMessageBox,
    QProgressBar,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.content_area import ModulePage
from app.widgets.glass_button import GlassButton
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassCheckBox, GlassCombo, GlassInput, GlassSpinBox, GlassTextEdit
from core.dir_scanner_engine import (
    DICTIONARY_ORDER,
    EXPORT_FILTER_TEXT,
    MAX_WORKERS,
    STATUS_CODE_OPTIONS,
    DirScanOptions,
    DirScanResult,
    DirScannerEngine,
    discover_dictionary_options,
    parse_urls,
    results_to_csv,
    results_to_html,
    results_to_txt,
    results_to_xlsx,
    _dictionary_dir,
)


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

NUMERIC_CONTROL_WIDTH = 142
ACTION_BUTTON_MIN_WIDTH = 104
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

CUSTOM_DICT_LABEL = "自定义字典"


# ---------------------------------------------------------------------------
# 后台扫描线程
# ---------------------------------------------------------------------------

class DirScanWorker(QThread):
    """后台目录扫描线程"""

    statusChanged = Signal(str)
    progressChanged = Signal(int)
    scanFinished = Signal()

    def __init__(
        self,
        settings,
        options: DirScanOptions,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._settings = settings
        self._options = options
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._result_queue: queue.Queue = queue.Queue()

    def stop(self) -> None:
        """请求完全停止扫描"""
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
        """执行扫描任务"""
        try:
            engine = DirScannerEngine(self._settings)
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


# ---------------------------------------------------------------------------
# 页面 UI
# ---------------------------------------------------------------------------

class DirScannerPage(ModulePage):
    """目录扫描页面"""

    TABLE_HEADERS = ["序号", "状态码", "URL", "长度", "重定向"]

    def __init__(self, settings, parent: Optional[QWidget] = None) -> None:
        super().__init__(
            "目录扫描",
            "对 Web 目标进行目录和文件枚举，发现隐藏路径",
            parent,
        )
        self._settings = settings
        self._worker: Optional[DirScanWorker] = None
        self._dictionary_options = discover_dictionary_options(_dictionary_dir())
        self._custom_dictionary_path: Optional[str] = None
        self._results_by_key: Dict[str, DirScanResult] = {}
        self._result_rows: Dict[str, int] = {}
        self._result_index: Dict[str, int] = {}
        self._result_counter: int = 0
        self._pending_status_message: Optional[str] = None
        self._last_validated_url_text: str = ""
        self._status_checkboxes: Dict[int, GlassCheckBox] = {}

        self.layout().setSpacing(8)
        self.content_layout.setSpacing(8)
        self._setup_ui()
        self._update_config_summary()

    def eventFilter(self, watched: QWidget, event: QEvent) -> bool:
        """处理多行输入框失焦校验"""
        if event.type() == QEvent.FocusOut:
            if QApplication.activePopupWidget() is not None:
                return super().eventFilter(watched, event)
            if watched is self._url_input.edit:
                self._validate_url_input()
        return super().eventFilter(watched, event)

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        """构建完整页面布局"""
        # ---- 配置卡片 ----
        self._config_card = GlassCard(padding=12)
        self._config_card.setMinimumHeight(348)
        self._config_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        # header
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

        # body — 3 列布局
        self._config_body = QWidget()
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(12)
        self._config_body.setLayout(body_layout)

        # ---- Col1: URL 输入区 (210px) ----
        url_panel = QWidget()
        url_layout = QVBoxLayout()
        url_layout.setContentsMargins(0, 0, 0, 0)
        url_layout.setSpacing(8)
        url_panel.setLayout(url_layout)
        body_layout.addWidget(url_panel)

        self._url_input = GlassTextEdit("目标 URL", readonly=False)
        self._url_input.setFixedWidth(210)
        self._url_input.edit.setPlaceholderText("https://example.com\nhttps://test.example.org")
        self._url_input.edit.setMinimumHeight(100)
        self._url_input.edit.setMaximumHeight(130)
        self._url_input.edit.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._url_input.edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        url_layout.addWidget(self._url_input)

        self._import_btn = GlassButton("导入 URL")
        self._import_btn.clicked.connect(self._import_urls)
        url_layout.addWidget(self._import_btn)
        url_layout.addStretch()

        # ---- Col2: 字典 + 状态码 + 关键词 + WAF/Bypass403 + 底部参数 (stretch) ----
        middle_panel = QWidget()
        middle_layout = QVBoxLayout()
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(8)
        middle_panel.setLayout(middle_layout)
        body_layout.addWidget(middle_panel, stretch=1)

        # 字典选择（下拉框）
        dict_label = QLabel("字典选择")
        dict_label.setObjectName("inputLabel")
        middle_layout.addWidget(dict_label)

        dict_combo_items: List[str] = [label for label, _path in self._dictionary_options]
        dict_combo_items.append(CUSTOM_DICT_LABEL)
        self._dict_combo = GlassCombo("", dict_combo_items)
        self._dict_combo.combo.setMaxVisibleItems(16)
        self._dict_combo.combo.view().setMinimumWidth(200)
        self._dict_combo.combo.setStyleSheet(COMBO_POPUP_STYLE)
        self._dict_combo.combo.currentIndexChanged.connect(self._on_dict_combo_changed)
        middle_layout.addWidget(self._dict_combo)

        # 状态码过滤 + 标题关键词 + WAF/Bypass403（同一行）
        status_label = QLabel("状态码过滤")
        status_label.setObjectName("inputLabel")
        middle_layout.addWidget(status_label)

        combined_row = QWidget()
        combined_layout = QHBoxLayout()
        combined_layout.setContentsMargins(0, 0, 0, 0)
        combined_layout.setSpacing(6)
        combined_row.setLayout(combined_layout)

        # 状态码 8 个 checkbox（两小行放在一个 VBox 里）
        status_cb_widget = QWidget()
        status_cb_layout = QVBoxLayout()
        status_cb_layout.setContentsMargins(0, 0, 0, 0)
        status_cb_layout.setSpacing(4)
        status_cb_widget.setLayout(status_cb_layout)

        status_row1 = QWidget()
        status_row1_layout = QHBoxLayout()
        status_row1_layout.setContentsMargins(0, 0, 0, 0)
        status_row1_layout.setSpacing(4)
        status_row1.setLayout(status_row1_layout)
        for code in STATUS_CODE_OPTIONS[:4]:
            cb = GlassCheckBox(str(code), checked=True)
            cb.check.clicked.connect(self._update_config_summary)
            self._status_checkboxes[code] = cb
            status_row1_layout.addWidget(cb)
        status_row1_layout.addStretch()
        status_cb_layout.addWidget(status_row1)

        status_row2 = QWidget()
        status_row2_layout = QHBoxLayout()
        status_row2_layout.setContentsMargins(0, 0, 0, 0)
        status_row2_layout.setSpacing(4)
        status_row2.setLayout(status_row2_layout)
        for code in STATUS_CODE_OPTIONS[4:]:
            checked = code != 500
            cb = GlassCheckBox(str(code), checked=checked)
            cb.check.clicked.connect(self._update_config_summary)
            self._status_checkboxes[code] = cb
            status_row2_layout.addWidget(cb)
        status_row2_layout.addStretch()
        status_cb_layout.addWidget(status_row2)

        combined_layout.addWidget(status_cb_widget)

        # 标题关键词（缩小宽度）
        self._keyword_exclude_input = GlassInput("标题关键词", "含此关键词则跳过")
        self._keyword_exclude_input.setFixedWidth(180)
        combined_layout.addWidget(self._keyword_exclude_input)

        # WAF 识别 + Bypass403
        switches_widget = QWidget()
        switches_layout = QVBoxLayout()
        switches_layout.setContentsMargins(0, 0, 0, 0)
        switches_layout.setSpacing(4)
        switches_widget.setLayout(switches_layout)

        self._waf_checkbox = GlassCheckBox("WAF 识别", checked=False)
        self._waf_checkbox.check.setToolTip("当目标超时20次以上，则为waf并且跳过")
        switches_layout.addWidget(self._waf_checkbox)

        self._bypass_checkbox = GlassCheckBox("ByPass403", checked=False)
        self._bypass_checkbox.check.setToolTip(
            "对403路径尝试多种绕过方式（路径变体/IP头欺骗/重写头），找到实际可访问的路径"
        )
        switches_layout.addWidget(self._bypass_checkbox)

        combined_layout.addWidget(switches_widget)
        combined_layout.addStretch()
        middle_layout.addWidget(combined_row)

        # 底部行：线程数 + 超时 + 排除长度
        bottom_row = QWidget()
        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(8)
        bottom_row.setLayout(bottom_layout)

        self._thread_input = GlassSpinBox("线程数", 1, 200, 200)
        self._thread_input.setFixedWidth(NUMERIC_CONTROL_WIDTH)
        bottom_layout.addWidget(self._thread_input)

        self._timeout_input = GlassSpinBox("超时(ms)", 3000, 60000, self._settings.get("timeout", 3000))
        self._timeout_input.setFixedWidth(NUMERIC_CONTROL_WIDTH)
        bottom_layout.addWidget(self._timeout_input)

        self._length_exclude_input = GlassSpinBox("排除长度(字节)", 0, 99999999, 0)
        self._length_exclude_input.spin.setToolTip("返回长度超过此值的路径将被跳过，0=不排除")
        self._length_exclude_input.setFixedWidth(NUMERIC_CONTROL_WIDTH + 20)
        bottom_layout.addWidget(self._length_exclude_input)
        bottom_layout.addStretch()
        middle_layout.addWidget(bottom_row)

        middle_layout.addStretch()

        # ---- Col3: 操作按钮 ----
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)
        right_panel.setLayout(right_layout)

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

        for button in [
            self._scan_btn,
            self._pause_btn,
            self._stop_btn,
            self._export_btn,
            self._clear_btn,
        ]:
            button.setMinimumWidth(ACTION_BUTTON_MIN_WIDTH)
            right_layout.addWidget(button)
        right_layout.addStretch()

        body_layout.addWidget(right_panel)

        self._config_card.layout().addWidget(self._config_body)

        # 输入变更 → 更新配置摘要
        self._url_input.edit.installEventFilter(self)
        self._url_input.edit.textChanged.connect(self._update_config_summary)
        self._thread_input.spin.valueChanged.connect(lambda _value: self._update_config_summary())
        self._timeout_input.spin.valueChanged.connect(lambda _value: self._update_config_summary())
        self._keyword_exclude_input.input.textChanged.connect(self._update_config_summary)
        self._length_exclude_input.spin.valueChanged.connect(lambda _value: self._update_config_summary())

        # 状态防抖定时器
        self._status_timer = QTimer(self)
        self._status_timer.setSingleShot(True)
        self._status_timer.setInterval(250)
        self._status_timer.timeout.connect(self._flush_status)

        # ---- 结果卡片 ----
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
        self._result_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._result_table.setColumnWidth(0, 50)
        self._result_table.setColumnWidth(1, 70)
        self._result_table.setColumnWidth(2, 400)
        self._result_table.setColumnWidth(3, 80)
        self._result_table.setColumnWidth(4, 220)
        self._result_table.setMinimumHeight(300)
        self._result_table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        self._result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._result_table.customContextMenuRequested.connect(self._on_context_menu)
        result_card.layout().addWidget(self._result_table)

        self.content_layout.addWidget(self._config_card)
        self.content_layout.addWidget(result_card, stretch=1)

    # ------------------------------------------------------------------
    # 字典管理（下拉框）
    # ------------------------------------------------------------------

    def _on_dict_combo_changed(self, index: int) -> None:
        """字典下拉框切换"""
        if index < 0:
            return
        current_text = self._dict_combo.current_text()
        if current_text == CUSTOM_DICT_LABEL:
            self._choose_custom_dictionary()
        else:
            self._custom_dictionary_path = None
        self._update_config_summary()

    def _choose_custom_dictionary(self) -> None:
        """选择自定义字典文件"""
        filepath, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "选择目录字典",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)",
        )
        if not filepath:
            # 用户取消，恢复到第一个内置字典
            self._dict_combo.combo.blockSignals(True)
            self._dict_combo.combo.setCurrentIndex(0)
            self._dict_combo.combo.blockSignals(False)
            self._custom_dictionary_path = None
            self._update_config_summary()
            return
        self._custom_dictionary_path = filepath
        self._update_config_summary()

    def _current_dictionary_label(self) -> str:
        """获取当前选中的字典名称"""
        if self._custom_dictionary_path:
            return os.path.basename(self._custom_dictionary_path)
        return self._dict_combo.current_text()

    def _selected_dictionary_paths(self) -> List[str]:
        """获取当前选中的字典文件路径"""
        if self._custom_dictionary_path:
            return [self._custom_dictionary_path]
        current_label = self._dict_combo.current_text()
        for label, path in self._dictionary_options:
            if label == current_label:
                return [path]
        return []

    # ------------------------------------------------------------------
    # 配置摘要
    # ------------------------------------------------------------------

    def _update_config_summary(self) -> None:
        """更新配置摘要文字"""
        url_count = len([line for line in self._url_input.text().splitlines() if line.strip()])
        dict_label = self._current_dictionary_label()
        active_codes = [str(c) for c in STATUS_CODE_OPTIONS if self._status_checkboxes[c].is_checked()]
        codes_text = ",".join(active_codes) if active_codes else "无"
        keyword_text = self._keyword_exclude_input.text().strip()
        length_exclude = self._length_exclude_input.value()
        parts = [
            "URL %s 个" % url_count,
            "字典 %s" % dict_label,
            "线程 %s" % self._thread_input.value(),
            "超时 %sms" % self._timeout_input.value(),
            "状态码 [%s]" % codes_text,
            "ByPass403 %s" % ("开" if self._bypass_checkbox.is_checked() else "关"),
        ]
        if keyword_text:
            parts.append("排除关键词:%s" % keyword_text)
        if length_exclude > 0:
            parts.append("排除长度>%s" % length_exclude)
        self._config_summary.setText(" · ".join(parts))

    # ------------------------------------------------------------------
    # 输入校验
    # ------------------------------------------------------------------

    def _validate_url_input(self) -> bool:
        """目标 URL 失焦校验，自动补全 http://（同一文本只弹一次错误）"""
        text = self._url_input.text().strip()
        if not text:
            self._last_validated_url_text = ""
            return True
        if text == self._last_validated_url_text:
            return True
        try:
            fixed_urls = parse_urls(text)
        except ValueError as error:
            self._last_validated_url_text = text
            self._show_styled_warning("URL 格式无效", str(error))
            QTimer.singleShot(0, self._url_input.edit.setFocus)
            return False
        current_lines = [l.strip() for l in text.splitlines() if l.strip()]
        if len(fixed_urls) == len(current_lines):
            new_text = "\n".join(fixed_urls)
            if new_text != text:
                self._url_input.edit.blockSignals(True)
                self._url_input.edit.setPlainText(new_text)
                self._url_input.edit.blockSignals(False)
        return True

    def _import_urls(self) -> None:
        """从 TXT 文件导入 URL 列表"""
        filepath, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "导入 URL 列表",
            "",
            "TXT 文件 (*.txt)",
        )
        if not filepath:
            return
        if os.path.splitext(filepath)[1].lower() != ".txt":
            self._show_styled_warning("导入失败", "URL 列表只支持 txt 文件")
            return
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as input_file:
                imported_urls = parse_urls(input_file.read())
        except (IOError, ValueError) as error:
            self._show_styled_warning("导入失败", str(error))
            return
        current_urls: List[str] = []
        try:
            current_urls = parse_urls(self._url_input.text())
        except ValueError:
            current_urls = []
        merged: List[str] = []
        seen: Set[str] = set()
        for url in current_urls + imported_urls:
            if url not in seen:
                merged.append(url)
                seen.add(url)
        self._url_input.setText("\n".join(merged))

    # ------------------------------------------------------------------
    # 扫描控制
    # ------------------------------------------------------------------

    def _start_scan(self) -> None:
        """启动扫描"""
        if self._worker is not None and self._worker.isRunning():
            return
        try:
            urls = parse_urls(self._url_input.text())
        except ValueError as error:
            self._show_styled_warning("输入错误", str(error))
            return

        dictionary_paths = self._selected_dictionary_paths()
        if not dictionary_paths:
            self._show_styled_warning("字典未选择", "请选择一个内置字典或自定义字典文件")
            return

        active_status_codes: Set[int] = set()
        for code in STATUS_CODE_OPTIONS:
            if self._status_checkboxes[code].is_checked():
                active_status_codes.add(code)

        retry_count = self._settings.get("retry_count", 3)

        options = DirScanOptions(
            base_urls=urls,
            dictionary_paths=dictionary_paths,
            thread_count=self._thread_input.value(),
            timeout_ms=self._timeout_input.value(),
            status_codes=active_status_codes,
            keyword_exclude=self._keyword_exclude_input.text().strip(),
            length_exclude=self._length_exclude_input.value(),
            waf_enabled=self._waf_checkbox.is_checked(),
            bypass_403=self._bypass_checkbox.is_checked(),
            retry_count=retry_count,
        )

        self._results_by_key = {}
        self._result_rows = {}
        self._result_index = {}
        self._result_counter = 0
        self._result_table.setRowCount(0)
        self._result_table.setSortingEnabled(False)
        self._progress_bar.setValue(0)
        self._scan_btn.setEnabled(False)
        self._pause_btn.setText("暂停扫描")
        self._pause_btn.setEnabled(True)
        self._stop_btn.setEnabled(True)
        self._clear_btn.setEnabled(False)
        self._set_inputs_enabled(False)
        self._set_status("扫描启动中...")

        self._worker = DirScanWorker(self._settings, options, self)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(30)
        self._poll_timer.timeout.connect(self._drain_results)
        self._poll_timer.start()
        self._worker.statusChanged.connect(self._queue_status)
        self._worker.progressChanged.connect(self._progress_bar.setValue)
        self._worker.scanFinished.connect(self._finish_scan)
        self._worker.start()

    def _toggle_pause(self) -> None:
        """暂停 / 继续扫描"""
        if self._worker is None or not self._worker.isRunning():
            return
        if self._worker.is_paused():
            self._worker.resume()
            self._pause_btn.setText("暂停扫描")
            self._set_status("扫描继续中...")
        else:
            self._worker.pause()
            self._pause_btn.setText("继续扫描")
            self._set_status("扫描已暂停，当前任务完成后不再提交新任务")

    def _stop_scan(self) -> None:
        """停止扫描"""
        if self._worker is None or not self._worker.isRunning():
            return
        self._worker.stop()
        if hasattr(self, '_poll_timer') and self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._set_status("正在停止扫描...")

    def _finish_scan(self) -> None:
        """扫描完成清理"""
        if hasattr(self, '_poll_timer') and self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        self._drain_results()
        self._scan_btn.setEnabled(True)
        self._pause_btn.setText("暂停扫描")
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._clear_btn.setEnabled(True)
        self._set_inputs_enabled(True)
        self._result_table.setSortingEnabled(True)
        self._flush_status()
        self._worker = None

    def _set_inputs_enabled(self, enabled: bool) -> None:
        """统一控制所有输入控件的启用/禁用"""
        self._url_input.setEnabled(enabled)
        self._import_btn.setEnabled(enabled)
        self._dict_combo.setEnabled(enabled)
        self._keyword_exclude_input.setEnabled(enabled)
        self._length_exclude_input.setEnabled(enabled)
        self._thread_input.setEnabled(enabled)
        self._timeout_input.setEnabled(enabled)
        self._waf_checkbox.setEnabled(enabled)
        self._bypass_checkbox.setEnabled(enabled)
        for cb in self._status_checkboxes.values():
            cb.setEnabled(enabled)

    # ------------------------------------------------------------------
    # 结果管理
    # ------------------------------------------------------------------

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

    def _add_result(self, result: DirScanResult) -> None:
        """添加单条结果并刷新表格"""
        self._results_by_key[result.url] = result
        self._upsert_result_row(result)
        if self._should_auto_scroll_results():
            self._result_table.scrollToBottom()

    def _upsert_result_row(self, result: DirScanResult) -> bool:
        """插入或更新一行结果"""
        key = result.url
        is_new_row = key not in self._result_rows
        if is_new_row:
            self._result_counter += 1
            row = self._result_table.rowCount()
            self._result_table.insertRow(row)
            self._result_rows[key] = row
            self._result_index[key] = self._result_counter
        else:
            row = self._result_rows[key]
        self._results_by_key[key] = result
        values = [
            str(self._result_index[key]),
            str(result.status_code),
            result.url,
            str(result.length),
            result.redirect,
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            self._result_table.setItem(row, column, item)
        return is_new_row

    def _should_auto_scroll_results(self) -> bool:
        """判断是否应自动滚动到底部"""
        scroll_bar = self._result_table.verticalScrollBar()
        return scroll_bar.value() >= scroll_bar.maximum() - 2

    def _clear_results(self) -> None:
        """清空所有结果"""
        if self._worker is not None and self._worker.isRunning():
            return
        self._results_by_key = {}
        self._result_rows = {}
        self._result_index = {}
        self._result_counter = 0
        self._result_table.setRowCount(0)
        self._progress_bar.setValue(0)
        self._set_status("结果已清空")

    # ------------------------------------------------------------------
    # 导出结果
    # ------------------------------------------------------------------

    def _export_results(self) -> None:
        """导出扫描结果"""
        results = list(self._results_by_key.values())
        if not results:
            self._show_styled_warning("导出结果", "当前没有可导出的目录扫描结果")
            return
        filepath, selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出目录扫描结果",
            "dirscan_results.csv",
            EXPORT_FILTER_TEXT,
        )
        if not filepath:
            return
        filepath = self._normalize_export_path(filepath, selected_filter)
        if filepath is None:
            self._show_styled_warning("导出失败", "仅支持 csv、txt、html、xlsx 格式")
            return
        extension = os.path.splitext(filepath)[1].lower()
        try:
            if extension == ".xlsx":
                with open(filepath, "wb") as output_file:
                    output_file.write(results_to_xlsx(results))
                self._show_styled_message("导出完成", "目录扫描结果已导出", QMessageBox.Information)
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
        self._show_styled_message("导出完成", "目录扫描结果已导出", QMessageBox.Information)

    def _normalize_export_path(self, filepath: str, selected_filter: str) -> Optional[str]:
        """规范化导出路径"""
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

    # ------------------------------------------------------------------
    # 样式与弹窗
    # ------------------------------------------------------------------

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

    def _show_styled_message(self, title: str, message: str, icon: QMessageBox.Icon) -> int:
        """显示与全局设置一致的毛玻璃提示弹窗"""
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

    def _show_styled_warning(self, title: str, message: str) -> int:
        """显示与全局设置一致的警告弹窗"""
        return self._show_styled_message(title, message, QMessageBox.Warning)

    def _set_status(self, message: str) -> None:
        """直接设置状态文本"""
        self._status_label.setText(message)

    def _queue_status(self, message: str) -> None:
        """将状态文本加入防抖队列"""
        self._pending_status_message = message
        if not self._status_timer.isActive():
            self._status_timer.start()

    def _flush_status(self) -> None:
        """刷新暂存的状态文本"""
        if self._pending_status_message is None:
            self._status_timer.stop()
            return
        self._status_label.setText(self._pending_status_message)
        self._pending_status_message = None
        self._status_timer.stop()


# ---------------------------------------------------------------------------
# 工厂函数
# ---------------------------------------------------------------------------

def create_page(settings = None) -> ModulePage:
    """创建目录扫描页面"""
    if settings is None:
        from core.settings import AppSettings
        settings = AppSettings()
    return DirScannerPage(settings)
