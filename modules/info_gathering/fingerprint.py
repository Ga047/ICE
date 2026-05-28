"""指纹识别模块 — 识别目标网站 CMS/框架/技术栈"""
import os
import queue
import threading
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from core._app_root import get_app_root

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
from app.widgets.glass_input import GlassSpinBox, GlassTextEdit
from core.fingerprint_engine import (
    EXPORT_FILTER_TEXT,
    FingerprintEngine,
    FingerprintResult,
    results_to_csv,
    results_to_html,
    results_to_txt,
    results_to_xlsx,
)
from core.request_handler import RequestHandler
from core.settings import AppSettings


# ============================================================================
# 常量
# ============================================================================

NUMERIC_CONTROL_WIDTH = 142
ACTION_BUTTON_MIN_WIDTH = 104
TABLE_COLUMNS = ["URL", "标题", "响应码", "返回长度", "识别结果"]

# finger.json 默认查找路径（相对于项目根目录）
def _default_rules_path() -> str:
    project_root = get_app_root()
    path = os.path.join(project_root, "resources", "dir", "finger", "finger.json")
    if os.path.exists(path):
        return path
    return path  # 透传，让引擎报错


# ============================================================================
# URL 解析（独立实现，失焦时自动补全 http://）
# ============================================================================

def parse_urls(text: str) -> List[str]:
    """解析多行 URL 输入，自动补全协议头，去重并校验格式。"""
    urls: List[str] = []
    seen: Set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not line.startswith(("http://", "https://")):
            line = "http://" + line
        parsed = urlparse(line)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("URL 格式无效：{}".format(raw_line.strip()))
        base = line if not line.endswith("/") or parsed.path == "/" else line.rstrip("/")
        if base not in seen:
            urls.append(base)
            seen.add(base)
    if not urls:
        raise ValueError("请输入至少一个目标 URL")
    return urls


# ============================================================================
# 后台扫描线程
# ============================================================================

class FingerprintWorker(QThread):
    """后台指纹识别线程"""

    statusChanged = Signal(str)
    progressChanged = Signal(int)
    scanFinished = Signal()

    def __init__(
        self,
        settings: AppSettings,
        urls: List[str],
        thread_count: int,
        timeout_ms: int,
        rules_path: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._settings = settings
        self._urls = urls
        self._thread_count = thread_count
        self._timeout_ms = timeout_ms
        self._rules_path = rules_path
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
        """执行扫描任务 — 使用线程池并发"""
        from concurrent.futures import as_completed, ThreadPoolExecutor
        import time
        try:
            handler = RequestHandler(self._settings)
            engine = FingerprintEngine(
                rules_path=self._rules_path,
                request_handler=handler,
                timeout_ms=self._timeout_ms,
            )
            total = len(self._urls)
            self.statusChanged.emit("已加载 {} 条指纹规则，开始识别 {} 个目标...".format(
                engine.rule_count, total))

            completed = 0

            def identify_url(url: str):
                """在后台线程中识别单个 URL"""
                if self._stop_event.is_set():
                    return None
                while self._pause_event.is_set():
                    if self._stop_event.is_set():
                        return None
                    time.sleep(0.1)
                try:
                    return engine.identify(
                        url,
                        stop_event=self._stop_event,
                        pause_event=self._pause_event,
                    )
                except Exception:
                    return FingerprintResult(url=url)

            with ThreadPoolExecutor(max_workers=self._thread_count) as executor:
                futures = {}
                for url in self._urls:
                    if self._stop_event.is_set():
                        break
                    futures[executor.submit(identify_url, url)] = url

                for future in as_completed(futures):
                    if self._stop_event.is_set():
                        break
                    result = future.result()
                    if result is not None:
                        self._result_queue.put(result)
                    completed += 1
                    progress = int(completed / total * 100) if total > 0 else 0
                    self.progressChanged.emit(progress)

        finally:
            self.progressChanged.emit(100)
            self.statusChanged.emit("识别完成，共 {} 个目标".format(completed))
            self.scanFinished.emit()


# ============================================================================
# 页面 UI
# ============================================================================

class FingerprintPage(ModulePage):
    """指纹识别页面"""

    def __init__(
        self,
        settings: Optional[AppSettings] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(
            "指纹识别",
            "识别目标网站的 CMS、框架等技术栈信息",
            parent,
        )
        if settings is None:
            settings = AppSettings()
        self._settings = settings
        self._rules_path = _default_rules_path()
        self._worker: Optional[FingerprintWorker] = None
        self._results_by_url: Dict[str, FingerprintResult] = {}
        self._result_rows: Dict[str, int] = {}
        self._pending_status_message: Optional[str] = None
        self._last_validated_url_text: str = ""

        self.layout().setSpacing(8)
        self.content_layout.setSpacing(8)
        self._setup_ui()
        self._update_config_summary()

    # ------------------------------------------------------------------
    # 事件过滤器 (URL 失焦校验)
    # ------------------------------------------------------------------

    def eventFilter(self, watched: QWidget, event: QEvent) -> bool:
        """处理 URL 输入框失焦校验"""
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
        self._config_card.setMinimumHeight(220)
        self._config_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        # header 行
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
        self._url_input.edit.setMaximumHeight(150)
        self._url_input.edit.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._url_input.edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        url_layout.addWidget(self._url_input)

        self._import_btn = GlassButton("导入 URL")
        self._import_btn.clicked.connect(self._import_urls)
        url_layout.addWidget(self._import_btn)
        url_layout.addStretch()

        # ---- Col2: 参数区 (stretch) ----
        middle_panel = QWidget()
        middle_layout = QVBoxLayout()
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(8)
        middle_panel.setLayout(middle_layout)
        body_layout.addWidget(middle_panel, stretch=1)

        # 线程数 + 超时 同一行
        param_row = QWidget()
        param_row_layout = QHBoxLayout()
        param_row_layout.setContentsMargins(0, 0, 0, 0)
        param_row_layout.setSpacing(8)
        param_row.setLayout(param_row_layout)

        self._thread_input = GlassSpinBox("线程数", 1, 200, 50)
        self._thread_input.setFixedWidth(NUMERIC_CONTROL_WIDTH)
        param_row_layout.addWidget(self._thread_input)

        self._timeout_input = GlassSpinBox(
            "超时(ms)", 1000, 60000, self._settings.get("timeout", 3000)
        )
        self._timeout_input.setFixedWidth(NUMERIC_CONTROL_WIDTH)
        param_row_layout.addWidget(self._timeout_input)

        param_row_layout.addStretch()
        middle_layout.addWidget(param_row)
        middle_layout.addStretch()

        # ---- Col3: 操作按钮 ----
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)
        right_panel.setLayout(right_layout)

        self._scan_btn = GlassButton("开始识别")
        self._scan_btn.clicked.connect(self._start_scan)

        self._pause_btn = GlassButton("暂停识别")
        self._pause_btn.setEnabled(False)
        self._pause_btn.clicked.connect(self._toggle_pause)

        self._stop_btn = GlassButton("停止识别")
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

        # 状态防抖定时器
        self._status_timer = QTimer(self)
        self._status_timer.setSingleShot(True)
        self._status_timer.setInterval(250)
        self._status_timer.timeout.connect(self._flush_status)

        # ---- 结果卡片 ----
        result_card = GlassCard(padding=16)
        result_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self._result_table = QTableWidget(0, len(TABLE_COLUMNS))
        self._result_table.setHorizontalHeaderLabels(TABLE_COLUMNS)
        self._result_table.setObjectName("portResultTable")
        self._result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._result_table.setAlternatingRowColors(True)
        self._result_table.setSortingEnabled(True)
        self._result_table.verticalHeader().setVisible(False)
        self._result_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._result_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._result_table.horizontalHeader().setStretchLastSection(False)
        self._result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._result_table.setColumnWidth(1, 200)
        self._result_table.setColumnWidth(2, 70)
        self._result_table.setColumnWidth(3, 80)
        self._result_table.setColumnWidth(4, 180)
        self._result_table.setMinimumHeight(300)
        self._result_table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        self._result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._result_table.customContextMenuRequested.connect(self._on_context_menu)
        result_card.layout().addWidget(self._result_table)

        self.content_layout.addWidget(self._config_card)
        self.content_layout.addWidget(result_card, stretch=1)

    # ------------------------------------------------------------------
    # 配置摘要
    # ------------------------------------------------------------------

    def _update_config_summary(self) -> None:
        """更新配置摘要文字"""
        url_count = len([
            line for line in self._url_input.text().splitlines() if line.strip()
        ])
        parts = [
            "URL {} 个".format(url_count),
            "线程 {}".format(self._thread_input.value()),
            "超时 {}ms".format(self._timeout_input.value()),
        ]
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
        # 自动补全协议头后写回
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
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                imported_urls = parse_urls(fh.read())
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

        self._results_by_url = {}
        self._result_rows = {}
        self._result_table.setRowCount(0)
        self._result_table.setSortingEnabled(False)
        self._progress_bar.setValue(0)
        self._scan_btn.setEnabled(False)
        self._pause_btn.setText("暂停识别")
        self._pause_btn.setEnabled(True)
        self._stop_btn.setEnabled(True)
        self._clear_btn.setEnabled(False)
        self._set_inputs_enabled(False)
        self._set_status("扫描启动中...")

        self._worker = FingerprintWorker(
            settings=self._settings,
            urls=urls,
            thread_count=self._thread_input.value(),
            timeout_ms=self._timeout_input.value(),
            rules_path=self._rules_path,
            parent=self,
        )
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
            self._pause_btn.setText("暂停识别")
            self._set_status("识别继续中...")
        else:
            self._worker.pause()
            self._pause_btn.setText("继续识别")
            self._set_status("识别已暂停，当前任务完成后不再提交新任务")

    def _stop_scan(self) -> None:
        """停止扫描"""
        if self._worker is None or not self._worker.isRunning():
            return
        self._worker.stop()
        if hasattr(self, "_poll_timer") and self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._set_status("正在停止识别...")

    def _finish_scan(self) -> None:
        """扫描完成清理"""
        if hasattr(self, "_poll_timer") and self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        self._drain_results()
        self._scan_btn.setEnabled(True)
        self._pause_btn.setText("暂停识别")
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
        self._thread_input.setEnabled(enabled)
        self._timeout_input.setEnabled(enabled)

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

    def _add_result(self, result: FingerprintResult) -> None:
        """添加单条结果并刷新表格"""
        self._results_by_url[result.url] = result
        self._upsert_result_row(result)
        if self._should_auto_scroll_results():
            self._result_table.scrollToBottom()

    def _upsert_result_row(self, result: FingerprintResult) -> bool:
        """插入或更新一行结果"""
        key = result.url
        is_new_row = key not in self._result_rows
        if is_new_row:
            row = self._result_table.rowCount()
            self._result_table.insertRow(row)
            self._result_rows[key] = row
        else:
            row = self._result_rows[key]

        values = [
            result.url,
            result.title,
            str(result.status_code) if result.status_code else "",
            str(result.length) if result.length else "",
            result.cms if result.cms else "",
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
        self._results_by_url = {}
        self._result_rows = {}
        self._result_table.setRowCount(0)
        self._progress_bar.setValue(0)
        self._set_status("结果已清空")

    # ------------------------------------------------------------------
    # 导出结果
    # ------------------------------------------------------------------

    def _export_results(self) -> None:
        """导出识别结果"""
        results = list(self._results_by_url.values())
        if not results:
            self._show_styled_warning("导出结果", "当前没有可导出的指纹识别结果")
            return
        filepath, selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出指纹识别结果",
            "fingerprint_results.csv",
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
                with open(filepath, "wb") as fh:
                    fh.write(results_to_xlsx(results))
                self._show_styled_message("导出完成", "指纹识别结果已导出", QMessageBox.Information)
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
            with open(filepath, "w", encoding=encoding, newline="") as fh:
                fh.write(content)
        except IOError as error:
            self._show_styled_warning("导出失败", "写入文件失败：{}".format(error))
            return
        self._show_styled_message("导出完成", "指纹识别结果已导出", QMessageBox.Information)

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

def create_page(settings: Optional[AppSettings] = None) -> ModulePage:
    """创建指纹识别页面"""
    if settings is None:
        settings = AppSettings()
    return FingerprintPage(settings)
