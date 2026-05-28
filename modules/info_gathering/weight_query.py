"""权重查询模块 — 查询域名 ICP 备案信息和 SEO 权重数据"""
import csv
import io
import os

import openpyxl
import queue
import threading
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

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
from app.widgets.glass_input import GlassInput, GlassSpinBox, GlassTextEdit
from core.request_handler import RequestHandler
from core.settings import AppSettings


# ============================================================================
# 常量
# ============================================================================

NUMERIC_CONTROL_WIDTH = 142
ACTION_BUTTON_MIN_WIDTH = 104
TABLE_COLUMNS = [
    "主域名", "主体", "备案号", "备案性质", "审核时间",
    "百度权重", "百度移动", "搜狗权重", "搜狗移动",
    "360权重", "360移动", "神马权重", "头条权重", "必应权重",
]

ICP_API_URL = "https://cn.apihz.cn/api/wangzhan/icp.php"
WEIGHT_API_URL = "https://cn.apihz.cn/api/wangzhan/aizhanqz.php"


# ============================================================================
# 域名解析
# ============================================================================

def extract_domain(text: str) -> str:
    """从 URL 或域名文本中提取主域（去掉协议、路径、参数、端口、认证信息）"""
    text = text.strip()
    # 若无协议前缀则补全，确保 urlparse 正确解析
    if not text.startswith(("http://", "https://")):
        text = "http://" + text
    parsed = urlparse(text)
    # hostname 自动去除端口和认证信息，优于 netloc
    domain = parsed.hostname or ""
    return domain.strip().lower()


def parse_domains(text: str) -> List[str]:
    """解析多行域名输入，逐行提取主域，去重并校验格式。"""
    domains: List[str] = []
    seen: Set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        domain = extract_domain(line)
        if not domain:
            raise ValueError("域名格式无效：{}".format(raw_line.strip()))
        if "." not in domain:
            raise ValueError("域名格式无效（缺少顶级域）：{}".format(raw_line.strip()))
        if domain not in seen:
            domains.append(domain)
            seen.add(domain)
    if not domains:
        raise ValueError("请输入至少一个目标域名")
    return domains


# ============================================================================
# 后台查询线程
# ============================================================================

class WeightQueryWorker(QThread):
    """后台权重查询线程 — 每个域名并行请求 ICP 备案 API 和权重 API"""

    statusChanged = Signal(str)
    progressChanged = Signal(int)
    queryFinished = Signal()

    def __init__(
        self,
        settings: AppSettings,
        domains: List[str],
        api_id: str,
        api_key: str,
        thread_count: int,
        timeout_ms: int,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._settings = settings
        self._domains = domains
        self._api_id = api_id
        self._api_key = api_key
        self._thread_count = thread_count
        self._timeout_ms = timeout_ms
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._result_queue: queue.Queue = queue.Queue()

    def stop(self) -> None:
        """请求完全停止查询"""
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
        """执行查询任务 — 使用线程池并发处理多个域名"""
        from concurrent.futures import as_completed, ThreadPoolExecutor

        completed = 0
        try:
            handler = RequestHandler(self._settings)
            total = len(self._domains)
            self.statusChanged.emit("开始查询 {} 个域名...".format(total))

            timeout_seconds = self._timeout_ms / 1000.0
            api_headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
                    "Gecko/20100101 Firefox/120.0"
                ),
            }

            def query_domain(domain: str) -> None:
                """查询单个域名的 ICP + 权重（请求通过 handler 走代理配置）"""
                # 暂停等待
                while self._pause_event.is_set():
                    if self._stop_event.is_set():
                        return
                    time.sleep(0.1)
                if self._stop_event.is_set():
                    return

                # ICP 备案查询
                try:
                    icp_url = "{}?id={}&key={}&domain={}".format(
                        ICP_API_URL, self._api_id, self._api_key, domain)
                    resp = handler.get(icp_url, headers=api_headers, timeout=timeout_seconds)
                    data = resp.json()
                    if data.get("code") == 200:
                        self._result_queue.put(("icp", domain, data))
                    else:
                        self._result_queue.put(("icp_error", domain, data.get("msg", "未知错误")))
                except Exception as exc:
                    self._result_queue.put(("icp_error", domain, str(exc)))

                # 权重查询
                try:
                    weight_url = "{}?id={}&key={}&domain={}".format(
                        WEIGHT_API_URL, self._api_id, self._api_key, domain)
                    resp = handler.get(weight_url, headers=api_headers, timeout=timeout_seconds)
                    data = resp.json()
                    if data.get("code") == 200:
                        self._result_queue.put(("weight", domain, data))
                    else:
                        self._result_queue.put(("weight_error", domain, data.get("msg", "未知错误")))
                except Exception as exc:
                    self._result_queue.put(("weight_error", domain, str(exc)))

            with ThreadPoolExecutor(max_workers=self._thread_count) as executor:
                future_map = {}
                for domain in self._domains:
                    if self._stop_event.is_set():
                        break
                    future_map[executor.submit(query_domain, domain)] = domain

                for future in as_completed(future_map):
                    if self._stop_event.is_set():
                        break
                    future.result()  # 传播线程异常
                    completed += 1
                    progress = int(completed / total * 100)
                    self.progressChanged.emit(progress)

        finally:
            self.progressChanged.emit(100)
            self.statusChanged.emit("查询完成，共 {} 个域名".format(completed))
            self.queryFinished.emit()


# ============================================================================
# 页面 UI
# ============================================================================

class WeightQueryPage(ModulePage):
    """权重查询页面"""

    def __init__(
        self,
        settings: Optional[AppSettings] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(
            "权重查询",
            "查询域名的 ICP 备案信息及各大搜索引擎权重",
            parent,
        )
        if settings is None:
            settings = AppSettings()
        self._settings = settings
        self._worker: Optional[WeightQueryWorker] = None
        self._domain_data: Dict[str, Dict[str, str]] = {}
        self._result_rows: Dict[str, int] = {}
        self._pending_status_message: Optional[str] = None
        self._last_validated_domain_text: str = ""
        self._api_id_input: GlassInput = None  # type: ignore[assignment]
        self._api_key_input: GlassInput = None  # type: ignore[assignment]

        self.layout().setSpacing(8)
        self.content_layout.setSpacing(8)
        self._setup_ui()
        self._update_config_summary()

    # ------------------------------------------------------------------
    # 事件过滤器（域名失焦校验）
    # ------------------------------------------------------------------

    def eventFilter(self, watched: QWidget, event: QEvent) -> bool:
        """处理域名输入框失焦校验"""
        if event.type() == QEvent.FocusOut:
            if QApplication.activePopupWidget() is not None:
                return super().eventFilter(watched, event)
            if watched is self._domain_input.edit:
                self._validate_domain_input()
        return super().eventFilter(watched, event)

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        """构建完整页面布局"""
        # ---- 配置卡片 ----
        self._config_card = GlassCard(padding=12)
        self._config_card.setMinimumHeight(280)
        self._config_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

        # header 行
        header_widget = QWidget()
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)
        header_widget.setLayout(header_layout)

        config_title = QLabel("查询配置")
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

        # body — 3 列布局（与指纹识别模块一致）
        self._config_body = QWidget()
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(12)
        self._config_body.setLayout(body_layout)

        # ---- Col1: 域名输入区 (210px) ----
        domain_panel = QWidget()
        domain_layout = QVBoxLayout()
        domain_layout.setContentsMargins(0, 0, 0, 0)
        domain_layout.setSpacing(8)
        domain_panel.setLayout(domain_layout)
        body_layout.addWidget(domain_panel)

        self._domain_input = GlassTextEdit("目标域名", readonly=False)
        self._domain_input.setFixedWidth(210)
        self._domain_input.edit.setPlaceholderText("example.com\nbaidu.com\nqq.com")
        self._domain_input.edit.setMinimumHeight(100)
        self._domain_input.edit.setMaximumHeight(150)
        self._domain_input.edit.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._domain_input.edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        domain_layout.addWidget(self._domain_input)

        self._import_btn = GlassButton("导入域名")
        self._import_btn.clicked.connect(self._import_domains)
        domain_layout.addWidget(self._import_btn)
        domain_layout.addStretch()

        # ---- Col2: 参数区 (stretch) ----
        middle_panel = QWidget()
        middle_layout = QVBoxLayout()
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(8)
        middle_panel.setLayout(middle_layout)
        body_layout.addWidget(middle_panel, stretch=1)

        # API 密钥提示
        api_hint = QLabel(
            "请前往 https://www.apihz.cn/ 注册获取 API_ID 和 API_KEY"
        )
        api_hint.setObjectName("apiHint")
        api_hint.setOpenExternalLinks(True)
        api_hint.setWordWrap(True)
        api_hint.setStyleSheet(
            "QLabel#apiHint {"
            "  color: #64748B;"
            "  font-size: 11px;"
            "  padding: 4px 0;"
            "}"
        )
        middle_layout.addWidget(api_hint)

        # API ID / KEY 输入行
        api_row = QWidget()
        api_row_layout = QHBoxLayout()
        api_row_layout.setContentsMargins(0, 0, 0, 0)
        api_row_layout.setSpacing(8)
        api_row.setLayout(api_row_layout)

        self._api_id_input = GlassInput("API_ID", "输入 API_ID")
        self._api_id_input.setFixedWidth(180)
        self._api_id_input.input.setEchoMode(self._api_id_input.input.EchoMode.Normal)
        api_row_layout.addWidget(self._api_id_input)

        self._api_key_input = GlassInput("API_KEY", "输入 API_KEY")
        self._api_key_input.setFixedWidth(280)
        self._api_key_input.input.setEchoMode(self._api_key_input.input.EchoMode.Password)
        api_row_layout.addWidget(self._api_key_input)
        api_row_layout.addStretch()
        middle_layout.addWidget(api_row)

        param_row = QWidget()
        param_row_layout = QHBoxLayout()
        param_row_layout.setContentsMargins(0, 0, 0, 0)
        param_row_layout.setSpacing(8)
        param_row.setLayout(param_row_layout)

        self._thread_input = GlassSpinBox(
            "线程数", 1, 200, 5
        )
        self._thread_input.setFixedWidth(NUMERIC_CONTROL_WIDTH)
        param_row_layout.addWidget(self._thread_input)

        self._timeout_input = GlassSpinBox(
            "超时(ms)", 1000, 30000, self._settings.get("timeout", 5000)
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

        self._query_btn = GlassButton("开始查询")
        self._query_btn.clicked.connect(self._start_query)

        self._pause_btn = GlassButton("暂停查询")
        self._pause_btn.setEnabled(False)
        self._pause_btn.clicked.connect(self._toggle_pause)

        self._stop_btn = GlassButton("停止查询")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_query)

        self._export_btn = GlassButton("导出结果")
        self._export_btn.clicked.connect(self._export_results)

        self._clear_btn = GlassButton("清空结果")
        self._clear_btn.clicked.connect(self._clear_results)

        for button in [
            self._query_btn,
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
        self._domain_input.edit.installEventFilter(self)
        self._domain_input.edit.textChanged.connect(self._update_config_summary)
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
        self._result_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self._result_table.horizontalHeader().setStretchLastSection(False)
        self._result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self._result_table.setColumnWidth(0, 150)
        self._result_table.setColumnWidth(1, 100)
        self._result_table.setColumnWidth(2, 140)
        self._result_table.setColumnWidth(3, 90)
        self._result_table.setColumnWidth(4, 120)
        self._result_table.setColumnWidth(5, 85)
        self._result_table.setColumnWidth(6, 85)
        self._result_table.setColumnWidth(7, 85)
        self._result_table.setColumnWidth(8, 85)
        self._result_table.setColumnWidth(9, 85)
        self._result_table.setColumnWidth(10, 85)
        self._result_table.setColumnWidth(11, 85)
        self._result_table.setColumnWidth(12, 85)
        self._result_table.setColumnWidth(13, 85)
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
        domain_count = len([
            line for line in self._domain_input.text().splitlines() if line.strip()
        ])
        parts = [
            "域名 {} 个".format(domain_count),
            "线程 {}".format(self._thread_input.value()),
            "超时 {}ms".format(self._timeout_input.value()),
        ]
        self._config_summary.setText(" · ".join(parts))

    # ------------------------------------------------------------------
    # 输入校验
    # ------------------------------------------------------------------

    def _validate_domain_input(self) -> bool:
        """域名输入失焦校验，自动提取主域（同一文本只弹一次错误）"""
        text = self._domain_input.text().strip()
        if not text:
            self._last_validated_domain_text = ""
            return True
        if text == self._last_validated_domain_text:
            return True
        try:
            fixed_domains = parse_domains(text)
        except ValueError as error:
            self._last_validated_domain_text = text
            self._show_styled_warning("域名格式无效", str(error))
            QTimer.singleShot(0, self._domain_input.edit.setFocus)
            return False
        # 自动提取主域后写回
        current_lines = [l.strip() for l in text.splitlines() if l.strip()]
        if len(fixed_domains) == len(current_lines):
            new_text = "\n".join(fixed_domains)
            if new_text != text:
                self._domain_input.edit.blockSignals(True)
                self._domain_input.edit.setPlainText(new_text)
                self._domain_input.edit.blockSignals(False)
        return True

    def _import_domains(self) -> None:
        """从 TXT 文件导入域名列表"""
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
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                imported_domains = parse_domains(fh.read())
        except (IOError, ValueError) as error:
            self._show_styled_warning("导入失败", str(error))
            return

        current_domains: List[str] = []
        try:
            current_domains = parse_domains(self._domain_input.text())
        except ValueError:
            current_domains = []

        merged: List[str] = []
        seen: Set[str] = set()
        for domain in current_domains + imported_domains:
            if domain not in seen:
                merged.append(domain)
                seen.add(domain)
        self._domain_input.setText("\n".join(merged))

    # ------------------------------------------------------------------
    # 查询控制
    # ------------------------------------------------------------------

    def _start_query(self) -> None:
        """启动查询"""
        if self._worker is not None and self._worker.isRunning():
            return
        try:
            domains = parse_domains(self._domain_input.text())
        except ValueError as error:
            self._show_styled_warning("输入错误", str(error))
            return

        api_id = self._api_id_input.text().strip()
        api_key = self._api_key_input.text().strip()
        if not api_id:
            self._show_styled_warning("缺少 API_ID", "请输入 API_ID，可前往 apihz.cn 注册获取")
            return
        if not api_key:
            self._show_styled_warning("缺少 API_KEY", "请输入 API_KEY，可前往 apihz.cn 注册获取")
            return

        self._domain_data = {}
        self._result_rows = {}
        self._result_table.setRowCount(0)
        self._result_table.setSortingEnabled(False)
        self._progress_bar.setValue(0)
        self._query_btn.setEnabled(False)
        self._pause_btn.setText("暂停查询")
        self._pause_btn.setEnabled(True)
        self._stop_btn.setEnabled(True)
        self._clear_btn.setEnabled(False)
        self._set_inputs_enabled(False)
        self._set_status("查询启动中...")

        self._worker = WeightQueryWorker(
            settings=self._settings,
            domains=domains,
            api_id=api_id,
            api_key=api_key,
            thread_count=self._thread_input.value(),
            timeout_ms=self._timeout_input.value(),
            parent=self,
        )
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(30)
        self._poll_timer.timeout.connect(self._drain_results)
        self._poll_timer.start()
        self._worker.statusChanged.connect(self._queue_status)
        self._worker.progressChanged.connect(self._progress_bar.setValue)
        self._worker.queryFinished.connect(self._finish_query)
        self._worker.start()

    def _toggle_pause(self) -> None:
        """暂停 / 继续查询"""
        if self._worker is None or not self._worker.isRunning():
            return
        if self._worker.is_paused():
            self._worker.resume()
            self._pause_btn.setText("暂停查询")
            self._set_status("查询继续中...")
        else:
            self._worker.pause()
            self._pause_btn.setText("继续查询")
            self._set_status("查询已暂停，当前任务完成后不再提交新任务")

    def _stop_query(self) -> None:
        """停止查询"""
        if self._worker is None or not self._worker.isRunning():
            return
        self._worker.stop()
        if hasattr(self, "_poll_timer") and self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._set_status("正在停止查询...")

    def _finish_query(self) -> None:
        """查询完成清理"""
        if hasattr(self, "_poll_timer") and self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        self._drain_results()
        self._query_btn.setEnabled(True)
        self._pause_btn.setText("暂停查询")
        self._pause_btn.setEnabled(False)
        self._stop_btn.setEnabled(False)
        self._clear_btn.setEnabled(True)
        self._set_inputs_enabled(True)
        self._result_table.setSortingEnabled(True)
        self._flush_status()
        self._worker = None

    def _set_inputs_enabled(self, enabled: bool) -> None:
        """统一控制所有输入控件的启用/禁用"""
        self._domain_input.setEnabled(enabled)
        self._import_btn.setEnabled(enabled)
        self._api_id_input.setEnabled(enabled)
        self._api_key_input.setEnabled(enabled)
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
                item = result_queue.get_nowait()
            except queue.Empty:
                break
            self._process_result(item)
            drained = True
        if drained:
            self._result_table.repaint()

    def _process_result(self, item: Tuple[str, str, object]) -> None:
        """处理单个队列条目，更新 _domain_data 并刷新表格行"""
        msg_type, domain, payload = item

        # 初始化域名数据
        if domain not in self._domain_data:
            self._domain_data[domain] = {
                "unit_name": "",
                "filing_number": "",
                "filing_nature": "",
                "audit_time": "",
                "baidu_pc": "",
                "baidu_mobile": "",
                "sougou_pc": "",
                "sougou_mobile": "",
                "so360_pc": "",
                "so360_mobile": "",
                "shenma": "",
                "toutiao": "",
                "bing": "",
            }

        entry = self._domain_data[domain]

        if msg_type == "icp":
            # ICP 备案 API 返回字段
            entry["unit_name"] = str(payload.get("unit", ""))
            entry["filing_number"] = str(payload.get("icp", ""))
            entry["filing_nature"] = str(payload.get("type", ""))
            entry["audit_time"] = str(payload.get("time", ""))
        elif msg_type == "weight":
            # 权重 API 返回字段
            entry["baidu_pc"] = str(payload.get("bdpcqz", ""))
            entry["baidu_mobile"] = str(payload.get("bdmqz", ""))
            entry["sougou_pc"] = str(payload.get("sgpcqz", ""))
            entry["sougou_mobile"] = str(payload.get("sgmqz", ""))
            entry["so360_pc"] = str(payload.get("sllpcqz", ""))
            entry["so360_mobile"] = str(payload.get("sllmqz", ""))
            entry["shenma"] = str(payload.get("smqz", ""))
            entry["toutiao"] = str(payload.get("ttqz", ""))
            entry["bing"] = str(payload.get("byqz", ""))
        elif msg_type == "icp_error":
            entry["unit_name"] = "错误: {}".format(payload)
        elif msg_type == "weight_error":
            entry["baidu_pc"] = "错误: {}".format(payload)

        self._upsert_result_row(domain)
        if self._should_auto_scroll_results():
            self._result_table.scrollToBottom()

    def _upsert_result_row(self, domain: str) -> bool:
        """插入或更新一行结果"""
        is_new_row = domain not in self._result_rows
        if is_new_row:
            row = self._result_table.rowCount()
            self._result_table.insertRow(row)
            self._result_rows[domain] = row
        else:
            row = self._result_rows[domain]

        entry = self._domain_data.get(domain, {})
        values = [
            domain,
            entry.get("unit_name", ""),
            entry.get("filing_number", ""),
            entry.get("filing_nature", ""),
            entry.get("audit_time", ""),
            entry.get("baidu_pc", ""),
            entry.get("baidu_mobile", ""),
            entry.get("sougou_pc", ""),
            entry.get("sougou_mobile", ""),
            entry.get("so360_pc", ""),
            entry.get("so360_mobile", ""),
            entry.get("shenma", ""),
            entry.get("toutiao", ""),
            entry.get("bing", ""),
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
        self._domain_data = {}
        self._result_rows = {}
        self._result_table.setRowCount(0)
        self._progress_bar.setValue(0)
        self._set_status("结果已清空")

    # ------------------------------------------------------------------
    # 导出结果
    # ------------------------------------------------------------------

    def _export_results(self) -> None:
        """导出查询结果到文件"""
        if not self._domain_data:
            self._show_styled_warning("导出结果", "当前没有可导出的查询结果")
            return
        filepath, selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出权重查询结果",
            "weight_query_results.xlsx",
            "Excel 文件 (*.xlsx);;CSV 文件 (*.csv);;TXT 文件 (*.txt)",
        )
        if not filepath:
            return
        extension = os.path.splitext(filepath)[1].lower()
        if not extension:
            if "*.txt" in selected_filter:
                filepath += ".txt"
                extension = ".txt"
            elif "*.csv" in selected_filter:
                filepath += ".csv"
                extension = ".csv"
            else:
                filepath += ".xlsx"
                extension = ".xlsx"
        if extension not in (".csv", ".txt", ".xlsx"):
            self._show_styled_warning("导出失败", "仅支持 xlsx、csv、txt 格式")
            return

        try:
            if extension == ".xlsx":
                self._export_xlsx(filepath)
            else:
                self._export_text(filepath, extension)
        except IOError as error:
            self._show_styled_warning("导出失败", "写入文件失败：{}".format(error))
            return
        self._show_styled_message("导出完成", "查询结果已导出", QMessageBox.Information)

    def _export_text(self, filepath: str, extension: str) -> None:
        """导出为 CSV 或 TXT"""
        delimiter = "," if extension == ".csv" else "\t"
        output = io.StringIO()
        writer = csv.writer(output, delimiter=delimiter)
        writer.writerow(TABLE_COLUMNS)
        for domain, entry in self._domain_data.items():
            writer.writerow(self._build_export_row(domain, entry))
        with open(filepath, "w", encoding="utf-8-sig", newline="") as fh:
            fh.write(output.getvalue())

    def _export_xlsx(self, filepath: str) -> None:
        """导出为 Excel 文件"""
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "权重查询结果"
        ws.append(TABLE_COLUMNS)
        for domain, entry in self._domain_data.items():
            ws.append(self._build_export_row(domain, entry))
        # 自动调整列宽
        for col_idx, _col_cells in enumerate(ws.columns, 1):
            max_width = 0
            for cell in _col_cells:
                if cell.value:
                    # 中文字符按 2 倍宽度计算
                    cell_len = sum(2 if ord(c) > 127 else 1 for c in str(cell.value))
                    max_width = max(max_width, cell_len)
            ws.column_dimensions[openpyxl.utils.get_column_letter(col_idx)].width = min(max_width + 4, 40)
        wb.save(filepath)

    def _build_export_row(self, domain: str, entry: Dict[str, str]) -> List[str]:
        """构建导出数据行"""
        return [
            domain,
            entry.get("unit_name", ""),
            entry.get("filing_number", ""),
            entry.get("filing_nature", ""),
            entry.get("audit_time", ""),
            entry.get("baidu_pc", ""),
            entry.get("baidu_mobile", ""),
            entry.get("sougou_pc", ""),
            entry.get("sougou_mobile", ""),
            entry.get("so360_pc", ""),
            entry.get("so360_mobile", ""),
            entry.get("shenma", ""),
            entry.get("toutiao", ""),
            entry.get("bing", ""),
        ]

    # ------------------------------------------------------------------
    # 交互与弹窗
    # ------------------------------------------------------------------

    def _on_cell_double_clicked(self, row: int, col: int) -> None:
        """双击单元格弹出完整内容"""
        item = self._result_table.item(row, col)
        if item is None or not item.text().strip():
            return
        header = TABLE_COLUMNS[col] if col < len(TABLE_COLUMNS) else "内容"
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
    """创建权重查询页面"""
    if settings is None:
        settings = AppSettings()
    return WeightQueryPage(settings)
