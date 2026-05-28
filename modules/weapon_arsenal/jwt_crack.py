"""JWT 破解模块 —— 解码 / 编码 / 校验 / 字典破解 / 时间戳转换"""
import base64
import hashlib
import json
import os
import threading
import datetime as dt
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

import jwt
from jwt.exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidSignatureError,
)

from app.content_area import ModulePage
from app.widgets.glass_button import GlassButton
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassCombo, GlassInput, GlassTextEdit

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

ALGORITHMS = [
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EdDSA", "NONE",
]

ENCODING_MODES = ["Base64", "MD5", "16位MD5", "NONE"]
ASYMMETRIC_PREFIXES = ("RS", "ES", "PS", "Ed")

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

from core._app_root import get_app_root

_PROJECT_ROOT = get_app_root()
DEFAULT_DICT_PATH = os.path.join(_PROJECT_ROOT, "resources", "dir", "jwt", "jwt.txt")


# ---------------------------------------------------------------------------
# 后台破解线程
# ---------------------------------------------------------------------------

class JwtCrackWorker(QThread):
    """后台字典破解线程，支持启动 / 暂停 / 停止控制。"""

    progressChanged = Signal(int, int)  # current, total
    statusChanged = Signal(str)
    resultFound = Signal(str)
    crackFinished = Signal()

    def __init__(
        self,
        token: str,
        algorithm: str,
        dict_path: str,
        encoding_mode: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._token = token
        self._algorithm = algorithm
        self._dict_path = dict_path
        self._encoding_mode = encoding_mode
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()

    # -- 外部控制接口 --

    def stop(self) -> None:
        self._stop_event.set()
        self._pause_event.clear()

    def pause(self) -> None:
        self._pause_event.set()

    def resume(self) -> None:
        self._pause_event.clear()

    def is_paused(self) -> bool:
        return self._pause_event.is_set()

    # -- 内部 --

    def _apply_encoding(self, secret: str) -> str:
        """对字典中的原始密钥应用用户选择的编码转换。"""
        if self._encoding_mode == "NONE":
            return secret
        if self._encoding_mode == "Base64":
            try:
                padded = secret + "=" * (-len(secret) % 4)
                return base64.b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                return secret
        if self._encoding_mode == "MD5":
            return hashlib.md5(secret.encode("utf-8", errors="ignore")).hexdigest()
        if self._encoding_mode == "16位MD5":
            return hashlib.md5(secret.encode("utf-8", errors="ignore")).hexdigest()[8:24]
        return secret

    def run(self) -> None:
        try:
            # 第一遍扫描：统计总行数，用于进度条
            total = 0
            with open(self._dict_path, "r", encoding="utf-8", errors="ignore") as fh:
                for _ in fh:
                    total += 1

            self.statusChanged.emit("字典已加载，共 {} 条密钥".format(total))

            # 第二遍扫描：逐行尝试
            current = 0
            with open(self._dict_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if self._stop_event.is_set():
                        self.statusChanged.emit("破解已停止")
                        return

                    while self._pause_event.is_set():
                        if self._stop_event.is_set():
                            return
                        self.msleep(100)

                    secret = line.strip()
                    current += 1

                    if not secret:
                        continue

                    encoded_secret = self._apply_encoding(secret)

                    try:
                        jwt.decode(
                            self._token,
                            encoded_secret,
                            algorithms=[self._algorithm],
                        )
                        self.resultFound.emit(secret)
                        self.statusChanged.emit("破解成功！密钥：{}".format(secret))
                        self.progressChanged.emit(current, total)
                        return
                    except InvalidSignatureError:
                        pass
                    except Exception:
                        pass

                    if current % 100 == 0:
                        self.progressChanged.emit(current, total)

            self.progressChanged.emit(total, total)
            self.statusChanged.emit(
                "字典已耗尽，共尝试 {} 条密钥，未找到匹配".format(total)
            )
        except FileNotFoundError:
            self.statusChanged.emit("字典文件未找到：{}".format(self._dict_path))
        except Exception as exc:
            self.statusChanged.emit("破解出错：{}".format(str(exc)))
        finally:
            self.crackFinished.emit()


# ---------------------------------------------------------------------------
# 页面类
# ---------------------------------------------------------------------------

class JwtCrackPage(ModulePage):
    """JwtCrack 三列工具页面。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(
            "JwtCrack",
            "对 JWT Token 进行解析、签名验证和密钥爆破",
            parent,
        )
        self._worker: Optional[JwtCrackWorker] = None
        self._dict_path: str = DEFAULT_DICT_PATH

        self._setup_ui()
        self._connect_signals()

    # ------------------------------------------------------------------
    # UI 构建
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        """构建三列毛玻璃卡片布局。"""
        card = GlassCard(padding=20)

        # 三列容器
        columns_layout = QHBoxLayout()
        columns_layout.setSpacing(0)
        card.layout().addLayout(columns_layout)

        # 左列
        left_col = self._build_left_column()
        columns_layout.addLayout(left_col, stretch=2)

        columns_layout.addWidget(self._make_vline())

        # 中列
        middle_col = self._build_middle_column()
        columns_layout.addWidget(middle_col)

        columns_layout.addWidget(self._make_vline())

        # 右列
        right_col = self._build_right_column()
        columns_layout.addLayout(right_col, stretch=3)

        self.content_layout.addWidget(card)

        # 应用下拉框弹出列表统一样式
        self._encoding_combo.combo.setStyleSheet(COMBO_POPUP_STYLE)
        self._algo_combo.combo.setStyleSheet(COMBO_POPUP_STYLE)

    # -- 左列 -----------------------------------------------------------

    def _build_left_column(self) -> QVBoxLayout:
        col = QVBoxLayout()
        col.setSpacing(10)

        # JWT Token
        self._token_edit = GlassTextEdit("JWT Token", readonly=False)
        self._token_edit.edit.setPlaceholderText(
            "JWT Token 由三部分组成：Header.Payload.Signature\n"
            "Header：涵盖 JWT 元数据，包括签名算法、类型等。\n"
            "Payload：涵盖所需传递的数据内容。\n"
            "Signature：用于验证 JWT 的完整性、正确性。"
        )
        self._token_edit.edit.setMinimumHeight(100)
        token_btn_row = QHBoxLayout()
        token_btn_row.setSpacing(8)
        self._token_clear_btn = GlassButton("清空")
        self._token_copy_btn = GlassButton("复制")
        token_btn_row.addStretch()
        token_btn_row.addWidget(self._token_clear_btn)
        token_btn_row.addWidget(self._token_copy_btn)
        self._token_edit.layout().addLayout(token_btn_row)
        col.addWidget(self._token_edit)

        # 密钥 / Secret
        self._secret_input = GlassInput(
            "密钥 / Secret",
            "密钥用于对 Header 和 Payload 进行签名，校验 JWT 的完整性、正确性与安全性"
        )
        self._secret_input.input.setToolTip(
            "密钥用于对 Header 和 Payload 进行签名，来校验 JWT 的完整性、正确性、安全性"
        )

        encoding_row = QHBoxLayout()
        encoding_row.setSpacing(8)
        self._encoding_combo = GlassCombo("", ENCODING_MODES)
        self._encoding_combo.combo.setCurrentIndex(3)  # 默认 NONE
        self._secret_copy_btn = GlassButton("复制")
        encoding_row.addWidget(self._encoding_combo)
        encoding_row.addWidget(self._secret_copy_btn)
        encoding_row.addStretch()

        col.addWidget(self._secret_input)
        col.addLayout(encoding_row)

        # 字典选择
        dict_row = QHBoxLayout()
        dict_row.setSpacing(8)
        self._dict_label = QLabel(self._dict_path)
        self._dict_label.setObjectName("dictPathLabel")
        self._dict_label.setWordWrap(False)
        self._dict_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._dict_label.setStyleSheet(
            "color: #64748B; font-size: 12px; padding: 4px 8px;"
            "background: rgba(0,0,0,0.03); border-radius: 6px;"
        )
        self._dict_browse_btn = GlassButton("选择字典")
        dict_row.addWidget(self._dict_label, stretch=1)
        dict_row.addWidget(self._dict_browse_btn)
        col.addLayout(dict_row)

        # 破解控制按钮
        crack_btn_row = QHBoxLayout()
        crack_btn_row.setSpacing(8)
        self._crack_btn = GlassButton("开始破解")
        self._pause_btn = GlassButton("暂停破解")
        self._pause_btn.setEnabled(False)
        self._stop_btn = GlassButton("停止破解")
        self._stop_btn.setEnabled(False)
        crack_btn_row.addWidget(self._crack_btn)
        crack_btn_row.addWidget(self._pause_btn)
        crack_btn_row.addWidget(self._stop_btn)
        col.addLayout(crack_btn_row)

        # 进度条
        self._progress_bar = QProgressBar()
        self._progress_bar.setObjectName("crackProgressBar")
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setVisible(False)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFormat("%p%")
        col.addWidget(self._progress_bar)

        # 状态标签
        self._status_label = QLabel("")
        self._status_label.setObjectName("crackStatus")
        self._status_label.setWordWrap(True)
        self._status_label.setStyleSheet(
            "color: #64748B; font-size: 12px; padding: 2px 0;"
        )
        col.addWidget(self._status_label)

        return col

    # -- 中列 -----------------------------------------------------------

    def _build_middle_column(self) -> QWidget:
        middle_widget = QWidget()
        middle_widget.setFixedWidth(240)
        col = QVBoxLayout()
        col.setSpacing(10)
        middle_widget.setLayout(col)

        # 签名算法
        self._algo_combo = GlassCombo("签名算法", ALGORITHMS)
        self._algo_combo.combo.setCurrentIndex(0)  # 默认 HS256
        col.addWidget(self._algo_combo)

        # 解码 / 编码 / 校验
        self._decode_btn = GlassButton("解码 →")        # 解码 →
        self._encode_btn = GlassButton("← 编码")        # ← 编码
        self._verify_btn = GlassButton("校验")

        col.addWidget(self._decode_btn)
        col.addWidget(self._encode_btn)
        col.addWidget(self._verify_btn)

        # 分隔线
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("QFrame { border: none; border-top: 1px solid rgba(0,0,0,0.08); }")
        col.addWidget(sep)

        # 时间戳转换
        self._ts_input = GlassInput("Unix 时间戳", "输入 Unix 时间戳（秒），支持双向转换")
        self._ts_input.input.setMinimumWidth(200)
        self._ts_input.input.setToolTip("输入 Unix 时间戳（秒），点击转换按钮可双向转换为标准时间格式")
        col.addWidget(self._ts_input)

        ts_btn_row = QHBoxLayout()
        ts_btn_row.setSpacing(8)
        self._ts_to_time_btn = GlassButton("↓ 时间戳→时间")
        self._ts_to_time_btn.setStyleSheet(
            "QPushButton { font-size: 11px; padding: 6px 10px; }"
        )
        self._time_to_ts_btn = GlassButton("时间→时间戳 ↑")
        self._time_to_ts_btn.setStyleSheet(
            "QPushButton { font-size: 11px; padding: 6px 10px; }"
        )
        ts_btn_row.addWidget(self._ts_to_time_btn)
        ts_btn_row.addWidget(self._time_to_ts_btn)
        col.addLayout(ts_btn_row)

        self._time_input = GlassInput("标准时间", "YYYY-MM-DD HH:MM:SS，支持双向转换")
        self._time_input.input.setToolTip("输入标准时间格式（如 2024-01-01 12:00:00），点击转换按钮可双向转换为 Unix 时间戳")
        col.addWidget(self._time_input)

        col.addStretch()
        return middle_widget

    # -- 右列 -----------------------------------------------------------

    def _build_right_column(self) -> QVBoxLayout:
        col = QVBoxLayout()
        col.setSpacing(8)

        # Header
        self._header_edit = GlassTextEdit("头部 / Header", readonly=False)
        self._header_edit.edit.setPlaceholderText(
            "Header 是一个 JSON 对象，包含 JWT 的元数据，alg 属性表示签名的算法，默认为 HS256，"
            "typ 属性表示令牌类型，JWT 令牌统一为 JWT"
        )
        self._header_edit.edit.setMinimumHeight(100)
        header_btn_row = QHBoxLayout()
        header_btn_row.addStretch()
        self._header_copy_btn = GlassButton("复制")
        header_btn_row.addWidget(self._header_copy_btn)
        self._header_edit.layout().addLayout(header_btn_row)
        col.addWidget(self._header_edit)

        # Payload
        self._payload_edit = GlassTextEdit("载荷 / Payload", readonly=False)
        self._payload_edit.edit.setPlaceholderText(
            "Payload 部分是一个 JSON 对象，包含实际传输的数据，包含 7 个官方字段，可选用："
            "iss(Issuer)签发者 sub(Subject)主题 aud(Audience)接收者 "
            "exp(Expiration Time)过期时间 nbf(Not Before)生效时间 "
            "iat(Issued At)签发时间 jti(JWT ID)编号"
        )
        self._payload_edit.edit.setMinimumHeight(140)
        payload_btn_row = QHBoxLayout()
        payload_btn_row.addStretch()
        self._payload_copy_btn = GlassButton("复制")
        payload_btn_row.addWidget(self._payload_copy_btn)
        self._payload_edit.layout().addLayout(payload_btn_row)
        col.addWidget(self._payload_edit)

        # Verify 输出
        self._verify_edit = GlassTextEdit("校验 / Verify", readonly=True)
        self._verify_edit.edit.setPlaceholderText(
            "校验 Signature 部分是对 JWT 的签名，用于验证 JWT 的完整性与正确性"
        )
        self._verify_edit.edit.setMinimumHeight(60)
        verify_btn_row = QHBoxLayout()
        verify_btn_row.addStretch()
        self._verify_copy_btn = GlassButton("复制")
        verify_btn_row.addWidget(self._verify_copy_btn)
        self._verify_edit.layout().addLayout(verify_btn_row)
        col.addWidget(self._verify_edit)

        return col

    @staticmethod
    def _make_vline() -> QFrame:
        """创建列间垂直分隔线。"""
        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setStyleSheet(
            "QFrame { border: none; border-left: 1px solid rgba(0,0,0,0.08); }"
        )
        line.setFixedWidth(1)
        return line

    # ------------------------------------------------------------------
    # 信号连接
    # ------------------------------------------------------------------

    def _connect_signals(self) -> None:
        # 操作按钮
        self._decode_btn.clicked.connect(self._on_decode)
        self._encode_btn.clicked.connect(self._on_encode)
        self._verify_btn.clicked.connect(self._on_verify)

        # 时间戳
        self._ts_to_time_btn.clicked.connect(self._on_ts_to_time)
        self._time_to_ts_btn.clicked.connect(self._on_time_to_ts)
        # 回车也可触发转换
        self._ts_input.input.returnPressed.connect(self._on_ts_to_time)
        self._time_input.input.returnPressed.connect(self._on_time_to_ts)

        # 破解
        self._crack_btn.clicked.connect(self._start_crack)
        self._pause_btn.clicked.connect(self._toggle_pause)
        self._stop_btn.clicked.connect(self._stop_crack)

        # 字典浏览
        self._dict_browse_btn.clicked.connect(self._browse_dict)

        # 复制按钮
        self._token_copy_btn.clicked.connect(
            lambda: self._copy_to_clipboard(self._token_edit.text())
        )
        self._token_clear_btn.clicked.connect(
            lambda: self._token_edit.setText("")
        )
        self._secret_copy_btn.clicked.connect(
            lambda: self._copy_to_clipboard(self._secret_input.text())
        )
        self._header_copy_btn.clicked.connect(
            lambda: self._copy_to_clipboard(self._header_edit.text())
        )
        self._payload_copy_btn.clicked.connect(
            lambda: self._copy_to_clipboard(self._payload_edit.text())
        )
        self._verify_copy_btn.clicked.connect(
            lambda: self._copy_to_clipboard(self._verify_edit.text())
        )

    # ------------------------------------------------------------------
    # JWT 解码
    # ------------------------------------------------------------------

    def _on_decode(self) -> None:
        token = self._token_edit.text().strip()
        if not token:
            self._show_warning("请输入 JWT Token")
            return

        if token.count(".") != 2:
            self._show_warning("JWT Token 格式无效，应为 Header.Payload.Signature 三段")
            return

        try:
            header = jwt.get_unverified_header(token)
            self._header_edit.setText(
                json.dumps(header, indent=2, ensure_ascii=False)
            )

            payload = jwt.decode(
                token,
                options={"verify_signature": False},
                algorithms=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
                            "ES256", "ES384", "ES512", "PS256", "PS384", "PS512",
                            "EdDSA"],
            )
            self._payload_edit.setText(
                json.dumps(payload, indent=2, ensure_ascii=False)
            )

            # 自动同步算法下拉框
            alg = header.get("alg", "").upper()
            if alg:
                idx = self._algo_combo.combo.findText(alg)
                if idx >= 0:
                    self._algo_combo.combo.setCurrentIndex(idx)

            self._show_toast("解码成功 — 签名未校验")
        except DecodeError as exc:
            self._show_warning("JWT 解码失败：{}".format(str(exc)))
        except Exception as exc:
            self._show_warning("解码出错：{}".format(str(exc)))

    # ------------------------------------------------------------------
    # JWT 编码
    # ------------------------------------------------------------------

    def _on_encode(self) -> None:
        header_text = self._header_edit.text().strip()
        payload_text = self._payload_edit.text().strip()
        secret_raw = self._secret_input.text()
        algorithm = self._algo_combo.current_text()

        if not header_text:
            self._show_warning("Header 不能为空")
            return
        if not payload_text:
            self._show_warning("Payload 不能为空")
            return

        try:
            header = json.loads(header_text)
        except json.JSONDecodeError as exc:
            self._show_warning("Header JSON 格式无效：{}".format(str(exc)))
            return

        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as exc:
            self._show_warning("Payload JSON 格式无效：{}".format(str(exc)))
            return

        try:
            encoded_secret = self._encode_secret(secret_raw)

            if algorithm == "NONE":
                token = jwt.encode(
                    payload, "", algorithm="none", headers=header
                )
            elif algorithm.startswith(ASYMMETRIC_PREFIXES):
                self._show_warning(
                    "非对称算法（RS/ES/PS/EdDSA）需要 PEM 密钥文件，"
                    "无法使用纯文本密钥。请使用 HS* 算法。"
                )
                return
            else:
                token = jwt.encode(
                    payload,
                    encoded_secret,
                    algorithm=algorithm,
                    headers=header,
                )

            # PyJWT>=2.0 返回 str，旧版返回 bytes
            if isinstance(token, bytes):
                token = token.decode("utf-8")

            self._token_edit.setText(token)
            self._show_toast("JWT 编码成功")
        except Exception as exc:
            self._show_warning("编码失败：{}".format(str(exc)))

    # ------------------------------------------------------------------
    # JWT 校验
    # ------------------------------------------------------------------

    def _on_verify(self) -> None:
        token = self._token_edit.text().strip()
        secret_raw = self._secret_input.text()
        algorithm = self._algo_combo.current_text()

        if not token:
            self._show_warning("请输入 JWT Token")
            return

        try:
            encoded_secret = self._encode_secret(secret_raw)

            if algorithm == "NONE":
                decoded = jwt.decode(
                    token,
                    options={"verify_signature": False},
                )
                header = jwt.get_unverified_header(token)
                if header.get("alg", "").upper() == "NONE":
                    self._verify_edit.setText(
                        "[无签名 JWT (alg=none)]\nPayload:\n{}".format(
                            json.dumps(decoded, indent=2, ensure_ascii=False)
                        )
                    )
                else:
                    self._verify_edit.setText("[警告] 选择了 NONE 算法但 Token 声明了签名")
                return

            if algorithm.startswith(ASYMMETRIC_PREFIXES):
                self._show_warning(
                    "非对称算法（RS/ES/PS/EdDSA）需要 PEM 密钥文件，"
                    "无法使用纯文本密钥校验。"
                )
                return

            jwt.decode(token, encoded_secret, algorithms=[algorithm])
            self._verify_edit.setText(
                "[签名校验通过]\n算法：{}\n密钥：{}".format(algorithm, secret_raw)
            )
        except InvalidSignatureError:
            self._verify_edit.setText("[签名无效] 该 Token 不是用提供的密钥签名的")
        except DecodeError as exc:
            self._show_warning("JWT 解析失败：{}".format(str(exc)))
        except Exception as exc:
            self._show_warning("校验出错：{}".format(str(exc)))

    # ------------------------------------------------------------------
    # 时间戳转换（双向）
    # ------------------------------------------------------------------

    def _on_ts_to_time(self) -> None:
        """时间戳 → 标准时间（↓ 方向）。"""
        ts_text = self._ts_input.text().strip()
        if not ts_text:
            self._show_toast("请先输入 Unix 时间戳")
            return

        # 格式校验：必须为纯数字
        if not ts_text.lstrip("-").isdigit():
            self._show_toast("时间戳格式非法，请输入纯数字的 Unix 时间戳（如 1700000000）")
            return

        try:
            ts_val = int(ts_text)
            # 毫秒时间戳 → 秒
            if ts_val > 9999999999:
                ts_val = ts_val // 1000
            result = dt.datetime.fromtimestamp(ts_val)
            self._time_input.setText(
                result.strftime("%Y-%m-%d %H:%M:%S")
            )
            self._show_toast("时间戳 → 标准时间 转换成功")
        except (ValueError, OSError, OverflowError) as exc:
            self._show_warning(
                "时间戳转换失败：{}\n有效范围：1970-01-01 ~ 2038-01-19".format(str(exc))
            )

    def _on_time_to_ts(self) -> None:
        """标准时间 → 时间戳（↑ 方向）。"""
        time_text = self._time_input.text().strip()
        if not time_text:
            self._show_toast("请先输入标准时间")
            return

        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d",
            "%Y-%m-%dT%H:%M:%S",
        ]
        for fmt in formats:
            try:
                parsed = dt.datetime.strptime(time_text, fmt)
                self._ts_input.setText(str(int(parsed.timestamp())))
                self._show_toast("标准时间 → 时间戳 转换成功")
                return
            except ValueError:
                continue

        # 格式非法
        self._show_toast(
            "时间格式非法。支持的格式：YYYY-MM-DD HH:MM:SS, "
            "YYYY-MM-DD, YYYY/MM/DD HH:MM:SS, YYYY-MM-DDTHH:MM:SS"
        )

    # ------------------------------------------------------------------
    # 破解控制
    # ------------------------------------------------------------------

    def _start_crack(self) -> None:
        token = self._token_edit.text().strip()
        algorithm = self._algo_combo.current_text()

        if not token:
            self._show_warning("请输入 JWT Token")
            return
        if not os.path.exists(self._dict_path):
            self._show_warning("字典文件不存在：{}".format(self._dict_path))
            return
        if algorithm.startswith(ASYMMETRIC_PREFIXES):
            self._show_warning(
                "非对称算法（RS/ES/PS/EdDSA）不支持字典破解。"
            )
            return
        if algorithm == "NONE":
            self._show_warning("alg=none 的 Token 无需密钥，无需破解。")
            return
        if self._worker is not None and self._worker.isRunning():
            self._show_warning("已有破解任务在运行")
            return

        self._set_crack_ui_state("running")

        self._worker = JwtCrackWorker(
            token=token,
            algorithm=algorithm,
            dict_path=self._dict_path,
            encoding_mode=self._encoding_combo.current_text(),
        )
        self._worker.progressChanged.connect(self._on_crack_progress)
        self._worker.statusChanged.connect(self._on_crack_status)
        self._worker.resultFound.connect(self._on_result_found)
        self._worker.crackFinished.connect(self._on_crack_finished)
        self._worker.start()

    def _toggle_pause(self) -> None:
        if self._worker is None:
            return
        if self._worker.is_paused():
            self._worker.resume()
            self._pause_btn.setText("暂停破解")
            self._status_label.setText("破解已恢复...")
        else:
            self._worker.pause()
            self._pause_btn.setText("继续破解")
            self._status_label.setText("破解已暂停")

    def _stop_crack(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self._status_label.setText("正在停止...")

    # -- 破解回调 --------------------------------------------------------

    def _on_crack_progress(self, current: int, total: int) -> None:
        self._progress_bar.setVisible(True)
        if total > 0:
            pct = int(current / total * 100)
            self._progress_bar.setValue(pct)
            self._progress_bar.setFormat("{} / {} (%p%)".format(current, total))

    def _on_crack_status(self, message: str) -> None:
        self._status_label.setText(message)

    def _on_result_found(self, secret: str) -> None:
        self._secret_input.setText(secret)
        self._verify_edit.setText(
            "[破解成功]\n密钥：{}".format(secret)
        )

    def _on_crack_finished(self) -> None:
        self._worker = None
        self._set_crack_ui_state("idle")

    def _set_crack_ui_state(self, state: str) -> None:
        if state == "running":
            self._crack_btn.setEnabled(False)
            self._pause_btn.setEnabled(True)
            self._pause_btn.setText("暂停破解")
            self._stop_btn.setEnabled(True)
            self._progress_bar.setValue(0)
            self._progress_bar.setVisible(False)
            self._status_label.setText("")
        else:
            self._crack_btn.setEnabled(True)
            self._pause_btn.setEnabled(False)
            self._pause_btn.setText("暂停破解")
            self._stop_btn.setEnabled(False)

    # ------------------------------------------------------------------
    # 字典浏览
    # ------------------------------------------------------------------

    def _browse_dict(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 JWT 字典文件",
            os.path.dirname(self._dict_path),
            "文本文件 (*.txt);;所有文件 (*)",
        )
        if path and os.path.exists(path):
            self._dict_path = path
            self._dict_label.setText(path)
        elif path:
            self._show_warning("所选文件不存在：{}".format(path))

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------

    def _encode_secret(self, secret: str) -> str:
        """根据编码下拉框对密钥进行编码转换。"""
        mode = self._encoding_combo.current_text()
        if mode == "NONE" or not secret:
            return secret
        if mode == "Base64":
            try:
                padded = secret + "=" * (-len(secret) % 4)
                return base64.b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                return secret
        if mode == "MD5":
            return hashlib.md5(secret.encode("utf-8", errors="ignore")).hexdigest()
        if mode == "16位MD5":
            return hashlib.md5(secret.encode("utf-8", errors="ignore")).hexdigest()[8:24]
        return secret

    def _copy_to_clipboard(self, text: str) -> None:
        """将文本复制到系统剪贴板并弹出飘窗提示。"""
        if text:
            QApplication.clipboard().setText(text)
            self._show_toast("已复制到剪贴板")

    def _show_toast(self, message: str, duration: int = 1500) -> None:
        """显示毛玻璃风格自动消失飘窗（页面内浮动）。"""
        toast = QLabel(message, self)
        toast.setObjectName("toastNotification")
        toast.setAlignment(Qt.AlignCenter)
        toast.setWordWrap(True)
        toast.setMinimumWidth(300)
        toast.setMaximumWidth(520)
        toast.setStyleSheet(
            "#toastNotification {"
            "  background-color: rgba(255, 255, 255, 0.95);"
            "  border: 1px solid rgba(0, 0, 0, 0.08);"
            "  border-radius: 14px;"
            "  padding: 14px 28px;"
            "  color: #1E293B;"
            "  font-size: 14px;"
            "}"
        )
        toast.adjustSize()

        x = (self.width() - toast.width()) // 2
        y = 80
        toast.move(x, y)
        toast.show()
        toast.raise_()

        QTimer.singleShot(duration, toast.deleteLater)

    def _show_warning(self, message: str) -> None:
        """显示毛玻璃风格警告弹窗（与全局设置风格一致）。"""
        box = QMessageBox(self)
        box.setWindowTitle("提示")
        box.setText(message)
        box.setIcon(QMessageBox.Warning)
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
            "  font-size: 14px;"
            "  padding: 8px 0;"
            "}"
            "QPushButton {"
            "  background-color: #3B82F6;"
            "  color: #FFFFFF;"
            "  border: none;"
            "  border-radius: 8px;"
            "  padding: 8px 28px;"
            "  min-width: 80px;"
            "  font-size: 13px;"
            "}"
            "QPushButton:hover {"
            "  background-color: #2563EB;"
            "}"
        )
        box.exec_()


# ---------------------------------------------------------------------------
# 模块入口
# ---------------------------------------------------------------------------

def create_page() -> ModulePage:
    """创建 JwtCrack 页面实例。"""
    return JwtCrackPage()
