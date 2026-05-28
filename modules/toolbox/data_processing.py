"""
数据处理模块 — 左中右三栏布局，支持 25 种按行数据处理操作。
"""
import json
import re
from typing import List, Callable, Optional, Set, Tuple

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFileDialog, QApplication,
    QGridLayout, QSizePolicy, QDialog, QLineEdit,
)
from PySide6.QtCore import Qt

from app.content_area import ModulePage
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassTextEdit
from app.widgets.glass_button import GlassButton

# 已知的两段式 TLD（用于根域名提取）
_TWO_PART_TLDS: Set[str] = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "mil.cn",
    "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
}


class _StyledInputDialog(QDialog):
    """数据处理模块使用的单字段毛玻璃输入弹窗。"""

    _STYLE = (
        "#settingsPanel {"
        "  background-color: rgba(255,255,255,0.95);"
        "  border: 1px solid rgba(0,0,0,0.08);"
        "  border-radius: 14px;"
        "}"
        "QLabel#settingsTitle {"
        "  color: #1E293B;"
        "  font-size: 15px;"
        "  font-weight: 600;"
        "  padding-bottom: 4px;"
        "}"
        "QLabel#inputLabel {"
        "  color: #64748B;"
        "  font-size: 12px;"
        "  padding-bottom: 2px;"
        "}"
        "QLineEdit#glassInput {"
        "  background-color: rgba(255,255,255,0.9);"
        "  border: 1px solid rgba(0,0,0,0.08);"
        "  border-radius: 8px;"
        "  padding: 8px 14px;"
        "  color: #1E293B;"
        "  font-size: 13px;"
        "  selection-background-color: #3B82F6;"
        "}"
        "QLineEdit#glassInput:focus {"
        "  border: 1px solid rgba(59,130,246,0.4);"
        "  background-color: rgba(255,255,255,1);"
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

    def __init__(
        self,
        title: str,
        prompt: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setObjectName("settingsPanel")
        self.setStyleSheet(self._STYLE)
        self.setFixedWidth(400)

        layout = QVBoxLayout()
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)
        self.setLayout(layout)

        title_label = QLabel(title)
        title_label.setObjectName("settingsTitle")
        layout.addWidget(title_label)

        prompt_label = QLabel(prompt)
        prompt_label.setObjectName("inputLabel")
        layout.addWidget(prompt_label)

        self._input = QLineEdit()
        self._input.setObjectName("glassInput")
        self._input.returnPressed.connect(self.accept)
        layout.addWidget(self._input)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        cancel_button = GlassButton("取消", GlassButton.STYLE_PRIMARY)
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        confirm_button = GlassButton("确定", GlassButton.STYLE_PRIMARY)
        confirm_button.clicked.connect(self.accept)
        button_layout.addWidget(confirm_button)
        layout.addLayout(button_layout)

        self._input.setFocus()

    def text(self) -> str:
        """获取用户输入的文本。"""
        return self._input.text()


class DataProcessingPage(ModulePage):
    """数据处理页面，提供文本去重、排序、提取、格式化等操作。"""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__("数据处理", "文本去重、排序、提取、格式化等常用数据处理操作")
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI 搭建
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        """搭建左中右三栏布局。"""
        main_row = QHBoxLayout()
        main_row.setSpacing(12)
        main_row.setContentsMargins(0, 0, 0, 0)

        # ---- 左侧：输入区 ----
        left_card = GlassCard()
        left_card.setObjectName("glassCard")
        left_layout = left_card.layout()

        left_btn_row = QHBoxLayout()
        left_btn_row.setSpacing(8)
        import_btn = GlassButton("导入")
        import_btn.clicked.connect(self._import_file)
        clear_btn = GlassButton("清空")
        clear_btn.clicked.connect(self._clear_input)
        left_btn_row.addWidget(import_btn)
        left_btn_row.addWidget(clear_btn)
        left_btn_row.addStretch()
        left_layout.addLayout(left_btn_row)

        self._input_edit = GlassTextEdit("输入数据（每行一条）", readonly=False)
        self._input_edit.edit.setMinimumHeight(200)
        self._input_edit.edit.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        left_layout.addWidget(self._input_edit)

        # ---- 中间：操作区 ----
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setMinimumWidth(320)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        middle_container = QWidget()
        middle_container.setStyleSheet("background: transparent;")
        middle_layout = QVBoxLayout()
        middle_layout.setContentsMargins(0, 0, 0, 0)
        middle_layout.setSpacing(14)
        middle_container.setLayout(middle_layout)

        # 分组定义
        middle_layout.addWidget(self._make_group("排序与去重", [
            ("去重", self._dedup),
            ("排序(A-Z)", self._sort_az),
            ("倒序(Z-A)", self._sort_za),
            ("逆序", self._reverse),
        ]))
        middle_layout.addWidget(self._make_group("分割与合并", [
            ("逗号转行", self._split_comma),
            ("合并一行", self._join_lines),
            ("分隔符转行", self._split_by_delim),
        ]))
        middle_layout.addWidget(self._make_group("清理与格式", [
            ("去空行", self._remove_empty),
            ("去首尾空格", self._trim_lines),
            ("JSON格式化", self._json_format),
            ("去特殊字符", self._remove_special),
        ]))
        middle_layout.addWidget(self._make_group("网络处理(1)", [
            ("去协议头", self._remove_proto),
            ("去端口", self._remove_port),
            ("加http://", self._add_http),
            ("加https://", self._add_https),
        ]))
        middle_layout.addWidget(self._make_group("网络处理(2)", [
            ("提取根域名", self._extract_root_domain),
            ("提取IP", self._extract_ip),
            ("提取URL", self._extract_url),
            ("提取C段", self._extract_c_segment),
        ]))
        middle_layout.addWidget(self._make_group("字符过滤", [
            ("去中文", self._remove_chinese),
            ("保留中文", self._keep_chinese),
            ("自定义去除", self._custom_remove),
            ("自定义保留", self._custom_keep),
        ]))
        middle_layout.addWidget(self._make_group("自定义", [
            ("自定义前缀", self._custom_prefix),
            ("自定义后缀", self._custom_suffix),
        ]))

        middle_layout.addStretch()
        scroll.setWidget(middle_container)

        # ---- 右侧：输出区 ----
        right_card = GlassCard()
        right_card.setObjectName("glassCard")
        right_layout = right_card.layout()

        right_btn_row = QHBoxLayout()
        right_btn_row.setSpacing(8)
        copy_btn = GlassButton("复制")
        copy_btn.clicked.connect(self._copy_output)
        export_btn = GlassButton("导出TXT")
        export_btn.clicked.connect(self._export_file)
        right_btn_row.addWidget(copy_btn)
        right_btn_row.addWidget(export_btn)
        right_btn_row.addStretch()
        right_layout.addLayout(right_btn_row)

        self._output_edit = GlassTextEdit("处理结果")
        self._output_edit.edit.setMinimumHeight(200)
        self._output_edit.edit.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        right_layout.addWidget(self._output_edit)

        # 加入主布局（三等分，中间操作区足够宽以容纳按钮）
        main_row.addWidget(left_card, 3)
        main_row.addWidget(scroll, 3)
        main_row.addWidget(right_card, 3)
        self.content_layout.addLayout(main_row, 1)
        self.layout().setStretchFactor(self.content_layout, 1)

    def _make_group(self, title: str, button_specs: List[tuple]) -> QWidget:
        """创建一个操作按钮分组。

        Args:
            title: 分组标题。
            button_specs: [(按钮文本, 回调函数), ...] 列表。
        """
        group = QWidget()
        group.setStyleSheet("background: transparent;")
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        group.setLayout(layout)

        lbl = QLabel(title)
        lbl.setObjectName("inputLabel")
        layout.addWidget(lbl)

        grid = QGridLayout()
        grid.setSpacing(6)
        cols = 2 if len(button_specs) == 4 else 3
        # 1-3 个按钮用 3 列单行；4 个按钮用 2×2
        if len(button_specs) <= 3:
            cols = len(button_specs)
        elif len(button_specs) == 4:
            cols = 2
        else:
            cols = 4  # 8 个按钮用 4 列

        for i, (text, callback) in enumerate(button_specs):
            btn = GlassButton(text)
            btn.clicked.connect(callback)
            row, col = divmod(i, cols)
            grid.addWidget(btn, row, col)

        layout.addLayout(grid)
        return group

    # ------------------------------------------------------------------
    # 数据读写辅助
    # ------------------------------------------------------------------

    def _get_lines(self) -> List[str]:
        """获取左侧输入框的所有行。"""
        text = self._input_edit.text()
        if not text:
            return []
        return text.splitlines()

    def _set_output(self, lines: List[str]) -> None:
        """将行列表写入右侧输出框。"""
        self._output_edit.setText("\n".join(lines))

    def _request_text(self, title: str, prompt: str) -> Tuple[str, bool]:
        """通过统一样式弹窗获取单行文本。"""
        dialog = _StyledInputDialog(title, prompt, self)
        if dialog.exec() != QDialog.Accepted:
            return "", False
        return dialog.text(), True

    # ------------------------------------------------------------------
    # 文件与剪贴板操作
    # ------------------------------------------------------------------

    def _import_file(self) -> None:
        """从 TXT 文件导入文本到输入框。"""
        path, _ = QFileDialog.getOpenFileName(
            self, "导入文本文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            self._input_edit.setText(text)
        except (OSError, UnicodeDecodeError):
            try:
                with open(path, "r", encoding="gbk") as f:
                    text = f.read()
                self._input_edit.setText(text)
            except (OSError, UnicodeDecodeError):
                pass

    def _clear_input(self) -> None:
        """清空输入框。"""
        self._input_edit.setText("")

    def _copy_output(self) -> None:
        """复制输出内容到剪贴板。"""
        text = self._output_edit.text()
        if text:
            QApplication.clipboard().setText(text)

    def _export_file(self) -> None:
        """导出输出内容为 TXT 文件。"""
        text = self._output_edit.text()
        path, _ = QFileDialog.getSaveFileName(
            self, "导出文本文件", "output.txt", "文本文件 (*.txt);;所有文件 (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # 排序与去重
    # ------------------------------------------------------------------

    def _dedup(self) -> None:
        """去重，保留首次出现顺序。"""
        lines = self._get_lines()
        seen: Set[str] = set()
        result: List[str] = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                result.append(line)
        self._set_output(result)

    def _sort_az(self) -> None:
        """按字母升序排序（A → Z）。"""
        lines = self._get_lines()
        self._set_output(sorted(lines))

    def _sort_za(self) -> None:
        """按字母降序排序（Z → A）。"""
        lines = self._get_lines()
        self._set_output(sorted(lines, reverse=True))

    def _reverse(self) -> None:
        """逆序（反转行顺序）。"""
        lines = self._get_lines()
        self._set_output(list(reversed(lines)))

    # ------------------------------------------------------------------
    # 分割与合并
    # ------------------------------------------------------------------

    def _split_comma(self) -> None:
        """每行按逗号分割，每个元素独立成行。"""
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            for part in line.split(","):
                result.append(part.strip())
        self._set_output(result)

    def _join_lines(self) -> None:
        """所有行直接合并为一行（无分隔符）。"""
        lines = self._get_lines()
        self._set_output(["".join(lines)])

    def _split_by_delim(self) -> None:
        """弹窗输入分隔符，每行按分隔符分割后展开。"""
        delim, ok = self._request_text("分隔符转行", "请输入分隔符：")
        if not ok:
            return
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            for part in line.split(delim):
                result.append(part)
        self._set_output(result)

    # ------------------------------------------------------------------
    # 清理与格式
    # ------------------------------------------------------------------

    def _remove_empty(self) -> None:
        """去除空行（空白行也视为空行）。"""
        lines = self._get_lines()
        self._set_output([line for line in lines if line.strip()])

    def _trim_lines(self) -> None:
        """去除每行首尾空格。"""
        lines = self._get_lines()
        self._set_output([line.strip() for line in lines])

    def _json_format(self) -> None:
        """尝试将每行解析为 JSON 并格式化，非 JSON 行保持不变。"""
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                result.append(line)
                continue
            try:
                obj = json.loads(stripped)
                result.append(json.dumps(obj, ensure_ascii=False, indent=2))
            except (json.JSONDecodeError, ValueError):
                result.append(line)
        self._set_output(result)

    def _remove_special(self) -> None:
        """去除每行中的特殊字符（保留字母、数字、空格和常见标点）。"""
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            # 保留：字母、数字、空格、常见标点
            cleaned = re.sub(
                r"[^a-zA-Z0-9\s\.\,\;\:\!\?\-\_\'\"\(\)\[\]\{\}\/\\\@\#\$\%\^\&\*\=\+\~\`\|\<\>]",
                "", line
            )
            result.append(cleaned)
        self._set_output(result)

    # ------------------------------------------------------------------
    # 网络处理
    # ------------------------------------------------------------------

    def _remove_proto(self) -> None:
        """去除协议头（http:// 和 https://）。"""
        lines = self._get_lines()
        result = [re.sub(r"^https?://", "", line) for line in lines]
        self._set_output(result)

    def _remove_port(self) -> None:
        """去除端口号（:port 形式）。"""
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            # 匹配 :port 后跟 / 或行尾
            cleaned = re.sub(r":\d+(?=/|$)", "", line)
            result.append(cleaned)
        self._set_output(result)

    def _add_http(self) -> None:
        """每行前面添加 http://"""
        lines = self._get_lines()
        self._set_output(["http://" + line for line in lines])

    def _add_https(self) -> None:
        """每行前面添加 https://"""
        lines = self._get_lines()
        self._set_output(["https://" + line for line in lines])

    def _extract_root_domain(self) -> None:
        """从 URL 或域名中提取根域名（如 www.example.com → example.com）。"""
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            root = self._parse_root_domain(line)
            if root:
                result.append(root)
        self._set_output(result)

    @staticmethod
    def _parse_root_domain(raw: str) -> str:
        """从原始字符串解析根域名。"""
        # 去除协议头
        host = re.sub(r"^https?://", "", raw)
        # 去除路径、端口、查询参数
        host = host.split("/")[0].split(":")[0].split("?")[0].split("#")[0]
        # 去除可能的用户信息 (user@host)
        if "@" in host:
            host = host.split("@")[-1]
        host = host.strip().lower()
        if not host:
            return ""

        parts = host.split(".")
        if len(parts) <= 1:
            return host  # 单段直接返回（可能是 IP 或单独主机名）

        # IPv4 地址直接返回
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            return host

        # 检查最后两段是否是两段式 TLD
        if len(parts) >= 3:
            last_two = ".".join(parts[-2:])
            if last_two in _TWO_PART_TLDS:
                return ".".join(parts[-3:])
        # 默认取最后两段
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    def _extract_ip(self) -> None:
        """从每行提取 IPv4 地址，去重。"""
        lines = self._get_lines()
        result: List[str] = []
        seen: Set[str] = set()
        for line in lines:
            for match in re.findall(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", line):
                if match not in seen:
                    seen.add(match)
                    result.append(match)
        self._set_output(result)

    def _extract_url(self) -> None:
        """从每行提取 HTTP/HTTPS URL，去重。"""
        lines = self._get_lines()
        result: List[str] = []
        seen: Set[str] = set()
        for line in lines:
            for match in re.findall(r"https?://[^\s\'\"\<\>\\]+", line):
                if match not in seen:
                    seen.add(match)
                    result.append(match)
        self._set_output(result)

    def _extract_c_segment(self) -> None:
        """从每行提取 IPv4 地址并转换为 C 段（/24 网段格式），去重。"""
        lines = self._get_lines()
        result: List[str] = []
        seen: Set[str] = set()
        for line in lines:
            for match in re.findall(r"(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}(?!\d)", line):
                c_seg = match + ".0/24"
                if c_seg not in seen:
                    seen.add(c_seg)
                    result.append(c_seg)
        self._set_output(result)

    # ------------------------------------------------------------------
    # 字符过滤
    # ------------------------------------------------------------------

    def _remove_chinese(self) -> None:
        """去除每行中的中文字符（包括中文标点）。"""
        lines = self._get_lines()
        result = [re.sub(r"[一-鿿㐀-䶿　-〿＀-￯]", "", line) for line in lines]
        self._set_output(result)

    def _keep_chinese(self) -> None:
        """保留每行中的中文字符（包括中文标点），去除其余字符。"""
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            chars = re.findall(r"[一-鿿㐀-䶿　-〿＀-￯]", line)
            result.append("".join(chars))
        self._set_output(result)

    def _custom_remove(self) -> None:
        """弹窗输入要删除的字符，从每行中去除这些字符。"""
        chars, ok = self._request_text("自定义字符去除", "请输入要删除的字符：")
        if not ok:
            return
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            for ch in chars:
                line = line.replace(ch, "")
            result.append(line)
        self._set_output(result)

    def _custom_keep(self) -> None:
        """弹窗输入要保留的字符，每行只保留这些字符。"""
        chars, ok = self._request_text("自定义字符保留", "请输入要保留的字符：")
        if not ok:
            return
        keep_set = set(chars)
        lines = self._get_lines()
        result: List[str] = []
        for line in lines:
            filtered = "".join(ch for ch in line if ch in keep_set)
            result.append(filtered)
        self._set_output(result)

    def _custom_prefix(self) -> None:
        """弹窗输入前缀，为每行添加。"""
        prefix, ok = self._request_text("添加前缀", "请输入前缀（可为空）:")
        if not ok:
            return
        lines = self._get_lines()
        self._set_output([prefix + line for line in lines])

    def _custom_suffix(self) -> None:
        """弹窗输入后缀，为每行添加。"""
        suffix, ok = self._request_text("添加后缀", "请输入后缀（可为空）:")
        if not ok:
            return
        lines = self._get_lines()
        self._set_output([line + suffix for line in lines])


def create_page() -> ModulePage:
    """工厂函数：创建数据处理页面实例。"""
    return DataProcessingPage()
