"""社工字典生成模块"""
from typing import Dict, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.content_area import ModulePage
from app.widgets.glass_button import GlassButton
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassCheckBox, GlassInput, GlassTextEdit
from core.dict_generator_engine import DictGeneratorEngine

# ── 字段配置：(标签, 变量名, 占位提示) ──
FIELD_CONFIG = [
    ("姓名(全拼)", "姓名", "zhangsan"),
    ("姓名(简拼)", "简拼", "zs"),
    ("姓名(首字母缩写)", "缩写", "zs"),
    ("姓名(英文名)", "英文名", "john"),
    ("电话号码", "电话", "13800138000"),
    ("生日", "生日", "19900101"),
    ("QQ/邮箱", "邮箱", "123456@qq.com"),
    ("域名", "域名", "example.com"),
    ("公司", "公司", "abc"),
    ("工号", "工号", "001"),
    ("亲友", "亲友", "friend"),
    ("身份证号码", "身份证", "110101199001011234"),
    ("历史密码", "历史密码", "oldpass123"),
    ("年份", "年份", "2024"),
    ("常用词组", "常用词", "admin,root"),
    ("连接符", "连接符", "_,-"),
]

GRID_COLUMNS = 2


class DictGeneratorPage(ModulePage):
    """社工字典生成页面"""

    def __init__(self, parent=None):
        super().__init__(
            "社工字典生成", "根据目标个人信息生成定制化密码字典", parent
        )
        self._inputs: Dict[str, GlassInput] = {}
        self._generated_passwords: List[str] = []

        self._setup_ui()

    # ── UI 搭建 ──────────────────────────────────────────────

    def _setup_ui(self) -> None:
        """构建完整 UI 布局"""
        # 上方左右两栏
        top_row = QHBoxLayout()
        top_row.setSpacing(16)
        top_row.addWidget(self._build_left_card(), stretch=5)
        top_row.addWidget(self._build_right_card(), stretch=4)
        self.content_layout.addLayout(top_row)

        # 状态标签
        self._status_label = QLabel("")
        self._status_label.setObjectName("configSummary")
        self.content_layout.addWidget(self._status_label)

        # 输出区域
        self._output = GlassTextEdit("生成的字典", readonly=True)
        self._output.edit.setMinimumHeight(200)
        self.content_layout.addWidget(self._output)

    # ── 左侧卡片 ────────────────────────────────────────────

    def _build_left_card(self) -> GlassCard:
        """构建左侧信息输入卡片"""
        card = GlassCard(padding=16)
        card.setObjectName("leftInputCard")

        title = QLabel("信息输入")
        title.setObjectName("sectionTitle")
        card.layout().addWidget(title)

        grid_widget = QWidget()
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        grid_widget.setLayout(grid)

        for idx, (label, var_name, placeholder) in enumerate(FIELD_CONFIG):
            inp = GlassInput(label, placeholder)
            self._inputs[var_name] = inp
            row = idx // GRID_COLUMNS
            col = idx % GRID_COLUMNS
            grid.addWidget(inp, row, col)

        card.layout().addWidget(grid_widget)

        hint = QLabel("多个值以英文逗号(,)分割")
        hint.setObjectName("inputLabel")
        hint.setStyleSheet("color: #64748B; font-size: 11px;")
        card.layout().addWidget(hint)

        return card

    # ── 右侧卡片 ────────────────────────────────────────────

    def _build_right_card(self) -> GlassCard:
        """构建右侧生成规则卡片"""
        card = GlassCard(padding=16)
        card.setObjectName("rightRuleCard")

        title = QLabel("生成规则配置")
        title.setObjectName("sectionTitle")
        card.layout().addWidget(title)

        # 1. 模式选择（互斥）
        card.layout().addWidget(self._build_mode_toggle())

        # 2. 项目模式区域
        self._project_area = self._build_project_area()
        card.layout().addWidget(self._project_area)

        # 3. 自定义组合区域
        self._custom_area = self._build_custom_area()
        card.layout().addWidget(self._custom_area)

        # 4. 过滤选项
        card.layout().addWidget(self._build_filter_section())

        # 5. 操作按钮行
        card.layout().addWidget(self._build_action_row())

        return card

    def _build_mode_toggle(self) -> QWidget:
        """模式互斥选择：项目模式 / 自定义组合"""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)
        widget.setLayout(layout)

        self._mode_group = QButtonGroup(widget)
        self._mode_group.setExclusive(True)

        self._project_mode_cb = GlassCheckBox("项目模式", True)
        self._custom_mode_cb = GlassCheckBox("自定义组合", False)

        self._mode_group.addButton(self._project_mode_cb.check, 0)
        self._mode_group.addButton(self._custom_mode_cb.check, 1)

        self._project_mode_cb.check.toggled.connect(self._on_mode_changed)
        self._custom_mode_cb.check.toggled.connect(self._on_mode_changed)

        layout.addWidget(self._project_mode_cb)
        layout.addWidget(self._custom_mode_cb)
        layout.addStretch()
        return widget

    def _build_project_area(self) -> QWidget:
        """项目模式：一/二/三项目互斥按钮"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        widget.setLayout(layout)

        label = QLabel("选取项目数")
        label.setObjectName("inputLabel")
        layout.addWidget(label)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self._project_btn_group = QButtonGroup(widget)
        self._project_btn_group.setExclusive(True)

        btn_configs = [
            ("one", "一项目", "随机取 1 个"),
            ("two", "二项目", "取 2 个全排列"),
            ("three", "三项目", "取 3 个全排列"),
        ]
        self._project_btns: Dict[str, GlassButton] = {}
        for mode_key, text, tooltip in btn_configs:
            btn = GlassButton(text)
            btn.setCheckable(True)
            btn.setToolTip(tooltip)
            btn.setMinimumWidth(80)
            btn.clicked.connect(
                lambda _checked=False, k=mode_key: self._on_project_mode_selected(k)
            )
            self._project_btns[mode_key] = btn
            self._project_btn_group.addButton(btn)
            btn_layout.addWidget(btn)

        # 默认选中一项目
        self._project_btns["one"].setChecked(True)
        self._current_project_mode = "one"

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self._project_mode_hint = QLabel("当前：一项目 — 随机取 1 个字段值作为密码")
        self._project_mode_hint.setObjectName("inputLabel")
        self._project_mode_hint.setStyleSheet("color: #3B82F6; font-size: 11px;")
        layout.addWidget(self._project_mode_hint)

        return widget

    def _build_custom_area(self) -> QWidget:
        """自定义组合：模板输入"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        widget.setLayout(layout)

        self._template_input = GlassInput("自定义组合模板", "{姓名}+{电话}+{生日}")
        layout.addWidget(self._template_input)

        var_names = ", ".join("{%s}" % v for (_l, v, _p) in FIELD_CONFIG)
        hint = QLabel("可用变量: %s" % var_names)
        hint.setStyleSheet("color: #64748B; font-size: 11px;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        # 初始禁用（项目模式默认选中）
        widget.setEnabled(False)
        return widget

    def _build_filter_section(self) -> QWidget:
        """过滤选项区域"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        widget.setLayout(layout)

        label = QLabel("过滤与变换选项")
        label.setObjectName("inputLabel")
        layout.addWidget(label)

        # 过滤小于 N 位
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        self._filter_min_cb = GlassCheckBox("过滤小于", False)
        self._filter_min_spin = QSpinBox()
        self._filter_min_spin.setObjectName("glassSpinBox")
        self._filter_min_spin.setRange(1, 99)
        self._filter_min_spin.setValue(6)
        self._filter_min_spin.setFixedWidth(80)
        row1.addWidget(self._filter_min_cb)
        row1.addWidget(self._filter_min_spin)
        suffix1 = QLabel("位的密码")
        suffix1.setObjectName("inputLabel")
        row1.addWidget(suffix1)
        row1.addStretch()
        layout.addLayout(row1)

        # 过滤大于 N 位
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        self._filter_max_cb = GlassCheckBox("过滤大于", False)
        self._filter_max_spin = QSpinBox()
        self._filter_max_spin.setObjectName("glassSpinBox")
        self._filter_max_spin.setRange(1, 99)
        self._filter_max_spin.setValue(12)
        self._filter_max_spin.setFixedWidth(80)
        row2.addWidget(self._filter_max_cb)
        row2.addWidget(self._filter_max_spin)
        suffix2 = QLabel("位的密码")
        suffix2.setObjectName("inputLabel")
        row2.addWidget(suffix2)
        row2.addStretch()
        layout.addLayout(row2)

        # 首字符为字母
        self._first_alpha_cb = GlassCheckBox("首字符必须为字母", False)
        layout.addWidget(self._first_alpha_cb)

        # 首字母大写
        self._capitalize_cb = GlassCheckBox("首字母大写", False)
        layout.addWidget(self._capitalize_cb)

        # 过滤纯数字
        self._filter_digits_cb = GlassCheckBox("过滤纯数字", False)
        layout.addWidget(self._filter_digits_cb)

        # 过滤纯字母
        self._filter_alpha_cb = GlassCheckBox("过滤纯字母", False)
        layout.addWidget(self._filter_alpha_cb)

        # 前缀
        row_prefix = QHBoxLayout()
        row_prefix.setSpacing(8)
        self._prefix_cb = GlassCheckBox("每个密码前加", False)
        self._prefix_input = GlassInput("", "")
        self._prefix_input.input.setFixedWidth(80)
        self._prefix_input.input.setPlaceholderText("如: !@#")
        self._prefix_input.setEnabled(False)
        self._prefix_cb.check.toggled.connect(self._prefix_input.setEnabled)
        row_prefix.addWidget(self._prefix_cb)
        row_prefix.addWidget(self._prefix_input)
        row_prefix.addStretch()
        layout.addLayout(row_prefix)

        # 后缀
        row_suffix = QHBoxLayout()
        row_suffix.setSpacing(8)
        self._suffix_cb = GlassCheckBox("每个密码后加", False)
        self._suffix_input = GlassInput("", "")
        self._suffix_input.input.setFixedWidth(80)
        self._suffix_input.input.setPlaceholderText("如: 123")
        self._suffix_input.setEnabled(False)
        self._suffix_cb.check.toggled.connect(self._suffix_input.setEnabled)
        row_suffix.addWidget(self._suffix_cb)
        row_suffix.addWidget(self._suffix_input)
        row_suffix.addStretch()
        layout.addLayout(row_suffix)

        return widget

    def _build_action_row(self) -> QWidget:
        """操作按钮行：生成 / 导出 / 重置（右对齐）"""
        widget = QWidget()
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        widget.setLayout(layout)

        layout.addStretch()

        self._gen_btn = GlassButton("生成字典", GlassButton.STYLE_PRIMARY)
        self._gen_btn.clicked.connect(self._on_generate)
        layout.addWidget(self._gen_btn)

        self._export_btn = GlassButton("导出字典")
        self._export_btn.clicked.connect(self._on_export)
        layout.addWidget(self._export_btn)

        self._clear_output_btn = GlassButton("清空输出")
        self._clear_output_btn.clicked.connect(self._on_clear_output)
        layout.addWidget(self._clear_output_btn)

        self._reset_btn = GlassButton("信息重置")
        self._reset_btn.clicked.connect(self._on_reset)
        layout.addWidget(self._reset_btn)

        return widget

    # ── 交互逻辑 ──────────────────────────────────────────────

    def _on_mode_changed(self) -> None:
        """模式切换：启用项目模式则禁用自定义，反之亦然"""
        is_project = self._project_mode_cb.is_checked()
        self._project_area.setEnabled(is_project)
        self._custom_area.setEnabled(not is_project)

    _PROJECT_MODE_HINTS = {
        "one": "当前：一项目 — 随机取 1 个字段值作为密码",
        "two": "当前：二项目 — 取 2 个字段值进行全排列",
        "three": "当前：三项目 — 取 3 个字段值进行全排列",
    }

    def _on_project_mode_selected(self, mode_key: str) -> None:
        """记录当前选中的项目模式并更新提示"""
        self._current_project_mode = mode_key
        self._project_mode_hint.setText(
            self._PROJECT_MODE_HINTS.get(mode_key, "")
        )

    def _collect_fields(self) -> Dict[str, str]:
        """从输入控件收集所有字段数据"""
        fields: Dict[str, str] = {}
        for var_name, inp in self._inputs.items():
            fields[var_name] = inp.text()
        return fields

    def _on_generate(self) -> None:
        """生成字典"""
        fields = self._collect_fields()

        # 确定模式
        if self._project_mode_cb.is_checked():
            mode = self._current_project_mode
            template = ""
        else:
            mode = "custom"
            template = self._template_input.text().strip()

        # 收集过滤参数
        enable_min = self._filter_min_cb.is_checked()
        enable_max = self._filter_max_cb.is_checked()
        min_len = self._filter_min_spin.value()
        max_len = self._filter_max_spin.value()

        # 校验：最小值不应大于最大值
        if enable_min and enable_max and min_len > max_len:
            self._show_styled_warning(
                "参数错误", "最小长度(%d)不能大于最大长度(%d)" % (min_len, max_len)
            )
            return

        prefix = self._prefix_input.text().strip() if self._prefix_cb.is_checked() else ""
        suffix = self._suffix_input.text().strip() if self._suffix_cb.is_checked() else ""

        passwords, info = DictGeneratorEngine.generate(
            fields=fields,
            mode=mode,
            template=template,
            enable_min_len=enable_min,
            min_len=min_len,
            enable_max_len=enable_max,
            max_len=max_len,
            filter_first_alpha=self._first_alpha_cb.is_checked(),
            capitalize_first=self._capitalize_cb.is_checked(),
            filter_digits_only=self._filter_digits_cb.is_checked(),
            filter_alpha_only=self._filter_alpha_cb.is_checked(),
            prefix=prefix,
            suffix=suffix,
        )

        self._generated_passwords = passwords
        self._status_label.setText(info)

        if passwords:
            # 限制显示：最多显示 5000 条，超出则截断提示
            display_limit = 5000
            if len(passwords) <= display_limit:
                self._output.setText("\n".join(passwords))
            else:
                self._output.setText(
                    "\n".join(passwords[:display_limit])
                    + "\n\n... 共 %d 条，仅显示前 %d 条" % (len(passwords), display_limit)
                )
        else:
            self._output.setText("")
            if "未生成" in info or "请至少" in info or "需要至少" in info:
                self._show_styled_warning("生成失败", info)

    def _on_export(self) -> None:
        """导出字典为 TXT 文件"""
        if not self._generated_passwords:
            self._show_styled_warning("导出结果", "当前没有可导出的密码字典，请先生成")
            return

        filepath, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出社工字典",
            "dict.txt",
            "TXT 文件 (*.txt)",
        )
        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(self._generated_passwords))
        except IOError as error:
            self._show_styled_warning("导出失败", "写入文件失败：%s" % error)
            return

        self._show_styled_message(
            "导出完成",
            "已导出 %d 个密码到 %s" % (len(self._generated_passwords), filepath),
            QMessageBox.Information,
        )

    def _on_clear_output(self) -> None:
        """仅清空生成的字典输出"""
        self._output.setText("")
        self._generated_passwords = []
        self._status_label.setText("")

    def _on_reset(self) -> None:
        """重置所有输入和输出"""
        for inp in self._inputs.values():
            inp.setText("")

        # 恢复默认模式选择
        self._project_mode_cb.check.setChecked(True)

        # 恢复默认项目按钮
        self._project_btns["one"].setChecked(True)
        self._current_project_mode = "one"

        # 清空模板
        self._template_input.setText("")

        # 恢复过滤默认值
        self._filter_min_cb.check.setChecked(False)
        self._filter_min_spin.setValue(6)
        self._filter_max_cb.check.setChecked(False)
        self._filter_max_spin.setValue(12)
        self._first_alpha_cb.check.setChecked(False)
        self._capitalize_cb.check.setChecked(False)
        self._filter_digits_cb.check.setChecked(False)
        self._filter_alpha_cb.check.setChecked(False)
        self._prefix_cb.check.setChecked(False)
        self._prefix_input.setText("")
        self._suffix_cb.check.setChecked(False)
        self._suffix_input.setText("")

        # 清空输出
        self._output.setText("")
        self._generated_passwords = []
        self._status_label.setText("")

    # ── 弹窗工具 ──────────────────────────────────────────────

    def _show_styled_message(self, title: str, message: str, icon) -> None:
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
        box.exec()

    def _show_styled_warning(self, title: str, message: str) -> None:
        """显示毛玻璃警告弹窗"""
        self._show_styled_message(title, message, QMessageBox.Warning)


def create_page() -> ModulePage:
    """创建社工字典生成页面（工厂函数）"""
    return DictGeneratorPage()
