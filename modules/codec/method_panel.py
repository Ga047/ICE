"""
动态方法面板 — 根据 method_config 配置动态生成参数控件

MethodPanel 根据传入的 params 列表创建控件，处理 on_change 联动，
暴露 get_config() 获取当前所有参数值。
"""
from typing import Any, Dict, List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
)
from PySide6.QtCore import Qt

from app.widgets.glass_input import GlassInput, GlassCombo, GlassSpinBox


# 下拉框弹出样式（与 dir_scanner 一致）
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


class MethodPanel(QWidget):
    """根据方法配置动态生成参数控件的面板"""

    def __init__(self, method_config: Dict[str, Any], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._config = method_config
        self._widgets: Dict[str, QWidget] = {}  # name -> widget
        self._labels: Dict[str, QLabel] = {}     # name -> label (for on_change label updates)
        self._param_configs: Dict[str, Dict] = {}  # name -> param config

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        self.setLayout(layout)

        params = method_config.get("params", [])
        if not params:
            # 无参数时显示一个占位标签
            hint_label = QLabel("此方法无需额外参数")
            hint_label.setObjectName("inputLabel")
            layout.addWidget(hint_label)
        else:
            self._build_params(layout, params)

        layout.addStretch()

    def _build_params(self, parent_layout: QVBoxLayout, params: List[Dict]):
        """根据参数定义列表构建控件"""
        # 将参数排列为 2 列
        rows: List[List[tuple]] = []
        current_row: List[tuple] = []
        for param in params:
            current_row.append((param, len(current_row)))
            if len(current_row) == 2:
                rows.append(current_row)
                current_row = []
        if current_row:
            rows.append(current_row)

        for row in rows:
            row_layout = QHBoxLayout()
            row_layout.setSpacing(12)
            for param, _col_idx in row:
                widget_wrapper = self._create_param_widget(param)
                row_layout.addWidget(widget_wrapper, 1)
            parent_layout.addLayout(row_layout)

    def _create_param_widget(self, param: Dict) -> QWidget:
        """创建单个参数控件"""
        name = param["name"]
        label_text = param.get("label", name)
        param_type = param.get("type", "input")

        wrapper = QWidget()
        wrapper_layout = QVBoxLayout()
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(6)
        wrapper.setLayout(wrapper_layout)

        lbl = QLabel(label_text)
        lbl.setObjectName("inputLabel")
        wrapper_layout.addWidget(lbl)
        self._labels[name] = lbl
        self._param_configs[name] = param

        if param_type == "input":
            widget = GlassInput("", param.get("placeholder", ""))
            widget.input.setText(str(param.get("default", "")))
            self._widgets[name] = widget
            wrapper_layout.addWidget(widget)

        elif param_type == "combo":
            options = param.get("options", [])
            default = param.get("default", options[0] if options else "")
            widget = GlassCombo("", options)
            widget.combo.setStyleSheet(COMBO_POPUP_STYLE)
            widget.combo.setMaxVisibleItems(16)
            widget.combo.view().setMinimumWidth(160)

            for i, opt in enumerate(options):
                if opt == default:
                    widget.combo.setCurrentIndex(i)
                    break

            self._widgets[name] = widget
            wrapper_layout.addWidget(widget)

            # 处理 on_change 联动
            on_change = param.get("on_change", {})
            if on_change:
                widget.combo.currentTextChanged.connect(
                    lambda text, n=name, oc=on_change: self._apply_on_change(n, text, oc)
                )
                # 初始化时立即应用一次
                self._apply_on_change(name, default, on_change)

        elif param_type == "spin":
            min_val = param.get("min", 0)
            max_val = param.get("max", 9999)
            default = param.get("default", min_val)
            widget = GlassSpinBox("", min_val, max_val)
            widget.spin.setValue(default)
            self._widgets[name] = widget
            wrapper_layout.addWidget(widget)

        return wrapper

    def _apply_on_change(self, trigger_name: str, selected: str, rules: Dict):
        """处理 on_change 联动规则"""
        rule = rules.get(selected, {})
        if not rule:
            # 恢复所有被隐藏的控件
            for param_name, _param_cfg in self._param_configs.items():
                if param_name != trigger_name:
                    w = self._widgets.get(param_name)
                    if w:
                        w.setVisible(True)
                        # 恢复默认 label
                        lbl = self._labels.get(param_name)
                        orig_label = self._param_configs.get(param_name, {}).get("label", param_name)
                        if lbl and orig_label:
                            lbl.setText(orig_label)
                        # 恢复默认 placeholder
                        orig_ph = self._param_configs.get(param_name, {}).get("placeholder", "")
                        if hasattr(w, 'input') and orig_ph:
                            w.input.setPlaceholderText(orig_ph)
            return

        # 应用隐藏规则
        hidden = rule.get("hide", [])
        for param_name, _param_cfg in self._param_configs.items():
            if param_name != trigger_name:
                w = self._widgets.get(param_name)
                if w:
                    w.setVisible(param_name not in hidden)

        # 应用 label 更改
        label_changes = rule.get("label", {})
        for param_name, new_label in label_changes.items():
            lbl = self._labels.get(param_name)
            if lbl:
                lbl.setText(new_label)

        # 应用 placeholder 更改
        placeholder_changes = rule.get("placeholder", {})
        for param_name, new_ph in placeholder_changes.items():
            w = self._widgets.get(param_name)
            if w and hasattr(w, 'input'):
                w.input.setPlaceholderText(new_ph)

    def get_config(self) -> Dict[str, Any]:
        """获取所有参数的当前值"""
        result: Dict[str, Any] = {}
        for name, widget in self._widgets.items():
            if isinstance(widget, GlassInput):
                result[name] = widget.text()
            elif isinstance(widget, GlassCombo):
                result[name] = widget.current_text()
            elif isinstance(widget, GlassSpinBox):
                result[name] = widget.spin.value()
        return result

    def set_config(self, values: Dict[str, Any]):
        """设置参数值（如生成密钥后回填）"""
        for name, value in values.items():
            widget = self._widgets.get(name)
            if isinstance(widget, GlassInput):
                widget.input.setText(str(value))
            elif isinstance(widget, GlassCombo):
                for i in range(widget.combo.count()):
                    if widget.combo.itemText(i) == value:
                        widget.combo.setCurrentIndex(i)
                        break

    def set_widget_visible(self, name: str, visible: bool):
        """设置某个参数控件的可见性"""
        widget = self._widgets.get(name)
        if widget:
            widget.setVisible(visible)
