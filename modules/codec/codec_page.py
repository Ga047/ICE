"""
编码转换模块 — 主页面

左侧：三组手风琴树形菜单（编码转化/加密解密/哈希计算）
右侧：QStackedWidget 动态方法面板 + 输入输出框 + 操作按钮
"""
from typing import Dict, List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QStackedWidget, QScrollArea, QFrame, QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer

from app.content_area import ModulePage
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassTextEdit, GlassCombo
from app.widgets.glass_button import GlassButton

from modules.codec.method_config import METHODS, CHARSET_OPTIONS
from modules.codec.method_panel import MethodPanel, COMBO_POPUP_STYLE

import modules.codec.codec_engine as codec_engine
import modules.codec.crypto_engine as crypto_engine
import modules.codec.hash_engine as hash_engine


# ---- 树形菜单样式 ----

TREE_MENU_STYLE = """
#codecTreeMenu {
    background-color: rgba(248, 250, 252, 0.6);
    border-right: 1px solid rgba(0, 0, 0, 0.06);
}
#treeMenuTitle {
    font-size: 11px;
    font-weight: 600;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 1px;
}
#treeGroupHeader {
    background: transparent;
    border: none;
    border-radius: 6px;
    padding: 8px 12px;
    text-align: left;
    font-size: 13px;
    font-weight: 600;
    color: #1E293B;
}
#treeGroupHeader:hover {
    background-color: rgba(0, 0, 0, 0.04);
}
#treeItem {
    background: transparent;
    border: none;
    border-radius: 6px;
    padding: 7px 12px 7px 24px;
    text-align: left;
    font-size: 13px;
    color: #475569;
}
#treeItem:hover {
    background-color: rgba(59, 130, 246, 0.08);
    color: #1E293B;
}
#treeItem[active="true"] {
    background-color: rgba(59, 130, 246, 0.12);
    color: #3B82F6;
    font-weight: 600;
}
#swapButton {
    background-color: rgba(255, 255, 255, 0.9);
    border: 1px solid rgba(0, 0, 0, 0.08);
    border-radius: 8px;
    font-size: 18px;
    color: #3B82F6;
}
#swapButton:hover {
    background-color: rgba(59, 130, 246, 0.1);
    border-color: rgba(59, 130, 246, 0.3);
}
"""


# ============================================================
#  左侧树形菜单组件
# ============================================================

class TreeGroup(QWidget):
    """单个手风琴分组（被动容器，展开/折叠由 TreeMenu 控制）"""

    def __init__(self, title: str, items: List[Dict], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._title = title
        self._expanded = False

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setLayout(layout)

        # 分组标题按钮（不连接 _toggle，由 TreeMenu 统一管理）
        self._header_btn = QPushButton(f"▸ {title}")
        self._header_btn.setObjectName("treeGroupHeader")
        self._header_btn.setCursor(Qt.PointingHandCursor)
        layout.addWidget(self._header_btn)

        # 子项容器
        self._items_container = QWidget()
        self._items_container.setVisible(False)
        items_layout = QVBoxLayout()
        items_layout.setContentsMargins(0, 0, 0, 0)
        items_layout.setSpacing(0)
        self._items_container.setLayout(items_layout)

        self._item_buttons: Dict[str, QPushButton] = {}
        for item in items:
            btn = QPushButton(f"  {item['name']}")
            btn.setObjectName("treeItem")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("method_id", item["id"])
            items_layout.addWidget(btn)
            self._item_buttons[item["id"]] = btn

        layout.addWidget(self._items_container)

    def set_expanded(self, expanded: bool):
        self._expanded = expanded
        self._items_container.setVisible(expanded)
        arrow = "▾" if expanded else "▸"
        self._header_btn.setText(f"{arrow} {self._title}")

    @property
    def is_expanded(self) -> bool:
        return self._expanded

    @property
    def header_button(self) -> QPushButton:
        return self._header_btn

    @property
    def item_buttons(self) -> Dict[str, QPushButton]:
        return self._item_buttons


class TreeMenu(QWidget):
    """左侧树形菜单（三个手风琴分组）"""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedWidth(220)
        self.setObjectName("codecTreeMenu")
        self.setStyleSheet(TREE_MENU_STYLE)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 8, 0, 8)
        layout.setSpacing(0)
        self.setLayout(layout)

        # 标题
        title_lbl = QLabel("方法列表")
        title_lbl.setObjectName("treeMenuTitle")
        title_lbl.setContentsMargins(14, 8, 14, 8)
        layout.addWidget(title_lbl)

        # 滚动区域
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout()
        scroll_layout.setContentsMargins(4, 0, 4, 0)
        scroll_layout.setSpacing(2)
        scroll_content.setLayout(scroll_layout)

        self._groups: Dict[str, TreeGroup] = {}
        self._all_item_buttons: Dict[str, QPushButton] = {}

        for group_name, method_items in METHODS.items():
            group = TreeGroup(group_name, method_items)
            self._groups[group_name] = group
            scroll_layout.addWidget(group)

            # 收集所有子项按钮
            for btn_id, btn in group.item_buttons.items():
                self._all_item_buttons[btn_id] = btn

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll, 1)

        # 默认展开第一个分组
        first_name = list(METHODS.keys())[0]
        self._groups[first_name].set_expanded(True)

        # 连接手风琴联动（通过 header_button 属性）
        for name, group in self._groups.items():
            group.header_button.clicked.connect(
                lambda _checked=None, n=name: self._on_group_toggled(n)
            )

    def _on_group_toggled(self, group_name: str):
        """手风琴联动：展开当前分组，折叠其他"""
        target = self._groups[group_name]
        was_expanded = target.is_expanded
        for name, group in self._groups.items():
            group.set_expanded(False)
        if not was_expanded:
            target.set_expanded(True)

    def connect_item_clicked(self, handler):
        """为所有子项按钮连接点击事件"""
        for btn_id, btn in self._all_item_buttons.items():
            btn.clicked.connect(lambda _checked=None, bid=btn_id: handler(bid))

    def set_active_item(self, method_id: str):
        """高亮指定方法项"""
        for bid, btn in self._all_item_buttons.items():
            btn.setProperty("active", "true" if bid == method_id else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)


# ============================================================
#  主页面
# ============================================================

class CodecPage(ModulePage):
    """编码转换主页面"""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__("编码转换", "Base64 / AES / RSA / MD5 等编解码、加解密、哈希计算")
        self._current_method_id: str = ""
        self._current_config: Dict = {}

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        # ---- 主水平布局 ----
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ---- 左侧树形菜单 ----
        self._tree_menu = TreeMenu()
        self._tree_menu.setMinimumHeight(500)
        main_layout.addWidget(self._tree_menu)

        # 分隔线
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet("QFrame { color: rgba(0,0,0,0.06); }")
        main_layout.addWidget(sep)

        # ---- 右侧操作区 ----
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(16, 0, 16, 0)
        right_layout.setSpacing(12)
        right_widget.setLayout(right_layout)

        # 方法标题
        self._method_title = QLabel("Base64")
        self._method_title.setObjectName("sectionTitle")
        right_layout.addWidget(self._method_title)

        # 滚动区域包裹方法面板
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setMinimumHeight(500)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        scroll_content = QWidget()
        scroll_layout = QVBoxLayout()
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(0)
        scroll_content.setLayout(scroll_layout)

        # 参数面板卡片
        self._panel_card = GlassCard(padding=16)
        self._panel_stack = QStackedWidget()
        self._panel_card.layout().addWidget(self._panel_stack)
        scroll_layout.addWidget(self._panel_card)

        # 字符集选择器
        charset_card = GlassCard(padding=12)
        charset_row = QHBoxLayout()
        charset_row.setContentsMargins(0, 0, 0, 0)
        charset_row.setSpacing(8)
        charset_label = QLabel("字符集:")
        charset_label.setObjectName("inputLabel")
        charset_row.addWidget(charset_label)
        self._charset_combo = GlassCombo("", CHARSET_OPTIONS)
        self._charset_combo.combo.setStyleSheet(COMBO_POPUP_STYLE)
        self._charset_combo.combo.setFixedWidth(120)
        charset_row.addWidget(self._charset_combo)
        charset_row.addStretch()
        charset_card.layout().addLayout(charset_row)
        scroll_layout.addWidget(charset_card)

        # 输入/输出区
        io_card = GlassCard(padding=12)
        io_layout = QHBoxLayout()
        io_layout.setContentsMargins(0, 0, 0, 0)
        io_layout.setSpacing(10)

        # 输入
        self._input_edit = GlassTextEdit("输入", readonly=False)
        io_layout.addWidget(self._input_edit, 1)

        # 交换按钮
        swap_wrapper = QWidget()
        swap_wrapper.setFixedWidth(40)
        swap_layout = QVBoxLayout()
        swap_layout.setContentsMargins(0, 16, 0, 0)
        swap_layout.setSpacing(0)
        self._swap_btn = QPushButton("⇅")
        self._swap_btn.setObjectName("swapButton")
        self._swap_btn.setCursor(Qt.PointingHandCursor)
        self._swap_btn.setFixedSize(36, 36)
        self._swap_btn.setToolTip("交换输入和输出内容")
        swap_layout.addWidget(self._swap_btn)
        swap_layout.addStretch()
        swap_wrapper.setLayout(swap_layout)
        io_layout.addWidget(swap_wrapper)

        # 输出
        self._output_edit = GlassTextEdit("输出", readonly=False)
        io_layout.addWidget(self._output_edit, 1)

        io_card.layout().addLayout(io_layout)
        scroll_layout.addWidget(io_card)

        # 操作按钮
        self._action_card = GlassCard(padding=12)
        self._button_row = QHBoxLayout()
        self._button_row.setContentsMargins(0, 0, 0, 0)
        self._button_row.setSpacing(8)
        self._action_card.layout().addLayout(self._button_row)
        scroll_layout.addWidget(self._action_card)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        right_layout.addWidget(scroll, 1)

        main_layout.addWidget(right_widget, 1)

        # 将主布局添加到 content_layout（stretch=1 占满可用高度）
        self.content_layout.addLayout(main_layout, 1)

        # ---- 构建所有 MethodPanel ----
        self._panels: Dict[str, MethodPanel] = {}
        for group_name, method_items in METHODS.items():
            for item in method_items:
                panel = MethodPanel(item)
                self._panels[item["id"]] = panel
                self._panel_stack.addWidget(panel)

        # 默认选中第一个方法
        first_method = list(METHODS.values())[0][0]
        self._switch_method(first_method["id"])

    def _switch_method(self, method_id: str):
        """切换到指定方法"""
        self._current_method_id = method_id
        config = self._find_method_config(method_id)
        self._current_config = config

        # 更新标题
        self._method_title.setText(config.get("name", method_id))

        # 更新输入输出提示
        hints = config.get("hints", {})
        self._input_edit.edit.setPlaceholderText(hints.get("input", ""))
        self._output_edit.edit.setPlaceholderText(hints.get("output", ""))

        # 切换面板
        panel = self._panels.get(method_id)
        if panel:
            self._panel_stack.setCurrentWidget(panel)

        # 更新按钮行
        self._rebuild_buttons()

        # 高亮树形菜单项
        self._tree_menu.set_active_item(method_id)

    def _find_method_config(self, method_id: str) -> Dict:
        """查找方法配置"""
        for group_name, items in METHODS.items():
            for item in items:
                if item.get("id") == method_id:
                    return item
        return {}

    def _rebuild_buttons(self):
        """根据当前方法重建操作按钮"""
        # 清空旧按钮
        while self._button_row.count():
            item = self._button_row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._button_row.addStretch()

        button_type = self._current_config.get("button_type", "encode_decode")
        has_keygen = self._current_config.get("has_keygen", False)

        if button_type == "encode_decode":
            btn_encode = GlassButton("编码", GlassButton.STYLE_PRIMARY)
            btn_encode.clicked.connect(self._on_encode)
            self._button_row.addWidget(btn_encode)

            btn_decode = GlassButton("解码", GlassButton.STYLE_PRIMARY)
            btn_decode.clicked.connect(self._on_decode)
            self._button_row.addWidget(btn_decode)

        elif button_type == "encrypt_decrypt":
            btn_encrypt = GlassButton("加密", GlassButton.STYLE_PRIMARY)
            btn_encrypt.clicked.connect(self._on_encrypt)
            self._button_row.addWidget(btn_encrypt)

            btn_decrypt = GlassButton("解密", GlassButton.STYLE_PRIMARY)
            btn_decrypt.clicked.connect(self._on_decrypt)
            self._button_row.addWidget(btn_decrypt)

            if has_keygen:
                btn_keygen = GlassButton("生成密钥", GlassButton.STYLE_PRIMARY)
                btn_keygen.clicked.connect(self._on_generate_keys)
                self._button_row.addWidget(btn_keygen)

        elif button_type == "hash":
            btn_hash = GlassButton("计算哈希", GlassButton.STYLE_PRIMARY)
            btn_hash.clicked.connect(self._on_hash)
            self._button_row.addWidget(btn_hash)

        elif button_type == "convert":
            btn_convert = GlassButton("转换", GlassButton.STYLE_PRIMARY)
            btn_convert.clicked.connect(self._on_convert)
            self._button_row.addWidget(btn_convert)

        # 交换按钮（统一放在操作按钮行末尾）
        btn_swap = GlassButton("⇅ 交换内容", GlassButton.STYLE_PRIMARY)
        btn_swap.clicked.connect(self._on_swap)
        self._button_row.addWidget(btn_swap)

    def _connect_signals(self):
        # 树形菜单项点击
        self._tree_menu.connect_item_clicked(self._switch_method)

        # 交换按钮
        self._swap_btn.clicked.connect(self._on_swap)

    # ---- 按钮事件 ----

    def _on_encode(self):
        input_text = self._input_edit.edit.toPlainText().strip()
        if not input_text:
            self._show_toast("请输入编码内容")
            return
        charset = self._charset_combo.current_text()
        config = self._panel_stack.currentWidget().get_config() if self._panel_stack.currentWidget() else {}
        method_id = self._current_method_id

        try:
            result = self._call_encode(method_id, input_text, charset, config)
            self._output_edit.edit.setPlainText(result)
        except Exception as e:
            self._show_toast(f"编码失败: {e}")

    def _on_decode(self):
        input_text = self._input_edit.edit.toPlainText().strip()
        if not input_text:
            self._show_toast("请输入解码内容")
            return
        charset = self._charset_combo.current_text()
        config = self._panel_stack.currentWidget().get_config() if self._panel_stack.currentWidget() else {}
        method_id = self._current_method_id

        try:
            result = self._call_decode(method_id, input_text, charset, config)
            self._output_edit.edit.setPlainText(result)
        except Exception as e:
            self._show_toast(f"解码失败: {e}")

    def _on_encrypt(self):
        input_text = self._input_edit.edit.toPlainText().strip()
        if not input_text:
            self._show_toast("请输入加密内容")
            return
        charset = self._charset_combo.current_text()
        config = self._panel_stack.currentWidget().get_config() if self._panel_stack.currentWidget() else {}
        method_id = self._current_method_id

        try:
            result = self._call_encrypt(method_id, input_text, charset, config)
            self._output_edit.edit.setPlainText(result)
        except Exception as e:
            self._show_toast(f"加密失败: {e}")

    def _on_decrypt(self):
        input_text = self._input_edit.edit.toPlainText().strip()
        if not input_text:
            self._show_toast("请输入解密内容")
            return
        charset = self._charset_combo.current_text()
        config = self._panel_stack.currentWidget().get_config() if self._panel_stack.currentWidget() else {}
        method_id = self._current_method_id

        try:
            result = self._call_decrypt(method_id, input_text, charset, config)
            self._output_edit.edit.setPlainText(result)
        except Exception as e:
            self._show_toast(f"解密失败: {e}")

    def _on_hash(self):
        input_text = self._input_edit.edit.toPlainText().strip()
        if not input_text:
            self._show_toast("请输入内容")
            return
        charset = self._charset_combo.current_text()
        config = self._panel_stack.currentWidget().get_config() if self._panel_stack.currentWidget() else {}
        method_id = self._current_method_id

        try:
            result = self._call_hash(method_id, input_text, charset, config)
            self._output_edit.edit.setPlainText(result)
        except Exception as e:
            self._show_toast(f"哈希计算失败: {e}")

    def _on_convert(self):
        input_text = self._input_edit.edit.toPlainText().strip()
        if not input_text:
            self._show_toast("请输入内容")
            return
        config = self._panel_stack.currentWidget().get_config() if self._panel_stack.currentWidget() else {}

        try:
            result = codec_engine.radix_convert(
                input_text,
                config.get("source_base", 10),
                config.get("target_base", 16),
            )
            self._output_edit.edit.setPlainText(result)
        except Exception as e:
            self._show_toast(f"转换失败: {e}")

    def _on_swap(self):
        """交换输入/输出内容"""
        input_text = self._input_edit.edit.toPlainText()
        output_text = self._output_edit.edit.toPlainText()
        self._input_edit.edit.setPlainText(output_text)
        self._output_edit.edit.setPlainText(input_text)

    def _on_generate_keys(self):
        """生成密钥对（RSA/SM2）"""
        method_id = self._current_method_id
        panel = self._panels.get(method_id)
        if not panel:
            return
        try:
            if method_id == "rsa":
                key_size_str = panel.get_config().get("key_size", "2048")
                key_size = int(key_size_str)
                priv, pub = crypto_engine.rsa_generate_keypair(key_size)
                panel.set_config({"public_key": pub, "private_key": priv})
            elif method_id == "sm2":
                priv, pub = crypto_engine.sm2_generate_keypair_func()
                panel.set_config({"public_key": pub, "private_key": priv})
            self._show_toast("密钥对已生成")
        except Exception as e:
            self._show_toast(f"密钥生成失败: {e}")

    # ---- 引擎调用分发 ----

    def _call_encode(self, method_id: str, data: str, charset: str, config: Dict) -> str:
        mapper = {
            "base64": codec_engine.base64_encode,
            "base16": codec_engine.base16_encode,
            "base32": codec_engine.base32_encode,
            "base58": codec_engine.base58_encode,
            "base62": codec_engine.base62_encode,
            "base85": lambda d, c, **kw: codec_engine.base85_encode(d, c, kw.get("variant", "ASCII85")),
            "base91": codec_engine.base91_encode,
            "base92": codec_engine.base92_encode,
            "ascii_codec": lambda d, c, **kw: codec_engine.ascii_encode(d, c, kw.get("separator", "空格")),
            "url": codec_engine.url_encode,
            "brainfuck": codec_engine.brainfuck_encode,
            "xor_codec": lambda d, c, **kw: codec_engine.xor_encode(d, c, kw.get("key", "")),
            "unicode": lambda d, c, **kw: codec_engine.unicode_encode(d, c, kw.get("format", "\\uXXXX")),
            "html": codec_engine.html_encode,
            "morse": lambda d, c, **kw: codec_engine.morse_encode(d, c, kw.get("delimiter", "空格")),
        }
        func = mapper.get(method_id)
        if not func:
            raise ValueError(f"未知编码方法: {method_id}")
        return func(data, charset, **config)

    def _call_decode(self, method_id: str, data: str, charset: str, config: Dict) -> str:
        mapper = {
            "base64": codec_engine.base64_decode,
            "base16": codec_engine.base16_decode,
            "base32": codec_engine.base32_decode,
            "base58": codec_engine.base58_decode,
            "base62": codec_engine.base62_decode,
            "base85": lambda d, c, **kw: codec_engine.base85_decode(d, c, kw.get("variant", "ASCII85")),
            "base91": codec_engine.base91_decode,
            "base92": codec_engine.base92_decode,
            "ascii_codec": lambda d, c, **kw: codec_engine.ascii_decode(d, c, kw.get("separator", "空格")),
            "url": codec_engine.url_decode,
            "brainfuck": codec_engine.brainfuck_decode,
            "xor_codec": lambda d, c, **kw: codec_engine.xor_decode(d, c, kw.get("key", "")),
            "unicode": lambda d, c, **kw: codec_engine.unicode_decode(d, c, kw.get("format", "\\uXXXX")),
            "html": codec_engine.html_decode,
            "morse": lambda d, c, **kw: codec_engine.morse_decode(d, c, kw.get("delimiter", "空格")),
        }
        func = mapper.get(method_id)
        if not func:
            raise ValueError(f"未知解码方法: {method_id}")
        return func(data, charset, **config)

    def _call_encrypt(self, method_id: str, data: str, charset: str, config: Dict) -> str:
        if method_id == "aes":
            return crypto_engine.aes_encrypt(data, **config, charset=charset)
        elif method_id == "des":
            return crypto_engine.des_encrypt(data, **config, charset=charset)
        elif method_id == "triple_des":
            return crypto_engine.triple_des_encrypt(data, **config, charset=charset)
        elif method_id == "sm4":
            return crypto_engine.sm4_encrypt_func(data, **config, charset=charset)
        elif method_id == "rsa":
            return crypto_engine.rsa_encrypt(data, **config, charset=charset)
        elif method_id == "sm2":
            return crypto_engine.sm2_encrypt_func(data, **config, charset=charset)
        elif method_id == "xor_crypto":
            return crypto_engine.xor_crypto(data, **config, charset=charset)
        elif method_id == "rc4":
            return crypto_engine.rc4_encrypt(data, **config, charset=charset)
        elif method_id == "rabbit":
            return crypto_engine.rabbit_encrypt(data, **config, charset=charset)
        elif method_id == "hmac":
            return crypto_engine.hmac_encrypt(data, **config, charset=charset)
        raise ValueError(f"未知加密方法: {method_id}")

    def _call_decrypt(self, method_id: str, data: str, charset: str, config: Dict) -> str:
        if method_id == "aes":
            return crypto_engine.aes_decrypt(data, **config, charset=charset)
        elif method_id == "des":
            return crypto_engine.des_decrypt(data, **config, charset=charset)
        elif method_id == "triple_des":
            return crypto_engine.triple_des_decrypt(data, **config, charset=charset)
        elif method_id == "sm4":
            return crypto_engine.sm4_decrypt_func(data, **config, charset=charset)
        elif method_id == "rsa":
            return crypto_engine.rsa_decrypt(data, **config, charset=charset)
        elif method_id == "sm2":
            return crypto_engine.sm2_decrypt_func(data, **config, charset=charset)
        elif method_id == "xor_crypto":
            return crypto_engine.xor_crypto_decrypt(data, **config, charset=charset)
        elif method_id == "rc4":
            return crypto_engine.rc4_decrypt(data, **config, charset=charset)
        elif method_id == "rabbit":
            return crypto_engine.rabbit_decrypt(data, **config, charset=charset)
        elif method_id == "hmac":
            return crypto_engine.hmac_decrypt(data, **config, charset=charset)
        raise ValueError(f"未知解密方法: {method_id}")

    def _call_hash(self, method_id: str, data: str, charset: str, config: Dict) -> str:
        if method_id == "md5":
            return hash_engine.md5_hash(data, charset)
        elif method_id == "sm3":
            return hash_engine.sm3_hash_func(data, charset)
        elif method_id == "sha1":
            return hash_engine.sha1_hash(data, charset)
        elif method_id == "sha2":
            return hash_engine.sha2_hash(data, charset, config.get("variant", "SHA-256"))
        elif method_id == "sha3":
            return hash_engine.sha3_hash(data, charset, config.get("variant", "SHA3-256"))
        elif method_id == "ntlm":
            return hash_engine.ntlm_hash(data, charset)
        raise ValueError(f"未知哈希方法: {method_id}")

    # ---- Toast 提示 ----

    def _show_toast(self, message: str, duration: int = 1500):
        """毛玻璃风格飘窗提示（页面顶部居中，与 JwtCrack 一致）"""
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
            "  padding: 14px 24px;"
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


# ============================================================
#  模块入口
# ============================================================

def create_page() -> ModulePage:
    return CodecPage()
