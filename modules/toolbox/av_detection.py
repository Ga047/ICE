"""杀软识别模块 — 通过 tasklist /svc 输出识别目标主机安装的安全软件"""
import json
import os
import re
from typing import Dict, List

from core._app_root import get_app_root

from app.content_area import ModulePage
from app.widgets.glass_card import GlassCard
from app.widgets.glass_input import GlassTextEdit
from app.widgets.glass_button import GlassButton

# 加载指纹库
_FP_PATH = os.path.join(
    get_app_root(), "resources", "dir", "av", "av.json"
)

def _load_signatures() -> Dict[str, str]:
    """从 JSON 文件加载杀软进程指纹，返回 {进程名小写: 杀软名称}。"""
    sig_map: Dict[str, str] = {}
    try:
        with open(_FP_PATH, "r", encoding="utf-8") as f:
            entries = json.load(f)
        for entry in entries:
            exe = entry.get("av_exe", "").strip().lower()
            name = entry.get("av_name", "").strip()
            if exe and name:
                sig_map[exe] = name
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return sig_map

AV_SIGNATURE_MAP = _load_signatures()


def _parse_processes(text: str) -> List[str]:
    """从 tasklist /svc 或 tasklist /FO CSV 输出中提取进程名列表。"""
    processes: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # CSV 格式："MsMpEng.exe","1234","N/A"
        if line.startswith('"'):
            parts = line.split(",")
            if parts:
                name = parts[0].strip('"').strip()
                if name.lower().endswith(".exe"):
                    processes.append(name)
        else:
            # 标准表格格式：取第一列
            match = re.match(r"^(\S+\.exe)", line, re.IGNORECASE)
            if match:
                processes.append(match.group(1))
    return processes


def create_page() -> ModulePage:
    page = ModulePage("杀软识别", "通过进程/服务特征识别目标主机安装的安全软件")

    card = GlassCard()

    input_area = GlassTextEdit("进程列表", readonly=False)
    input_area.edit.setPlaceholderText(
        "粘贴 tasklist /SVC 输出\n"
        "或 Windows: tasklist /FO CSV\n"
        "或 Linux: ps aux"
    )
    card.layout().addWidget(input_area)

    output = GlassTextEdit("识别结果")

    def _detect() -> None:
        """执行杀软识别。"""
        raw_text = input_area.text()
        if not raw_text.strip():
            output.setText("请先粘贴 tasklist /svc 的输出内容")
            return

        processes = _parse_processes(raw_text)
        if not processes:
            output.setText("未检测到任何 .exe 进程，请确认输入为 tasklist /svc 输出")
            return

        results: List[str] = []
        seen: set = set()
        for proc in processes:
            av_name = AV_SIGNATURE_MAP.get(proc.lower())
            if av_name:
                results.append(proc + " → " + av_name)
                seen.add(proc.lower())

        if results:
            output.setText(
                "检测到 {} 款杀软，共 {} 条匹配进程:\n\n{}".format(
                    len(set(r.split(" → ")[1] for r in results)),
                    len(results),
                    "\n".join(results),
                )
            )
        else:
            output.setText("未识别到已知杀软进程（共解析 {} 个进程）".format(len(processes)))

    detect_btn = GlassButton("开始识别")
    detect_btn.clicked.connect(_detect)
    card.add_button_row(detect_btn)

    page.content_layout.addWidget(card)
    page.content_layout.addWidget(output)

    return page
