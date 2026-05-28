"""
应用根目录解析工具。

解决开发环境与 PyInstaller 打包环境中路径解析方式的差异。
开发模式下基于 __file__ 推算项目根目录；打包模式下基于 sys.executable 定位。
"""
import os
import sys


def get_app_root() -> str:
    """返回应用根目录的绝对路径。

    开发模式：基于本模块文件的 __file__ 向上推算（core/_app_root.py → core → 根目录）。
    PyInstaller 打包模式：基于 sys.executable 所在目录（即 ICE.exe 所在目录）。
    """
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    # _app_root.py 位于 core/ 目录下，上一级为项目根目录
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
