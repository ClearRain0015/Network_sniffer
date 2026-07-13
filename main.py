#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sniffer - 网络数据包嗅探器
==========================
程序入口：启动 GUI 主窗口
推荐运行方式：python main.py（需要管理员/root 权限抓包）
"""

import sys
import os

# 将项目根目录加入 Python 搜索路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import MainWindow


def main():
    """程序入口"""
    # 优先使用 PyQt5，不可用时回退到 Tkinter
    try:
        from PyQt5.QtWidgets import QApplication
        app = QApplication(sys.argv)
        app.setApplicationName("Sniffer")
        window = MainWindow(backend="pyqt5")
        window.show()
        sys.exit(app.exec_())
    except ImportError:
        print("[!] PyQt5 未安装，回退到 Tkinter 模式")
        print("[*] 安装 PyQt5 以获得更专业的界面：pip install PyQt5")
        window = MainWindow(backend="tkinter")
        window.run()


if __name__ == "__main__":
    main()
