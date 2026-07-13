"""
gui/ — 图形用户界面模块
=======================
模仿 Wireshark 布局：
  ┌─────────────────────────────────────────┐
  │  开始抓包  停止  保存  清空  过滤框      │
  ├─────────────────────────────────────────┤
  │  No │ Time │ Source │ Destination │ ... │  ← 数据包列表
  ├─────────────────────────────────────────┤
  │  Ethernet / IPv4 / TCP 字段树           │  ← 数据包详情
  ├─────────────────────────────────────────┤
  │  0000  12 34 56 ...                     │  ← 十六进制显示
  └─────────────────────────────────────────┘
"""

from .main_window import MainWindow
from .packet_table import PacketTable
from .packet_detail import PacketDetailPanel

__all__ = ["MainWindow", "PacketTable", "PacketDetailPanel"]
