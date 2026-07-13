#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gui/packet_detail.py — 数据包详情面板
=====================================
显示选中数据包的两部分信息：
  上半部分：协议字段树（Ethernet → IPv4 → TCP/UDP → HTTP…）
  下半部分：十六进制 dump（模仿 Wireshark）

01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f  0123456789abcdef
"""

from typing import Optional

from protocols.base import ParsedPacket, ProtocolLayer


class PacketDetailPanel:
    """
    数据包详情面板

    用法:
        panel = PacketDetailPanel(backend="pyqt5")
        panel.show_packet(parsed_packet)
    """

    def __init__(self, backend: str = "pyqt5", parent=None):
        self.backend = backend
        self.widget = None

        if backend == "pyqt5":
            self._init_pyqt5()
        else:
            self._init_tkinter(parent)

    # ── PyQt5 实现 ─────────────────────────

    def _init_pyqt5(self):
        from PyQt5.QtWidgets import (
            QWidget, QVBoxLayout, QSplitter,
            QTreeWidget, QTreeWidgetItem, QTextEdit,
        )
        from PyQt5.QtCore import Qt
        from PyQt5.QtGui import QFont

        widget = QSplitter(Qt.Vertical)

        # 上半：协议字段树
        self._proto_tree = QTreeWidget()
        self._proto_tree.setHeaderLabels(["字段", "值"])
        self._proto_tree.setRootIsDecorated(True)
        self._proto_tree.header().setStretchLastSection(True)
        widget.addWidget(self._proto_tree)

        # 下半：十六进制面板
        self._hex_view = QTextEdit()
        self._hex_view.setReadOnly(True)
        self._hex_view.setFont(QFont("Consolas, Courier New", 10))
        self._hex_view.setStyleSheet(
            "QTextEdit { background-color: #1e1e1e; color: #d4d4d4; }"
        )
        widget.addWidget(self._hex_view)

        widget.setStretchFactor(0, 2)
        widget.setStretchFactor(1, 1)
        self.widget = widget

    # ── Tkinter 实现 ──────────────────────

    def _init_tkinter(self, parent):
        import tkinter as tk
        from tkinter import ttk

        frame = ttk.Frame(parent)
        self._tk_parent = parent

        # 上半：协议树
        tree_frame = ttk.LabelFrame(frame, text="协议详情")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)

        self._tk_tree = ttk.Treeview(tree_frame, show="tree headings",
                                      columns=("value",))
        self._tk_tree.heading("#0", text="字段")
        self._tk_tree.heading("value", text="值")
        self._tk_tree.column("#0", width=250)
        self._tk_tree.column("value", width=400)
        self._tk_tree.pack(fill=tk.BOTH, expand=True)

        # 下半：十六进制
        hex_frame = ttk.LabelFrame(frame, text="十六进制")
        hex_frame.pack(fill=tk.BOTH, expand=False, padx=4, pady=2)

        self._tk_hex = tk.Text(hex_frame, height=10, font=("Consolas", 10),
                               bg="#1e1e1e", fg="#d4d4d4")
        self._tk_hex.pack(fill=tk.BOTH, expand=True)

        self.widget = frame

    # ── 公共方法 ──────────────────────────

    def show_packet(self, packet: ParsedPacket):
        """显示数据包完整信息"""
        self._show_protocol_tree(packet)
        self._show_hex_dump(packet)

    def clear(self):
        """清空面板"""
        if self.backend == "pyqt5":
            self._proto_tree.clear()
            self._hex_view.clear()
        else:
            for item in self._tk_tree.get_children():
                self._tk_tree.delete(item)
            self._tk_hex.delete("1.0", "end")

    # ── 协议树 ────────────────────────────

    def _show_protocol_tree(self, packet: ParsedPacket):
        """构建协议字段树"""
        if self.backend == "pyqt5":
            self._proto_tree.clear()
            # 添加每个协议层
            for layer in packet.layers:
                layer_item = QTreeWidgetItem(self._proto_tree)
                layer_item.setText(0, f"▼ {layer.name}")
                layer_item.setExpanded(True)
                for field_name, field_value in layer.fields.items():
                    child = QTreeWidgetItem(layer_item)
                    child.setText(0, field_name)
                    child.setText(1, str(field_value))
            self._proto_tree.expandAll()
        else:
            # Tkinter
            for item in self._tk_tree.get_children():
                self._tk_tree.delete(item)
            for layer in packet.layers:
                layer_node = self._tk_tree.insert(
                    "", "end", text=f"▼ {layer.name}", values=("",),
                    open=True,
                )
                for field_name, field_value in layer.fields.items():
                    self._tk_tree.insert(
                        layer_node, "end",
                        text=field_name,
                        values=(str(field_value),),
                    )

    # ── 十六进制 dump ─────────────────────

    def _show_hex_dump(self, packet: ParsedPacket):
        """
        生成十六进制 dump（模仿 Wireshark 格式）

        示例输出:
          0000  00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff   .."3DUfw........
          0010  00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff   .."3DUfw........
        """
        data = packet.raw_data
        lines = []

        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = ""
            ascii_part = ""

            for i in range(16):
                if i < len(chunk):
                    b = chunk[i]
                    hex_part += f"{b:02x} "
                    # 中间加一个额外空格区分前后 8 字节
                    if i == 7:
                        hex_part += " "
                    # 可打印字符
                    if 32 <= b < 127:
                        ascii_part += chr(b)
                    else:
                        ascii_part += "."
                else:
                    hex_part += "   "
                    if i == 7:
                        hex_part += " "

            # 补齐不足16字节的情况
            hex_part = hex_part.ljust(50)
            lines.append(f"{offset:04x}  {hex_part} {ascii_part}")

        text = "\n".join(lines)

        if self.backend == "pyqt5":
            self._hex_view.setPlainText(text)
        else:
            self._tk_hex.delete("1.0", "end")
            self._tk_hex.insert("1.0", text)
