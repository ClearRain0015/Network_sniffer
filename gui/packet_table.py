#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gui/packet_table.py — 数据包列表组件
====================================
以表格形式展示已捕获数据包概览：
  No │ Time │ Source │ Destination │ Protocol │ Length │ Info

支持 PyQt5 QTreeWidget 和 Tkinter Treeview 两种后端。
"""

from typing import Optional, Callable

from protocols.base import ParsedPacket


class PacketTable:
    """
    数据包列表

    用法:
        table = PacketTable(backend="pyqt5")
        table.add_packet(parsed_packet)
        table.on_select = lambda pkt: show_detail(pkt)
    """

    def __init__(self, backend: str = "pyqt5"):
        self.backend = backend
        self.on_select: Optional[Callable[[ParsedPacket], None]] = None
        self._packets = []
        self.widget = None

        if backend == "pyqt5":
            self._init_pyqt5()
        else:
            self._init_tkinter()

    # ── PyQt5 实现 ─────────────────────────

    def _init_pyqt5(self):
        from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView
        from PyQt5.QtCore import Qt

        tree = QTreeWidget()
        tree.setColumnCount(7)
        tree.setHeaderLabels([
            "No", "Time", "Source", "Destination",
            "Protocol", "Length", "Info",
        ])
        tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True)
        tree.setSelectionBehavior(tree.SelectRows)
        tree.setSelectionMode(tree.SingleSelection)

        # 列宽
        header = tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)

        tree.itemSelectionChanged.connect(self._on_selection_changed)
        tree.itemClicked.connect(lambda *_: self._on_selection_changed())

        self._tree = tree
        self.widget = tree

    def _on_selection_changed(self):
        """PyQt5 选中行事件"""
        from PyQt5.QtCore import Qt

        items = self._tree.selectedItems()
        if not items:
            return
        item = items[0]
        packet = item.data(0, Qt.UserRole)
        if packet is not None and self.on_select:
            self.on_select(packet)
            return

        idx = self._tree.indexOfTopLevelItem(item)
        if 0 <= idx < len(self._packets) and self.on_select:
            self.on_select(self._packets[idx])

    # ── Tkinter 实现 ──────────────────────

    def _init_tkinter(self):
        import tkinter as tk
        from tkinter import ttk

        frame = ttk.Frame()
        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
        col_widths = [50, 120, 150, 150, 80, 70, 400]
        for col, w in zip(columns, col_widths):
            tree.column(col, width=w, anchor=tk.W)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        tree.bind("<<TreeviewSelect>>", self._on_tk_select)
        self._tk_tree = tree
        self._tk_frame = frame
        self.widget = frame

    def _on_tk_select(self, event):
        selection = self._tk_tree.selection()
        if selection and self.on_select:
            idx = self._tk_tree.index(selection[0])
            if idx < len(self._packets):
                self.on_select(self._packets[idx])

    # ── 公共方法 ──────────────────────────

    def add_packet(self, packet: ParsedPacket):
        """添加一行数据包"""
        self._packets.append(packet)

        row_data = (
            str(packet.no),
            packet.timestamp_str,
            packet.src_str,
            packet.dst_str,
            packet.proto_name,
            packet.length_str,
            packet.info or packet.summary,
        )

        if self.backend == "pyqt5":
            from PyQt5.QtCore import Qt
            from PyQt5.QtWidgets import QTreeWidgetItem
            had_selection = bool(self._tree.selectedItems())
            item = QTreeWidgetItem(list(row_data))
            item.setData(0, Qt.UserRole, packet)
            self._tree.insertTopLevelItem(self._tree.topLevelItemCount(), item)
            # 自动滚动到底部
            self._tree.scrollToBottom()
            if not had_selection:
                self._tree.setCurrentItem(item)
                if self.on_select:
                    self.on_select(packet)
        else:
            self._tk_tree.insert("", "end", values=row_data)
            # Tkinter 自动滚动
            children = self._tk_tree.get_children()
            if children:
                self._tk_tree.see(children[-1])

    def clear(self):
        """清空列表"""
        self._packets.clear()
        if self.backend == "pyqt5":
            self._tree.clear()
        else:
            for item in self._tk_tree.get_children():
                self._tk_tree.delete(item)
