#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gui/packet_table.py — 数据包列表组件
====================================
以表格形式展示已捕获数据包概览：
  No │ Time │ Source │ Destination │ Protocol │ Length │ Info

PyQt5：使用 QTableView + QAbstractTableModel（高性能，只渲染可见行）
Tkinter：使用 Treeview（回退方案）
"""

from typing import Optional, Callable, List

from parser.base import ParsedPacket

HEADERS = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
COL_WIDTHS = [50, 130, 160, 160, 80, 70, 400]
MAX_PACKETS = 10000


# ═══════════════════════════════════════════════════════════
#  PyQt5：QTableView + Model
# ═══════════════════════════════════════════════════════════

_HAS_PYQT5 = False
try:
    from PyQt5.QtWidgets import (
        QTableView, QHeaderView, QAbstractItemView, QTreeView, QFrame,
    )
    from PyQt5.QtCore import (
        Qt, QAbstractTableModel, QModelIndex, pyqtSignal,
    )
    _HAS_PYQT5 = True
except ImportError:
    pass

if _HAS_PYQT5:

    class _PacketTableModel(QAbstractTableModel):
        """数据包表格 Model — 数据存 Python list，只渲染可见行"""

        def __init__(self):
            super().__init__()
            self._packets: List[ParsedPacket] = []

        # ── QAbstractTableModel 接口 ──────────

        def rowCount(self, parent=QModelIndex()):
            return len(self._packets)

        def columnCount(self, parent=QModelIndex()):
            return 7

        def data(self, index, role=Qt.DisplayRole):
            if not index.isValid() or role != Qt.DisplayRole:
                return None
            pkt = self._packets[index.row()]
            col = index.column()
            values = [
                str(pkt.no), pkt.timestamp_str,
                pkt.src_str, pkt.dst_str,
                pkt.proto_name, pkt.length_str,
                pkt.info or pkt.summary,
            ]
            return values[col]

        def headerData(self, section, orientation, role=Qt.DisplayRole):
            if orientation == Qt.Horizontal and role == Qt.DisplayRole:
                return HEADERS[section]
            return None

        # ── 批量操作 ──────────────────────────

        def add_packets(self, packets: list):
            """批量追加，超过上限自动裁剪旧行"""
            if not packets:
                return
            old_count = len(self._packets)

            self.beginInsertRows(QModelIndex(), old_count,
                                 old_count + len(packets) - 1)
            self._packets.extend(packets)
            self.endInsertRows()

            # 超过上限则从头部裁剪
            over = len(self._packets) - MAX_PACKETS
            if over > 0:
                self.beginRemoveRows(QModelIndex(), 0, over - 1)
                del self._packets[:over]
                self.endRemoveRows()

        def clear(self):
            """清空"""
            if not self._packets:
                return
            self.beginRemoveRows(QModelIndex(), 0, len(self._packets) - 1)
            self._packets.clear()
            self.endRemoveRows()

        def get_packet(self, row: int) -> Optional[ParsedPacket]:
            if 0 <= row < len(self._packets):
                return self._packets[row]
            return None


    class PacketTable:
        """
        数据包列表（PyQt5 高性能版）

        用法:
            table = PacketTable(backend="pyqt5")
            table.add_packets([pkt1, pkt2, ...])
            table.on_select = lambda pkt: show_detail(pkt)
        """

        def __init__(self, backend: str = "pyqt5"):
            self.backend = backend
            self.on_select: Optional[Callable[[ParsedPacket], None]] = None
            self._model = _PacketTableModel()
            self._build()
            self.widget = self._view

        def _build(self):
            view = QTableView()
            view.setModel(self._model)
            view.setSelectionBehavior(QAbstractItemView.SelectRows)
            view.setSelectionMode(QAbstractItemView.SingleSelection)
            view.setAlternatingRowColors(True)
            view.setShowGrid(False)
            view.verticalHeader().setVisible(False)
            view.setSortingEnabled(False)
            view.setEditTriggers(QAbstractItemView.NoEditTriggers)

            header = view.horizontalHeader()
            header.setStretchLastSection(True)
            for i, w in enumerate(COL_WIDTHS[:-1]):
                header.resizeSection(i, w)

            # 选中回调
            view.selectionModel().selectionChanged.connect(self._on_select)

            self._view = view

        def _on_select(self, selected, deselected):
            if not self.on_select:
                return
            rows = self._view.selectionModel().selectedRows()
            if rows:
                pkt = self._model.get_packet(rows[0].row())
                if pkt:
                    self.on_select(pkt)

        # ── 公共方法 ──────────────────────────

        def add_packets(self, packets: list):
            self._model.add_packets(packets)
            # 滚动到底部
            self._view.scrollToBottom()

        def clear(self):
            self._model.clear()


# ═══════════════════════════════════════════════════════════
#  Tkinter 回退方案（Treeview，保持不变）
# ═══════════════════════════════════════════════════════════

else:

    class PacketTable:
        """数据包列表（Tkinter 版）"""

        def __init__(self, backend: str = "tkinter"):
            self.backend = backend
            self.on_select: Optional[Callable[[ParsedPacket], None]] = None
            self._packets = []
            self.widget = None
            self._init_tkinter()

        def _init_tkinter(self):
            import tkinter as tk
            from tkinter import ttk

            frame = ttk.Frame()
            columns = HEADERS
            tree = ttk.Treeview(frame, columns=columns, show="headings")
            for col, w in zip(columns, COL_WIDTHS):
                tree.heading(col, text=col)
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

        def add_packets(self, packets: list):
            tree = self._tk_tree
            for pkt in packets:
                self._packets.append(pkt)
                tree.insert("", "end", values=(
                    str(pkt.no), pkt.timestamp_str,
                    pkt.src_str, pkt.dst_str,
                    pkt.proto_name, pkt.length_str,
                    pkt.info or pkt.summary,
                ))
            # 滚动到底部
            if packets:
                tree.yview_moveto(1.0)

            # 内存保护
            while len(self._packets) > MAX_PACKETS:
                self._packets.pop(0)
                children = tree.get_children()
                if children:
                    tree.delete(children[0])

        def clear(self):
            self._packets.clear()
            for item in self._tk_tree.get_children():
                self._tk_tree.delete(item)
