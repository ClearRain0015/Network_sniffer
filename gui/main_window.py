#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gui/main_window.py — 主窗口
===========================
负责：
  - 组织整体布局（工具栏 + 包列表 + 详情 + 十六进制）
  - 连接 Controller 层（启动/停止抓包、过滤、保存）
  - 实时刷新包列表

支持两种后端：PyQt5（推荐）和 Tkinter（回退）
"""

import threading
from typing import List

from .packet_table import PacketTable
from .packet_detail import PacketDetailPanel
from capture import Sniffer, list_interfaces
from protocols.base import ParsedPacket
from protocols.parser_chain import ParserChain
from reassembly.ip_fragment import FragmentReassembler
from filter.bpf_filter import BPFFilter


# ═══════════════════════════════════════════════
#  PyQt5 后端
# ═══════════════════════════════════════════════

try:
    from PyQt5.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLineEdit, QLabel, QComboBox,
        QSplitter, QTextEdit, QTreeWidget, QTreeWidgetItem,
        QHeaderView, QMessageBox, QStatusBar,
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont

    class _SniffThread(QThread):
        """PyQt5 抓包线程"""
        packet_received = pyqtSignal(object)

        def __init__(self, interface: str, bpf_filter: str = ""):
            super().__init__()
            self.sniffer = Sniffer(interface, bpf_filter)
            self.sniffer.on_packet = self._on_packet

        def _on_packet(self, packet: ParsedPacket):
            self.packet_received.emit(packet)

        def run(self):
            self.sniffer.start()

        def stop(self):
            self.sniffer.stop()


    class MainWindow(QMainWindow):
        """
        PyQt5 主窗口
        -----------
        布局模仿 Wireshark：
          - 顶部工具栏
          - 中间包列表
          - 底部协议详情树 + 十六进制面板
        """

        def __init__(self, backend: str = "pyqt5"):
            super().__init__()
            self.backend = backend
            self.setWindowTitle("Sniffer — 网络数据包分析器")
            self.resize(1200, 800)

            # ── 核心组件 ──────────────────────
            self.sniff_thread: _SniffThread = None
            self.packets: List[ParsedPacket] = []
            self._capture_counter = 0
            self._reassembler = FragmentReassembler()

            # ── 构建 UI ───────────────────────
            self._build_toolbar()
            self._build_central_area()
            self._build_statusbar()

            # ── 定时刷新 UI ───────────────────
            self._pending_packets: List[ParsedPacket] = []
            self._pending_lock = threading.Lock()
            self._refresh_timer = QTimer()
            self._refresh_timer.timeout.connect(self._flush_packets)
            self._refresh_timer.start(100)  # 每 100ms 刷新一次

        # ── 工具栏 ──────────────────────────

        def _build_toolbar(self):
            """构建顶部工具栏"""
            toolbar = QWidget()
            toolbar_layout = QHBoxLayout(toolbar)
            toolbar_layout.setContentsMargins(6, 6, 6, 6)

            # 网卡选择
            toolbar_layout.addWidget(QLabel("网卡:"))
            self.iface_combo = QComboBox()
            self.iface_combo.setMinimumWidth(180)
            self._refresh_interfaces()
            toolbar_layout.addWidget(self.iface_combo)

            # 按钮
            self.btn_start = QPushButton("▶ 开始抓包")
            self.btn_start.clicked.connect(self._on_start)
            toolbar_layout.addWidget(self.btn_start)

            self.btn_stop = QPushButton("⏹ 停止")
            self.btn_stop.setEnabled(False)
            self.btn_stop.clicked.connect(self._on_stop)
            toolbar_layout.addWidget(self.btn_stop)

            self.btn_save = QPushButton("💾 保存PCAP")
            self.btn_save.clicked.connect(self._on_save)
            toolbar_layout.addWidget(self.btn_save)

            self.btn_clear = QPushButton("🗑 清空")
            self.btn_clear.clicked.connect(self._on_clear)
            toolbar_layout.addWidget(self.btn_clear)

            toolbar_layout.addSpacing(20)

            # 过滤器
            toolbar_layout.addWidget(QLabel("过滤:"))
            self.filter_input = QLineEdit()
            self.filter_input.setPlaceholderText("例如: tcp, udp port 80, host 192.168.1.1 ...")
            self.filter_input.setMinimumWidth(250)
            self.filter_input.returnPressed.connect(self._on_filter_apply)
            toolbar_layout.addWidget(self.filter_input)

            self.btn_filter = QPushButton("应用")
            self.btn_filter.clicked.connect(self._on_filter_apply)
            toolbar_layout.addWidget(self.btn_filter)

            toolbar_layout.addStretch()

            # 统计按钮
            self.btn_stats = QPushButton("📊 统计")
            self.btn_stats.clicked.connect(self._on_show_stats)
            toolbar_layout.addWidget(self.btn_stats)

            toolbar_widget = QWidget()
            toolbar_widget.setLayout(toolbar_layout)
            self.layout().addWidget(toolbar_widget)
            # 放 layout 中备用
            self._toolbar_widget = toolbar_widget

        # ── 中央区域 ─────────────────────────

        def _build_central_area(self):
            """构建中央区域：包列表 + 详情面板"""
            central = QSplitter(Qt.Vertical)

            # 上方：数据包表格
            self.packet_table = PacketTable(backend="pyqt5")
            central.addWidget(self.packet_table.widget)

            # 下方：详情 + 十六进制
            self.detail_panel = PacketDetailPanel(backend="pyqt5")
            central.addWidget(self.detail_panel.widget)

            central.setStretchFactor(0, 3)
            central.setStretchFactor(1, 2)

            # 包列表选中事件 → 显示详情
            self.packet_table.on_select = self._on_packet_select

            # ⚠️ 这里需要把 toolbar + central 组合
            # 由于 QMainWindow 需要 setCentralWidget
            container = QWidget()
            layout = QVBoxLayout(container)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(self._toolbar_widget)
            layout.addWidget(central)
            self.setCentralWidget(container)

        # ── 状态栏 ──────────────────────────

        def _build_statusbar(self):
            self.statusbar = QStatusBar()
            self.setStatusBar(self.statusbar)
            self.status_label = QLabel("就绪 — 请选择网卡并点击「开始抓包」")
            self.statusbar.addWidget(self.status_label)

        # ── 事件处理 ────────────────────────

        def _refresh_interfaces(self):
            """刷新网卡列表"""
            self.iface_combo.clear()
            interfaces = list_interfaces()
            for iface in interfaces:
                label = f"{iface.name} ({iface.ip})"
                if iface.is_loopback:
                    label += " [Loopback]"
                self.iface_combo.addItem(label)
            if interfaces:
                self.iface_combo.setCurrentIndex(0)

        def _on_start(self):
            """开始抓包"""
            iface_text = self.iface_combo.currentText()
            iface_name = iface_text.split(" ")[0] if iface_text else "eth0"
            bpf = self.filter_input.text().strip()

            self._capture_counter = 0
            self.packets.clear()
            self._pending_packets.clear()
            self.packet_table.clear()

            try:
                self.sniff_thread = _SniffThread(iface_name, bpf)
                self.sniff_thread.packet_received.connect(self._on_packet_arrived)
                self.sniff_thread.start()

                self.btn_start.setEnabled(False)
                self.btn_stop.setEnabled(True)
                self.status_label.setText(f"正在监听 {iface_name} …")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"无法开始抓包:\n{e}")

        def _on_stop(self):
            """停止抓包"""
            if self.sniff_thread:
                self.sniff_thread.stop()
                self.sniff_thread.wait(3000)
                self.sniff_thread = None

            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.status_label.setText(f"已停止 — 共捕获 {self._capture_counter} 个数据包")

        def _on_save(self):
            """保存 PCAP"""
            from save.pcap_save import save_packets
            if not self.packets:
                QMessageBox.information(self, "提示", "没有数据包可保存")
                return
            path = save_packets(self.packets)
            self.status_label.setText(f"已保存到 {path}")

        def _on_clear(self):
            """清空列表"""
            self.packets.clear()
            self._pending_packets.clear()
            self.packet_table.clear()
            self.detail_panel.clear()
            self._capture_counter = 0
            self.status_label.setText("已清空")

        def _on_filter_apply(self):
            """应用过滤器"""
            bpf = self.filter_input.text().strip()
            if self.sniff_thread and self.sniff_thread.isRunning():
                self.sniff_thread.sniffer.set_filter(bpf)
            self.status_label.setText(f"过滤器: {bpf if bpf else '(无)'}")

        def _on_show_stats(self):
            """显示统计信息"""
            from statistics.flow_statistics import compute_statistics, format_statistics
            stats = compute_statistics(self.packets)
            text = format_statistics(stats)
            QMessageBox.information(self, "流量统计", text)

        def _on_packet_arrived(self, packet: ParsedPacket):
            """收到新包（来自抓包线程）"""
            with self._pending_lock:
                self._pending_packets.append(packet)

        def _flush_packets(self):
            """定时将累积的包刷入 UI"""
            with self._pending_lock:
                if not self._pending_packets:
                    return
                batch = self._pending_packets[:]
                self._pending_packets.clear()

            for packet in batch:
                # 解析
                packet = ParserChain.parse(packet)
                # IP 分片重组
                packet = self._reassembler.process(packet)
                # 过滤
                if self.filter_input.text().strip():
                    bpf = self.filter_input.text().strip()
                    if not BPFFilter.match(packet, bpf):
                        continue
                self._capture_counter += 1
                packet.no = self._capture_counter
                self.packets.append(packet)
                self.packet_table.add_packet(packet)

        def _on_packet_select(self, packet: ParsedPacket):
            """选中包列表某一行 → 显示详情"""
            self.detail_panel.show_packet(packet)

        def run(self):
            """Tkinter 兼容接口"""
            self.show()

except ImportError:
    # PyQt5 不可用 — MainWindow 需要在 Tkinter 模式下使用
    pass


# ═══════════════════════════════════════════════
#  Tkinter 后端（回退方案）
# ═══════════════════════════════════════════════

class MainWindow:
    """
    Tkinter 主窗口
    -------------
    当 PyQt5 不可用时的回退方案。
    功能相同但界面较简洁。
    """

    def __init__(self, backend: str = "tkinter"):
        import tkinter as tk
        from tkinter import ttk

        self.backend = backend
        self.tk = tk
        self.ttk = ttk

        self.root = tk.Tk()
        self.root.title("Sniffer — 网络数据包分析器")
        self.root.geometry("1200x800")

        self.sniffer: Sniffer = None
        self.packets: List[ParsedPacket] = []
        self._capture_counter = 0
        self._reassembler = FragmentReassembler()

        self._build_tk_ui()

    def _build_tk_ui(self):
        """构建 Tkinter 界面"""
        # 工具栏
        toolbar = self.tk.Frame(self.root)
        toolbar.pack(fill=self.tk.X, padx=4, pady=4)

        self.tk.Label(toolbar, text="网卡:").pack(side=self.tk.LEFT)
        self.iface_var = self.tk.StringVar()
        self.iface_combo = self.ttk.Combobox(
            toolbar, textvariable=self.iface_var, width=20,
        )
        self._refresh_interfaces_tk()
        self.iface_combo.pack(side=self.tk.LEFT, padx=4)

        self.btn_start = self.tk.Button(
            toolbar, text="▶ 开始抓包", command=self._on_start_tk,
        )
        self.btn_start.pack(side=self.tk.LEFT, padx=2)

        self.btn_stop = self.tk.Button(
            toolbar, text="⏹ 停止", command=self._on_stop_tk, state=self.tk.DISABLED,
        )
        self.btn_stop.pack(side=self.tk.LEFT, padx=2)

        self.btn_save = self.tk.Button(
            toolbar, text="💾 保存PCAP", command=self._on_save_tk,
        )
        self.btn_save.pack(side=self.tk.LEFT, padx=2)

        self.btn_clear = self.tk.Button(
            toolbar, text="🗑 清空", command=self._on_clear_tk,
        )
        self.btn_clear.pack(side=self.tk.LEFT, padx=2)

        self.tk.Label(toolbar, text="  过滤:").pack(side=self.tk.LEFT)
        self.filter_var = self.tk.StringVar()
        self.filter_entry = self.tk.Entry(
            toolbar, textvariable=self.filter_var, width=30,
        )
        self.filter_entry.pack(side=self.tk.LEFT, padx=4)

        self.btn_filter = self.tk.Button(
            toolbar, text="应用", command=self._on_filter_apply_tk,
        )
        self.btn_filter.pack(side=self.tk.LEFT, padx=2)

        # 分隔线
        self.ttk.Separator(self.root, orient=self.tk.HORIZONTAL).pack(
            fill=self.tk.X, padx=4,
        )

        # 包列表
        list_frame = self.tk.Frame(self.root)
        list_frame.pack(fill=self.tk.BOTH, expand=True, padx=4, pady=2)

        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = self.ttk.Treeview(
            list_frame, columns=columns, show="headings", height=15,
        )
        col_widths = [50, 120, 150, 150, 80, 70, 400]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=self.tk.W)

        scrollbar = self.ttk.Scrollbar(
            list_frame, orient=self.tk.VERTICAL, command=self.tree.yview,
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=self.tk.LEFT, fill=self.tk.BOTH, expand=True)
        scrollbar.pack(side=self.tk.RIGHT, fill=self.tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select_tk)

        # 详情面板
        self.detail_panel = PacketDetailPanel(backend="tkinter",
                                              parent=self.root)

        # 状态栏
        self.status_var = self.tk.StringVar(value="就绪 — 请选择网卡并点击「开始抓包」")
        statusbar = self.tk.Label(
            self.root, textvariable=self.status_var,
            relief=self.tk.SUNKEN, anchor=self.tk.W,
        )
        statusbar.pack(side=self.tk.BOTTOM, fill=self.tk.X)

        # 定时刷新
        self._tk_pending: List[ParsedPacket] = []
        self._tk_lock = threading.Lock()
        self._tk_flush()

    # ── Tkinter 事件处理 ─────────────────

    def _refresh_interfaces_tk(self):
        interfaces = list_interfaces()
        self.iface_combo["values"] = [
            f"{i.name} ({i.ip})" for i in interfaces
        ]
        if interfaces:
            self.iface_combo.current(0)

    def _on_start_tk(self):
        iface_text = self.iface_combo.get()
        iface_name = iface_text.split(" ")[0] if iface_text else "eth0"
        bpf = self.filter_var.get().strip()

        self._capture_counter = 0
        self.packets.clear()
        self._tk_pending.clear()
        # 清空树
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.sniffer = Sniffer(iface_name, bpf)
        self.sniffer.on_packet = self._on_tk_packet
        self._sniff_thread = threading.Thread(
            target=self.sniffer.start, daemon=True,
        )
        self._sniff_thread.start()

        self.btn_start.config(state=self.tk.DISABLED)
        self.btn_stop.config(state=self.tk.NORMAL)
        self.status_var.set(f"正在监听 {iface_name} …")

    def _on_stop_tk(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        self.btn_start.config(state=self.tk.NORMAL)
        self.btn_stop.config(state=self.tk.DISABLED)
        self.status_var.set(f"已停止 — 共捕获 {self._capture_counter} 个数据包")

    def _on_save_tk(self):
        from save.pcap_save import save_packets
        if not self.packets:
            return
        path = save_packets(self.packets)
        self.status_var.set(f"已保存到 {path}")

    def _on_clear_tk(self):
        self.packets.clear()
        self._tk_pending.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detail_panel.clear()
        self._capture_counter = 0
        self.status_var.set("已清空")

    def _on_filter_apply_tk(self):
        bpf = self.filter_var.get().strip()
        if self.sniffer:
            self.sniffer.set_filter(bpf)
        self.status_var.set(f"过滤器: {bpf if bpf else '(无)'}")

    def _on_tk_packet(self, packet: ParsedPacket):
        with self._tk_lock:
            self._tk_pending.append(packet)

    def _tk_flush(self):
        """Tkinter 定时刷新 UI"""
        with self._tk_lock:
            if self._tk_pending:
                batch = self._tk_pending[:]
                self._tk_pending.clear()
            else:
                batch = []

        for packet in batch:
            packet = ParserChain.parse(packet)
            packet = self._reassembler.process(packet)

            bpf = self.filter_var.get().strip()
            if bpf and not BPFFilter.match(packet, bpf):
                continue

            self._capture_counter += 1
            packet.no = self._capture_counter
            self.packets.append(packet)

            self.tree.insert("", self.tk.END, values=(
                packet.no,
                packet.timestamp_str,
                packet.src_str,
                packet.dst_str,
                packet.proto_name,
                packet.length_str,
                packet.info or packet.summary,
            ))

        self.root.after(100, self._tk_flush)

    def _on_tree_select_tk(self, event):
        selection = self.tree.selection()
        if selection:
            idx = self.tree.index(selection[0])
            if idx < len(self.packets):
                self.detail_panel.show_packet(self.packets[idx])

    def run(self):
        """启动 Tkinter 主循环"""
        self.root.mainloop()
