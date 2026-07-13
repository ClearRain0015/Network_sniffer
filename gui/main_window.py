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
from capture.device import InterfaceInfo
from parser.base import ParsedPacket
from parser.parser_chain import ParserChain
from reassembly.ip_fragment import FragmentReassembler
from filter.bpf_filter import BPFFilter

# ── 检测 PyQt5 是否可用 ────────────────────
_HAS_PYQT5 = False
try:
    from PyQt5.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLineEdit, QLabel, QComboBox,
        QSplitter, QTextEdit, QTreeWidget, QTreeWidgetItem,
        QHeaderView, QMessageBox, QStatusBar, QDialog,
        QScrollArea,
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QPixmap
    _HAS_PYQT5 = True
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════
#  PyQt5 版本
# ═══════════════════════════════════════════════════════════

if _HAS_PYQT5:

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
        PyQt5 主窗口 — 模仿 Wireshark 布局
        """

        def __init__(self, backend: str = "pyqt5"):
            super().__init__()
            self.backend = backend
            self.setWindowTitle("Sniffer — 网络数据包分析器")
            self.resize(1200, 800)

            self.sniff_thread: _SniffThread = None
            self.packets: List[ParsedPacket] = []
            self._capture_counter = 0
            self._reassembler = FragmentReassembler()
            self._interfaces: List[InterfaceInfo] = []  # 网卡列表
            self._build_ui()

            self._pending_packets: List[ParsedPacket] = []
            self._pending_lock = threading.Lock()
            self._refresh_timer = QTimer()
            self._refresh_timer.timeout.connect(self._flush_packets)
            self._refresh_timer.start(100)

        # ── UI 构建 ──────────────────────────

        def _build_ui(self):
            # 工具栏
            toolbar = QWidget()
            tl = QHBoxLayout(toolbar)
            tl.setContentsMargins(6, 6, 6, 6)

            tl.addWidget(QLabel("网卡:"))
            self.iface_combo = QComboBox()
            self.iface_combo.setMinimumWidth(200)
            self._refresh_interfaces()
            tl.addWidget(self.iface_combo)

            self.btn_start = QPushButton("▶ 开始抓包")
            self.btn_start.clicked.connect(self._on_start)
            tl.addWidget(self.btn_start)

            self.btn_stop = QPushButton("⏹ 停止")
            self.btn_stop.setEnabled(False)
            self.btn_stop.clicked.connect(self._on_stop)
            tl.addWidget(self.btn_stop)

            self.btn_save = QPushButton("保存PCAP")
            self.btn_save.clicked.connect(self._on_save)
            tl.addWidget(self.btn_save)

            self.btn_clear = QPushButton("清空")
            self.btn_clear.clicked.connect(self._on_clear)
            tl.addWidget(self.btn_clear)

            tl.addSpacing(20)

            tl.addWidget(QLabel("过滤:"))
            self.filter_input = QLineEdit()
            self.filter_input.setPlaceholderText("例如: tcp, udp port 80, host 192.168.1.1 ...")
            self.filter_input.setMinimumWidth(250)
            self.filter_input.returnPressed.connect(self._on_filter_apply)
            tl.addWidget(self.filter_input)

            self.btn_filter = QPushButton("应用")
            self.btn_filter.clicked.connect(self._on_filter_apply)
            tl.addWidget(self.btn_filter)

            tl.addStretch()

            self.btn_stats = QPushButton("统计")
            self.btn_stats.clicked.connect(self._on_show_stats)
            tl.addWidget(self.btn_stats)

            # 中央区域
            splitter = QSplitter(Qt.Vertical)

            self.packet_table = PacketTable(backend="pyqt5")
            splitter.addWidget(self.packet_table.widget)
            self.packet_table.on_select = self._on_packet_select

            self.detail_panel = PacketDetailPanel(backend="pyqt5")
            splitter.addWidget(self.detail_panel.widget)

            splitter.setStretchFactor(0, 3)
            splitter.setStretchFactor(1, 2)

            container = QWidget()
            layout = QVBoxLayout(container)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(toolbar)
            layout.addWidget(splitter)
            self.setCentralWidget(container)

            # 状态栏
            self.statusbar = QStatusBar()
            self.setStatusBar(self.statusbar)
            self.status_label = QLabel("就绪 — 请选择网卡并点击「开始抓包」")
            self.statusbar.addWidget(self.status_label)

        # ── 事件处理 ──────────────────────────

        def _refresh_interfaces(self):
            """刷新网卡列表"""
            self.iface_combo.clear()
            self._interfaces = list_interfaces()
            for iface in self._interfaces:
                label = f"{iface.name} ({iface.ip})"
                if iface.is_loopback:
                    label += " [Loopback]"
                self.iface_combo.addItem(label)
            if self.iface_combo.count():
                self.iface_combo.setCurrentIndex(0)

        def _get_selected_iface(self) -> str:
            """获取当前选中网卡的 scapy 可用名称"""
            idx = self.iface_combo.currentIndex()
            if 0 <= idx < len(self._interfaces):
                return self._interfaces[idx].scapy_name
            return "eth0"

        def _on_start(self):
            """开始抓包"""
            iface_name = self._get_selected_iface()
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
                self.btn_stats.setEnabled(False)
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
            self.btn_stats.setEnabled(True)
            self.status_label.setText(f"已停止 — 共捕获 {self._capture_counter} 个数据包")

        def _on_save(self):
            """保存 PCAP + CSV"""
            from save.pcap_save import save_packets
            if not self.packets:
                QMessageBox.information(self, "提示", "没有数据包可保存")
                return
            path = save_packets(self.packets)
            self.status_label.setText(f"已保存到 {path}（含 CSV）")

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
            """显示统计信息 + 协议分布图表"""
            import os, tempfile
            from statistics.flow_statistics import (
                compute_statistics, format_statistics, plot_protocol_distribution,
            )

            stats = compute_statistics(self.packets)
            text = format_statistics(stats)

            # 保存图表到临时文件（避免 plt.show() 与 Qt 冲突）
            tmp_path = os.path.join(tempfile.gettempdir(), "sniffer_stats.png")
            plot_protocol_distribution(stats, save_path=tmp_path)

            # 可缩放对话框
            dialog = QDialog(self)
            dialog.setWindowTitle("流量统计")
            dialog.resize(760, 1050)
            dialog.setMinimumSize(520, 600)
            layout = QVBoxLayout(dialog)

            # 图表 + 文本用 Splitter 分隔，图表区初始 700px 方形
            if os.path.exists(tmp_path):
                pixmap = QPixmap(tmp_path)
                splitter = QSplitter(Qt.Vertical)

                scroll = QScrollArea()
                chart_label = QLabel()
                chart_label.setPixmap(pixmap)
                chart_label.setAlignment(Qt.AlignCenter)
                scroll.setWidget(chart_label)
                scroll.setWidgetResizable(True)
                splitter.addWidget(scroll)

                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setPlainText(text)
                text_edit.setFont(QFont("Consolas", 10))
                splitter.addWidget(text_edit)

                splitter.setSizes([720, 400])
                layout.addWidget(splitter, 1)
            else:
                dialog.setMinimumSize(480, 400)
                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setPlainText(text)
                text_edit.setFont(QFont("Consolas", 10))
                layout.addWidget(text_edit, 1)

            btn = QPushButton("关闭")
            btn.clicked.connect(dialog.accept)
            layout.addWidget(btn)
            dialog.exec_()

        def _on_packet_arrived(self, packet: ParsedPacket):
            with self._pending_lock:
                self._pending_packets.append(packet)

        def _flush_packets(self):
            with self._pending_lock:
                if not self._pending_packets:
                    return
                # 每批最多 200 个（QTableView 性能好，可以多拿）
                batch = self._pending_packets[:200]
                self._pending_packets = self._pending_packets[200:]

            parsed = []
            for packet in batch:
                packet = ParserChain.parse(packet)
                packet = self._reassembler.process(packet)
                if self.filter_input.text().strip():
                    if not BPFFilter.match(packet, self.filter_input.text().strip()):
                        continue
                self._capture_counter += 1
                packet.no = self._capture_counter
                self.packets.append(packet)
                parsed.append(packet)

            if parsed:
                self.packet_table.add_packets(parsed)

            # 同步 self.packets 上限
            while len(self.packets) > 10000:
                self.packets.pop(0)

        def _on_packet_select(self, packet: ParsedPacket):
            self.detail_panel.show_packet(packet)

        def run(self):
            """Tkinter 兼容接口"""
            self.show()


# ═══════════════════════════════════════════════════════════
#  Tkinter 版本（回退方案）
# ═══════════════════════════════════════════════════════════

else:

    class MainWindow:
        """
        Tkinter 主窗口 — 当 PyQt5 不可用时的回退方案
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
            self._interfaces: List[InterfaceInfo] = []

            self._build_tk_ui()

        def _build_tk_ui(self):
            # 工具栏
            toolbar = self.tk.Frame(self.root)
            toolbar.pack(fill=self.tk.X, padx=4, pady=4)

            self.tk.Label(toolbar, text="网卡:").pack(side=self.tk.LEFT)
            self.iface_var = self.tk.StringVar()
            self.iface_combo = self.ttk.Combobox(
                toolbar, textvariable=self.iface_var, width=25)
            self._refresh_interfaces_tk()
            self.iface_combo.pack(side=self.tk.LEFT, padx=4)

            self.btn_start = self.tk.Button(
                toolbar, text="▶ 开始抓包", command=self._on_start_tk)
            self.btn_start.pack(side=self.tk.LEFT, padx=2)

            self.btn_stop = self.tk.Button(
                toolbar, text="⏹ 停止", command=self._on_stop_tk, state=self.tk.DISABLED)
            self.btn_stop.pack(side=self.tk.LEFT, padx=2)

            self.btn_save = self.tk.Button(
                toolbar, text="保存PCAP", command=self._on_save_tk)
            self.btn_save.pack(side=self.tk.LEFT, padx=2)

            self.btn_clear = self.tk.Button(
                toolbar, text="清空", command=self._on_clear_tk)
            self.btn_clear.pack(side=self.tk.LEFT, padx=2)

            self.tk.Label(toolbar, text="  过滤:").pack(side=self.tk.LEFT)
            self.filter_var = self.tk.StringVar()
            self.filter_entry = self.tk.Entry(
                toolbar, textvariable=self.filter_var, width=30)
            self.filter_entry.pack(side=self.tk.LEFT, padx=4)

            self.btn_filter = self.tk.Button(
                toolbar, text="应用", command=self._on_filter_apply_tk)
            self.btn_filter.pack(side=self.tk.LEFT, padx=2)

            self.btn_stats = self.tk.Button(
                toolbar, text="统计", command=self._on_show_stats_tk)
            self.btn_stats.pack(side=self.tk.LEFT, padx=6)

            # 分隔线
            self.ttk.Separator(self.root, orient=self.tk.HORIZONTAL).pack(
                fill=self.tk.X, padx=4)

            # 包列表
            list_frame = self.tk.Frame(self.root)
            list_frame.pack(fill=self.tk.BOTH, expand=True, padx=4, pady=2)

            columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
            self.tree = self.ttk.Treeview(
                list_frame, columns=columns, show="headings", height=15)
            col_widths = [50, 120, 150, 150, 80, 70, 400]
            for col, width in zip(columns, col_widths):
                self.tree.heading(col, text=col)
                self.tree.column(col, width=width, anchor=self.tk.W)

            scrollbar = self.ttk.Scrollbar(
                list_frame, orient=self.tk.VERTICAL, command=self.tree.yview)
            self.tree.configure(yscrollcommand=scrollbar.set)
            self.tree.pack(side=self.tk.LEFT, fill=self.tk.BOTH, expand=True)
            scrollbar.pack(side=self.tk.RIGHT, fill=self.tk.Y)
            self.tree.bind("<<TreeviewSelect>>", self._on_tree_select_tk)

            self.detail_panel = PacketDetailPanel(backend="tkinter", parent=self.root)

            self.status_var = self.tk.StringVar(value="就绪 — 请选择网卡并点击「开始抓包」")
            statusbar = self.tk.Label(
                self.root, textvariable=self.status_var,
                relief=self.tk.SUNKEN, anchor=self.tk.W)
            statusbar.pack(side=self.tk.BOTTOM, fill=self.tk.X)

            self._tk_pending: List[ParsedPacket] = []
            self._tk_lock = threading.Lock()
            self._tk_flush()

        # ── Tkinter 事件处理 ──────────────────

        def _refresh_interfaces_tk(self):
            self._interfaces = list_interfaces()
            self.iface_combo["values"] = [
                f"{i.name} ({i.ip})" + (" [Loopback]" if i.is_loopback else "")
                for i in self._interfaces
            ]
            if self._interfaces:
                self.iface_combo.current(0)

        def _get_selected_iface(self) -> str:
            """获取当前选中网卡的 scapy 可用名称"""
            idx = self.iface_combo.current()
            if 0 <= idx < len(self._interfaces):
                return self._interfaces[idx].scapy_name
            return "eth0"

        def _on_start_tk(self):
            iface_name = self._get_selected_iface()
            bpf = self.filter_var.get().strip()
            self._capture_counter = 0
            self.packets.clear()
            self._tk_pending.clear()
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.sniffer = Sniffer(iface_name, bpf)
            self.sniffer.on_packet = self._on_tk_packet
            self._sniff_thread = threading.Thread(
                target=self.sniffer.start, daemon=True)
            self._sniff_thread.start()
            self.btn_start.config(state=self.tk.DISABLED)
            self.btn_stop.config(state=self.tk.NORMAL)
            self.btn_stats.config(state=self.tk.DISABLED)
            self.status_var.set(f"正在监听 {iface_name} …")

        def _on_stop_tk(self):
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
            self.btn_start.config(state=self.tk.NORMAL)
            self.btn_stop.config(state=self.tk.DISABLED)
            self.btn_stats.config(state=self.tk.NORMAL)
            self.status_var.set(f"已停止 — 共捕获 {self._capture_counter} 个数据包")

        def _on_save_tk(self):
            from save.pcap_save import save_packets
            if not self.packets:
                return
            path = save_packets(self.packets)
            self.status_var.set(f"已保存到 {path}（含 CSV）")

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

        def _on_show_stats_tk(self):
            """显示统计信息 + 协议分布图表"""
            import os, tempfile
            from statistics.flow_statistics import (
                compute_statistics, format_statistics, plot_protocol_distribution,
            )
            if not self.packets:
                return
            stats = compute_statistics(self.packets)
            text = format_statistics(stats)

            # 保存图表到临时文件（避免 plt.show() 与 Tk 冲突）
            tmp_path = os.path.join(tempfile.gettempdir(), "sniffer_stats.png")
            plot_protocol_distribution(stats, save_path=tmp_path)

            # 可缩放对话框 — 按图片尺寸设置窗口大小
            dlg = self.tk.Toplevel(self.root)
            dlg.title("流量统计")

            # 图表 — 完整显示
            if os.path.exists(tmp_path):
                from PIL import Image, ImageTk
                img = Image.open(tmp_path)
                dlg.geometry("740x1100")
                dlg.minsize(500, 600)
                self._tk_chart_img = ImageTk.PhotoImage(img)
                chart_label = self.tk.Label(dlg, image=self._tk_chart_img)
                chart_label.pack(pady=4)
            else:
                dlg.geometry("680x600")
                dlg.minsize(480, 400)

            # 文本统计
            frame = self.tk.Frame(dlg)
            frame.pack(fill=self.tk.BOTH, expand=True, padx=4, pady=2)
            text_widget = self.tk.Text(frame, font=("Consolas", 10), wrap=self.tk.NONE)
            text_widget.insert("1.0", text)
            text_widget.config(state=self.tk.DISABLED)
            scrollbar = self.ttk.Scrollbar(frame, orient=self.tk.VERTICAL, command=text_widget.yview)
            text_widget.config(yscrollcommand=scrollbar.set)
            text_widget.pack(side=self.tk.LEFT, fill=self.tk.BOTH, expand=True)
            scrollbar.pack(side=self.tk.RIGHT, fill=self.tk.Y)

            self.tk.Button(dlg, text="关闭", command=dlg.destroy).pack(pady=4)

        def _on_tk_packet(self, packet: ParsedPacket):
            with self._tk_lock:
                self._tk_pending.append(packet)

        def _tk_flush(self):
            with self._tk_lock:
                if not self._tk_pending:
                    self.root.after(100, self._tk_flush)
                    return
                # 每批最多处理 100 个，防止 UI 卡死
                batch = self._tk_pending[:100]
                self._tk_pending = self._tk_pending[100:]

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
                    packet.no, packet.timestamp_str,
                    packet.src_str, packet.dst_str,
                    packet.proto_name, packet.length_str,
                    packet.info or packet.summary,
                ))

            # 内存保护：超过 10000 条丢弃旧包
            while len(self.packets) > 10000:
                self.packets.pop(0)
                children = self.tree.get_children()
                if children:
                    self.tree.delete(children[0])

            self.root.after(100, self._tk_flush)

        def _on_tree_select_tk(self, event):
            selection = self.tree.selection()
            if selection:
                idx = self.tree.index(selection[0])
                if idx < len(self.packets):
                    self.detail_panel.show_packet(self.packets[idx])

        def run(self):
            self.root.mainloop()
