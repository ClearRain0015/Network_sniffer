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
from statistics.alerts import SynFloodDetector, detect_syn_alerts
from analysis.http_pairs import build_http_pairs, format_http_pairs
from capture.replay import inject_hex_packet, replay_packet
from i18n import t as translate

# ═══════════════════════════════════════════════════════════
#  全局配置（修改这里即可调整参数）
# ═══════════════════════════════════════════════════════════
SYNDetection_THRESHOLD = 5  # SYN 告警阈值（测试用5，改为100恢复默认）

# ── 检测 PyQt5 是否可用 ────────────────────
_HAS_PYQT5 = False
try:
    from PyQt5.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLineEdit, QLabel, QComboBox,
        QSplitter, QTextEdit, QTreeWidget, QTreeWidgetItem,
        QHeaderView, QMessageBox, QStatusBar,
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QColor, QPalette
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
            self._lang = "zh"
            self.setWindowTitle(self._t("app_title"))
            self.resize(1550, 1050)
            self.setMinimumSize(1000, 700)

            self._zoom = 100  # 缩放百分比，100=默认
            self._dark = False  # 暗色模式
            self._search_matches = []
            self._search_pos = -1

            self.sniff_thread: _SniffThread = None
            self.packets: List[ParsedPacket] = []
            self._capture_counter = 0
            self._auto_alerted = False
            self._reassembler = FragmentReassembler()
            self._syn_detector = SynFloodDetector()
            self._last_alert_at = 0.0
            self._build_ui()

            self._pending_packets: List[ParsedPacket] = []
            self._pending_lock = threading.Lock()
            self._refresh_timer = QTimer()
            self._refresh_timer.timeout.connect(self._flush_packets)
            self._refresh_timer.start(100)

        # ── UI 构建 ──────────────────────────

        def _build_ui(self):
            self._apply_theme()

            # 工具栏
            toolbar = QWidget()
            toolbar.setObjectName("toolbar")
            tl = QHBoxLayout(toolbar)
            tl.setContentsMargins(8, 6, 8, 6)

            # — 抓包区 —
            self.lbl_iface = QLabel()
            tl.addWidget(self.lbl_iface)
            self.iface_combo = QComboBox()
            self.iface_combo.setMinimumWidth(200)
            self._refresh_interfaces()
            tl.addWidget(self.iface_combo)

            self.btn_start = QPushButton()
            self.btn_start.clicked.connect(self._on_start)
            tl.addWidget(self.btn_start)

            self.btn_stop = QPushButton()
            self.btn_stop.setEnabled(False)
            self.btn_stop.clicked.connect(self._on_stop)
            tl.addWidget(self.btn_stop)

            vsep = QLabel("│")
            vsep.setStyleSheet("color: #dadce0; font-size: 16px; margin: 0 4px;")
            vsep.setFixedWidth(10)
            tl.addWidget(vsep)

            # — 数据区 —
            self.btn_open = QPushButton()
            self.btn_open.clicked.connect(self._on_open_pcap)
            tl.addWidget(self.btn_open)

            self.btn_save = QPushButton()
            self.btn_save.clicked.connect(self._on_save)
            tl.addWidget(self.btn_save)

            self.btn_clear = QPushButton()
            self.btn_clear.clicked.connect(self._on_clear)
            tl.addWidget(self.btn_clear)

            vsep = QLabel("│")
            vsep.setStyleSheet("color: #dadce0; font-size: 16px; margin: 0 4px;")
            vsep.setFixedWidth(10)
            tl.addWidget(vsep)

            # — 过滤区 —
            self.lbl_filter = QLabel()
            tl.addWidget(self.lbl_filter)
            self.filter_input = QLineEdit()
            self.filter_input.setPlaceholderText("tcp / tcp.srcport == 80 / ip.ttl < 64 / tcp.flags.syn == 1 ...")
            self.filter_input.setMinimumWidth(220)
            self.filter_input.returnPressed.connect(self._on_filter_apply)
            tl.addWidget(self.filter_input)

            self.btn_filter = QPushButton()
            self.btn_filter.clicked.connect(self._on_filter_apply)
            tl.addWidget(self.btn_filter)

            self.btn_filter_help = QPushButton("?")
            self.btn_filter_help.setFixedWidth(28)
            self.btn_filter_help.clicked.connect(self._on_filter_help)
            tl.addWidget(self.btn_filter_help)

            tl.addSpacing(8)

            self.search_input = QLineEdit()
            self.search_input.setMinimumWidth(160)
            self.search_input.setMaximumWidth(220)
            self.search_input.returnPressed.connect(self._on_search_next)
            tl.addWidget(self.search_input)

            self.btn_search_prev = QPushButton("↑")
            self.btn_search_prev.setFixedWidth(30)
            self.btn_search_prev.clicked.connect(self._on_search_prev)
            tl.addWidget(self.btn_search_prev)

            self.btn_search_next = QPushButton("↓")
            self.btn_search_next.setFixedWidth(30)
            self.btn_search_next.clicked.connect(self._on_search_next)
            tl.addWidget(self.btn_search_next)

            tl.addStretch()

            # — 分析区 —
            self.btn_stats = QPushButton()
            self.btn_stats.clicked.connect(self._on_show_stats)
            tl.addWidget(self.btn_stats)

            self.btn_trend = QPushButton()
            self.btn_trend.clicked.connect(self._on_show_trend)
            tl.addWidget(self.btn_trend)

            self.btn_expert = QPushButton()
            self.btn_expert.clicked.connect(self._on_show_expert)
            tl.addWidget(self.btn_expert)

            self.btn_alerts = QPushButton()
            self.btn_alerts.clicked.connect(self._on_show_alerts)
            tl.addWidget(self.btn_alerts)

            from PyQt5.QtWidgets import QMenu, QAction
            self.btn_advanced = QPushButton()
            self.advanced_menu = QMenu(self)
            self.act_http_pairs = QAction(self)
            self.act_http_pairs.triggered.connect(self._on_show_http_pairs)
            self.advanced_menu.addAction(self.act_http_pairs)
            self.act_replay = QAction(self)
            self.act_replay.triggered.connect(self._on_replay_selected)
            self.advanced_menu.addAction(self.act_replay)
            self.act_inject = QAction(self)
            self.act_inject.triggered.connect(self._on_inject_hex)
            self.advanced_menu.addAction(self.act_inject)
            self.advanced_menu.addSeparator()
            self.act_lang_zh = QAction(self)
            self.act_lang_zh.triggered.connect(lambda: self._set_language("zh"))
            self.advanced_menu.addAction(self.act_lang_zh)
            self.act_lang_en = QAction(self)
            self.act_lang_en.triggered.connect(lambda: self._set_language("en"))
            self.advanced_menu.addAction(self.act_lang_en)
            self.btn_advanced.setMenu(self.advanced_menu)
            tl.addWidget(self.btn_advanced)

            tl.addSpacing(8)

            # — 缩放 —
            self.btn_zoom_out = QPushButton("−")
            self.btn_zoom_out.setFixedWidth(30)
            self.btn_zoom_out.clicked.connect(self._zoom_out)
            tl.addWidget(self.btn_zoom_out)

            self.zoom_label = QLabel("100%")
            self.zoom_label.setAlignment(Qt.AlignCenter)
            self.zoom_label.setFixedWidth(42)
            tl.addWidget(self.zoom_label)

            self.btn_zoom_in = QPushButton("+")
            self.btn_zoom_in.setFixedWidth(30)
            self.btn_zoom_in.clicked.connect(self._zoom_in)
            tl.addWidget(self.btn_zoom_in)

            tl.addSpacing(8)

            self.btn_dark = QPushButton("🌙")
            self.btn_dark.setMinimumWidth(48)
            self.btn_dark.setMinimumHeight(40)
            self.btn_dark.setStyleSheet("font-size: 22px; padding: 4px 8px;")
            self.btn_dark.clicked.connect(self._toggle_dark)
            tl.addWidget(self.btn_dark)

            # 中央区域
            splitter = QSplitter(Qt.Vertical)

            self.packet_table = PacketTable(backend="pyqt5")
            splitter.addWidget(self.packet_table.widget)
            self.packet_table.on_select = self._on_packet_select
            self.packet_table.on_context_menu = self._on_packet_context_menu

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
            from PyQt5.QtWidgets import QSlider
            self.statusbar = QStatusBar()
            self.setStatusBar(self.statusbar)
            self.status_label = QLabel()
            self.statusbar.addWidget(self.status_label)

            self.zoom_slider = QSlider(Qt.Horizontal)
            self.zoom_slider.setRange(80, 200)
            self.zoom_slider.setValue(self._zoom)
            self.zoom_slider.setFixedWidth(120)
            self.zoom_slider.valueChanged.connect(self._on_zoom_slider)
            self.zoom_label = QLabel("100%")
            self.zoom_label.setObjectName("zoomLabel")
            self.statusbar.addPermanentWidget(self.zoom_label)
            self.statusbar.addPermanentWidget(self.zoom_slider)
            self._refresh_ui_texts(reset_status=True)

        # ── 主题 & 缩放 ──────────────────────

        def _s(self, base_px: int) -> str:
            """Scale a base pixel value by the current zoom factor."""
            return f"{max(1, round(base_px * self._zoom / 100))}px"

        def _toggle_dark(self):
            """切换暗色模式"""
            self._dark = not self._dark
            self.btn_dark.setText("☀" if self._dark else "🌙")
            self._apply_theme()

        def _apply_theme(self):
            """Apply Google Material Design inspired theme with current zoom."""
            s = self._s  # shorthand
            d = self._dark
            # 色彩变量
            c = {
                "bg":         "#1e1e1e" if d else "#f8f9fa",
                "surface":    "#2d2d2d" if d else "#ffffff",
                "surface2":   "#252525" if d else "#fafbfc",
                "text":       "#e0e0e0" if d else "#202124",
                "text2":      "#9aa0a6" if d else "#5f6368",
                "border":     "#3d3d3d" if d else "#dadce0",
                "border2":    "#333333" if d else "#e8eaed",
                "hover":      "#3a3a3a" if d else "#f1f3f4",
                "hover2":     "#333333" if d else "#e8eaed",
                "press":      "#404040" if d else "#e8eaed",
                "select":     "#1a3a5c" if d else "#e8f0fe",
                "select_t":   "#4da3ff" if d else "#1a73e8",
                "disabled":   "#3a3a3a" if d else "#f8f9fa",
                "disabled_t": "#666666" if d else "#9aa0a6",
            }
            self.setStyleSheet(f"""
            /* ── 全局 ─────────────────────── */
            QMainWindow {{
                background-color: {c["bg"]};
            }}
            QWidget {{
                background-color: {c["bg"]};
                color: {c["text"]};
                font-family: "Google Sans", "Segoe UI", "Microsoft YaHei UI", sans-serif;
                font-size: {s(16)};
            }}

            /* ── 工具栏 ───────────────────── */
            QWidget#toolbar {{
                background-color: {c["surface"]};
                border-bottom: 1px solid {c["border"]};
                padding: {s(4)} 0;
            }}

            /* ── 缩放标签 ───────────────── */
            QLabel#zoomLabel {{
                color: {c["text"]};
                font-size: {s(16)};
                font-weight: 500;
            }}

            /* ── 按钮 ─────────────────────── */
            QPushButton {{
                background-color: {c["surface"]};
                color: {c["text"]};
                border: 1px solid {c["border"]};
                border-radius: {s(8)};
                padding: {s(7)} {s(18)};
                min-height: {s(36)};
                font-size: {s(16)};
                font-weight: 500;
                letter-spacing: 0.2px;
            }}
            QPushButton:hover {{
                background-color: {c["hover"]};
                border-color: {c["border"]};
            }}
            QPushButton:pressed {{
                background-color: {c["press"]};
            }}
            QPushButton:disabled {{
                background-color: {c["disabled"]};
                color: {c["disabled_t"]};
                border-color: {c["border2"]};
            }}
            QPushButton#btnStart {{
                background-color: #1a73e8;
                color: #ffffff;
                border: none;
            }}
            QPushButton#btnStart:hover {{
                background-color: #1557b0;
            }}
            QPushButton#btnStop {{
                background-color: #ea4335;
                color: #ffffff;
                border: none;
            }}
            QPushButton#btnStop:hover {{
                background-color: #c5221f;
            }}
            QPushButton#btnZoom {{
                background-color: transparent;
                color: {c["text2"]};
                border: none;
                border-radius: {s(4)};
                padding: {s(4)} {s(6)};
                min-height: {s(28)};
                font-size: {s(18)};
                font-weight: 600;
            }}
            QPushButton#btnZoom:hover {{
                background-color: {c["hover2"]};
            }}

            /* ── 输入框 ──────────────────── */
            QLineEdit {{
                background-color: {c["surface"]};
                color: {c["text"]};
                border: 1px solid {c["border"]};
                border-radius: {s(8)};
                padding: {s(8)} {s(12)};
                font-size: {s(18)};
                selection-background-color: {c["select"]};
            }}
            QLineEdit:focus {{
                border-color: #1a73e8;
                border-width: 2px;
                padding: {s(7)} {s(11)};
            }}

            /* ── 下拉框 ──────────────────── */
            QComboBox {{
                background-color: {c["surface"]};
                color: {c["text"]};
                border: 1px solid {c["border"]};
                border-radius: {s(8)};
                padding: {s(7)} {s(12)};
                min-width: {s(200)};
                font-size: {s(18)};
            }}
            QComboBox:hover {{
                border-color: {c["border"]};
            }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: {s(28)};
                border-left: 1px solid {c["hover2"]};
            }}
            QComboBox QAbstractItemView {{
                background-color: {c["surface"]};
                color: {c["text"]};
                selection-background-color: {c["select"]};
                border: 1px solid {c["border"]};
                outline: none;
                padding: {s(4)} 0;
                font-size: {s(18)};
            }}

            /* ── 分隔条 ──────────────────── */
            QSplitter::handle {{
                background-color: {c["border"]};
            }}
            QSplitter::handle:vertical {{
                height: 1px;
            }}

            /* ── 树形/表格 ──────────────── */
            QTreeWidget {{
                background-color: {c["surface"]};
                color: {c["text"]};
                border: 1px solid {c["border"]};
                alternate-background-color: {c["surface2"]};
                outline: none;
                font-size: {s(16)};
            }}
            QTreeWidget::item {{
                padding: {s(5)} {s(10)};
                min-height: {s(28)};
            }}
            QTreeWidget::item:selected {{
                background-color: {c["select"]};
                color: #1a73e8;
            }}
            QTreeWidget::item:hover {{
                background-color: {c["hover"]};
            }}
            QHeaderView::section {{
                background-color: {c["surface"]};
                color: {c["text2"]};
                padding: {s(8)} {s(12)};
                border: none;
                border-right: 1px solid {c["hover2"]};
                border-bottom: 1px solid {c["border"]};
                font-weight: 600;
                font-size: {s(18)};
                letter-spacing: 0.3px;
                text-transform: uppercase;
            }}

            /* ── 滚动条 ──────────────────── */
            QScrollBar:vertical {{
                background-color: transparent;
                width: {s(8)};
                margin: {s(4)} 0;
            }}
            QScrollBar::handle:vertical {{
                background-color: {c["border"]};
                border-radius: {s(4)};
                min-height: {s(36)};
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: #9aa0a6;
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar:horizontal {{
                background-color: transparent;
                height: {s(8)};
                margin: 0 {s(4)};
            }}
            QScrollBar::handle:horizontal {{
                background-color: {c["border"]};
                border-radius: {s(4)};
                min-width: {s(32)};
            }}
            QScrollBar::handle:horizontal:hover {{
                background-color: #9aa0a6;
            }}
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal {{
                width: 0;
            }}

            /* ── 状态栏 ──────────────────── */
            QStatusBar {{
                background-color: {c["surface"]};
                color: {c["text2"]};
                border-top: 1px solid {c["border"]};
                padding: {s(4)} {s(14)};
                font-size: {s(16)};
            }}

            /* ── 文本视图 ──────────────── */
            QTextEdit {{
                background-color: {c["surface"]};
                color: {c["text"]};
                border: 1px solid {c["border"]};
                border-radius: {s(8)};
                font-family: "SF Mono", "Consolas", "Courier New", monospace;
                font-size: {s(16)};
                selection-background-color: {c["select"]};
            }}

            /* ── 标签 ──────────────────── */
            QLabel {{
                background-color: transparent;
                color: {c["text2"]};
                font-size: {s(18)};
            }}
            """)

            p = self.palette()
            _dark = self._dark
            p.setColor(QPalette.Window, QColor("#2d2d2d" if _dark else "#f8f9fa"))
            p.setColor(QPalette.WindowText, QColor("#e0e0e0" if _dark else "#202124"))
            p.setColor(QPalette.Base, QColor("#2d2d2d" if _dark else "#ffffff"))
            p.setColor(QPalette.Text, QColor("#e0e0e0" if _dark else "#202124"))
            p.setColor(QPalette.Button, QColor("#2d2d2d" if _dark else "#ffffff"))
            p.setColor(QPalette.ButtonText, QColor("#e0e0e0" if _dark else "#202124"))
            p.setColor(QPalette.Highlight, QColor("#1a73e8"))
            p.setColor(QPalette.HighlightedText, QColor("#ffffff"))
            self.setPalette(p)

        # ── 缩放 ──────────────────────────────

        def _on_zoom_slider(self, value):
            """缩放滑块拖动"""
            if value != self._zoom:
                self._zoom = value
                self._apply_zoom(for_slider=True)

        def _apply_zoom(self, for_slider=False):
            """Re-apply theme with current zoom and update the label/slider."""
            self._apply_theme()
            if hasattr(self, "zoom_label") and self.zoom_label:
                self.zoom_label.setText(f"{self._zoom}%")
            if not for_slider and hasattr(self, "zoom_slider") and self.zoom_slider:
                self.zoom_slider.blockSignals(True)
                self.zoom_slider.setValue(self._zoom)
                self.zoom_slider.blockSignals(False)
            if hasattr(self, "zoom_slider") and self.zoom_slider:
                self.zoom_slider.setToolTip(self._tf("zoom_slider_tip", zoom=self._zoom))

        def _zoom_in(self):
            if self._zoom >= 200:
                return
            self._zoom = min(200, self._zoom + 10)
            self._apply_zoom()

        def _zoom_out(self):
            if self._zoom <= 80:
                return
            self._zoom = max(80, self._zoom - 10)
            self._apply_zoom()

        def _zoom_reset(self):
            self._zoom = 100
            self._apply_zoom()

        def keyPressEvent(self, event):
            """Handle Ctrl+Plus, Ctrl+Minus, Ctrl+0 for zoom."""
            ctrl = event.modifiers() & Qt.ControlModifier
            if ctrl and event.key() == Qt.Key_Equal:    # Ctrl+=
                self._zoom_in()
            elif ctrl and event.key() == Qt.Key_Minus:   # Ctrl+-
                self._zoom_out()
            elif ctrl and event.key() == Qt.Key_0:       # Ctrl+0
                self._zoom_reset()
            else:
                super().keyPressEvent(event)

        def wheelEvent(self, event):
            """Ctrl+MouseWheel to zoom."""
            if event.modifiers() & Qt.ControlModifier:
                delta = event.angleDelta().y()
                if delta > 0:
                    self._zoom_in()
                elif delta < 0:
                    self._zoom_out()
            else:
                super().wheelEvent(event)

        # ── 事件处理 ──────────────────────────

        def _refresh_interfaces(self):
            self.iface_combo.clear()
            self._iface_names = []  # 存 UUID 名
            for iface in list_interfaces():
                self.iface_combo.addItem(iface.display)
                self._iface_names.append(iface.name)
            if self.iface_combo.count():
                self.iface_combo.setCurrentIndex(0)

        def _on_start(self):
            idx = self.iface_combo.currentIndex()
            iface_name = self._iface_names[idx] if idx >= 0 else None
            bpf = self.filter_input.text().strip()

            # 如果有已有数据，询问是否清空
            if self.packets:
                reply = QMessageBox.question(
                    self, self._t("start_title"),
                    self._tf("start_keep_or_clear", count=len(self.packets)),
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes,
                )
                if reply == QMessageBox.Yes:
                    # 清空并开始
                    self._capture_counter = 0
                    self.packets.clear()
                    self._pending_packets.clear()
                    self.packet_table.clear()
                # 否则保留数据，计数器从当前数量继续

            try:
                self.sniff_thread = _SniffThread(iface_name, bpf)
                self.sniff_thread.packet_received.connect(self._on_packet_arrived)
                self.sniff_thread.start()
                self.btn_start.setEnabled(False)
                self.btn_stop.setEnabled(True)
                self.status_label.setText(
                    self._tf("listening", iface=iface_name, count=self._capture_counter)
                )
            except Exception as e:
                QMessageBox.critical(self, self._t("error"), self._tf("cannot_start", error=e))

        def _on_stop(self):
            # 立即停止刷新，清空待处理队列
            self._refresh_timer.stop()
            with self._pending_lock:
                self._pending_packets.clear()
            if self.sniff_thread:
                self.sniff_thread.stop()
                self.sniff_thread.wait(3000)
                self.sniff_thread = None
            # 处理剩余包后恢复
            self._flush_packets()
            self._refresh_timer.start(100)
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.status_label.setText(self._tf("stopped", count=self._capture_counter))

        def _on_save(self):
            from PyQt5.QtWidgets import QFileDialog
            from save.pcap_save import save_packets
            if not self.packets:
                QMessageBox.information(self, self._t("hint"), self._t("no_packets_to_save"))
                return
            path, _ = QFileDialog.getSaveFileName(
                self, self._t("save_pcap_title"), "capture.pcap",
                self._t("pcap_filter"),
            )
            if not path:
                return
            saved = save_packets(self.packets, path)
            self.status_label.setText(self._tf("saved", path=saved))

        def _on_open_pcap(self):
            from PyQt5.QtWidgets import QFileDialog
            from save.pcap_save import read_pcap
            from protocols.parser_chain import ParserChain

            path, _ = QFileDialog.getOpenFileName(
                self, self._t("open_pcap_title"), "",
                self._t("pcap_open_filter"),
            )
            if not path:
                return

            try:
                imported = read_pcap(path)
                if not imported:
                    QMessageBox.warning(self, self._t("hint"), self._t("no_readable_packets"))
                    return

                # 解析所有导入的包
                for pkt in imported:
                    pkt = ParserChain.parse(pkt)

                # 追加到现有列表
                start_no = self._capture_counter
                for pkt in imported:
                    start_no += 1
                    pkt.no = start_no
                    self.packets.append(pkt)
                    self.packet_table.add_packet(pkt)
                self._capture_counter = start_no

                self.status_label.setText(
                    self._tf("imported", imported=len(imported), total=self._capture_counter)
                )
            except Exception as e:
                QMessageBox.critical(self, self._t("error"), self._tf("cannot_open", error=e))

        def _on_clear(self):
            self.packets.clear()
            self._pending_packets.clear()
            self.packet_table.clear()
            self.detail_panel.clear()
            self._capture_counter = 0
            self.status_label.setText(self._t("cleared"))

        def _on_filter_apply(self):
            bpf = self.filter_input.text().strip()
            if self.sniff_thread and self.sniff_thread.isRunning():
                self.sniff_thread.sniffer.set_filter(bpf)
            self.status_label.setText(self._tf("filter_status", filter=bpf if bpf else self._t("none")))

        def _on_filter_help(self):
            QMessageBox.information(
                self,
                self._t("filter_help_title"),
                self._t("filter_help_text"),
            )

        def _t(self, key: str) -> str:
            return translate(key, self._lang)

        def _tf(self, key: str, **kwargs) -> str:
            return self._t(key).format(**kwargs)

        def _refresh_ui_texts(self, reset_status: bool = False):
            self.setWindowTitle(self._t("app_title"))
            self.lbl_iface.setText(self._t("iface"))
            self.lbl_filter.setText(self._t("filter"))
            self.btn_start.setText(self._t("start"))
            self.btn_start.setToolTip(self._t("start_tip"))
            self.btn_stop.setText(self._t("stop"))
            self.btn_stop.setToolTip(self._t("stop_tip"))
            self.btn_open.setText(self._t("open"))
            self.btn_open.setToolTip(self._t("open_tip"))
            self.btn_save.setText(self._t("save"))
            self.btn_save.setToolTip(self._t("save_tip"))
            self.btn_clear.setText(self._t("clear"))
            self.btn_clear.setToolTip(self._t("clear_tip"))
            self.btn_filter.setText(self._t("apply"))
            self.btn_filter.setToolTip(self._t("filter_tip"))
            self.btn_filter_help.setToolTip(self._t("filter_help_tip"))
            self.btn_stats.setText(self._t("stats"))
            self.btn_stats.setToolTip(self._t("stats_tip"))
            self.btn_trend.setText(self._t("trend"))
            self.btn_trend.setToolTip(self._t("trend_tip"))
            self.btn_expert.setText(self._t("expert"))
            self.btn_expert.setToolTip(self._t("expert_tip"))
            self.btn_alerts.setText(self._t("alerts"))
            self.btn_alerts.setToolTip(self._t("alerts_tip"))
            self.btn_advanced.setText(self._t("advanced"))
            self.btn_advanced.setToolTip(self._t("advanced_tip"))
            self.search_input.setPlaceholderText(self._t("search_placeholder"))
            self.btn_search_prev.setToolTip(self._t("search_prev_tip"))
            self.btn_search_next.setToolTip(self._t("search_next_tip"))
            self.act_http_pairs.setText(self._t("http_pairs"))
            self.act_replay.setText(self._t("replay"))
            self.act_inject.setText(self._t("inject"))
            self.act_lang_zh.setText(self._t("language_zh"))
            self.act_lang_en.setText(self._t("language_en"))
            self.btn_zoom_out.setToolTip(self._t("zoom_out_tip"))
            self.btn_zoom_in.setToolTip(self._t("zoom_in_tip"))
            self.btn_dark.setToolTip(self._t("dark_tip"))
            self.zoom_slider.setToolTip(self._tf("zoom_slider_tip", zoom=self._zoom))
            if hasattr(self.packet_table, "set_language"):
                self.packet_table.set_language(self._lang)
            if hasattr(self.detail_panel, "set_language"):
                self.detail_panel.set_language(self._lang)
            if reset_status:
                self.status_label.setText(self._t("ready"))

        def _set_language(self, lang: str):
            self._lang = lang
            self._refresh_ui_texts()
            self.status_label.setText(self._t("language_changed"))

        def _search_packet(self, forward: bool):
            matches = self.packet_table.find_packets(self.search_input.text())
            if not matches:
                self._search_matches = []
                self._search_pos = -1
                self.status_label.setText(self._t("no_match"))
                return

            if matches != self._search_matches:
                self._search_matches = matches
                self._search_pos = 0 if forward else len(matches) - 1
            else:
                step = 1 if forward else -1
                self._search_pos = (self._search_pos + step) % len(matches)

            packet = self._search_matches[self._search_pos]
            self.packet_table.select_packet(packet)
            self.status_label.setText(
                f"{self._t('search_next' if forward else 'search_prev')}: "
                f"{self._search_pos + 1}/{len(matches)} -> No {packet.no}"
            )

        def _on_search_next(self):
            self._search_packet(True)

        def _on_search_prev(self):
            self._search_packet(False)

        def _on_show_http_pairs(self):
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit
            pairs = build_http_pairs(self.packets)
            dlg = QDialog(self)
            dlg.setWindowTitle(self._t("http_pairs"))
            dlg.resize(720, 520)
            layout = QVBoxLayout(dlg)
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(format_http_pairs(pairs, lang=self._lang))
            text_edit.setFont(QFont("Consolas", 10))
            layout.addWidget(text_edit)
            dlg.exec_()

        def _current_iface_name(self):
            idx = self.iface_combo.currentIndex()
            return self._iface_names[idx] if 0 <= idx < len(self._iface_names) else None

        def _on_replay_selected(self):
            packet = self.packet_table.current_packet()
            if packet is None:
                QMessageBox.information(self, self._t("replay"), self._t("no_packet"))
                return
            reply = QMessageBox.question(
                self,
                self._t("replay"),
                self._tf("replay_confirm", no=packet.no, length=packet.length),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return
            try:
                result = replay_packet(packet, iface=self._current_iface_name())
                self.status_label.setText(
                    self._tf(
                        "replayed_status",
                        count=result["count"],
                        bytes=result["bytes"],
                        mode=result["mode"],
                    )
                )
            except Exception as e:
                QMessageBox.critical(self, self._t("replay"), str(e))

        def _on_inject_hex(self):
            from PyQt5.QtWidgets import QInputDialog
            hex_text, ok = QInputDialog.getMultiLineText(
                self,
                self._t("inject"),
                self._t("inject_prompt"),
                "",
            )
            if not ok or not hex_text.strip():
                return
            reply = QMessageBox.question(
                self,
                self._t("inject"),
                self._t("inject_confirm"),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return
            try:
                result = inject_hex_packet(hex_text, iface=self._current_iface_name())
                self.status_label.setText(
                    self._tf(
                        "injected_status",
                        count=result["count"],
                        bytes=result["bytes"],
                        mode=result["mode"],
                    )
                )
            except Exception as e:
                QMessageBox.critical(self, self._t("inject"), str(e))

        def _on_show_stats(self):
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit
            from statistics.flow_statistics import compute_statistics, format_statistics_html
            stats = compute_statistics(self.packets)
            html = format_statistics_html(stats, zoom=self._zoom, lang=self._lang)

            z = self._zoom / 100
            dlg = QDialog(self)
            dlg.setWindowTitle(self._t("traffic_stats"))
            dlg.resize(int(620 * z), int(600 * z))
            dlg.setMinimumSize(int(480 * z), int(400 * z))
            dlg.setStyleSheet(f"""
                QDialog {{ background-color: #ffffff; }}
                QTextEdit {{ font-size: {int(14 * z)}px; }}
            """)
            layout = QVBoxLayout(dlg)
            layout.setContentsMargins(int(8 * z), int(8 * z), int(8 * z), int(8 * z))
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setHtml(html)
            text_edit.setObjectName("statsView")
            layout.addWidget(text_edit)
            dlg.exec_()

        def _on_show_trend(self):
            from statistics.flow_statistics import compute_traffic_trend
            if not self.packets:
                QMessageBox.information(self, self._t("hint"), self._t("no_packets_for_trend"))
                return
            trend = compute_traffic_trend(self.packets)
            if not trend:
                QMessageBox.information(self, self._t("hint"), self._t("not_enough_trend"))
                return
            try:
                from statistics.flow_statistics import plot_traffic_trend
                plot_traffic_trend(trend, lang=self._lang)
            except Exception as e:
                QMessageBox.critical(self, self._t("error"), self._tf("plot_failed", error=e))

        def _on_show_alerts(self):
            # 统计 SYN 包信息（调试用）
            syn_count = sum(
                1 for p in self.packets
                if p.proto_name == "TCP" and (p.tcp_flags & 0x02)
            )
            alerts = detect_syn_alerts(self.packets, threshold=SYNDetection_THRESHOLD)
            if not alerts:
                QMessageBox.information(
                    self, self._t("realtime_alert"),
                    self._tf(
                        "no_syn_alert",
                        total=len(self.packets),
                        syn=syn_count,
                        threshold=SYNDetection_THRESHOLD,
                    )
                )
                return
            text = "\n".join(
                self._tf("syn_flood", ip=ip, count=count)
                for ip, count, _ in alerts[-10:]
            )
            QMessageBox.warning(self, self._t("realtime_alert"), text)

        def _on_show_expert(self):
            from statistics.expert_info import analyze_packets, format_expert_info
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit

            if not self.packets:
                QMessageBox.information(self, self._t("expert_info"), self._t("no_packets_for_expert"))
                return
            items = analyze_packets(self.packets)
            report = format_expert_info(items, lang=self._lang)
            dlg = QDialog(self)
            dlg.setWindowTitle(self._t("expert_panel"))
            dlg.resize(700, 500)
            layout = QVBoxLayout(dlg)
            editor = QTextEdit()
            editor.setReadOnly(True)
            editor.setPlainText(report)
            from PyQt5.QtGui import QFont
            editor.setFont(QFont("Consolas", 11))
            layout.addWidget(editor)
            dlg.exec_()

        def _on_packet_arrived(self, packet: ParsedPacket):
            with self._pending_lock:
                self._pending_packets.append(packet)

        def _flush_packets(self):
            with self._pending_lock:
                if not self._pending_packets:
                    return
                # 每次最多处理 50 个包，防止 UI 卡顿
                batch = self._pending_packets[:50]
                self._pending_packets = self._pending_packets[50:]
            for packet in batch:
                packet = ParserChain.parse(packet)
                packet = self._reassembler.process(packet)
                if packet is None:
                    continue  # 分片未到齐，等待后续
                if self.filter_input.text().strip():
                    if not BPFFilter.match(packet, self.filter_input.text().strip()):
                        continue
                self._capture_counter += 1
                packet.no = self._capture_counter
                self.packets.append(packet)
                self.packet_table.add_packet(packet)

            # ── 自动告警：检测到 SYN 洪水就弹窗 ──
            alerts = detect_syn_alerts(self.packets, threshold=SYNDetection_THRESHOLD)
            if alerts and not self._auto_alerted:
                self._auto_alerted = True
                msg = "\n".join(
                    self._tf("syn_flood", ip=ip, count=count)
                    for ip, count, _ in alerts[-5:]
                ) if alerts else ""
                QMessageBox.warning(
                    self, self._t("auto_alert"), msg
                )
            elif not alerts:
                self._auto_alerted = False  # 解除锁定，允许下次报警

        def _on_packet_select(self, packet: ParsedPacket):
            self.detail_panel.show_packet(packet)

        def _on_packet_context_menu(self, packet: ParsedPacket, action: str):
            if action == "follow_tcp":
                self._follow_tcp_stream(packet)

        def _follow_tcp_stream(self, packet: ParsedPacket):
            from statistics.tcp_stream import find_stream, format_stream_text
            from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit

            stream = find_stream(self.packets, packet)
            if not stream:
                QMessageBox.information(self, self._t("hint"), self._t("tcp_stream_not_found"))
                return

            text = format_stream_text(stream)
            dlg = QDialog(self)
            dlg.setWindowTitle(self._tf("tcp_stream", label=stream.label))
            dlg.resize(900, 600)
            layout = QVBoxLayout(dlg)
            editor = QTextEdit()
            editor.setReadOnly(True)
            editor.setPlainText(text)
            from PyQt5.QtGui import QFont
            editor.setFont(QFont("Consolas", 10))
            layout.addWidget(editor)
            dlg.exec_()

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
            self.root.geometry("1280x860")
            self.root.minsize(960, 600)
            self.root.configure(bg="#f8f9fa")

            self._tk_zoom = 100

            # Google Material 风格配色
            self._tk_colors = {
                "bg": "#f8f9fa", "frame_bg": "#ffffff",
                "fg": "#202124", "entry_bg": "#ffffff",
                "btn_bg": "#ffffff", "btn_fg": "#202124",
                "active_btn_bg": "#1a73e8", "stop_btn_bg": "#ea4335",
                "tree_bg": "#ffffff", "tree_fg": "#202124",
                "select_bg": "#e8f0fe", "select_fg": "#1a73e8",
            }
            self._setup_tk_ttk_style()

            self.sniffer: Sniffer = None
            self.packets: List[ParsedPacket] = []
            self._capture_counter = 0
            self._reassembler = FragmentReassembler()
            self._syn_detector = SynFloodDetector()
            self._last_alert_at = 0.0

            self._build_tk_ui()

        def _setup_tk_ttk_style(self):
            """Configure ttk styles for Google Material theme."""
            style = self.ttk.Style()
            style.theme_use("clam")
            c = self._tk_colors
            style.configure(".", background=c["bg"], foreground=c["fg"],
                           fieldbackground=c["entry_bg"], font=("", 10))
            style.configure("TLabel", background=c["bg"], foreground=c["fg"])
            style.configure("TFrame", background=c["bg"])
            style.configure("TLabelframe", background=c["bg"], foreground=c["fg"])
            style.configure("TLabelframe.Label", background=c["bg"], foreground=c["fg"])
            style.configure("Treeview",
                background=c["tree_bg"], foreground=c["tree_fg"],
                fieldbackground=c["tree_bg"], borderwidth=0,
                font=("", 10), rowheight=30,
            )
            style.configure("Treeview.Heading",
                background=c["frame_bg"], foreground="#5f6368",
                relief="flat", borderwidth=0, padding=(10, 7),
                font=("", 10, "bold"),
            )
            style.map("Treeview",
                background=[("selected", c["select_bg"])],
                foreground=[("selected", c["select_fg"])],
            )
            style.map("Treeview.Heading",
                background=[("active", "#f1f3f4")],
            )
            style.configure("TCombobox",
                fieldbackground=c["frame_bg"], background=c["frame_bg"],
                foreground=c["fg"], arrowcolor="#5f6368",
                font=("", 10), padding=(8, 4),
            )
            style.map("TCombobox",
                fieldbackground=[("readonly", c["frame_bg"])],
                foreground=[("readonly", c["fg"])],
            )
            style.configure("TSeparator", background="#dadce0")
            style.configure("TScrollbar",
                background=c["bg"], troughcolor=c["bg"],
                arrowcolor="#9aa0a6",
            )

        def _build_tk_ui(self):
            c = self._tk_colors

            # 工具栏
            toolbar = self.tk.Frame(self.root, bg=c["frame_bg"], padx=10, pady=8)
            toolbar.pack(fill=self.tk.X)

            self.tk.Label(toolbar, text="网卡:", bg=c["frame_bg"], fg=c["fg"]).pack(side=self.tk.LEFT)
            self.iface_var = self.tk.StringVar()
            self.iface_combo = self.ttk.Combobox(
                toolbar, textvariable=self.iface_var, width=20, state="readonly")
            self._refresh_interfaces_tk()
            self.iface_combo.pack(side=self.tk.LEFT, padx=4)

            self.btn_start = self.tk.Button(
                toolbar, text="开始抓包", command=self._on_start_tk,
                bg=c["active_btn_bg"], fg="#ffffff", font=("", 10, "bold"),
                relief=self.tk.FLAT, padx=16, pady=5, cursor="hand2")
            self.btn_start.pack(side=self.tk.LEFT, padx=3)

            self.btn_stop = self.tk.Button(
                toolbar, text="停止", command=self._on_stop_tk, state=self.tk.DISABLED,
                bg=c["stop_btn_bg"], fg="#ffffff", font=("", 10, "bold"),
                relief=self.tk.FLAT, padx=16, pady=5, cursor="hand2")
            self.btn_stop.pack(side=self.tk.LEFT, padx=3)

            self.btn_save = self.tk.Button(
                toolbar, text="保存PCAP", command=self._on_save_tk,
                bg=c["btn_bg"], fg=c["btn_fg"], font=("", 10),
                relief=self.tk.FLAT, padx=14, pady=5, cursor="hand2")
            self.btn_save.pack(side=self.tk.LEFT, padx=3)

            self.btn_clear = self.tk.Button(
                toolbar, text="清空", command=self._on_clear_tk,
                bg=c["btn_bg"], fg=c["btn_fg"], font=("", 10),
                relief=self.tk.FLAT, padx=14, pady=5, cursor="hand2")
            self.btn_clear.pack(side=self.tk.LEFT, padx=3)

            self.tk.Label(toolbar, text="  过滤:", bg=c["frame_bg"], fg=c["fg"]).pack(side=self.tk.LEFT)
            self.filter_var = self.tk.StringVar()
            self.filter_entry = self.tk.Entry(
                toolbar, textvariable=self.filter_var, width=28,
                bg=c["entry_bg"], fg=c["fg"], insertbackground=c["fg"],
                relief=self.tk.FLAT, font=("Consolas", 10),
            )
            self.filter_entry.pack(side=self.tk.LEFT, padx=4, ipady=2)

            self.btn_filter = self.tk.Button(
                toolbar, text="应用", command=self._on_filter_apply_tk,
                bg="#1a73e8", fg="#ffffff", font=("", 10),
                relief=self.tk.FLAT, padx=14, pady=5, cursor="hand2")
            self.btn_filter.pack(side=self.tk.LEFT, padx=3)

            self.tk.Frame(toolbar, bg=c["frame_bg"], width=16).pack(side=self.tk.LEFT)

            self.btn_stats = self.tk.Button(
                toolbar, text="统计", command=self._on_show_stats_tk,
                bg=c["btn_bg"], fg=c["btn_fg"], font=("", 10),
                relief=self.tk.FLAT, padx=14, pady=5, cursor="hand2")
            self.btn_stats.pack(side=self.tk.LEFT, padx=3)

            self.btn_trend = self.tk.Button(
                toolbar, text="趋势图", command=self._on_show_trend_tk,
                bg=c["btn_bg"], fg=c["btn_fg"], font=("", 10),
                relief=self.tk.FLAT, padx=14, pady=5, cursor="hand2")
            self.btn_trend.pack(side=self.tk.LEFT, padx=3)

            self.btn_alerts = self.tk.Button(
                toolbar, text="告警", command=self._on_show_alerts_tk,
                bg=c["btn_bg"], fg=c["btn_fg"], font=("", 10),
                relief=self.tk.FLAT, padx=14, pady=5, cursor="hand2")
            self.btn_alerts.pack(side=self.tk.LEFT, padx=3)

            # 缩放控件
            self.tk.Frame(toolbar, bg=c["frame_bg"], width=10).pack(side=self.tk.LEFT)
            self.btn_zoom_out_tk = self.tk.Button(
                toolbar, text="−", command=self._zoom_out_tk,
                bg=c["btn_bg"], fg="#5f6368", font=("", 13, "bold"),
                relief=self.tk.FLAT, padx=6, pady=3, cursor="hand2",
                bd=0, highlightthickness=0)
            self.btn_zoom_out_tk.pack(side=self.tk.LEFT)

            self.zoom_label_tk = self.tk.Label(
                toolbar, text="100%", bg=c["frame_bg"], fg=c["fg"],
                font=("", 10), width=5)
            self.zoom_label_tk.pack(side=self.tk.LEFT)

            self.btn_zoom_in_tk = self.tk.Button(
                toolbar, text="+", command=self._zoom_in_tk,
                bg=c["btn_bg"], fg="#5f6368", font=("", 13, "bold"),
                relief=self.tk.FLAT, padx=6, pady=3, cursor="hand2",
                bd=0, highlightthickness=0)
            self.btn_zoom_in_tk.pack(side=self.tk.LEFT)

            # 分隔线
            self.tk.Frame(self.root, bg="#dadce0", height=1).pack(fill=self.tk.X)

            # 包列表
            list_frame = self.tk.Frame(self.root, bg=c["bg"])
            list_frame.pack(fill=self.tk.BOTH, expand=True, padx=4, pady=(4, 0))

            columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
            self.tree = self.ttk.Treeview(
                list_frame, columns=columns, show="headings", height=15)
            col_widths = [50, 120, 150, 150, 80, 70, 400]
            for col, width in zip(columns, col_widths):
                self.tree.heading(col, text=col)
                self.tree.column(col, width=width, anchor=self.tk.W, minwidth=40)

            vsb = self.ttk.Scrollbar(list_frame, orient=self.tk.VERTICAL, command=self.tree.yview)
            self.tree.configure(yscrollcommand=vsb.set)
            self.tree.pack(side=self.tk.LEFT, fill=self.tk.BOTH, expand=True)
            vsb.pack(side=self.tk.RIGHT, fill=self.tk.Y)
            self.tree.bind("<<TreeviewSelect>>", self._on_tree_select_tk)

            self.detail_panel = PacketDetailPanel(backend="tkinter", parent=self.root)

            # 状态栏
            self.status_var = self.tk.StringVar(value="就绪 — 请选择网卡并点击「开始抓包」")
            statusbar = self.tk.Label(
                self.root, textvariable=self.status_var,
                bg=c["frame_bg"], fg="#5f6368",
                relief=self.tk.FLAT, anchor=self.tk.W, padx=14, pady=5,
                font=("", 9))
            statusbar.pack(side=self.tk.BOTTOM, fill=self.tk.X)

            self._tk_pending: List[ParsedPacket] = []
            self._tk_lock = threading.Lock()
            self._bind_tk_zoom_keys()
            self._tk_flush()

        # ── Tkinter 缩放 ──────────────────────

        def _apply_zoom_tk(self):
            """Apply tk scaling and update label."""
            self.root.tk.call("tk", "scaling", self._tk_zoom / 100)
            self.zoom_label_tk.config(text=f"{self._tk_zoom}%")

        def _zoom_in_tk(self):
            if self._tk_zoom >= 200:
                return
            self._tk_zoom = min(200, self._tk_zoom + 10)
            self._apply_zoom_tk()

        def _zoom_out_tk(self):
            if self._tk_zoom <= 80:
                return
            self._tk_zoom = max(80, self._tk_zoom - 10)
            self._apply_zoom_tk()

        def _zoom_reset_tk(self):
            self._tk_zoom = 100
            self._apply_zoom_tk()

        def _bind_tk_zoom_keys(self):
            """Bind Ctrl+Plus/Minus/0 and Ctrl+MouseWheel."""
            self.root.bind("<Control-=>", lambda e: self._zoom_in_tk())
            self.root.bind("<Control-+>", lambda e: self._zoom_in_tk())
            self.root.bind("<Control-minus>", lambda e: self._zoom_out_tk())
            self.root.bind("<Control-0>", lambda e: self._zoom_reset_tk())
            # Ctrl+MouseWheel
            self.root.bind("<Control-MouseWheel>",
                           lambda e: self._zoom_in_tk() if e.delta > 0 else self._zoom_out_tk())

        # ── Tkinter 事件处理 ──────────────────

        def _refresh_interfaces_tk(self):
            interfaces = list_interfaces()
            self._tk_iface_names = [i.name for i in interfaces]
            self.iface_combo["values"] = [i.display for i in interfaces]
            if interfaces:
                self.iface_combo.current(0)

        def _on_start_tk(self):
            idx = self.iface_combo.current()
            iface_name = self._tk_iface_names[idx] if idx >= 0 else None
            bpf = self.filter_var.get().strip()
            # 如果有已有数据，询问是否清空
            if self.packets:
                from tkinter import messagebox
                clear = messagebox.askyesno(
                    "开始抓包",
                    f"当前已有 {len(self.packets)} 个数据包。\n\n"
                    "清空后重新开始，还是保留数据继续抓包？",
                )
                if clear:
                    self._capture_counter = 0
                    self.packets.clear()
                    self._tk_pending.clear()
                    for item in self.tree.get_children():
                        self.tree.delete(item)
            else:
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
            self.status_var.set(f"正在监听 {iface_name} ...")

        def _on_stop_tk(self):
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
            # 清空待处理队列
            with self._tk_lock:
                self._tk_pending.clear()
            self.btn_start.config(state=self.tk.NORMAL)
            self.btn_stop.config(state=self.tk.DISABLED)
            self.status_var.set(f"已停止 — 共捕获 {self._capture_counter} 个数据包")

        def _on_save_tk(self):
            from tkinter import filedialog
            from save.pcap_save import save_packets
            if not self.packets:
                return
            path = filedialog.asksaveasfilename(
                title="保存 PCAP 文件",
                defaultextension=".pcap",
                filetypes=[("PCAP 文件", "*.pcap"), ("所有文件", "*.*")],
            )
            if not path:
                return
            saved = save_packets(self.packets, path)
            self.status_var.set(f"已保存到 {saved}")

        def _on_clear_tk(self):
            self.packets.clear()
            self._tk_pending.clear()
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.detail_panel.clear()
            self._capture_counter = 0
            self._syn_detector = SynFloodDetector()
            self._last_alert_at = 0.0
            self.status_var.set("已清空")

        def _on_filter_apply_tk(self):
            bpf = self.filter_var.get().strip()
            if self.sniffer:
                self.sniffer.set_filter(bpf)
            self.status_var.set(f"过滤器: {bpf if bpf else '(无)'}")

        def _on_show_stats_tk(self):
            from statistics.flow_statistics import compute_statistics, format_statistics
            stats = compute_statistics(self.packets)
            text = format_statistics(stats)
            c = self._tk_colors

            z = self._tk_zoom / 100
            dlg = self.tk.Toplevel(self.root, bg=c["bg"])
            dlg.title("流量统计")
            dlg.geometry(f"{int(560*z)}x{int(520*z)}")
            dlg.minsize(int(420*z), int(340*z))

            bar = self.tk.Frame(dlg, bg=c["frame_bg"], height=int(36*z))
            bar.pack(fill=self.tk.X)
            self.tk.Label(bar, text="流量统计", bg=c["frame_bg"], fg=c["fg"],
                          font=("", int(12*z), "bold")).pack(
                side=self.tk.LEFT, padx=int(12*z), pady=int(6*z))

            text_frame = self.tk.Frame(dlg, bg=c["bg"])
            text_frame.pack(fill=self.tk.BOTH, expand=True,
                            padx=int(8*z), pady=int(8*z))

            text_widget = self.tk.Text(text_frame, wrap=self.tk.NONE,
                                       bg=c["entry_bg"], fg=c["fg"],
                                       insertbackground=c["fg"],
                                       font=("Consolas", int(10*z)),
                                       relief=self.tk.FLAT,
                                       padx=int(8*z), pady=int(8*z))
            scroll_y = self.tk.Scrollbar(text_frame, orient=self.tk.VERTICAL,
                                         command=text_widget.yview, bg=c["bg"])
            scroll_x = self.tk.Scrollbar(text_frame, orient=self.tk.HORIZONTAL,
                                         command=text_widget.xview, bg=c["bg"])
            text_widget.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

            text_widget.insert("1.0", text)
            text_widget.configure(state=self.tk.DISABLED)

            text_widget.grid(row=0, column=0, sticky="nsew")
            scroll_y.grid(row=0, column=1, sticky="ns")
            scroll_x.grid(row=1, column=0, sticky="ew")
            text_frame.grid_rowconfigure(0, weight=1)
            text_frame.grid_columnconfigure(0, weight=1)

        def _on_show_trend_tk(self):
            from tkinter import messagebox
            from statistics.flow_statistics import plot_traffic_trend
            if not self.packets:
                messagebox.showinfo("提示", "没有数据包可绘制趋势图")
                return
            if not plot_traffic_trend(self.packets, zoom=self._tk_zoom):
                messagebox.showinfo("提示", "无法绘制趋势图，请确认已安装 matplotlib")

        def _on_show_alerts_tk(self):
            from tkinter import messagebox
            alerts = detect_syn_alerts(self.packets, threshold=SYNDetection_THRESHOLD)
            syn_count = sum(
                1 for p in self.packets
                if p.proto_name == "TCP" and (p.tcp_flags & 0x02)
            )
            if not alerts:
                messagebox.showinfo(
                    "实时告警",
                    f"当前未检测到大量 SYN 包\n"
                    f"（总包数: {len(self.packets)}, "
                    f"SYN包: {syn_count}, "
                    f"阈值: {SYNDetection_THRESHOLD}）"
                )
                return
            messagebox.showwarning("实时告警", "\n".join(alerts[-10:]))

        def _on_tk_packet(self, packet: ParsedPacket):
            with self._tk_lock:
                self._tk_pending.append(packet)

        def _tk_flush(self):
            with self._tk_lock:
                if self._tk_pending:
                    batch = self._tk_pending[:50]
                    self._tk_pending = self._tk_pending[50:]
                else:
                    batch = []
            for packet in batch:
                packet = ParserChain.parse(packet)
                packet = self._reassembler.process(packet)
                if packet is None:
                    continue  # 分片未到齐，等待后续
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
            self.root.after(100, self._tk_flush)

        def _check_tk_realtime_alert(self, packet: ParsedPacket):
            alert = self._syn_detector.observe(packet)
            if not alert:
                return
            self.status_var.set(alert)
            if packet.timestamp - self._last_alert_at >= 10:
                self._last_alert_at = packet.timestamp
                from tkinter import messagebox
                messagebox.showwarning("实时告警", alert)

        def _on_tree_select_tk(self, event):
            selection = self.tree.selection()
            if selection:
                idx = self.tree.index(selection[0])
                if idx < len(self.packets):
                    self.detail_panel.show_packet(self.packets[idx])

        def run(self):
            self.root.mainloop()
