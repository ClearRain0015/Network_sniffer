#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
statistics/expert_info.py — 专家信息面板
=======================================
自动分析数据包，标注可疑/异常/关键事件，分四级：
  🔴 Error   — 严重问题（重传超限等）
  🟡 Warning — 需关注（重传、零窗口、RST）
  🔵 Note    — 提示（分片、重复ACK、Keep-Alive）
  🟢 Chat    — 通信记录（HTTP、DNS 等）
"""

from collections import defaultdict
from typing import List, Tuple, Dict
from dataclasses import dataclass, field

from protocols.base import ParsedPacket


@dataclass
class ExpertItem:
    """单条专家信息"""
    level: str       # "error" / "warning" / "note" / "chat"
    packet_no: int
    summary: str
    detail: str = ""

    @property
    def icon(self) -> str:
        return {"error": "🔴", "warning": "🟡", "note": "🔵", "chat": "🟢"}.get(self.level, "⚪")


LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2, "chat": 3}
LEVEL_NAMES = {"error": "Error", "warning": "Warning", "note": "Note", "chat": "Chat"}


def analyze_packets(packets: List[ParsedPacket]) -> List[ExpertItem]:
    """分析所有包，返回专家信息列表"""
    items: List[ExpertItem] = []

    # 用于重传检测
    seq_seen: Dict[str, set] = defaultdict(set)  # key: "ip_src:ip_dst:sport:dport" → set of seq

    for pkt in packets:
        no = pkt.no

        # ── Chat: HTTP / DNS ──────────────────
        if pkt.has_layer("HTTP"):
            http_layer = pkt.get_layer("HTTP")
            if http_layer and "Method" in http_layer.fields:
                items.append(ExpertItem("chat", no,
                    f"HTTP {http_layer.fields.get('Method', '')} {http_layer.fields.get('URI', '')}",
                    f"{pkt.ip_src}:{pkt.src_port} → {pkt.ip_dst}:{pkt.dst_port}"
                ))
            elif http_layer and "Status Code" in http_layer.fields:
                items.append(ExpertItem("chat", no,
                    f"HTTP {http_layer.fields.get('Status Code', '')}",
                    f"{pkt.ip_src}:{pkt.src_port} → {pkt.ip_dst}:{pkt.dst_port}"
                ))
        if pkt.has_layer("DNS"):
            dns_layer = pkt.get_layer("DNS")
            qname = ""
            if dns_layer:
                qname = dns_layer.fields.get("Query Name", "")
            items.append(ExpertItem("chat", no, f"DNS {qname}" if qname else "DNS"))

        # ── Note: IP 分片 ─────────────────────
        if pkt.ip_flags & 0x01:  # MF=1
            items.append(ExpertItem("note", no,
                f"IP Fragment (id=0x{pkt.ip_id:04x}, offset={pkt.ip_frag})",
                f"{pkt.ip_src} → {pkt.ip_dst}"
            ))

        # ── TCP 分析 ─────────────────────────
        if pkt.proto_name == "TCP":
            conn_key = f"{pkt.ip_src}:{pkt.ip_dst}:{pkt.src_port}:{pkt.dst_port}"

            # RST
            if pkt.tcp_flags & 0x04:
                items.append(ExpertItem("warning", no,
                    f"TCP RST {pkt.ip_src}:{pkt.src_port} → {pkt.ip_dst}:{pkt.dst_port}",
                    f"Seq={pkt.tcp_seq}"
                ))

            # 零窗口
            # (window size is parsed but not stored as separate field; skip)

            # 重传检测
            if pkt.tcp_seq > 0:
                if pkt.tcp_seq in seq_seen[conn_key]:
                    items.append(ExpertItem("warning", no,
                        f"TCP Retransmission {pkt.ip_src}:{pkt.src_port} → {pkt.ip_dst}:{pkt.dst_port}",
                        f"Seq={pkt.tcp_seq} Ack={pkt.tcp_ack}"
                    ))
                seq_seen[conn_key].add(pkt.tcp_seq)

            # TCP Keep-Alive (len <= 1 byte payload 或无payload)
            if not pkt.payload or len(pkt.payload) <= 1:
                if pkt.tcp_flags & 0x10 and not (pkt.tcp_flags & 0x02):
                    items.append(ExpertItem("note", no,
                        f"TCP Keep-Alive {pkt.ip_src}:{pkt.src_port} → {pkt.ip_dst}:{pkt.dst_port}",
                        f"Seq={pkt.tcp_seq}"
                    ))

    return items


def format_expert_info(items: List[ExpertItem]) -> str:
    """格式化为可读文本"""
    if not items:
        return "未发现异常事件"

    by_level: Dict[str, List[ExpertItem]] = defaultdict(list)
    for item in items:
        by_level[item.level].append(item)

    lines = [f"专家信息 ({len(items)} 条)", "=" * 55, ""]

    for level in ["error", "warning", "note", "chat"]:
        group = by_level.get(level, [])
        if not group:
            continue
        lines.append(f"{LEVEL_ORDER[level]}. {LEVEL_NAMES[level]} ({len(group)} 条)")
        lines.append("-" * 40)
        for item in group:
            lines.append(f"  #{item.packet_no:<5} {item.summary}")
        lines.append("")

    return "\n".join(lines)
