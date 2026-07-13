#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
save/pcap_save.py — 数据包保存模块
==================================
职责：
  - 保存为 PCAP 格式（Wireshark 可直接打开）
  - 导出为 TXT 格式
  - 导出为 CSV 格式
"""

import os
import time
from typing import List

from protocols.base import ParsedPacket


# 默认保存目录
DEFAULT_SAVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "captures")


def save_packets(packets: List[ParsedPacket],
                 filepath: str = None) -> str:
    """
    保存数据包（智能选择格式）
    -------------------------
    优先保存为 PCAP，scapy 不可用时回退到 TXT。
    返回保存路径。
    """
    if filepath is None:
        os.makedirs(DEFAULT_SAVE_DIR, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(DEFAULT_SAVE_DIR, f"capture_{timestamp}")

    # 尝试 PCAP
    try:
        return save_as_pcap(packets, filepath + ".pcap")
    except ImportError:
        pass

    # 回退 TXT
    return save_as_txt(packets, filepath + ".txt")


def save_as_pcap(packets: List[ParsedPacket], filepath: str) -> str:
    """
    保存为 PCAP 格式
    ----------------
    优先使用 scapy 的 wrpcap()，其次尝试 dpkt。
    """
    # ── 方案1：scapy ────────────────────────
    try:
        from scapy.all import wrpcap
        from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw
        from scapy.all import raw as scapy_raw

        # 尝试从原始字节重建 scapy 包
        scapy_packets = []
        for pkt in packets:
            try:
                # 直接用原始字节构造，scapy 会自动解析
                sp = Ether(pkt.raw_data)
                scapy_packets.append(sp)
            except Exception:
                # 如果重建失败，创建最小化可写包
                sp = Ether() / IP() / Raw(pkt.raw_data)
                scapy_packets.append(sp)

        wrpcap(filepath, scapy_packets)
        return filepath
    except ImportError:
        pass

    # ── 方案2：dpkt ────────────────────────
    try:
        import dpkt

        with open(filepath, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            for pkt in packets:
                writer.writepkt(pkt.raw_data, ts=pkt.timestamp)
            writer.close()
        return filepath
    except ImportError:
        pass

    raise ImportError("需要 scapy 或 dpkt 来保存 PCAP 文件。pip install scapy")


def save_as_txt(packets: List[ParsedPacket], filepath: str) -> str:
    """
    导出为可读文本
    -------------
    格式：Time | Source | Destination | Protocol | Length | Info
    """
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"{'Time':<16} {'Source':<18} {'Destination':<18} "
                f"{'Protocol':<10} {'Length':<8} {'Info'}\n")
        f.write("-" * 110 + "\n")

        for pkt in packets:
            f.write(
                f"{pkt.timestamp_str:<16} "
                f"{pkt.src_str:<18} "
                f"{pkt.dst_str:<18} "
                f"{pkt.proto_name:<10} "
                f"{pkt.length:<8} "
                f"{pkt.info or pkt.summary}\n"
            )

    return filepath


def save_as_csv(packets: List[ParsedPacket], filepath: str) -> str:
    """
    导出为 CSV 格式
    --------------
    格式：No, Time, Source, Destination, Protocol, Length, Info
    """
    import csv

    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["No", "Time", "Source", "Destination",
                          "Protocol", "Length", "Info"])

        for pkt in packets:
            writer.writerow([
                pkt.no,
                pkt.timestamp_str,
                pkt.src_str,
                pkt.dst_str,
                pkt.proto_name,
                pkt.length,
                pkt.info or pkt.summary,
            ])

    return filepath
