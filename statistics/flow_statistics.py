#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
statistics/flow_statistics.py — 流量统计
========================================
对已捕获数据包做统计分析：
  - 协议分布
  - Top N IP 地址
  - 包速率
  - 端口分布
"""

from collections import Counter, defaultdict
from typing import List, Dict
import time

from protocols.base import ParsedPacket


def compute_statistics(packets: List[ParsedPacket]) -> dict:
    """
    计算流量统计数据

    返回字典包含：
      - total_packets    : 总包数
      - total_bytes      : 总字节数
      - duration         : 捕获时长（秒）
      - pps              : 每秒包数
      - protocol_dist    : 协议分布 {协议: 数量}
      - top_src_ips      : Top 源 IP
      - top_dst_ips      : Top 目的 IP
      - top_src_ports    : Top 源端口
      - top_dst_ports    : Top 目的端口
    """
    if not packets:
        return {"total_packets": 0}

    total_bytes = sum(p.length for p in packets)

    # 时长
    first_ts = packets[0].timestamp
    last_ts = packets[-1].timestamp
    duration = max(last_ts - first_ts, 0.001)

    # 协议分布
    proto_counter = Counter(p.proto_name or "Other" for p in packets)

    # Top IP
    src_ip_counter = Counter(p.ip_src for p in packets if p.ip_src)
    dst_ip_counter = Counter(p.ip_dst for p in packets if p.ip_dst)

    # Top 端口
    src_port_counter = Counter(
        p.src_port for p in packets if p.src_port
    )
    dst_port_counter = Counter(
        p.dst_port for p in packets if p.dst_port
    )

    # 包大小分布
    size_buckets = {
        "< 64B": 0, "64-128B": 0, "128-256B": 0,
        "256-512B": 0, "512-1024B": 0, "> 1024B": 0,
    }
    for p in packets:
        l = p.length
        if l < 64: size_buckets["< 64B"] += 1
        elif l < 128: size_buckets["64-128B"] += 1
        elif l < 256: size_buckets["128-256B"] += 1
        elif l < 512: size_buckets["256-512B"] += 1
        elif l < 1024: size_buckets["512-1024B"] += 1
        else: size_buckets["> 1024B"] += 1

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "duration": duration,
        "pps": len(packets) / duration,
        "protocol_dist": dict(proto_counter.most_common()),
        "top_src_ips": src_ip_counter.most_common(10),
        "top_dst_ips": dst_ip_counter.most_common(10),
        "top_src_ports": src_port_counter.most_common(10),
        "top_dst_ports": dst_port_counter.most_common(10),
        "size_buckets": size_buckets,
    }


def format_statistics(stats: dict) -> str:
    """将统计数据格式化为可读文本"""
    if stats.get("total_packets", 0) == 0:
        return "暂无数据"

    lines = []
    lines.append("=" * 50)
    lines.append("  流量统计报告")
    lines.append("=" * 50)
    lines.append("")

    # 基本统计
    lines.append(f"📦 总数据包:    {stats['total_packets']}")
    lines.append(f"📏 总字节数:    {stats['total_bytes']:,} bytes "
                 f"({stats['total_bytes']/1024:.1f} KB)")
    lines.append(f"⏱  捕获时长:    {stats['duration']:.2f} 秒")
    lines.append(f"⚡ 平均速率:    {stats['pps']:.1f} pps")
    lines.append("")

    # 协议分布
    lines.append("─" * 50)
    lines.append("📊 协议分布:")
    for proto, count in stats.get("protocol_dist", {}).items():
        pct = count / stats["total_packets"] * 100
        bar = "█" * int(pct / 5)
        lines.append(f"  {proto:<8} {count:>5} ({pct:>5.1f}%) {bar}")
    lines.append("")

    # 包大小分布
    lines.append("─" * 50)
    lines.append("📏 包大小分布:")
    for bucket, count in stats.get("size_buckets", {}).items():
        pct = count / stats["total_packets"] * 100 if stats["total_packets"] else 0
        lines.append(f"  {bucket:<12} {count:>5} ({pct:>5.1f}%)")
    lines.append("")

    # Top Source IP
    lines.append("─" * 50)
    lines.append("⬆  Top 10 源 IP:")
    for ip, count in stats.get("top_src_ips", []):
        lines.append(f"  {ip:<18} {count:>5}")
    lines.append("")

    # Top Destination IP
    lines.append("⬇  Top 10 目的 IP:")
    for ip, count in stats.get("top_dst_ips", []):
        lines.append(f"  {ip:<18} {count:>5}")
    lines.append("")

    # Top Ports
    lines.append("─" * 50)
    lines.append("🔌 Top 源端口:")
    for port, count in stats.get("top_src_ports", []):
        lines.append(f"  {port:<8} {count:>5}")
    lines.append("")
    lines.append("🔌 Top 目的端口:")
    for port, count in stats.get("top_dst_ports", []):
        lines.append(f"  {port:<8} {count:>5}")

    lines.append("")
    lines.append("=" * 50)

    return "\n".join(lines)


# ── 可选：流量图表 ──────────────────────────

def plot_protocol_distribution(stats: dict, save_path: str = None):
    """
    绘制协议分布饼图（需要 matplotlib）

    pip install matplotlib
    """
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] 需要安装 matplotlib: pip install matplotlib")
        return

    proto_dist = stats.get("protocol_dist", {})
    if not proto_dist:
        return

    labels = list(proto_dist.keys())
    sizes = list(proto_dist.values())
    colors = plt.cm.Set3(range(len(labels)))

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%",
           startangle=90, pctdistance=0.85)
    ax.set_title("协议分布", fontsize=14)

    # 中心空心 → 环形图效果
    centre_circle = plt.Circle((0, 0), 0.70, fc="white")
    fig.gca().add_artist(centre_circle)

    ax.axis("equal")

    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
    else:
        plt.show()
