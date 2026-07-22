#!/usr/bin/env python3
# -*- coding: utf-8 -*-
try:
    import matplotlib
    matplotlib.use("Agg")  # 非交互模式，避免 PyQt5 冲突
except ImportError:
    pass

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
        "avg_packet_size": total_bytes / len(packets),
        "duration": duration,
        "pps": len(packets) / duration,
        "bps": total_bytes / duration,
        "protocol_dist": dict(proto_counter.most_common()),
        "top_src_ips": src_ip_counter.most_common(10),
        "top_dst_ips": dst_ip_counter.most_common(10),
        "top_src_ports": src_port_counter.most_common(10),
        "top_dst_ports": dst_port_counter.most_common(10),
        "size_buckets": size_buckets,
        "traffic_trend": compute_traffic_trend(packets),
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


# ── 图表显示工具 ────────────────────────────

def _show_plot(fig, save_path: str = None):
    """安全地显示或保存图表（避免 PyQt5 事件循环冲突）"""
    import tempfile, os, subprocess, sys

    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
        return

    # 保存到临时文件，用系统默认程序打开
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        tmp_path = f.name
    try:
        fig.savefig(tmp_path, dpi=150, bbox_inches="tight")
        import matplotlib.pyplot as plt
        plt.close(fig)
        if sys.platform == "win32":
            os.startfile(tmp_path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", tmp_path])
        else:
            subprocess.Popen(["xdg-open", tmp_path])
    except Exception:
        pass


# ── 可选：流量图表 ──────────────────────────

def plot_protocol_distribution(stats: dict, save_path: str = None):
    """
    绘制协议分布饼图（需要 matplotlib）
    """
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] 需要 matplotlib")
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

    _show_plot(fig, save_path)


# ── 流量趋势 ──────────────────────────────

def compute_traffic_trend(packets, interval: float = 1.0, bucket_seconds: float = None) -> list:
    """计算按时间分桶的流量趋势（每秒包数）"""
    if bucket_seconds is not None:
        interval = bucket_seconds
    if not packets:
        return []
    start = packets[0].timestamp
    buckets = {}
    for p in packets:
        bucket = int((p.timestamp - start) / interval)
        if bucket not in buckets:
            buckets[bucket] = {"packets": 0, "bytes": 0}
        buckets[bucket]["packets"] += 1
        buckets[bucket]["bytes"] += p.length
    max_bucket = max(buckets.keys()) if buckets else -1
    result = []
    for i in range(max_bucket + 1):
        entry = buckets.get(i, {"packets": 0, "bytes": 0})
        result.append({
            "time": i * interval,
            "packets": entry["packets"],
            "bytes": entry["bytes"],
        })
    return result


def plot_traffic_trend(trend: list, save_path: str = None):
    """绘制流量趋势折线图"""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("[!] 需要 matplotlib")
        return False
    if not trend:
        return False
    x = [t["time"] for t in trend]
    y = [t["packets"] for t in trend]
    fig = plt.figure(figsize=(10, 4))
    plt.plot(x, y, marker="o", markersize=2, linewidth=1)
    plt.xlabel("时间 (秒)")
    plt.ylabel("数据包数")
    plt.title("流量趋势")
    plt.grid(True, alpha=0.3)
    _show_plot(fig, save_path)
    return True


# ── HTML 统计报告 ──────────────────────────

def _pct(count, total):
    return f"{count/total*100:.1f}%" if total else "0%"


def format_statistics_html(stats: dict, zoom: int = 100) -> str:
    """Return the statistics report as styled HTML for rich display."""
    z = zoom / 100
    if stats.get("total_packets", 0) == 0:
        return (f'<p style="color:#9aa0a6;text-align:center;'
                f'padding:{int(48*z)}px;font-size:{int(15*z)}px;">暂无数据</p>')

    total = stats["total_packets"]

    def row(label, value, color="#202124"):
        return (
            f'<tr>'
            f'<td style="padding:{int(5*z)}px {int(14*z)}px;color:#5f6368;'
            f'font-size:{int(14*z)}px;">{label}</td>'
            f'<td style="padding:{int(5*z)}px {int(14*z)}px;color:{color};'
            f'font-weight:500;text-align:right;font-size:{int(14*z)}px;">{value}</td>'
            f'</tr>'
        )

    def section(title, rows_html):
        return (
            f'<div style="margin-bottom:{int(20*z)}px;">'
            f'<h3 style="color:#1a73e8;margin:0 0 {int(10*z)}px 0;'
            f'padding:{int(6*z)}px 0;border-bottom:2px solid #1a73e8;'
            f'font-size:{int(15*z)}px;font-weight:600;">{title}</h3>'
            f'<table style="width:100%;border-collapse:collapse;">{rows_html}</table>'
            f'</div>'
        )

    # 概览卡片
    cards = (
        f'<div style="display:flex;gap:{int(14*z)}px;margin-bottom:{int(22*z)}px;">'
        f'<div style="flex:1;background:#e8f0fe;border-radius:{int(12*z)}px;'
        f'padding:{int(18*z)}px;text-align:center;">'
        f'<div style="font-size:{int(28*z)}px;font-weight:600;color:#1a73e8;">{total}</div>'
        f'<div style="font-size:{int(12*z)}px;color:#5f6368;margin-top:{int(6*z)}px;">数据包</div></div>'
        f'<div style="flex:1;background:#e6f4ea;border-radius:{int(12*z)}px;'
        f'padding:{int(18*z)}px;text-align:center;">'
        f'<div style="font-size:{int(28*z)}px;font-weight:600;color:#1e8e3e;">{stats["total_bytes"]/1024:.1f} KB</div>'
        f'<div style="font-size:{int(12*z)}px;color:#5f6368;margin-top:{int(6*z)}px;">总流量</div></div>'
        f'<div style="flex:1;background:#fef7e0;border-radius:{int(12*z)}px;'
        f'padding:{int(18*z)}px;text-align:center;">'
        f'<div style="font-size:{int(28*z)}px;font-weight:600;color:#f9ab00;">{stats["pps"]:.1f}</div>'
        f'<div style="font-size:{int(12*z)}px;color:#5f6368;margin-top:{int(6*z)}px;">包/秒</div></div>'
        f'<div style="flex:1;background:#f3e8fd;border-radius:{int(12*z)}px;'
        f'padding:{int(18*z)}px;text-align:center;">'
        f'<div style="font-size:{int(28*z)}px;font-weight:600;color:#9334e6;">{stats["duration"]:.2f} s</div>'
        f'<div style="font-size:{int(12*z)}px;color:#5f6368;margin-top:{int(6*z)}px;">捕获时长</div></div>'
        f'</div>'
    )

    html = f'<div style="font-family:Segoe UI,sans-serif;padding:4px;">{cards}'

    # 概览表
    overview = "".join([
        row("平均包长", f'{stats["avg_packet_size"]:.1f} bytes'),
        row("平均速率", f'{stats["bps"]:.1f} bytes/s'),
    ])
    html += section("概览", overview)

    # 协议分布
    proto_rows = "".join([
        row(proto, f'{count} ({_pct(count, total)})')
        for proto, count in stats.get("protocol_dist", {}).items()
    ])
    html += section("协议分布", proto_rows)

    # Top IP
    ip_rows = "".join([
        row(ip, str(count)) for ip, count in stats.get("top_ips", [])
    ])
    html += section("Top IP", ip_rows)

    # 包大小
    size_rows = "".join([
        row(bucket, f'{count} ({_pct(count, total)})')
        for bucket, count in stats.get("size_buckets", {}).items()
    ])
    html += section("包大小分布", size_rows)

    html += '</div>'
    return html
