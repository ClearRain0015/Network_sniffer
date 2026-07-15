#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Traffic statistics for captured packets."""

from collections import Counter
from typing import List

from protocols.base import ParsedPacket


def compute_statistics(packets: List[ParsedPacket]) -> dict:
    if not packets:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "duration": 0,
            "pps": 0,
        }

    total_bytes = sum(p.length for p in packets)
    duration = max(packets[-1].timestamp - packets[0].timestamp, 0.001)
    proto_counter = Counter(_packet_protocol(p) for p in packets)
    src_ip_counter = Counter(p.ip_src for p in packets if p.ip_src)
    dst_ip_counter = Counter(p.ip_dst for p in packets if p.ip_dst)
    ip_counter = Counter()
    ip_counter.update(src_ip_counter)
    ip_counter.update(dst_ip_counter)
    src_port_counter = Counter(p.src_port for p in packets if p.src_port)
    dst_port_counter = Counter(p.dst_port for p in packets if p.dst_port)
    port_counter = Counter()
    port_counter.update(src_port_counter)
    port_counter.update(dst_port_counter)

    size_buckets = {
        "<64B": 0,
        "64-127B": 0,
        "128-255B": 0,
        "256-511B": 0,
        "512-1023B": 0,
        ">=1024B": 0,
    }
    for pkt in packets:
        length = pkt.length
        if length < 64:
            size_buckets["<64B"] += 1
        elif length < 128:
            size_buckets["64-127B"] += 1
        elif length < 256:
            size_buckets["128-255B"] += 1
        elif length < 512:
            size_buckets["256-511B"] += 1
        elif length < 1024:
            size_buckets["512-1023B"] += 1
        else:
            size_buckets[">=1024B"] += 1

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "avg_packet_size": total_bytes / len(packets),
        "duration": duration,
        "pps": len(packets) / duration,
        "bps": total_bytes / duration,
        "protocol_dist": dict(proto_counter.most_common()),
        "top_ips": ip_counter.most_common(10),
        "top_src_ips": src_ip_counter.most_common(10),
        "top_dst_ips": dst_ip_counter.most_common(10),
        "top_ports": port_counter.most_common(10),
        "top_src_ports": src_port_counter.most_common(10),
        "top_dst_ports": dst_port_counter.most_common(10),
        "size_buckets": size_buckets,
        "traffic_trend": compute_traffic_trend(packets),
    }


def _packet_protocol(packet: ParsedPacket) -> str:
    if packet.has_layer("HTTP"):
        return "HTTP"
    if packet.has_layer("DNS"):
        return "DNS"
    if packet.proto_name:
        return packet.proto_name
    if packet.eth_type == 0x0806:
        return "ARP"
    if packet.ip_proto == 6:
        return "TCP"
    if packet.ip_proto == 17:
        return "UDP"
    if packet.ip_proto == 1:
        return "ICMP"
    if packet.ip_src or packet.ip_dst:
        return "IPv4"
    return "Other"


def format_statistics(stats: dict) -> str:
    if stats.get("total_packets", 0) == 0:
        return "暂无数据"

    total = stats["total_packets"]
    lines = [
        "流量统计报告",
        "=" * 48,
        f"数据包数量: {total}",
        f"总字节数: {stats['total_bytes']:,} bytes ({stats['total_bytes'] / 1024:.1f} KB)",
        f"平均包长: {stats['avg_packet_size']:.1f} bytes",
        f"捕获时长: {stats['duration']:.2f} s",
        f"平均速率: {stats['pps']:.1f} packets/s, {stats['bps']:.1f} bytes/s",
        "",
        "协议分布:",
    ]
    for proto, count in stats.get("protocol_dist", {}).items():
        lines.append(f"  {proto:<8} {count:>6} ({_pct(count, total)})")

    lines.extend(["", "Top IP:"])
    for ip, count in stats.get("top_ips", []):
        lines.append(f"  {ip:<18} {count:>6}")

    lines.extend(["", "Top 源 IP:"])
    for ip, count in stats.get("top_src_ips", []):
        lines.append(f"  {ip:<18} {count:>6}")

    lines.extend(["", "Top 目的 IP:"])
    for ip, count in stats.get("top_dst_ips", []):
        lines.append(f"  {ip:<18} {count:>6}")

    lines.extend(["", "Top 端口:"])
    for port, count in stats.get("top_ports", []):
        lines.append(f"  {port:<8} {count:>6}")

    lines.extend(["", "包大小分布:"])
    for bucket, count in stats.get("size_buckets", {}).items():
        lines.append(f"  {bucket:<10} {count:>6} ({_pct(count, total)})")

    return "\n".join(lines)


def format_statistics_html(stats: dict, zoom: int = 100) -> str:
    """Return the statistics report as styled HTML for rich display."""
    z = zoom / 100
    if stats.get("total_packets", 0) == 0:
        return (f'<p style="color:#9aa0a6; text-align:center; '
                f'padding:{int(48*z)}px; font-size:{int(15*z)}px;">暂无数据</p>')

    total = stats["total_packets"]

    def row(label, value, color="#202124"):
        return (
            f'<tr>'
            f'<td style="padding:{int(5*z)}px {int(14*z)}px; color:#5f6368; '
            f'font-size:{int(14*z)}px;">{label}</td>'
            f'<td style="padding:{int(5*z)}px {int(14*z)}px; color:{color}; font-weight:500; '
            f'text-align:right; font-size:{int(14*z)}px;">{value}</td>'
            f'</tr>'
        )

    def section(title, rows_html):
        return (
            f'<div style="margin-bottom:{int(20*z)}px;">'
            f'<h3 style="color:#1a73e8; margin:0 0 {int(10*z)}px 0; '
            f'padding:{int(6*z)}px 0; '
            f'border-bottom:2px solid #1a73e8; font-size:{int(15*z)}px; '
            f'font-weight:600; letter-spacing:0.3px;">{title}</h3>'
            f'<table style="width:100%; border-collapse:collapse;">{rows_html}</table>'
            f'</div>'
        )

    # ── 概览卡片 ──────────────────────────
    cards = (
        f'<div style="display:flex; gap:{int(14*z)}px; margin-bottom:{int(22*z)}px;">'
        f'<div style="flex:1; background:#e8f0fe; border-radius:{int(12*z)}px; '
        f'padding:{int(18*z)}px; text-align:center;">'
        f'<div style="font-size:{int(28*z)}px; font-weight:600; color:#1a73e8;">{total}</div>'
        f'<div style="font-size:{int(12*z)}px; color:#5f6368; margin-top:{int(6*z)}px;">数据包</div></div>'
        f'<div style="flex:1; background:#e6f4ea; border-radius:{int(12*z)}px; '
        f'padding:{int(18*z)}px; text-align:center;">'
        f'<div style="font-size:{int(28*z)}px; font-weight:600; color:#1e8e3e;">{stats["total_bytes"]/1024:.1f} KB</div>'
        f'<div style="font-size:{int(12*z)}px; color:#5f6368; margin-top:{int(6*z)}px;">总流量</div></div>'
        f'<div style="flex:1; background:#fef7e0; border-radius:{int(12*z)}px; '
        f'padding:{int(18*z)}px; text-align:center;">'
        f'<div style="font-size:{int(28*z)}px; font-weight:600; color:#f9ab00;">{stats["pps"]:.1f}</div>'
        f'<div style="font-size:{int(12*z)}px; color:#5f6368; margin-top:{int(6*z)}px;">包/秒</div></div>'
        f'<div style="flex:1; background:#f3e8fd; border-radius:{int(12*z)}px; '
        f'padding:{int(18*z)}px; text-align:center;">'
        f'<div style="font-size:{int(28*z)}px; font-weight:600; color:#9334e6;">{stats["duration"]:.2f} s</div>'
        f'<div style="font-size:{int(12*z)}px; color:#5f6368; margin-top:{int(6*z)}px;">捕获时长</div></div>'
        f'</div>'
    )

    html = f'<div style="font-family:\'Google Sans\',\'Segoe UI\',\'Microsoft YaHei UI\',sans-serif; padding:4px;">{cards}'

    # ── 概览表 ─────────────────────────────
    overview = "".join([
        row("平均包长", f'{stats["avg_packet_size"]:.1f} bytes'),
        row("平均速率", f'{stats["bps"]:.1f} bytes/s'),
    ])
    html += section("概览", overview)

    # ── 协议分布 ──────────────────────────
    proto_rows = "".join(
        row(proto, f'{count} ({_pct(count, total)})',
            "#1a73e8" if proto in ("TCP", "HTTP", "HTTPS") else
            "#1e8e3e" if proto in ("UDP", "DNS") else
            "#f9ab00" if proto == "ICMP" else "#202124")
        for proto, count in stats.get("protocol_dist", {}).items()
    )
    html += section("协议分布", proto_rows)

    # ── Top IP ────────────────────────────
    ip_rows = "".join(row(ip, str(cnt)) for ip, cnt in stats.get("top_ips", []))
    html += section("Top IP 地址", ip_rows)

    # ── Top 端口 ──────────────────────────
    port_rows = "".join(row(str(port), str(cnt)) for port, cnt in stats.get("top_ports", []))
    html += section("Top 端口", port_rows)

    # ── 包大小分布 ────────────────────────
    size_rows = "".join(
        row(bucket, f'{count} ({_pct(count, total)})')
        for bucket, count in stats.get("size_buckets", {}).items()
    )
    html += section("包大小分布", size_rows)

    html += "</div>"
    return html


def _pct(count: int, total: int) -> str:
    return f"{(count / total * 100 if total else 0):.1f}%"


def plot_protocol_distribution(stats: dict, save_path: str = None, zoom: int = 100):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is required for plotting")
        return

    proto_dist = stats.get("protocol_dist", {})
    if not proto_dist:
        return

    z = zoom / 100
    _setup_google_style()

    labels = list(proto_dist.keys())
    sizes = list(proto_dist.values())
    google_colors = ["#1a73e8", "#ea4335", "#f9ab00", "#1e8e3e",
                     "#4285f4", "#ff6d01", "#34a853", "#9334e6",
                     "#46bdc6", "#fbbc04"]
    colors = [google_colors[i % len(google_colors)] for i in range(len(labels))]

    fig, ax = plt.subplots(figsize=(9.5 * z, 6.5 * z))
    fig.patch.set_facecolor("#ffffff")
    ax.set_facecolor("#ffffff")

    wedges, texts, autotexts = ax.pie(
        sizes, labels=None, autopct="%1.1f%%",
        startangle=90, colors=colors,
        pctdistance=0.78,
        wedgeprops={"linewidth": 2 * z, "edgecolor": "#ffffff"},
    )
    for at in autotexts:
        at.set_color("#202124")
        at.set_fontweight("600")
        at.set_fontsize(11 * z)
    ax.set_title("Protocol Distribution", color="#202124",
                 fontsize=19 * z, fontweight="600", pad=22 * z)
    ax.axis("equal")

    # Legend to the right
    ax.legend(
        wedges, labels,
        loc="center left",
        bbox_to_anchor=(1, 0.5),
        frameon=False,
        fontsize=11 * z,
        labelcolor="#202124",
        handletextpad=0.8,
    )

    fig.tight_layout(pad=2)
    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    else:
        plt.show()


def _setup_google_style():
    """Apply Google Material Design matplotlib style."""
    try:
        import matplotlib.pyplot as plt
        import matplotlib as mpl
    except ImportError:
        return
    try:
        plt.style.use("seaborn-v0_8-whitegrid")
    except Exception:
        pass
    mpl.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Segoe UI", "Microsoft YaHei UI", "Arial", "sans-serif"],
        "axes.edgecolor": "#dadce0",
        "axes.linewidth": 0.8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "grid.color": "#e8eaed",
        "grid.linewidth": 0.5,
        "xtick.color": "#5f6368",
        "ytick.color": "#5f6368",
    })


def compute_traffic_trend(packets: List[ParsedPacket], bucket_seconds: int = 1) -> List[dict]:
    """Group packets into time buckets for trend charts."""
    if not packets:
        return []
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")

    start = packets[0].timestamp
    buckets = {}
    for packet in packets:
        bucket_index = int((packet.timestamp - start) // bucket_seconds)
        bucket = buckets.setdefault(bucket_index, {
            "time": bucket_index * bucket_seconds,
            "packets": 0,
            "bytes": 0,
        })
        bucket["packets"] += 1
        bucket["bytes"] += packet.length

    return [buckets[i] for i in sorted(buckets)]


def plot_traffic_trend(packets: List[ParsedPacket], bucket_seconds: int = 1,
                       save_path: str = None, zoom: int = 100) -> bool:
    """Plot packet and byte trends over time with Google Material style."""
    trend = compute_traffic_trend(packets, bucket_seconds)
    if not trend:
        return False

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is required for plotting")
        return False

    z = zoom / 100
    _setup_google_style()

    times = [item["time"] for item in trend]
    packet_counts = [item["packets"] for item in trend]
    byte_counts = [item["bytes"] for item in trend]

    fig, ax_packets = plt.subplots(figsize=(12 * z, 5.8 * z))
    fig.patch.set_facecolor("#ffffff")
    ax_packets.set_facecolor("#ffffff")

    # Fill beneath the packet line
    ax_packets.fill_between(times, packet_counts, alpha=0.08, color="#1a73e8")
    ax_packets.plot(times, packet_counts, marker="", color="#1a73e8",
                    linewidth=2.2 * z, label="Packets/s", zorder=3)
    ax_packets.set_xlabel("Time (s)", color="#5f6368", fontsize=12 * z, labelpad=10 * z)
    ax_packets.set_ylabel("Packets", color="#1a73e8", fontsize=12 * z, labelpad=10 * z)
    ax_packets.tick_params(axis="both", colors="#5f6368", labelsize=10.5 * z)
    ax_packets.tick_params(axis="y", labelcolor="#1a73e8")
    ax_packets.spines["top"].set_visible(False)

    ax_bytes = ax_packets.twinx()
    ax_bytes.fill_between(times, byte_counts, alpha=0.06, color="#ea4335")
    ax_bytes.plot(times, byte_counts, marker="", color="#ea4335",
                  linewidth=2.2 * z, label="Bytes/s", zorder=3)
    ax_bytes.set_ylabel("Bytes", color="#ea4335", fontsize=12 * z, labelpad=10 * z)
    ax_bytes.tick_params(axis="y", labelcolor="#ea4335", labelsize=10.5 * z)
    ax_bytes.spines["top"].set_visible(False)

    ax_packets.set_title("Traffic Trend", color="#202124",
                         fontsize=19 * z, fontweight="600", pad=22 * z)
    ax_packets.grid(True, linestyle="-", linewidth=0.5, alpha=0.6, color="#e8eaed")

    lines1, labels1 = ax_packets.get_legend_handles_labels()
    lines2, labels2 = ax_bytes.get_legend_handles_labels()
    ax_packets.legend(
        lines1 + lines2, labels1 + labels2, loc="upper right",
        facecolor="#ffffff", edgecolor="#dadce0",
        labelcolor="#202124", framealpha=1.0, fontsize=10.5 * z,
        borderpad=0.6, borderaxespad=0.8,
        handlelength=1.6,
    )

    fig.tight_layout(pad=2.5)
    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight", facecolor="#ffffff")
    else:
        plt.show()
    return True
