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


def _pct(count: int, total: int) -> str:
    return f"{(count / total * 100 if total else 0):.1f}%"


def plot_protocol_distribution(stats: dict, save_path: str = None):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is required for plotting")
        return

    proto_dist = stats.get("protocol_dist", {})
    if not proto_dist:
        return

    labels = list(proto_dist.keys())
    sizes = list(proto_dist.values())
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90)
    ax.set_title("Protocol Distribution")
    ax.axis("equal")

    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
    else:
        plt.show()


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
                       save_path: str = None) -> bool:
    """Plot packet and byte trends over time."""
    trend = compute_traffic_trend(packets, bucket_seconds)
    if not trend:
        return False

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is required for plotting")
        return False

    times = [item["time"] for item in trend]
    packet_counts = [item["packets"] for item in trend]
    byte_counts = [item["bytes"] for item in trend]

    fig, ax_packets = plt.subplots()
    ax_packets.plot(times, packet_counts, marker="o", color="#2563eb", label="Packets/s")
    ax_packets.set_xlabel("Time (s)")
    ax_packets.set_ylabel("Packets", color="#2563eb")
    ax_packets.tick_params(axis="y", labelcolor="#2563eb")

    ax_bytes = ax_packets.twinx()
    ax_bytes.plot(times, byte_counts, marker="s", color="#dc2626", label="Bytes/s")
    ax_bytes.set_ylabel("Bytes", color="#dc2626")
    ax_bytes.tick_params(axis="y", labelcolor="#dc2626")

    ax_packets.set_title("Traffic Trend")
    ax_packets.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
    fig.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
    else:
        plt.show()
    return True
