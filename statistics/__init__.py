"""
statistics/ — 流量统计模块
==========================
功能：
  - 协议分布统计
  - Top IP 来源/目的统计
  - 数据包数量/速率统计
  - 可选：流量趋势图（Matplotlib）
"""

from .flow_statistics import (
    compute_statistics,
    compute_traffic_trend,
    format_statistics,
    plot_protocol_distribution,
    plot_traffic_trend,
)
from .alerts import SynFloodDetector, detect_syn_alerts
from .tcp_stream import build_streams, find_stream, format_stream_text, TCPStream

__all__ = [
    "compute_statistics",
    "compute_traffic_trend",
    "format_statistics",
    "plot_protocol_distribution",
    "plot_traffic_trend",
    "SynFloodDetector",
    "detect_syn_alerts",
    "build_streams",
    "find_stream",
    "format_stream_text",
    "TCPStream",
]
