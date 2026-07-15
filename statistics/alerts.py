#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
statistics/alerts.py — 实时告警模块
===================================
检测异常流量模式，如 SYN 洪水攻击。
"""

from collections import defaultdict
import time


class SynFloodDetector:
    """SYN 洪水检测器"""

    def __init__(self, threshold: int = 100, window: float = 1.0,
                 window_seconds: float = None):
        self.threshold = threshold
        self.window = window_seconds if window_seconds is not None else window
        self._records = defaultdict(list)

    def observe(self, packet):
        """接收 ParsedPacket，返回告警消息或 None"""
        if packet.proto_name != "TCP" or not (packet.tcp_flags & 0x02):
            return None
        triggered = self.feed(packet.ip_src, packet.timestamp)
        if triggered:
            return f"SYN 告警: {packet.ip_src} 发送大量 SYN 包"
        return None

    def feed(self, src_ip: str, timestamp: float = None) -> bool:
        if timestamp is None:
            timestamp = time.time()
        self._records[src_ip].append(timestamp)
        self._cleanup(src_ip, timestamp)
        return len(self._records[src_ip]) >= self.threshold

    def _cleanup(self, src_ip: str, now: float):
        cutoff = now - self.window
        self._records[src_ip] = [
            t for t in self._records[src_ip] if t >= cutoff
        ]
        if not self._records[src_ip]:
            del self._records[src_ip]

    def get_top_syn_sources(self, n: int = 10) -> list:
        ranked = sorted(
            [(ip, len(times)) for ip, times in self._records.items()],
            key=lambda x: x[1], reverse=True,
        )
        return ranked[:n]

    def reset(self):
        self._records.clear()


def detect_syn_alerts(packets, threshold: int = 100,
                       window_seconds: float = None) -> list:
    detector = SynFloodDetector(threshold=threshold,
                                window_seconds=window_seconds)
    for packet in packets:
        if packet.proto_name == "TCP" and (packet.tcp_flags & 0x02):
            detector.feed(packet.ip_src, packet.timestamp)
    result = []
    for ip, count in detector.get_top_syn_sources(10):
        if count >= threshold:
            result.append((ip, count,
                           f"SYN Flood: {ip} 发送了 {count} 个 SYN 包"))
    return result
