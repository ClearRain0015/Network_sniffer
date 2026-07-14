#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Real-time traffic alert helpers."""

from collections import deque
from typing import Deque, List, Optional

from protocols.base import ParsedPacket


class SynFloodDetector:
    """Detect many TCP SYN packets in a short sliding window."""

    def __init__(self, threshold: int = 30, window_seconds: float = 10.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._syn_times: Deque[float] = deque()

    def observe(self, packet: ParsedPacket) -> Optional[str]:
        """Return an alert message when SYN volume crosses the threshold."""
        if not _is_initial_syn(packet):
            return None

        now = packet.timestamp
        self._syn_times.append(now)
        cutoff = now - self.window_seconds
        while self._syn_times and self._syn_times[0] < cutoff:
            self._syn_times.popleft()

        if len(self._syn_times) >= self.threshold:
            return (
                f"SYN 告警: {self.window_seconds:.0f} 秒内检测到 "
                f"{len(self._syn_times)} 个 TCP SYN 包"
            )
        return None


def detect_syn_alerts(packets: List[ParsedPacket],
                      threshold: int = 30,
                      window_seconds: float = 10.0) -> List[str]:
    """Analyze captured packets and return SYN alert messages."""
    detector = SynFloodDetector(threshold=threshold, window_seconds=window_seconds)
    alerts = []
    for packet in sorted(packets, key=lambda p: p.timestamp):
        alert = detector.observe(packet)
        if alert:
            alerts.append(alert)
    return alerts


def _is_initial_syn(packet: ParsedPacket) -> bool:
    if packet.proto_name != "TCP":
        return False
    try:
        flags = int(packet.tcp_flags)
    except (TypeError, ValueError):
        return False
    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    return syn and not ack
