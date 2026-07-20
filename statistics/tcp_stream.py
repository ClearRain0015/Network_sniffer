#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
statistics/tcp_stream.py — TCP 流跟踪
=====================================
类似 Wireshark 的 Follow TCP Stream 功能。
将同一 TCP 连接的双向数据拼接成完整对话。
"""

from collections import defaultdict
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass, field

from protocols.base import ParsedPacket


@dataclass
class StreamPacket:
    """流中的一个包"""
    packet: ParsedPacket
    direction: str  # "→" 或 "←"
    seq: int
    payload: bytes


@dataclass
class TCPStream:
    """一个完整的 TCP 流"""
    key: tuple
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: List[StreamPacket] = field(default_factory=list)

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def label(self) -> str:
        return f"{self.src_ip}:{self.src_port} ↔ {self.dst_ip}:{self.dst_port}"

    def get_payload_hex(self, max_len: int = 65536) -> str:
        """返回拼接后的原始数据十六进制"""
        data = b"".join(p.payload for p in self.packets if p.payload)
        if len(data) > max_len:
            data = data[:max_len]
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(
                chr(b) if 32 <= b < 127 else "." for b in chunk
            )
            lines.append(f"{i:08x}  {hex_part:<48}  {ascii_part}")
        return "\n".join(lines)

    def get_payload_text(self, max_len: int = 65536) -> str:
        """返回拼接后的可读文本"""
        data = b"".join(p.payload for p in self.packets if p.payload)
        if len(data) > max_len:
            data = data[:max_len]
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.decode("latin-1", errors="replace")


def _stream_key(packet: ParsedPacket) -> Optional[tuple]:
    """从 TCP 包生成流标识 key，双向归一化"""
    if packet.proto_name != "TCP" or not packet.ip_src or not packet.ip_dst:
        return None
    a = (packet.ip_src, packet.src_port)
    b = (packet.ip_dst, packet.dst_port)
    return tuple(sorted([a, b]))


def build_streams(packets: List[ParsedPacket]) -> List[TCPStream]:
    """从包列表构建所有 TCP 流"""
    groups: Dict[tuple, List[ParsedPacket]] = defaultdict(list)
    for p in packets:
        key = _stream_key(p)
        if key:
            groups[key].append(p)

    streams = []
    for key, pkts in groups.items():
        pkts.sort(key=lambda p: p.timestamp)
        # 确定方向
        first = pkts[0]
        src_ip, src_port = first.ip_src, first.src_port
        dst_ip, dst_port = first.ip_dst, first.dst_port

        stream = TCPStream(
            key=key,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )
        for p in pkts:
            direction = "→" if p.ip_src == src_ip and p.src_port == src_port else "←"
            stream.packets.append(StreamPacket(
                packet=p, direction=direction,
                seq=p.tcp_seq if p.tcp_seq else 0,
                payload=p.payload if p.payload else b"",
            ))
        streams.append(stream)

    # 按包数降序
    streams.sort(key=lambda s: s.packet_count, reverse=True)
    return streams


def find_stream(packets: List[ParsedPacket],
                target: ParsedPacket) -> Optional[TCPStream]:
    """找到包含指定包的 TCP 流"""
    key = _stream_key(target)
    if not key:
        return None
    matching = [p for p in packets if _stream_key(p) == key]
    if not matching:
        return None
    # build 单条流
    return build_streams(matching)[0] if matching else None


def format_stream_text(stream: TCPStream) -> str:
    """将 TCP 流格式化为可读文本"""
    lines = [
        f"{'═' * 60}",
        f"  TCP 流: {stream.label}",
        f"  共 {stream.packet_count} 个包",
        f"{'═' * 60}",
        "",
    ]
    for sp in stream.packets:
        p = sp.packet
        ts = p.timestamp_str
        direction = sp.direction
        info = p.info or p.summary or ""
        lines.append(f"[{ts}] {direction} {info}")
        if sp.payload:
            try:
                text = sp.payload.decode("utf-8", errors="replace")
                # 截断每行
                for line in text.split("\n")[:20]:  # 每个包最多显示20行payload
                    lines.append(f"       {line}")
                if len(text.split("\n")) > 20:
                    lines.append(f"       ... ({len(sp.payload)} bytes)")
            except Exception:
                lines.append(f"       [{len(sp.payload)} bytes binary]")
        lines.append("")
    return "\n".join(lines)
