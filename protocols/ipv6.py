#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/ipv6.py — IPv6 报文解析器
===============================
解析 IPv6 固定 40 字节头部。

IPv6 头部结构:
  [ ver_tc_fl(4) | payload_len(2) | next_header(1) | hop_limit(1) |
    src_ip(16) | dst_ip(16) ]

Next Header 常见值:
  6  = TCP
  17 = UDP
  58 = ICMPv6
"""

import struct
from .base import ParsedPacket


class IPv6Parser:
    """IPv6 报文解析器"""

    NAME = "IPv6"

    NEXT_HEADER_MAP = {
        6: "TCP",
        17: "UDP",
        58: "ICMPv6",
        0: "Hop-by-Hop Options",
        43: "Routing Header",
        44: "Fragment Header",
        50: "ESP",
        51: "AH",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        return packet.eth_type == 0x86DD and len(packet.raw_data) >= 54

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        raw = packet.raw_data[14:]  # 跳过以太网头

        if len(raw) < 40:
            return packet

        ver_tc_fl = struct.unpack("!I", raw[0:4])[0]
        version = (ver_tc_fl >> 28) & 0x0F
        traffic_class = (ver_tc_fl >> 20) & 0xFF
        flow_label = ver_tc_fl & 0xFFFFF

        payload_length = struct.unpack("!H", raw[4:6])[0]
        next_header = raw[6]
        hop_limit = raw[7]

        src_ip = IPv6Parser._format_ipv6(raw[8:24])
        dst_ip = IPv6Parser._format_ipv6(raw[24:40])

        proto_name = IPv6Parser.NEXT_HEADER_MAP.get(next_header, f"Unknown({next_header})")

        packet.ip_src = src_ip
        packet.ip_dst = dst_ip
        packet.ip_proto = next_header
        packet.ip_ttl = hop_limit
        packet.proto_name = proto_name
        packet.info = f"{src_ip} → {dst_ip}  Hop Limit={hop_limit}"

        packet.add_layer("IPv6", {
            "Version": version,
            "Traffic Class": f"0x{traffic_class:02x}",
            "Flow Label": f"0x{flow_label:05x}",
            "Payload Length": payload_length,
            "Next Header": f"{next_header} ({proto_name})",
            "Hop Limit": hop_limit,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
        }, raw=raw[0:40])

        return packet

    @staticmethod
    def _format_ipv6(addr: bytes) -> str:
        """将 16 字节 IPv6 地址格式化为压缩形式"""
        parts = [f"{(addr[i] << 8) | addr[i + 1]:04x}" for i in range(0, 16, 2)]
        # 简单处理：全零压缩为 ::
        ip_str = ":".join(parts)
        # 去掉前导零和最长连续零段
        return IPv6Parser._compress_ipv6(parts)

    @staticmethod
    def _compress_ipv6(parts: list) -> str:
        """IPv6 地址压缩（简化版）"""
        # 标准格式
        full = ":".join(p for p in parts)
        # 查找最长连续零段并压缩为 ::
        best_start, best_len = 0, 0
        i = 0
        while i < 8:
            if parts[i] == "0000":
                j = i
                while j < 8 and parts[j] == "0000":
                    j += 1
                if j - i > best_len:
                    best_start, best_len = i, j - i
                i = j
            else:
                i += 1

        if best_len >= 2:
            left = ":".join(parts[:best_start])
            right = ":".join(parts[best_start + best_len:])
            if left and right:
                full = f"{left}::{right}"
            elif left:
                full = f"{left}::"
            else:
                full = f"::{right}"

        return full
