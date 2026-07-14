#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/icmp.py — ICMP 报文解析器
===============================
解析字段：
  - Type             (1 byte) — 0=Echo Reply, 8=Echo Request
  - Code             (1 byte)
  - Checksum         (2 bytes)
  - Rest of Header   (4 bytes, 取决于 Type/Code)

Ping 时应该能看到 Echo Request / Echo Reply。
"""

import struct
from .base import ParsedPacket


class ICMPParser:
    """ICMP 报文解析器"""

    NAME = "ICMP"

    TYPE_MAP = {
        0: "Echo Reply (回显应答)",
        3: "Destination Unreachable (目标不可达)",
        5: "Redirect (重定向)",
        8: "Echo Request (回显请求)",
        11: "Time Exceeded (超时)",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """IPv4 Protocol == 1"""
        return packet.ip_proto == 1

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 ICMP 报文

        ICMP 头部结构（8字节）:
          [ type(1) | code(1) | checksum(2) | rest_of_header(4) ]
        """
        # 计算 IPv4 头部长度
        raw = packet.raw_data[packet._ip_offset:]  # 跳到 IP 头
        ihl = (raw[0] & 0x0F) * 4
        icmp_offset = packet._ip_offset + ihl
        icmp_raw = packet.raw_data[icmp_offset:]

        if len(icmp_raw) < 8:
            return packet

        icmp_type = icmp_raw[0]
        icmp_code = icmp_raw[1]
        icmp_checksum = struct.unpack("!H", icmp_raw[2:4])[0]
        rest_header = struct.unpack("!I", icmp_raw[4:8])[0]

        type_desc = ICMPParser.TYPE_MAP.get(icmp_type, f"Unknown Type")
        identifier = (rest_header >> 16) & 0xFFFF
        seq_num = rest_header & 0xFFFF

        packet.proto_name = "ICMP"
        packet.info = f"{type_desc}  Code={icmp_code}"

        # 提取 ICMP 头部之后的 payload
        packet.payload = icmp_raw[8:]

        packet.add_layer("ICMP", {
            "Type": f"{icmp_type} ({type_desc})",
            "Code": icmp_code,
            "Checksum": f"0x{icmp_checksum:04x}",
            "Identifier": f"0x{identifier:04x} ({identifier})",
            "Sequence Number": seq_num,
        }, raw=icmp_raw[:8])

        return packet
