#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/ip.py — IPv4 报文解析器
==============================
解析字段：
  - Version          (4 bits)
  - Header Length    (4 bits)
  - DSCP / ECN       (1 byte)
  - Total Length     (2 bytes)
  - Identification   (2 bytes)   ← IP分片重组关键字段
  - Flags            (3 bits)    ← MF/DF
  - Fragment Offset  (13 bits)   ← IP分片重组关键字段
  - TTL              (1 byte)
  - Protocol         (1 byte)    → 决定上层解析器
  - Header Checksum  (2 bytes)
  - Source IP        (4 bytes)
  - Destination IP   (4 bytes)

Protocol 常见值:
  1  = ICMP
  6  = TCP
  17 = UDP
"""

import struct
from .base import ParsedPacket


class IPv4Parser:
    """IPv4 报文解析器"""

    NAME = "IPv4"

    PROTO_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        2: "IGMP",
        89: "OSPF",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """以太网 EtherType == 0x0800（IPv4）"""
        return packet.eth_type == 0x0800 and len(packet.raw_data) >= 34

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 IPv4 报文头

        IPv4 头部结构（最小20字节）:
          [ ver_ihl(1) | dscp_ecn(1) | total_len(2) |
            id(2) | flags_frag(2) |
            ttl(1) | proto(1) | checksum(2) |
            src_ip(4) | dst_ip(4) ]
        """
        raw = packet.raw_data[14:]  # 跳过以太网头

        if len(raw) < 20:
            return packet

        # 版本 + 头部长度
        ver_ihl = raw[0]
        version = (ver_ihl >> 4) & 0x0F
        ihl = ver_ihl & 0x0F
        header_len = ihl * 4  # 单位：字节

        if len(raw) < header_len:
            return packet

        # DSCP + ECN
        dscp_ecn = raw[1]

        # 总长度
        total_length = struct.unpack("!H", raw[2:4])[0]

        # 标识
        identification = struct.unpack("!H", raw[4:6])[0]

        # 标志 + 片偏移
        flags_frag = struct.unpack("!H", raw[6:8])[0]
        flags = (flags_frag >> 13) & 0x07     # 高3位
        fragment_offset = flags_frag & 0x1FFF  # 低13位

        df_flag = (flags & 0x02) != 0  # Don't Fragment
        mf_flag = (flags & 0x01) != 0  # More Fragments

        # TTL
        ttl = raw[8]

        # 协议号
        proto = raw[9]

        # 校验和
        checksum = struct.unpack("!H", raw[10:12])[0]

        # 源/目的 IP
        src_ip = IPv4Parser._format_ip(raw[12:16])
        dst_ip = IPv4Parser._format_ip(raw[16:20])

        # 填入 packet 顶层字段
        packet.ip_src = src_ip
        packet.ip_dst = dst_ip
        packet.ip_proto = proto
        packet.ip_len = total_length
        packet.ip_id = identification
        packet.ip_flags = flags
        packet.ip_frag = fragment_offset
        packet.ip_ttl = ttl

        proto_name = IPv4Parser.PROTO_MAP.get(proto, f"Unknown({proto})")
        packet.proto_name = proto_name
        packet.info = f"{src_ip} → {dst_ip}  TTL={ttl}"

        packet.add_layer("IPv4", {
            "Version": version,
            "Header Length": f"{header_len} bytes ({ihl} words)",
            "DSCP/ECN": f"0x{dscp_ecn:02x}",
            "Total Length": total_length,
            "Identification": f"0x{identification:04x} ({identification})",
            "Flags": f"0x{flags:01x} (DF={1 if df_flag else 0}, MF={1 if mf_flag else 0})",
            "Fragment Offset": fragment_offset,
            "TTL": ttl,
            "Protocol": f"{proto} ({proto_name})",
            "Header Checksum": f"0x{checksum:04x}",
            "Source IP": src_ip,
            "Destination IP": dst_ip,
        }, raw=raw[0:header_len])

        return packet

    @staticmethod
    def _format_ip(addr: bytes) -> str:
        return ".".join(str(b) for b in addr)
