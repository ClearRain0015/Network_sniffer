#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/ethernet.py — 以太网帧解析器
==================================
解析字段：
  - Destination MAC  (6 bytes)
  - Source MAC       (6 bytes)
  - EtherType        (2 bytes)

EtherType 常见值：
  0x0800  IPv4
  0x0806  ARP
  0x86DD  IPv6
  0x8100  VLAN tag
"""

import struct
from .base import ParsedPacket, ProtocolLayer


class EthernetParser:
    """以太网帧解析器"""

    NAME = "Ethernet"

    # 常见 EtherType 映射
    ETHERTYPE_MAP = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "802.1Q VLAN",
        0x8847: "MPLS",
        0x8863: "PPPoE Discovery",
        0x8864: "PPPoE Session",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """判断是否能解析以太网帧（长度至少 14 字节）"""
        if len(packet.raw_data) < 14:
            return False
        # Raw socket fallback can start at IPv4 instead of Ethernet.
        first = packet.raw_data[0]
        return not ((first >> 4) == 4 and (first & 0x0F) >= 5)

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 Ethernet 帧头（前14字节）

        结构:
          [ dst_mac(6) | src_mac(6) | ethertype(2) ]
        """
        raw = packet.raw_data

        # 解析
        dst_mac = EthernetParser._format_mac(raw[0:6])
        src_mac = EthernetParser._format_mac(raw[6:12])
        ethertype = struct.unpack("!H", raw[12:14])[0]
        header_len = 14
        vlan_id = None
        inner_type = None

        if ethertype == 0x8100 and len(raw) >= 18:
            tci = struct.unpack("!H", raw[14:16])[0]
            vlan_id = tci & 0x0FFF
            inner_type = struct.unpack("!H", raw[16:18])[0]
            ethertype = inner_type
            header_len = 18

        # 填入 packet 顶层字段
        packet.eth_dst = dst_mac
        packet.eth_src = src_mac
        packet.eth_type = ethertype
        packet.network_offset = header_len

        # 添加协议层
        fields = {
            "Destination MAC": dst_mac,
            "Source MAC": src_mac,
            "EtherType": f"0x{ethertype:04x} ({EthernetParser.ETHERTYPE_MAP.get(ethertype, 'Unknown')})",
        }
        if vlan_id is not None:
            fields["802.1Q VLAN ID"] = vlan_id
            fields["Inner EtherType"] = f"0x{inner_type:04x} ({EthernetParser.ETHERTYPE_MAP.get(inner_type, 'Unknown')})"
        packet.add_layer("Ethernet", fields, raw=raw[0:header_len])

        return packet

    @staticmethod
    def _format_mac(addr_bytes: bytes) -> str:
        """将 6 字节 MAC 地址格式化为 'aa:bb:cc:dd:ee:ff'"""
        return ":".join(f"{b:02x}" for b in addr_bytes)
