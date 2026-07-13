#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/arp.py — ARP 报文解析器
==============================
解析字段：
  - Hardware Type   (2 bytes)
  - Protocol Type   (2 bytes)
  - HW Addr Length  (1 byte)
  - Proto Addr Len  (1 byte)
  - Opcode          (2 bytes) — 1=Request, 2=Reply
  - Sender MAC      (6 bytes)
  - Sender IP       (4 bytes)
  - Target MAC      (6 bytes)
  - Target IP       (4 bytes)

浏览网页时 ARP 会大量出现。
"""

import struct
from .base import ParsedPacket


class ARPParser:
    """ARP 报文解析器"""

    NAME = "ARP"

    OPCODE_MAP = {
        1: "Request (请求)",
        2: "Reply (应答)",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """以太网帧 EtherType == 0x0806 时为 ARP"""
        offset = packet.network_offset or 14
        return packet.eth_type == 0x0806 and len(packet.raw_data) >= offset + 28

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 ARP 报文（以太网帧 payload 区域）

        ARP 报文结构:
          [ hw_type(2) | proto_type(2) | hw_len(1) | proto_len(1) |
            opcode(2)  | sender_mac(6) | sender_ip(4) |
            target_mac(6) | target_ip(4) ]
        """
        arp_offset = packet.network_offset or 14
        raw = packet.raw_data[arp_offset:]  # 跳过以太网头

        if len(raw) < 28:
            return packet

        hw_type, proto_type, hw_len, proto_len = struct.unpack("!HHBB", raw[0:6])
        opcode = struct.unpack("!H", raw[6:8])[0]

        offset = 8
        sender_mac = ARPParser._format_mac(raw[offset:offset + hw_len])
        offset += hw_len
        sender_ip = ARPParser._format_ip(raw[offset:offset + proto_len])
        offset += proto_len
        target_mac = ARPParser._format_mac(raw[offset:offset + hw_len])
        offset += hw_len
        target_ip = ARPParser._format_ip(raw[offset:offset + proto_len])

        packet.proto_name = "ARP"
        packet.ip_src = sender_ip
        packet.ip_dst = target_ip
        packet.transport_offset = 0
        packet.set_payload(raw[28:], arp_offset + 28)
        packet.info = f"Who has {target_ip}? Tell {sender_ip}" if opcode == 1 else \
                      f"{sender_ip} is at {sender_mac}"

        packet.add_layer("ARP", {
            "Hardware Type": hw_type,
            "Protocol Type": f"0x{proto_type:04x}",
            "HW Address Length": hw_len,
            "Protocol Address Length": proto_len,
            "Opcode": f"{opcode} ({ARPParser.OPCODE_MAP.get(opcode, 'Unknown')})",
            "Sender MAC": sender_mac,
            "Sender IP": sender_ip,
            "Target MAC": target_mac,
            "Target IP": target_ip,
        }, raw=raw[0:28])

        return packet

    @staticmethod
    def _format_mac(addr: bytes) -> str:
        return ":".join(f"{b:02x}" for b in addr)

    @staticmethod
    def _format_ip(addr: bytes) -> str:
        return ".".join(str(b) for b in addr)
