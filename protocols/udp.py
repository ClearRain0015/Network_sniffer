#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/udp.py — UDP 报文解析器
==============================
解析字段：
  - Source Port       (2 bytes)
  - Destination Port  (2 bytes)
  - Length            (2 bytes)
  - Checksum          (2 bytes)
"""

import struct
from .base import ParsedPacket


class UDPParser:
    """UDP 报文解析器"""

    NAME = "UDP"

    PORT_SERVICE = {
        53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
        69: "TFTP", 123: "NTP", 161: "SNMP",
        514: "Syslog", 5353: "mDNS",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """IPv4 Protocol == 17"""
        return packet.ip_proto == 17

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 UDP 报文头

        UDP 头部结构（8字节）:
          [ src_port(2) | dst_port(2) | length(2) | checksum(2) ]
        """
        raw = packet.raw_data[packet._ip_offset:]  # 跳到 IP 头
        ip_ihl = (raw[0] & 0x0F) * 4
        udp_offset = packet._ip_offset + ip_ihl
        udp_raw = packet.raw_data[udp_offset:]

        if len(udp_raw) < 8:
            return packet

        src_port = struct.unpack("!H", udp_raw[0:2])[0]
        dst_port = struct.unpack("!H", udp_raw[2:4])[0]
        udp_length = struct.unpack("!H", udp_raw[4:6])[0]
        checksum = struct.unpack("!H", udp_raw[6:8])[0]

        packet.proto_name = "UDP"
        packet.src_port = src_port
        packet.dst_port = dst_port

        svc_src = UDPParser.PORT_SERVICE.get(src_port, "")
        svc_dst = UDPParser.PORT_SERVICE.get(dst_port, "")
        packet.info = f"{src_port}{'['+svc_src+']' if svc_src else ''} → " \
                      f"{dst_port}{'['+svc_dst+']' if svc_dst else ''}  Len={udp_length}"

        # 提取 payload（UDP 头部 8 字节之后的应用层数据）
        packet.payload = udp_raw[8:udp_length]

        packet.add_layer("UDP", {
            "Source Port": f"{src_port}{' ('+svc_src+')' if svc_src else ''}",
            "Destination Port": f"{dst_port}{' ('+svc_dst+')' if svc_dst else ''}",
            "Length": udp_length,
            "Checksum": f"0x{checksum:04x}",
        }, raw=udp_raw[:8])

        return packet
