#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/dhcp.py — DHCP 协议解析器
===============================
解析 DHCP 报文（UDP 端口 67/68）。

DHCP 报文结构:
  [ op(1) | htype(1) | hlen(1) | hops(1) |
    xid(4) | secs(2) | flags(2) |
    ciaddr(4) | yiaddr(4) | siaddr(4) | giaddr(4) |
    chaddr(16) | sname(64) | file(128) |
    options(variable) ]
"""

import struct
from .base import ParsedPacket


class DHCPParser:
    """DHCP 协议解析器"""

    NAME = "DHCP"

    DHCP_PORTS = {67, 68}

    OP_MAP = {1: "Boot Request", 2: "Boot Reply"}

    # DHCP Option 53 消息类型
    MSG_TYPE_MAP = {
        1: "DHCP Discover",
        2: "DHCP Offer",
        3: "DHCP Request",
        5: "DHCP Ack",
        6: "DHCP Nak",
        7: "DHCP Release",
        8: "DHCP Inform",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        if packet.proto_name != "UDP":
            return False
        return packet.src_port in DHCPParser.DHCP_PORTS or \
               packet.dst_port in DHCPParser.DHCP_PORTS

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        # 定位 DHCP 数据（UDP payload）
        raw = packet.raw_data[14:]
        ip_ihl = (raw[0] & 0x0F) * 4
        dhcp_offset = 14 + ip_ihl + 8
        dhcp_raw = packet.raw_data[dhcp_offset:]

        if len(dhcp_raw) < 240:
            return packet

        op, htype, hlen, hops = struct.unpack("!BBBB", dhcp_raw[0:4])
        xid = struct.unpack("!I", dhcp_raw[4:8])[0]
        secs, flags = struct.unpack("!HH", dhcp_raw[8:12])
        ciaddr = DHCPParser._format_ip(dhcp_raw[12:16])
        yiaddr = DHCPParser._format_ip(dhcp_raw[16:20])
        siaddr = DHCPParser._format_ip(dhcp_raw[20:24])
        giaddr = DHCPParser._format_ip(dhcp_raw[24:28])
        chaddr = DHCPParser._format_mac(dhcp_raw[28:34])

        # 解析 Option 53（DHCP Message Type）
        msg_type = ""
        if len(dhcp_raw) > 240:
            msg_type = DHCPParser._find_dhcp_type(dhcp_raw[240:])

        op_desc = DHCPParser.OP_MAP.get(op, f"Unknown({op})")
        packet.proto_name = "DHCP"
        packet.info = f"{msg_type or op_desc}  Client={chaddr}" + \
                      (f" → {yiaddr}" if yiaddr != "0.0.0.0" else "")

        packet.add_layer("DHCP", {
            "Opcode": f"{op} ({op_desc})",
            "Hardware Type": htype,
            "Hardware Length": hlen,
            "Hops": hops,
            "Transaction ID": f"0x{xid:08x}",
            "Seconds": secs,
            "Flags": f"0x{flags:04x}",
            "Client IP (ciaddr)": ciaddr,
            "Your IP (yiaddr)": yiaddr,
            "Server IP (siaddr)": siaddr,
            "Relay IP (giaddr)": giaddr,
            "Client MAC (chaddr)": chaddr,
            "Message Type": msg_type or "(未识别)",
        }, raw=dhcp_raw)

        return packet

    @staticmethod
    def _find_dhcp_type(options: bytes) -> str:
        """在 DHCP Options 中查找 Option 53 (Message Type)"""
        i = 0
        while i < len(options) - 1:
            code = options[i]
            if code == 0:     # Padding
                i += 1
                continue
            if code == 255:   # End
                break
            if i + 1 >= len(options):
                break
            length = options[i + 1]
            if i + 2 + length > len(options):
                break
            if code == 53 and length >= 1:
                mtype = options[i + 2]
                return DHCPParser.MSG_TYPE_MAP.get(mtype, f"Type {mtype}")
            i += 2 + length
        return ""

    @staticmethod
    def _format_mac(addr: bytes) -> str:
        return ":".join(f"{b:02x}" for b in addr[:6])

    @staticmethod
    def _format_ip(addr: bytes) -> str:
        return ".".join(str(b) for b in addr[:4])
