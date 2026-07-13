#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/tcp.py — TCP 报文解析器
==============================
解析字段：
  - Source Port       (2 bytes)
  - Destination Port  (2 bytes)
  - Sequence Number   (4 bytes)
  - ACK Number        (4 bytes)
  - Data Offset       (4 bits)
  - Reserved          (3 bits)
  - Flags             (9 bits) — NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
  - Window Size       (2 bytes)
  - Checksum          (2 bytes)
  - Urgent Pointer    (2 bytes)

Flags 全部显示：SYN / ACK / FIN / RST / PSH / URG
"""

import struct
from .base import ParsedPacket


class TCPParser:
    """TCP 报文解析器"""

    NAME = "TCP"

    # 常见端口 — 服务名映射
    PORT_SERVICE = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 3389: "RDP", 8080: "HTTP-Alt",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """IPv4 Protocol == 6"""
        return packet.ip_proto == 6

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 TCP 报文头

        TCP 头部结构（最小20字节）:
          [ src_port(2) | dst_port(2) |
            seq_num(4) | ack_num(4) |
            offset_reserved_flags(2) | window(2) |
            checksum(2) | urgent_ptr(2) ]
        """
        raw = packet.raw_data[14:]  # 跳过以太网头
        ip_ihl = (raw[0] & 0x0F) * 4
        tcp_offset = 14 + ip_ihl
        tcp_raw = packet.raw_data[tcp_offset:]

        if len(tcp_raw) < 20:
            return packet

        src_port = struct.unpack("!H", tcp_raw[0:2])[0]
        dst_port = struct.unpack("!H", tcp_raw[2:4])[0]
        seq_num = struct.unpack("!I", tcp_raw[4:8])[0]
        ack_num = struct.unpack("!I", tcp_raw[8:12])[0]
        offset_flags = struct.unpack("!H", tcp_raw[12:14])[0]
        window = struct.unpack("!H", tcp_raw[14:16])[0]
        checksum = struct.unpack("!H", tcp_raw[16:18])[0]
        urgent_ptr = struct.unpack("!H", tcp_raw[18:20])[0]

        # 解析 Data Offset
        data_offset = (offset_flags >> 12) & 0x0F
        tcp_header_len = data_offset * 4

        # 解析所有 Flags
        flag_ns  = (offset_flags >> 8) & 0x01
        flag_cwr = (offset_flags >> 7) & 0x01
        flag_ece = (offset_flags >> 6) & 0x01
        flag_urg = (offset_flags >> 5) & 0x01
        flag_ack = (offset_flags >> 4) & 0x01
        flag_psh = (offset_flags >> 3) & 0x01
        flag_rst = (offset_flags >> 2) & 0x01
        flag_syn = (offset_flags >> 1) & 0x01
        flag_fin = (offset_flags >> 0) & 0x01

        flags_present = []
        if flag_syn: flags_present.append("SYN")
        if flag_ack: flags_present.append("ACK")
        if flag_fin: flags_present.append("FIN")
        if flag_rst: flags_present.append("RST")
        if flag_psh: flags_present.append("PSH")
        if flag_urg: flags_present.append("URG")
        if flag_ece: flags_present.append("ECE")
        if flag_cwr: flags_present.append("CWR")
        if flag_ns:  flags_present.append("NS")
        flags_str = " · ".join(flags_present) if flags_present else "NONE"

        # 填充 packet
        packet.proto_name = "TCP"
        packet.src_port = src_port
        packet.dst_port = dst_port
        packet.tcp_flags = offset_flags & 0x01FF
        packet.tcp_seq = seq_num
        packet.tcp_ack = ack_num

        svc_src = TCPParser.PORT_SERVICE.get(src_port, "")
        svc_dst = TCPParser.PORT_SERVICE.get(dst_port, "")
        packet.info = f"{src_port}{'['+svc_src+']' if svc_src else ''} → " \
                      f"{dst_port}{'['+svc_dst+']' if svc_dst else ''}  [{flags_str}] " \
                      f"Seq={seq_num} Ack={ack_num} Win={window}"

        packet.add_layer("TCP", {
            "Source Port": f"{src_port}{' ('+svc_src+')' if svc_src else ''}",
            "Destination Port": f"{dst_port}{' ('+svc_dst+')' if svc_dst else ''}",
            "Sequence Number": seq_num,
            "Acknowledgment Number": ack_num,
            "Header Length": f"{tcp_header_len} bytes ({data_offset} words)",
            "Flags": f"0x{offset_flags & 0x01FF:03x} [{flags_str}]",
            "  ... SYN": flag_syn,
            "  ... ACK": flag_ack,
            "  ... FIN": flag_fin,
            "  ... RST": flag_rst,
            "  ... PSH": flag_psh,
            "  ... URG": flag_urg,
            "Window Size": window,
            "Checksum": f"0x{checksum:04x}",
            "Urgent Pointer": urgent_ptr,
        }, raw=tcp_raw[:tcp_header_len])

        return packet
