#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/dns.py — DNS 协议解析器（第五阶段加分项）
==============================================
解析 DNS 查询/响应报文。
"""

import struct
from .base import ParsedPacket


class DNSParser:
    """DNS 协议解析器"""

    NAME = "DNS"

    DNS_PORT = 53

    DNS_TYPE_MAP = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
    }

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """UDP 且端口 53"""
        if packet.proto_name != "UDP":
            return False
        return packet.src_port == DNSParser.DNS_PORT or \
               packet.dst_port == DNSParser.DNS_PORT

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 DNS 报文

        DNS 头部（12字节）:
          [ transaction_id(2) | flags(2) | questions(2) |
            answer_rrs(2) | authority_rrs(2) | additional_rrs(2) ]
        """
        raw = packet.raw_data[14:]
        ip_ihl = (raw[0] & 0x0F) * 4
        udp_offset = 14 + ip_ihl + 8  # UDP 头固定 8 字节
        dns_raw = packet.raw_data[udp_offset:]

        if len(dns_raw) < 12:
            return packet

        transaction_id = struct.unpack("!H", dns_raw[0:2])[0]
        flags = struct.unpack("!H", dns_raw[2:4])[0]
        qdcount = struct.unpack("!H", dns_raw[4:6])[0]
        ancount = struct.unpack("!H", dns_raw[6:8])[0]
        nscount = struct.unpack("!H", dns_raw[8:10])[0]
        arcount = struct.unpack("!H", dns_raw[10:12])[0]

        qr = (flags >> 15) & 0x01
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        is_query = (qr == 0)
        msg_type = "Query (查询)" if is_query else "Response (应答)"

        # ── 解析查询名（简单版本） ──────────────
        query_name = ""
        if len(dns_raw) > 12:
            offset = 12
            parts = []
            while offset < len(dns_raw) and dns_raw[offset] != 0:
                length = dns_raw[offset]
                if length == 0 or offset + 1 + length > len(dns_raw):
                    break
                parts.append(dns_raw[offset + 1:offset + 1 + length].decode("ascii", errors="replace"))
                offset += 1 + length
            query_name = ".".join(parts)

        packet.info = f"DNS {msg_type}: {query_name}" if query_name else f"DNS {msg_type}"

        packet.add_layer("DNS", {
            "Transaction ID": f"0x{transaction_id:04x}",
            "Type": msg_type,
            "Flags": f"0x{flags:04x}",
            "  ... QR": "Query" if qr == 0 else "Response",
            "  ... Opcode": opcode,
            "  ... RCode": rcode,
            "Questions": qdcount,
            "Answer RRs": ancount,
            "Authority RRs": nscount,
            "Additional RRs": arcount,
            "Query Name": query_name if query_name else "(compressed/not parsed)",
        }, raw=dns_raw)

        return packet
