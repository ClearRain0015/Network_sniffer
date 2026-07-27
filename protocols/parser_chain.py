#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/parser_chain.py — 解析器责任链（调度优化版）
==================================================
根据已解析的协议类型直接路由到对应解析器，
避免对所有 11 个解析器逐一调用 can_parse()。

解析路由树：
  Ethernet
    ├── ARP (eth_type=0x0806)
    ├── IPv4 (eth_type=0x0800)
    │   ├── ICMP (proto=1)
    │   ├── TCP  (proto=6) → HTTP / TLS
    │   └── UDP  (proto=17) → DNS / DHCP
    └── IPv6 (eth_type=0x86DD)
"""

from typing import List

from .base import ParsedPacket
from .ethernet import EthernetParser
from .arp import ARPParser
from .ip import IPv4Parser
from .ipv6 import IPv6Parser
from .icmp import ICMPParser
from .tcp import TCPParser
from .udp import UDPParser
from .http import HTTPParser
from .tls import TLSParser
from .dns import DNSParser
from .dhcp import DHCPParser


class ParserChain:
    """
    解析器链 — 按协议类型调度，避免无效的 can_parse() 调用

    用法:
        parsed = ParserChain.parse(packet)
    """

    # 保留注册表用于兼容（部分解析等场景）
    LAYERS = [
        EthernetParser,
        ARPParser,
        IPv4Parser,
        IPv6Parser,
        ICMPParser,
        TCPParser,
        UDPParser,
        DHCPParser,
        TLSParser,
        HTTPParser,
        DNSParser,
    ]

    @classmethod
    def parse(cls, packet: ParsedPacket) -> ParsedPacket:
        """
        按协议类型调度解析，避免无效 can_parse() 检查
        """
        try:
            # ── 第2层：以太网 ────────────────────
            has_eth = EthernetParser.can_parse(packet)
            if has_eth:
                packet = EthernetParser.parse(packet)
            eth_type = packet.eth_type

            # ── ARP ──────────────────────────────
            if eth_type == 0x0806:
                try:
                    if ARPParser.can_parse(packet):
                        packet = ARPParser.parse(packet)
                except Exception:
                    pass
                return packet

            # ── IPv6 ─────────────────────────────
            if eth_type == 0x86DD:
                try:
                    if IPv6Parser.can_parse(packet):
                        packet = IPv6Parser.parse(packet)
                except Exception:
                    pass
                return packet

            # ── IPv4 ─────────────────────────────
            if eth_type == 0x0800 or (not has_eth and (packet.raw_data[0] >> 4) == 4):
                try:
                    if IPv4Parser.can_parse(packet):
                        packet = IPv4Parser.parse(packet)
                except Exception:
                    pass

                proto = packet.ip_proto

                # ICMP
                if proto == 1:
                    try:
                        if ICMPParser.can_parse(packet):
                            packet = ICMPParser.parse(packet)
                    except Exception:
                        pass

                # TCP + 应用层
                elif proto == 6:
                    try:
                        if TCPParser.can_parse(packet):
                            packet = TCPParser.parse(packet)
                    except Exception:
                        pass
                    cls._try_tcp_app(packet)

                # UDP + 应用层
                elif proto == 17:
                    try:
                        if UDPParser.can_parse(packet):
                            packet = UDPParser.parse(packet)
                    except Exception:
                        pass
                    cls._try_udp_app(packet)

        except Exception:
            pass
        return packet

    # ── 应用层按端口快速路由 ──────────────────

    @classmethod
    def _try_tcp_app(cls, packet: ParsedPacket) -> None:
        """TCP 上层应用协议（按端口快速路由 + 内容检测）"""
        sp, dp = packet.src_port, packet.dst_port

        # HTTP 端口
        if sp in (80, 8080, 8000, 8888) or dp in (80, 8080, 8000, 8888):
            try:
                if HTTPParser.can_parse(packet):
                    HTTPParser.parse(packet)
            except Exception:
                pass

        # TLS 端口 (443 HTTPS, 8443, 465 SMTPS, 993 IMAPS, 995 POP3S)
        if sp in (443, 8443, 465, 993, 995, 636, 989, 990) or \
           dp in (443, 8443, 465, 993, 995, 636, 989, 990):
            try:
                if TLSParser.can_parse(packet):
                    TLSParser.parse(packet)
            except Exception:
                pass

    @classmethod
    def _try_udp_app(cls, packet: ParsedPacket) -> None:
        """UDP 上层应用协议"""
        sp, dp = packet.src_port, packet.dst_port

        # DNS
        if sp == 53 or dp == 53:
            try:
                if DNSParser.can_parse(packet):
                    DNSParser.parse(packet)
            except Exception:
                pass

        # DHCP
        if sp in (67, 68) or dp in (67, 68):
            try:
                if DHCPParser.can_parse(packet):
                    DHCPParser.parse(packet)
            except Exception:
                pass

    @classmethod
    def parse_partial(cls, packet: ParsedPacket,
                      stop_after: List[str] = None) -> ParsedPacket:
        """
        部分解析：只解析到指定层为止（兼容旧接口）
        """
        if stop_after is None:
            stop_after = []

        for parser_cls in cls.LAYERS:
            if parser_cls.NAME in stop_after:
                break
            try:
                if parser_cls.can_parse(packet):
                    packet = parser_cls.parse(packet)
            except Exception:
                pass
        return packet
