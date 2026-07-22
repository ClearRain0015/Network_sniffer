#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/parser_chain.py — 解析器责任链
====================================
将所有协议解析器串联成一条责任链。

解析顺序（与设计文档一致）：
  Ethernet → ARP? → IPv4? → TCP? / UDP? / ICMP?
                              │
                              ├→ HTTP / HTTPS / FTP
                              └→ DNS  / DHCP

每层只解析自己负责的协议，解析完一层后
根据该层信息决定下一层使用哪个解析器。
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
    解析器链 — 按序依次尝试解析各层协议

    用法:
        parsed = ParserChain.parse(packet)
    """

    # 解析器注册表（按调用顺序排列）
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
        完整解析一个数据包
        -----------------
        遍历所有已注册的解析器，满足 can_parse() 条件则调用 parse()。
        """
        for parser_cls in cls.LAYERS:
            try:
                if parser_cls.can_parse(packet):
                    packet = parser_cls.parse(packet)
            except Exception as e:
                # 单个解析器异常不中断整条链
                packet.info = f"[解析异常: {parser_cls.NAME} — {e}]"
        return packet

    @classmethod
    def parse_partial(cls, packet: ParsedPacket,
                      stop_after: List[str] = None) -> ParsedPacket:
        """
        部分解析：只解析到指定层为止
        ---------------------------
        用于只需要某几层信息的场景。
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
