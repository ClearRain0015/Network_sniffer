#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filter/bpf_filter.py — BPF 过滤器
==================================
在应用层实现 BPF 过滤。

GUI 中提供一个输入框，用户输入过滤表达式即可实时过滤。

示例：
  tcp                → 只显示 TCP
  udp port 53        → 只显示 DNS 流量
  host 192.168.1.1   → 只显示与该 IP 相关的流量
  tcp port 443       → 只显示 HTTPS
"""

from protocols.base import ParsedPacket


class BPFFilter:
    """BPF 过滤器（应用层实现）"""

    # 协议关键字 → 判定方法
    PROTO_KEYWORDS = {"tcp", "udp", "icmp", "arp", "ip", "http", "dns"}

    @classmethod
    def match(cls, packet: ParsedPacket, expression: str) -> bool:
        """
        检查数据包是否匹配 BPF 表达式

        参数:
            packet: 已解析的数据包
            expression: BPF 过滤表达式（如 "tcp port 80"）

        返回:
            True = 通过过滤，应显示
        """
        if not expression or not expression.strip():
            return True  # 无过滤条件，全部通过

        expr = expression.strip().lower()
        tokens = expr.split()

        # ── 协议过滤 ─────────────────────────
        proto_match = True
        for token in tokens:
            if token in cls.PROTO_KEYWORDS:
                proto_match = cls._match_proto(packet, token)
                if not proto_match:
                    return False

        # ── host 过滤 ────────────────────────
        try:
            host_idx = tokens.index("host")
            if host_idx + 1 < len(tokens):
                target_ip = tokens[host_idx + 1]
                if packet.ip_src != target_ip and packet.ip_dst != target_ip:
                    return False
        except ValueError:
            pass

        # ── port 过滤 ────────────────────────
        try:
            port_idx = tokens.index("port")
            if port_idx + 1 < len(tokens):
                target_port = int(tokens[port_idx + 1])
                if packet.src_port != target_port and packet.dst_port != target_port:
                    return False
        except (ValueError, IndexError):
            pass

        return True

    @classmethod
    def _match_proto(cls, packet: ParsedPacket, proto: str) -> bool:
        """匹配协议类型"""
        proto_map = {
            "tcp": lambda p: p.ip_proto == 6 or p.proto_name == "TCP" or p.has_layer("TCP"),
            "udp": lambda p: p.ip_proto == 17 or p.proto_name == "UDP" or p.has_layer("UDP"),
            "icmp": lambda p: p.ip_proto == 1 or p.proto_name == "ICMP" or p.has_layer("ICMP"),
            "arp": lambda p: p.eth_type == 0x0806 or p.proto_name == "ARP" or p.has_layer("ARP"),
            "ip": lambda p: bool(p.ip_src or p.ip_dst or p.has_layer("IPv4")),
            "http": "HTTP",
            "dns": "DNS",
        }

        expected = proto_map.get(proto)
        if expected is None:
            return True  # 未知协议关键字，忽略

        if callable(expected):
            return expected(packet)

        # 检查 main proto 或任意一层
        if packet.proto_name == expected:
            return True
        if packet.has_layer(expected):
            return True
        return False
