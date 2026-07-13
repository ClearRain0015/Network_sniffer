#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Application-level BPF-style packet filter.

Supported examples:
  tcp
  udp port 53
  tcp and dst port 443
  host 192.168.1.1
  src host 192.168.1.10
  dst port 80
  tcp or udp
  not arp
"""

from protocols.base import ParsedPacket


class BPFFilter:
    """Small BPF subset used by the GUI after protocol parsing."""

    PROTO_KEYWORDS = {"tcp", "udp", "icmp", "arp", "ip", "http", "dns"}
    DIRECTION_KEYWORDS = {"src", "dst"}

    @classmethod
    def match(cls, packet: ParsedPacket, expression: str) -> bool:
        if packet is None:
            return False
        if not expression or not expression.strip():
            return True

        tokens = (
            expression.strip()
            .lower()
            .replace("(", " ")
            .replace(")", " ")
            .replace("&&", " and ")
            .replace("||", " or ")
            .split()
        )
        if not tokens:
            return True

        # OR has the lowest precedence. Each OR group is made of AND terms.
        return any(cls._match_and_group(packet, group)
                   for group in cls._split_tokens(tokens, "or"))

    @classmethod
    def _match_and_group(cls, packet: ParsedPacket, tokens: list) -> bool:
        return all(cls._match_sequence(packet, part)
                   for part in cls._split_tokens(tokens, "and") if part)

    @staticmethod
    def _split_tokens(tokens: list, delimiter: str) -> list:
        groups = [[]]
        for token in tokens:
            if token == delimiter:
                if groups[-1]:
                    groups.append([])
                continue
            groups[-1].append(token)
        return [group for group in groups if group]

    @classmethod
    def _match_sequence(cls, packet: ParsedPacket, tokens: list) -> bool:
        negate = False
        if tokens and tokens[0] == "not":
            negate = True
            tokens = tokens[1:]
        result = cls._match_sequence_inner(packet, tokens)
        return not result if negate else result

    @classmethod
    def _match_sequence_inner(cls, packet: ParsedPacket, tokens: list) -> bool:
        if not tokens:
            return True

        if len(tokens) == 1:
            token = tokens[0]
            if token in cls.PROTO_KEYWORDS:
                return cls._match_proto(packet, token)
            if token.isdigit():
                return cls._match_port(packet, int(token), None)
            return cls._match_ip(packet, token, None)

        idx = 0
        proto = None
        direction = None

        if tokens[idx] in cls.PROTO_KEYWORDS:
            proto = tokens[idx]
            idx += 1
        if idx < len(tokens) and tokens[idx] in cls.DIRECTION_KEYWORDS:
            direction = tokens[idx]
            idx += 1

        if proto and not cls._match_proto(packet, proto):
            return False
        if idx >= len(tokens):
            return True

        keyword = tokens[idx]
        value = tokens[idx + 1] if idx + 1 < len(tokens) else None

        if keyword in ("host", "ip"):
            return bool(value) and cls._match_ip(packet, value, direction)
        if keyword == "port":
            return cls._match_port_value(packet, value, direction)
        if keyword == "portrange":
            return cls._match_port_range(packet, value, direction)
        if keyword in cls.DIRECTION_KEYWORDS and value:
            return cls._match_ip(packet, value, keyword)

        # Fallback: all tokens in the sequence must match independently.
        return all(cls._match_sequence(packet, [token]) for token in tokens)

    @classmethod
    def _match_proto(cls, packet: ParsedPacket, proto: str) -> bool:
        proto_map = {
            "tcp": lambda p: p.ip_proto == 6 or p.proto_name == "TCP" or p.has_layer("TCP"),
            "udp": lambda p: p.ip_proto == 17 or p.proto_name == "UDP" or p.has_layer("UDP"),
            "icmp": lambda p: p.ip_proto == 1 or p.proto_name == "ICMP" or p.has_layer("ICMP"),
            "arp": lambda p: p.eth_type == 0x0806 or p.proto_name == "ARP" or p.has_layer("ARP"),
            "ip": lambda p: bool(p.ip_src or p.ip_dst or p.has_layer("IPv4")),
            "http": lambda p: p.proto_name == "HTTP" or p.has_layer("HTTP"),
            "dns": lambda p: p.proto_name == "DNS" or p.has_layer("DNS"),
        }
        matcher = proto_map.get(proto)
        return matcher(packet) if matcher else True

    @staticmethod
    def _match_ip(packet: ParsedPacket, target_ip: str, direction: str = None) -> bool:
        if direction == "src":
            return packet.ip_src == target_ip
        if direction == "dst":
            return packet.ip_dst == target_ip
        return packet.ip_src == target_ip or packet.ip_dst == target_ip

    @classmethod
    def _match_port_value(cls, packet: ParsedPacket, value: str, direction: str = None) -> bool:
        try:
            return cls._match_port(packet, int(value), direction)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _match_port(packet: ParsedPacket, port: int, direction: str = None) -> bool:
        if direction == "src":
            return packet.src_port == port
        if direction == "dst":
            return packet.dst_port == port
        return packet.src_port == port or packet.dst_port == port

    @staticmethod
    def _match_port_range(packet: ParsedPacket, value: str, direction: str = None) -> bool:
        try:
            start_s, end_s = value.split("-", 1)
            start, end = int(start_s), int(end_s)
        except (AttributeError, ValueError):
            return False

        ports = []
        if direction in (None, "src"):
            ports.append(packet.src_port)
        if direction in (None, "dst"):
            ports.append(packet.dst_port)
        return any(start <= port <= end for port in ports if port)
