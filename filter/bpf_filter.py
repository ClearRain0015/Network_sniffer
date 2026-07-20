#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filter/bpf_filter.py — BPF 过滤器
==================================
支持两种过滤模式：

1. 简单模式（兼容旧版）：
   tcp / udp / icmp / arp / host 192.168.1.1 / port 80 / tcp port 443

2. 字段级模式（新增）：
   tcp.srcport == 80          ip.ttl < 64
   tcp.dstport != 443         ip.len > 1500
   ip.src == 192.168.1.1      frame.len >= 100
   tcp.flags.syn == 1         http.host contains baidu
"""

from protocols.base import ParsedPacket


class BPFFilter:
    """BPF 过滤器（支持字段级过滤）"""

    PROTO_KEYWORDS = {"tcp", "udp", "icmp", "arp", "ip", "http", "dns"}
    OPS = {"==": "__eq__", "!=": "__ne__", ">=": "__ge__",
           "<=": "__le__", ">": "__gt__", "<": "__lt__",
           "contains": "contains"}

    # ── 字段映射 ──────────────────────────────

    FIELD_MAP = {
        "frame.len":       lambda p: p.length,
        "eth.src":         lambda p: p.eth_src,
        "eth.dst":         lambda p: p.eth_dst,
        "ip.src":          lambda p: p.ip_src,
        "ip.dst":          lambda p: p.ip_dst,
        "ip.ttl":          lambda p: p.ip_ttl,
        "ip.len":          lambda p: p.ip_len,
        "ip.proto":        lambda p: p.ip_proto,
        "ip.id":           lambda p: p.ip_id,
        "ip.flags.mf":     lambda p: 1 if (p.ip_flags & 0x01) else 0,
        "ip.flags.df":     lambda p: 1 if (p.ip_flags & 0x02) else 0,
        "tcp.srcport":     lambda p: p.src_port if p.proto_name == "TCP" else 0,
        "tcp.dstport":     lambda p: p.dst_port if p.proto_name == "TCP" else 0,
        "tcp.seq":         lambda p: p.tcp_seq,
        "tcp.ack":         lambda p: p.tcp_ack,
        "tcp.flags.syn":   lambda p: 1 if (p.tcp_flags & 0x02) else 0,
        "tcp.flags.ack":   lambda p: 1 if (p.tcp_flags & 0x10) else 0,
        "tcp.flags.fin":   lambda p: 1 if (p.tcp_flags & 0x01) else 0,
        "tcp.flags.rst":   lambda p: 1 if (p.tcp_flags & 0x04) else 0,
        "tcp.flags.psh":   lambda p: 1 if (p.tcp_flags & 0x08) else 0,
        "udp.srcport":     lambda p: p.src_port if p.proto_name == "UDP" else 0,
        "udp.dstport":     lambda p: p.dst_port if p.proto_name == "UDP" else 0,
    }

    # ── 公共 API ──────────────────────────────

    @classmethod
    def match(cls, packet: ParsedPacket, expression: str) -> bool:
        """主入口：检查数据包是否匹配过滤表达式"""
        if packet is None:
            return False
        if not expression or not expression.strip():
            return True
        expr = expression.strip()
        # 检测是否包含字段级运算符
        if any(op in expr for op in cls.OPS):
            return cls._match_field_expr(packet, expr)
        return cls._match_simple(packet, expr)

    # ── 字段级解析 ────────────────────────────

    @classmethod
    def _match_field_expr(cls, packet, expr: str) -> bool:
        """解析字段级表达式: field op value"""
        # 按 and/or 分割
        parts = cls._split_bool(expr.lower(), " or ")
        return any(cls._match_and_clause(packet, p) for p in parts)

    @classmethod
    def _match_and_clause(cls, packet, expr: str) -> bool:
        parts = cls._split_bool(expr, " and ")
        return all(cls._match_one(packet, p) for p in parts)

    @classmethod
    def _match_one(cls, packet, expr: str) -> bool:
        """匹配单个条件"""
        expr = expr.strip()
        # not 前缀
        negate = expr.startswith("not ")
        if negate:
            expr = expr[4:].strip()
        # 找运算符
        for op in sorted(cls.OPS.keys(), key=len, reverse=True):
            if f" {op} " in expr:
                field_name, value = expr.split(f" {op} ", 1)
                field_name = field_name.strip()
                value = value.strip().strip('"').strip("'")
                result = cls._eval_op(packet, field_name, op, value)
                return not result if negate else result
            # 边缘情况: op前面没空格
            if op in expr and expr.index(op) > 0:
                idx = expr.index(op)
                field_name = expr[:idx].strip()
                value = expr[idx + len(op):].strip().strip('"').strip("'")
                result = cls._eval_op(packet, field_name, op, value)
                return not result if negate else result

        # 回退: 简单协议匹配
        if expr in cls.PROTO_KEYWORDS:
            result = cls._match_proto(packet, expr)
            return not result if negate else result
        return True

    @classmethod
    def _eval_op(cls, packet, field: str, op: str, value_str: str) -> bool:
        """计算字段值是否匹配"""
        # 协议限定的老语法: tcp port 80
        tokens = field.split()
        if len(tokens) >= 2 and tokens[0] in cls.PROTO_KEYWORDS and tokens[1] in ("port", "host"):
            return cls._match_simple(packet, f"{field} {op} {value_str}")

        getter = cls.FIELD_MAP.get(field)
        if getter is None:
            return True  # 未知字段，放行
        try:
            actual = getter(packet)
        except Exception:
            return False

        # 类型转换
        if op == "contains":
            return str(value_str).lower() in str(actual).lower()

        # 数字比较
        try:
            expected = int(value_str)
        except ValueError:
            # 字符串比较
            actual = str(actual)
            expected = value_str

        op_method = cls.OPS[op]
        try:
            return getattr(actual, op_method)(expected)
        except Exception:
            return False

    @classmethod
    def _split_bool(cls, expr: str, delimiter: str) -> list:
        """按 and/or 分割，忽略引号内的内容"""
        result = []
        current = ""
        in_quote = False
        i = 0
        while i < len(expr):
            if expr[i] in ('"', "'"):
                in_quote = not in_quote
                current += expr[i]
            elif not in_quote and expr[i:i + len(delimiter)] == delimiter:
                result.append(current.strip())
                current = ""
                i += len(delimiter) - 1
            else:
                current += expr[i]
            i += 1
        if current.strip():
            result.append(current.strip())
        return result or [expr]

    # ── 简单模式（兼容旧版）──────────────────

    @classmethod
    def _match_simple(cls, packet, expr: str) -> bool:
        tokens = expr.lower().split()
        return cls._match_tokens(packet, tokens)

    @classmethod
    def _match_tokens(cls, packet, tokens: list) -> bool:
        """简单 token 匹配"""
        # protocol
        for token in tokens:
            if token in cls.PROTO_KEYWORDS:
                if not cls._match_proto(packet, token):
                    return False
        # host
        try:
            idx = tokens.index("host")
            if idx + 1 < len(tokens) and not cls._match_ip(packet, tokens[idx + 1]):
                return False
        except ValueError:
            pass
        # port
        try:
            idx = tokens.index("port")
            if idx + 1 < len(tokens):
                if not cls._match_port(packet, int(tokens[idx + 1])):
                    return False
        except (ValueError, IndexError):
            pass
        return True

    @classmethod
    def _match_proto(cls, packet, proto: str) -> bool:
        proto_map = {
            "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "arp": "ARP",
            "http": "HTTP", "dns": "DNS",
            "ip": lambda p: p.proto_name in ("TCP", "UDP", "ICMP", "IPv4"),
        }
        expected = proto_map.get(proto)
        if expected is None:
            return True
        if callable(expected):
            return expected(packet)
        return packet.proto_name == expected or packet.has_layer(expected)

    @staticmethod
    def _match_ip(packet, target_ip: str) -> bool:
        return packet.ip_src == target_ip or packet.ip_dst == target_ip

    @staticmethod
    def _match_port(packet, port: int) -> bool:
        return packet.src_port == port or packet.dst_port == port
