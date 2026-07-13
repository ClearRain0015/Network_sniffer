#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/http.py — HTTP 协议解析器（第五阶段加分项）
=================================================
解析 HTTP 请求/响应头：
  - 请求行：GET /index.html HTTP/1.1
  - 状态行：HTTP/1.1 200 OK
  - 头部字段：Host, User-Agent, Content-Type …
"""

from .base import ParsedPacket


class HTTPParser:
    """HTTP 协议解析器"""

    NAME = "HTTP"

    HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                    b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}

    HTTP_PORTS = {80, 8080, 8000, 8888}

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """TCP 且端口为 HTTP 常见端口"""
        if packet.proto_name != "TCP":
            return False
        return packet.src_port in HTTPParser.HTTP_PORTS or \
               packet.dst_port in HTTPParser.HTTP_PORTS

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 HTTP 载荷
        --------------
        从 TCP payload 中提取 HTTP 头部文本。
        """
        raw = packet.raw_data[14:]
        ip_ihl = (raw[0] & 0x0F) * 4
        tcp_offset = 14 + ip_ihl
        tcp_raw = packet.raw_data[tcp_offset:]

        if len(tcp_raw) < 20:
            return packet

        tcp_data_offset = ((tcp_raw[12] >> 4) & 0x0F) * 4
        http_payload = tcp_raw[tcp_data_offset:]

        if len(http_payload) < 4:
            return packet

        try:
            text = http_payload.decode("utf-8", errors="replace")
        except Exception:
            return packet

        # ── 解析请求行 ─────────────────────────
        lines = text.split("\r\n")
        first_line = lines[0] if lines else ""

        http_fields = {}
        is_request = False
        is_response = False

        # 检查是否为 HTTP 请求
        parts = first_line.split(" ")
        if len(parts) >= 3:
            method = parts[0].upper()
            if method in {m.decode() if isinstance(m, bytes) else m
                          for m in HTTPParser.HTTP_METHODS}:
                is_request = True
                http_fields["Method"] = method
                http_fields["URI"] = parts[1]
                http_fields["Version"] = parts[2]
                packet.info = f"{method} {parts[1]}"

        # 检查是否为 HTTP 响应
        if first_line.upper().startswith("HTTP/"):
            is_response = True
            http_fields["Status Line"] = first_line
            if len(parts) >= 2:
                http_fields["Status Code"] = parts[1]
            packet.info = first_line

        if not is_request and not is_response:
            return packet

        # ── 解析头部字段 ───────────────────────
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                http_fields[key.strip()] = value.strip()
            elif line == "":
                break  # 空行表示头部结束

        packet.add_layer("HTTP", http_fields, raw=http_payload)

        return packet
