#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/http.py — HTTP 协议解析器（第五阶段加分项）
=================================================
解析 HTTP 请求/响应头：
  - 请求行：GET /index.html HTTP/1.1
  - 状态行：HTTP/1.1 200 OK
  - 头部字段：Host, User-Agent, Content-Type …
  - 请求体/响应体概览

改进：
  - 使用 TCPParser 已提取的 packet.payload 而非硬编码偏移
  - 支持通过 payload 内容自动检测 HTTP（不限端口）
  - 正确设置 proto_name 以便 GUI 和过滤器识别
"""

from .base import ParsedPacket


class HTTPParser:
    """HTTP 协议解析器"""

    NAME = "HTTP"

    HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                    b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"}

    HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 9000}

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """TCP 且端口为 HTTP 常见端口，或 payload 开头像 HTTP"""
        if packet.proto_name != "TCP":
            return False

        # 端口匹配
        if packet.src_port in HTTPParser.HTTP_PORTS or \
           packet.dst_port in HTTPParser.HTTP_PORTS:
            return True

        # Payload 内容匹配：检查是否以 HTTP 方法或 HTTP 响应开头
        if packet.payload and len(packet.payload) >= 4:
            return HTTPParser._looks_like_http(packet.payload)

        return False

    @staticmethod
    def _looks_like_http(data: bytes) -> bool:
        """检查数据是否像 HTTP 请求或响应"""
        # HTTP 请求：GET / POST / ... 开头
        for method in HTTPParser.HTTP_METHODS:
            if data.startswith(method + b" "):
                return True
        # HTTP 响应：HTTP/1.x 开头
        if data.startswith(b"HTTP/"):
            return True
        return False

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 HTTP 载荷
        --------------
        使用 TCPParser 已提取的 packet.payload，
        从中解析 HTTP 请求/响应头和头部字段。
        """
        # 使用 TCP parser 已经提取好的 payload
        http_payload = packet.payload

        if not http_payload or len(http_payload) < 4:
            return packet

        try:
            text = http_payload.decode("utf-8", errors="replace")
        except Exception:
            return packet

        # ── 解析请求行 / 状态行 ─────────────────
        lines = text.split("\r\n")
        first_line = lines[0] if lines else ""

        http_fields = {}
        is_request = False
        is_response = False

        # 检查是否为 HTTP 请求
        parts = first_line.split(" ")
        if len(parts) >= 3:
            method = parts[0].upper()
            known_methods = {m.decode() if isinstance(m, bytes) else m
                             for m in HTTPParser.HTTP_METHODS}
            if method in known_methods:
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
            if len(parts) >= 3:
                http_fields["Reason Phrase"] = " ".join(parts[2:])
            packet.info = first_line

        if not is_request and not is_response:
            return packet

        # ── 解析头部字段 ───────────────────────
        header_end = 0
        for i, line in enumerate(lines[1:], 1):
            if ":" in line:
                key, value = line.split(":", 1)
                http_fields[key.strip()] = value.strip()
            elif line == "":
                header_end = i + 1  # 空行后的起始位置
                break

        # ── 请求体/响应体概览 ─────────────────
        if header_end > 0 and header_end < len(lines):
            body_start_in_text = text.find("\r\n\r\n")
            if body_start_in_text >= 0:
                body_bytes = http_payload[body_start_in_text + 4:]
                if body_bytes:
                    body_len = len(body_bytes)
                    content_type = http_fields.get("Content-Type", "")
                    if "json" in content_type.lower():
                        try:
                            body_preview = body_bytes[:500].decode("utf-8", errors="replace")
                        except Exception:
                            body_preview = f"<binary {body_len} bytes>"
                    elif "text" in content_type.lower() or "html" in content_type.lower() or "xml" in content_type.lower():
                        try:
                            body_preview = body_bytes[:500].decode("utf-8", errors="replace")
                        except Exception:
                            body_preview = f"<binary {body_len} bytes>"
                    else:
                        body_preview = f"<{body_len} bytes>"
                    http_fields["Body"] = body_preview

        # ── 更新 packet ────────────────────────
        # 标记为 HTTP 协议（便于 GUI 和过滤器识别）
        packet.proto_name = "HTTP"
        packet.info = http_fields.get("Status Line") or packet.info or "HTTP"

        # 将 Host 头附加到 info 中
        if "Host" in http_fields:
            packet.info = f"{packet.info}  [{http_fields['Host']}]"

        packet.add_layer("HTTP", http_fields, raw=http_payload)

        return packet
