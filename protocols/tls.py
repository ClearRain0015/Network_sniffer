#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
protocols/tls.py — TLS/SSL 握手协议解析器
=========================================
解析 TLS ClientHello 和 ServerHello，提取：
  - SNI (Server Name Indication) — 访问的域名
  - TLS 版本
  - 支持的加密套件
  - 证书信息（如果可解析）

这是现代网络抓包的关键功能 — 虽然 HTTPS 流量是加密的，
但 TLS 握手阶段 ClientHello 中的 SNI 是明文的，
Wireshark 就是通过它来显示 "你正在访问哪个网站"。

TLS 记录层结构 (RFC 8446):
  [ ContentType(1) | Version(2) | Length(2) | Payload ]

握手协议 (ContentType = 0x16):
  [ HandshakeType(1) | Length(3) | ... ]

ClientHello 扩展中的 SNI (Extension Type = 0x0000):
  [ server_name_type(1) | server_name_length(2) | server_name ]
"""

import struct
from .base import ParsedPacket


class TLSParser:
    """TLS/SSL 握手协议解析器"""

    NAME = "TLS"

    # TLS 内容类型 (RFC 8446 Section 5.1)
    CONTENT_TYPES = {
        0x14: "Change Cipher Spec",
        0x15: "Alert",
        0x16: "Handshake",
        0x17: "Application Data",
        0x18: "Heartbeat",
    }

    # 握手消息类型 (RFC 8446 Section 4)
    HANDSHAKE_TYPES = {
        0x01: "Client Hello",
        0x02: "Server Hello",
        0x04: "New Session Ticket",
        0x05: "End of Early Data",
        0x08: "Encrypted Extensions",
        0x0B: "Certificate",
        0x0C: "Server Key Exchange",
        0x0D: "Certificate Request",
        0x0E: "Server Hello Done",
        0x0F: "Certificate Verify",
        0x10: "Client Key Exchange",
        0x14: "Finished",
    }

    # TLS 版本映射
    VERSIONS = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }

    # 常见 TLS 端口
    TLS_PORTS = {443, 8443, 465, 993, 995, 636, 989, 990}

    @staticmethod
    def can_parse(packet: ParsedPacket) -> bool:
        """检查 payload 开头是否为 TLS 记录"""
        if packet.proto_name != "TCP":
            return False

        payload = packet.payload
        if not payload or len(payload) < 5:
            return False

        # TLS 记录层: ContentType(1) | Version(2) | Length(2)
        content_type = payload[0]
        version = struct.unpack("!H", payload[1:3])[0]
        record_length = struct.unpack("!H", payload[3:5])[0]

        # 验证 ContentType (0x14-0x18)
        if content_type not in TLSParser.CONTENT_TYPES:
            return False

        # 验证 Version (SSL 3.0 ~ TLS 1.3)
        if version not in TLSParser.VERSIONS:
            # 也可能是 TLS 1.3 的降级信号 (0x0301/0x0303)
            if version not in (0x0301, 0x0303):
                return False

        # 验证记录长度不超过 payload
        if record_length > len(payload) - 5:
            return False

        return True

    @staticmethod
    def parse(packet: ParsedPacket) -> ParsedPacket:
        """
        解析 TLS 记录层和握手消息
        """
        payload = packet.payload
        if not payload or len(payload) < 5:
            return packet

        tls_fields = {}
        offset = 0
        sni = None
        handshake_type_name = None

        # ── 遍历 TLS 记录 ──────────────────────
        while offset + 5 <= len(payload):
            content_type = payload[offset]
            version = struct.unpack("!H", payload[offset + 1:offset + 3])[0]
            record_length = struct.unpack("!H", payload[offset + 3:offset + 5])[0]

            if offset + 5 + record_length > len(payload):
                break

            ct_name = TLSParser.CONTENT_TYPES.get(content_type, f"Unknown(0x{content_type:02x})")
            ver_name = TLSParser.VERSIONS.get(version, f"0x{version:04x}")

            tls_fields[f"Record {offset//5}"] = f"{ct_name}, {ver_name}, len={record_length}"

            # ── 解析握手消息 ────────────────────
            if content_type == 0x16 and record_length >= 4:  # Handshake
                record_start = offset + 5
                hs_type = payload[record_start]
                # Handshake length is 3 bytes
                hs_length = struct.unpack("!I", b'\x00' + payload[record_start + 1:record_start + 4])[0]
                hs_type_name = TLSParser.HANDSHAKE_TYPES.get(hs_type, f"Unknown(0x{hs_type:02x})")
                tls_fields["Handshake Type"] = hs_type_name

                # ── ClientHello 解析 ─────────────
                if hs_type == 0x01 and record_length >= 40:
                    sni = TLSParser._parse_client_hello(
                        payload, record_start, hs_length, tls_fields
                    )

                # ── ServerHello 解析 ─────────────
                elif hs_type == 0x02 and record_length >= 40:
                    TLSParser._parse_server_hello(
                        payload, record_start, hs_length, tls_fields
                    )

                # ── Certificate 解析 ─────────────
                elif hs_type == 0x0B and record_length >= 4:
                    tls_fields["Certificate"] = f"<{hs_length} bytes>"
                    # 尝试解析第一个证书的通用名
                    TLSParser._parse_certificate(
                        payload, record_start + 4, hs_length, tls_fields
                    )

            offset += 5 + record_length

        # ── 更新 packet 信息 ────────────────────
        if handshake_type_name:
            packet.proto_name = "TLSv1.2" if version >= 0x0303 else "TLS"
        else:
            packet.proto_name = "TLS"

        # 设置 info
        if sni:
            packet.info = f"Client Hello (SNI: {sni})"
        elif handshake_type_name:
            packet.info = f"{handshake_type_name}"
        else:
            ct = payload[0]
            ct_name = TLSParser.CONTENT_TYPES.get(ct, "TLS")
            packet.info = f"{ct_name}"

        # 存储 SNI 便于后续过滤
        if sni:
            tls_fields["SNI"] = sni
            packet._tls_sni = sni  # 用于 BPF 过滤

        packet.add_layer("TLS", tls_fields, raw=payload[:min(256, len(payload))])

        return packet

    @staticmethod
    def _parse_client_hello(payload: bytes, hs_start: int, hs_length: int,
                            fields: dict) -> str:
        """
        解析 ClientHello 消息，提取 SNI

        ClientHello 结构 (简化):
          [ version(2) | random(32) | session_id_len(1) | session_id(...)
            | cipher_suites_len(2) | cipher_suites(...)
            | compression_len(1) | compression(...)
            | extensions_len(2) | extensions(...) ]
        """
        sni = None
        pos = hs_start + 4  # 跳过 handshake_type(1) + length(3)

        if pos + 38 > len(payload):
            return sni

        # Client Version
        client_ver = struct.unpack("!H", payload[pos:pos + 2])[0]
        fields["Client Version"] = TLSParser.VERSIONS.get(
            client_ver, f"0x{client_ver:04x}"
        )

        # 支持的最高 TLS 版本在扩展中可能不同
        # 对于 TLS 1.3，ClientHello.legacy_version = 0x0303，supported_versions 扩展覆盖
        pos += 2  # version
        pos += 32  # random

        # Session ID
        if pos >= len(payload):
            return sni
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        # Cipher Suites
        if pos + 2 > len(payload):
            return sni
        cipher_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_len

        # Compression Methods
        if pos + 1 > len(payload):
            return sni
        comp_len = payload[pos]
        pos += 1 + comp_len

        # Extensions
        if pos + 2 > len(payload):
            return sni
        ext_total_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_total_len

        # ── 遍历扩展查找 SNI (type=0x0000) ────
        supported_versions = []
        while pos + 4 <= min(ext_end, len(payload)):
            ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
            ext_len = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
            pos += 4

            if pos + ext_len > len(payload):
                break

            if ext_type == 0x0000:  # server_name (SNI)
                sni = TLSParser._parse_sni_extension(payload, pos, ext_len)
                if sni:
                    fields["SNI"] = sni

            elif ext_type == 0x002B:  # supported_versions (TLS 1.3)
                # 格式: len(1) | version(2) ...
                if ext_len >= 3:
                    versions = []
                    ver_pos = pos + 1
                    while ver_pos + 2 <= pos + ext_len:
                        v = struct.unpack("!H", payload[ver_pos:ver_pos + 2])[0]
                        versions.append(TLSParser.VERSIONS.get(v, f"0x{v:04x}"))
                        ver_pos += 2
                    if versions:
                        fields["Supported Versions"] = ", ".join(versions)

            elif ext_type == 0x000A:  # supported_groups
                fields["Supported Groups"] = f"<{ext_len} bytes>"

            elif ext_type == 0x000D:  # signature_algorithms
                fields["Signature Algorithms"] = f"<{ext_len} bytes>"

            elif ext_type == 0x0033:  # key_share (TLS 1.3)
                fields["Key Share"] = f"<{ext_len} bytes>"

            elif ext_type == 0x0010:  # ALPN
                # 格式: list_len(2) | [proto_len(1) | proto] ...
                try:
                    alp_list_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                    alp_pos = pos + 2
                    alp_end = alp_pos + alp_list_len
                    protocols = []
                    while alp_pos + 1 <= min(alp_end, pos + ext_len):
                        proto_len = payload[alp_pos]
                        alp_pos += 1
                        if alp_pos + proto_len <= min(alp_end, pos + ext_len):
                            proto = payload[alp_pos:alp_pos + proto_len].decode("utf-8", errors="replace")
                            protocols.append(proto)
                            alp_pos += proto_len
                    if protocols:
                        fields["ALPN"] = ", ".join(protocols)
                except Exception:
                    pass

            pos += ext_len

        return sni

    @staticmethod
    def _parse_sni_extension(payload: bytes, pos: int, ext_len: int) -> str:
        """
        解析 SNI (Server Name Indication) 扩展

        格式:
          [ server_name_list_length(2)
            | server_name_type(1) | server_name_length(2) | server_name ]
        """
        try:
            list_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            end = pos + list_len

            names = []
            while pos + 3 <= min(end, len(payload)):
                name_type = payload[pos]
                name_len = struct.unpack("!H", payload[pos + 1:pos + 3])[0]
                pos += 3

                if pos + name_len <= min(end, len(payload)):
                    name = payload[pos:pos + name_len].decode("utf-8", errors="replace")
                    if name_type == 0:  # hostname
                        names.append(name)
                    pos += name_len

            return names[0] if names else None
        except Exception:
            return None

    @staticmethod
    def _parse_server_hello(payload: bytes, hs_start: int, hs_length: int,
                            fields: dict):
        """解析 ServerHello 消息"""
        pos = hs_start + 4

        if pos + 38 > len(payload):
            return

        server_ver = struct.unpack("!H", payload[pos:pos + 2])[0]
        fields["Server Version"] = TLSParser.VERSIONS.get(
            server_ver, f"0x{server_ver:04x}"
        )

        pos += 2 + 32  # version + random

        # Session ID
        if pos >= len(payload):
            return
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        # Cipher Suite
        if pos + 2 > len(payload):
            return
        cipher = struct.unpack("!H", payload[pos:pos + 2])[0]
        fields["Cipher Suite"] = TLSParser._cipher_name(cipher)
        pos += 2

        # Compression
        if pos < len(payload):
            fields["Compression"] = str(payload[pos])

    @staticmethod
    def _parse_certificate(payload: bytes, pos: int, length: int, fields: dict):
        """尝试解析证书中的通用名（简化版）"""
        # 完整的 X.509 证书解析很复杂，这里仅做简单的字符串搜索
        # 在 DER 编码的证书中搜索 CN (Common Name) 模式
        try:
            # 搜索 "CN=" 或域名模式
            data = payload[pos:pos + min(length, len(payload) - pos)]
            # 简单尝试: 查找常见域名模式
            import re
            # 匹配常见域名
            domains = re.findall(
                rb'\x06\x03\x55\x04\x03.{0,10}([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)',
                data[:min(4096, len(data))]
            )
            if not domains:
                # 尝试 *.domain.com 格式
                domains = re.findall(
                    rb'[\*a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}',
                    data[:min(4096, len(data))]
                )
            if domains:
                names = [d.decode("utf-8", errors="replace") for d in domains[:3]]
                fields["Certificate CN"] = ", ".join(names)
        except Exception:
            pass

    @staticmethod
    def _cipher_name(cipher_id: int) -> str:
        """将密码套件 ID 映射为可读名称"""
        CIPHERS = {
            0x0000: "TLS_NULL_WITH_NULL_NULL",
            0x0005: "TLS_RSA_WITH_RC4_128_SHA",
            0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
            0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
            0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384",
            0x1303: "TLS_CHACHA20_POLY1305_SHA256",
            0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        }
        return CIPHERS.get(cipher_id, f"0x{cipher_id:04X}")
