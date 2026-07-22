import struct
import time
import unittest

from protocols.base import ParsedPacket
from protocols.parser_chain import ParserChain


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return (
        bytes.fromhex("aabbccddeeff")
        + bytes.fromhex("112233445566")
        + struct.pack("!H", ethertype)
        + payload
    )


def ipv4(payload: bytes, proto: int) -> bytes:
    total_len = 20 + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0x1234,
        0x4000,
        64,
        proto,
        0,
        bytes([192, 168, 1, 10]),
        bytes([8, 8, 8, 8]),
    ) + payload


def parsed(raw: bytes) -> ParsedPacket:
    packet = ParsedPacket(no=1, timestamp=time.time(), raw_data=raw, length=len(raw))
    return ParserChain.parse(packet)


class ProtocolParserTests(unittest.TestCase):
    def test_tcp_payload_is_parsed_from_ethernet_ipv4(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        tcp = struct.pack(
            "!HHIIHHHH",
            12345,
            80,
            100,
            200,
            (5 << 12) | 0x18,
            4096,
            0,
            0,
        ) + payload

        packet = parsed(ethernet(ipv4(tcp, proto=6)))

        self.assertTrue(packet.has_layer("Ethernet"))
        self.assertTrue(packet.has_layer("IPv4"))
        self.assertTrue(packet.has_layer("TCP"))
        self.assertTrue(packet.has_layer("HTTP"))
        # HTTP parser now correctly sets proto_name to the highest protocol layer
        self.assertEqual(packet.proto_name, "HTTP")
        self.assertEqual(packet.src_port, 12345)
        self.assertEqual(packet.dst_port, 80)
        self.assertEqual(packet.payload, payload)
        self.assertIn("GET / HTTP/1.1", packet.payload_text)
        self.assertIn("example.com", packet.info)

    def test_udp_payload_is_parsed(self):
        payload = b"hello dns"
        udp_len = 8 + len(payload)
        udp = struct.pack("!HHHH", 53000, 5353, udp_len, 0) + payload

        packet = parsed(ethernet(ipv4(udp, proto=17)))

        self.assertTrue(packet.has_layer("UDP"))
        self.assertEqual(packet.proto_name, "UDP")
        self.assertEqual(packet.src_port, 53000)
        self.assertEqual(packet.dst_port, 5353)
        self.assertEqual(packet.payload, payload)

    def test_icmp_echo_payload_is_parsed(self):
        payload = b"ping-data"
        icmp = struct.pack("!BBHHH", 8, 0, 0, 7, 9) + payload

        packet = parsed(ethernet(ipv4(icmp, proto=1)))

        self.assertTrue(packet.has_layer("ICMP"))
        self.assertEqual(packet.proto_name, "ICMP")
        self.assertEqual(packet.payload, payload)
        self.assertIn("Identifier", packet.get_layer("ICMP").fields)

    def test_arp_is_parsed(self):
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        arp += bytes.fromhex("112233445566")
        arp += bytes([192, 168, 1, 10])
        arp += bytes.fromhex("000000000000")
        arp += bytes([192, 168, 1, 1])

        packet = parsed(ethernet(arp, ethertype=0x0806))

        self.assertTrue(packet.has_layer("ARP"))
        self.assertEqual(packet.proto_name, "ARP")
        self.assertEqual(packet.ip_src, "192.168.1.10")
        self.assertEqual(packet.ip_dst, "192.168.1.1")

    def test_raw_ipv4_without_ethernet_header_is_supported(self):
        payload = b"raw"
        udp = struct.pack("!HHHH", 1, 2, 8 + len(payload), 0) + payload

        packet = parsed(ipv4(udp, proto=17))

        self.assertFalse(packet.has_layer("Ethernet"))
        self.assertTrue(packet.has_layer("IPv4"))
        self.assertTrue(packet.has_layer("UDP"))
        self.assertEqual(packet.network_offset, 0)
        self.assertEqual(packet.payload, payload)

    # ── TLS/SSL 测试 ──────────────────────────

    def test_tls_client_hello_parsing(self):
        """TLS ClientHello 应该被正确解析并提取 SNI"""
        # 构造简化的 TLS ClientHello 包含 SNI
        # TLS Record: ContentType=Handshake(0x16), Version=TLS1.2(0x0303), Length=...
        # Handshake: Type=ClientHello(0x01), Length=...

        # 构造 SNI 扩展: www.example.com
        sni_host = b"www.example.com"
        sni_ext = (
            struct.pack("!H", 0x0000)  # extension_type: server_name
            + struct.pack("!H", 5 + len(sni_host))  # extension_length
            + struct.pack("!H", 3 + len(sni_host))  # server_name_list_length
            + b"\x00"  # name_type: hostname
            + struct.pack("!H", len(sni_host))  # name_length
            + sni_host
        )

        # 扩展总长度
        extensions = sni_ext
        extensions_len = len(extensions)

        # ClientHello 体
        client_hello = (
            struct.pack("!H", 0x0303)  # client_version: TLS 1.2
            + b"\x00" * 32  # random
            + b"\x00"  # session_id_length: 0
            + struct.pack("!H", 2) + b"\x00\x2f"  # cipher_suites: 1 suite
            + b"\x01\x00"  # compression: 1 method, null
            + struct.pack("!H", extensions_len)
            + extensions
        )

        # 握手消息
        handshake = (
            b"\x01"  # handshake_type: ClientHello
            + struct.pack("!I", len(client_hello))[1:]  # length (3 bytes)
            + client_hello
        )

        # TLS 记录
        tls_record = (
            b"\x16"  # content_type: Handshake
            + struct.pack("!H", 0x0303)  # version: TLS 1.2
            + struct.pack("!H", len(handshake))  # length
            + handshake
        )

        # TCP 头部
        tcp = struct.pack(
            "!HHIIHHHH",
            54321,
            443,  # dst port 443 (HTTPS)
            1000,
            2000,
            (5 << 12) | 0x18,  # data_offset=5, flags=ACK+PSH
            4096,
            0,
            0,
        ) + tls_record

        packet = parsed(ethernet(ipv4(tcp, proto=6)))

        self.assertTrue(packet.has_layer("Ethernet"))
        self.assertTrue(packet.has_layer("IPv4"))
        self.assertTrue(packet.has_layer("TCP"))
        self.assertTrue(packet.has_layer("TLS"),
                        f"TLS layer not found. Layers: {[l.name for l in packet.layers]}")
        self.assertIn("TLS", packet.proto_name)
        self.assertEqual(packet.src_port, 54321)
        self.assertEqual(packet.dst_port, 443)
        self.assertIn("www.example.com", packet.info,
                      f"SNI not found in info: {packet.info}")

    def test_tls_non_handshake_payload_is_not_misidentified(self):
        """非 TLS payload 不应被错误识别为 TLS"""
        # 普通 TCP payload（不是 TLS 格式）
        payload = b"some random data that is not TLS"
        tcp = struct.pack(
            "!HHIIHHHH",
            12345,
            443,
            100,
            200,
            (5 << 12) | 0x18,
            4096,
            0,
            0,
        ) + payload

        packet = parsed(ethernet(ipv4(tcp, proto=6)))

        self.assertTrue(packet.has_layer("TCP"))
        self.assertFalse(packet.has_layer("TLS"),
                         "Non-TLS payload should not be identified as TLS")

    def test_http_content_detection_without_standard_port(self):
        """HTTP 内容在非标准端口上也应被检测"""
        payload = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}"
        tcp = struct.pack(
            "!HHIIHHHH",
            9999,
            3000,  # non-standard port but HTTP
            100,
            200,
            (5 << 12) | 0x18,
            4096,
            0,
            0,
        ) + payload

        packet = parsed(ethernet(ipv4(tcp, proto=6)))

        self.assertTrue(packet.has_layer("HTTP"),
                        f"HTTP should be detected on non-standard port. Layers: {[l.name for l in packet.layers]}")
        self.assertEqual(packet.proto_name, "HTTP")
        self.assertIn("POST /api/data", packet.info)


if __name__ == "__main__":
    unittest.main()
