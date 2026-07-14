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
        self.assertEqual(packet.proto_name, "TCP")
        self.assertEqual(packet.src_port, 12345)
        self.assertEqual(packet.dst_port, 80)
        self.assertEqual(packet.payload, payload)
        self.assertIn("GET / HTTP/1.1", packet.payload_text)

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


if __name__ == "__main__":
    unittest.main()
