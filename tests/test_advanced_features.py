import os
import struct
import tempfile
import time
import unittest

from filter.bpf_filter import BPFFilter
from protocols.base import ParsedPacket
from protocols.parser_chain import ParserChain
from reassembly.ip_fragment import FragmentReassembler
from save.pcap_save import save_as_pcap
from statistics.flow_statistics import compute_statistics, format_statistics


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return (
        bytes.fromhex("aabbccddeeff")
        + bytes.fromhex("112233445566")
        + struct.pack("!H", ethertype)
        + payload
    )


def ipv4_fragment(payload: bytes, proto: int, ident: int, flags: int, offset: int) -> bytes:
    total_len = 20 + len(payload)
    flags_frag = ((flags & 0x7) << 13) | (offset & 0x1FFF)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ident,
        flags_frag,
        64,
        proto,
        0,
        bytes([192, 168, 1, 10]),
        bytes([8, 8, 8, 8]),
    ) + payload


def parse(raw: bytes) -> ParsedPacket:
    packet = ParsedPacket(no=1, timestamp=time.time(), raw_data=raw, length=len(raw))
    return ParserChain.parse(packet)


class AdvancedFeatureTests(unittest.TestCase):
    def test_bpf_filters_protocol_ip_and_port(self):
        udp_payload = b"hello"
        udp = struct.pack("!HHHH", 53000, 53, 8 + len(udp_payload), 0) + udp_payload
        packet = parse(ethernet(ipv4_fragment(udp, proto=17, ident=1, flags=0, offset=0)))

        self.assertTrue(BPFFilter.match(packet, "udp"))
        self.assertTrue(BPFFilter.match(packet, "udp and dst port 53"))
        self.assertTrue(BPFFilter.match(packet, "host 8.8.8.8"))
        self.assertTrue(BPFFilter.match(packet, "src host 192.168.1.10"))
        self.assertFalse(BPFFilter.match(packet, "tcp"))
        self.assertFalse(BPFFilter.match(packet, "dst port 80"))

    def test_ipv4_fragments_are_reassembled(self):
        app_payload = b"abcdefghijklmnopqrstuvwx"
        udp_datagram = struct.pack("!HHHH", 12345, 53, 8 + len(app_payload), 0) + app_payload
        first_piece = udp_datagram[:24]
        second_piece = udp_datagram[24:]

        frag1 = parse(ethernet(ipv4_fragment(first_piece, proto=17, ident=99, flags=1, offset=0)))
        frag2 = parse(ethernet(ipv4_fragment(second_piece, proto=17, ident=99, flags=0, offset=3)))

        reassembler = FragmentReassembler()
        self.assertIsNone(reassembler.process(frag1))
        packet = reassembler.process(frag2)

        self.assertIsNotNone(packet)
        self.assertTrue(packet.has_layer("IP Reassembly"))
        self.assertTrue(packet.has_layer("UDP"))
        self.assertEqual(packet.src_port, 12345)
        self.assertEqual(packet.dst_port, 53)
        self.assertEqual(packet.payload, app_payload)

    def test_save_as_pcap_writes_valid_header_and_packets(self):
        packet = parse(ethernet(ipv4_fragment(b"data", proto=1, ident=7, flags=0, offset=0)))
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "capture.pcap")
            save_as_pcap([packet], path)
            with open(path, "rb") as f:
                data = f.read()

        self.assertGreater(len(data), 24)
        self.assertEqual(data[:4], bytes.fromhex("d4 c3 b2 a1"))

    def test_statistics_include_protocols_top_ips_and_counts(self):
        tcp = struct.pack("!HHIIHHHH", 1000, 443, 1, 0, (5 << 12) | 0x10, 1, 0, 0)
        udp = struct.pack("!HHHH", 53000, 53, 8, 0)
        packets = [
            parse(ethernet(ipv4_fragment(tcp, proto=6, ident=2, flags=0, offset=0))),
            parse(ethernet(ipv4_fragment(udp, proto=17, ident=3, flags=0, offset=0))),
        ]

        stats = compute_statistics(packets)
        report = format_statistics(stats)

        self.assertEqual(stats["total_packets"], 2)
        self.assertIn("TCP", stats["protocol_dist"])
        self.assertIn("UDP", stats["protocol_dist"])
        self.assertIn(("8.8.8.8", 2), stats["top_dst_ips"])
        self.assertIn("协议分布", report)


if __name__ == "__main__":
    unittest.main()
