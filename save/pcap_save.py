#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Packet export helpers: PCAP, TXT and CSV."""

import csv
import os
import struct
import time
from typing import List

from protocols.base import ParsedPacket


DEFAULT_SAVE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "captures"
)

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101


def save_packets(packets: List[ParsedPacket], filepath: str = None) -> str:
    """Save captured packets as PCAP by default."""
    if filepath is None:
        os.makedirs(DEFAULT_SAVE_DIR, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(DEFAULT_SAVE_DIR, f"capture_{timestamp}.pcap")
    elif not os.path.splitext(filepath)[1]:
        filepath += ".pcap"

    return save_as_pcap(packets, filepath)


def save_as_pcap(packets: List[ParsedPacket], filepath: str) -> str:
    """Write a libpcap file using only the Python standard library."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    linktype = _guess_linktype(packets)

    with open(filepath, "wb") as f:
        # little-endian pcap global header
        f.write(struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,  # magic
            2,           # major
            4,           # minor
            0,           # timezone
            0,           # sigfigs
            65535,       # snaplen
            linktype,
        ))
        for pkt in packets:
            sec = int(pkt.timestamp)
            usec = int((pkt.timestamp - sec) * 1_000_000)
            data = pkt.raw_data or b""
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)
    return filepath


def _guess_linktype(packets: List[ParsedPacket]) -> int:
    raw_packets = [p.raw_data for p in packets if p.raw_data]
    if raw_packets and all((data[0] >> 4) == 4 for data in raw_packets):
        return LINKTYPE_RAW_IP
    return LINKTYPE_ETHERNET


def save_as_txt(packets: List[ParsedPacket], filepath: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"{'No':<6} {'Time':<16} {'Source':<18} {'Destination':<18} "
                f"{'Protocol':<10} {'Length':<8} Info\n")
        f.write("-" * 120 + "\n")
        for pkt in packets:
            f.write(
                f"{pkt.no:<6} {pkt.timestamp_str:<16} "
                f"{pkt.src_str:<18} {pkt.dst_str:<18} "
                f"{pkt.proto_name:<10} {pkt.length:<8} "
                f"{pkt.info or pkt.summary}\n"
            )
    return filepath


def save_as_csv(packets: List[ParsedPacket], filepath: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["No", "Time", "Source", "Destination",
                         "Protocol", "Length", "Info"])
        for pkt in packets:
            writer.writerow([
                pkt.no,
                pkt.timestamp_str,
                pkt.src_str,
                pkt.dst_str,
                pkt.proto_name,
                pkt.length,
                pkt.info or pkt.summary,
            ])
    return filepath
