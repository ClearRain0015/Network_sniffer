#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPv4 fragment reassembly.

The reassembler caches IPv4 fragments by source, destination, protocol and
identification. Once the final fragment arrives and the byte range is complete,
it rebuilds one complete packet and returns it for normal display/filtering.
"""

import time
from typing import Dict, List, Optional, Tuple

from protocols.base import ParsedPacket
from protocols.parser_chain import ParserChain


FragmentKey = Tuple[str, str, int, int]


def _ipv4_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += int.from_bytes(header[i:i + 2], "big")
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class _FragmentGroup:
    def __init__(self, key: FragmentKey):
        self.key = key
        self.fragments: List[ParsedPacket] = []
        self.created_at = time.time()
        self.total_payload_len: Optional[int] = None

    def add(self, packet: ParsedPacket) -> None:
        # Replace duplicate offset fragments with the newest copy.
        self.fragments = [p for p in self.fragments if p.ip_frag != packet.ip_frag]
        self.fragments.append(packet)

        mf_flag = (packet.ip_flags & 0x01) != 0
        if not mf_flag:
            self.total_payload_len = self._payload_start(packet) + len(self._payload(packet))

    def is_complete(self) -> bool:
        if self.total_payload_len is None or not self.fragments:
            return False

        ranges = []
        for frag in self.fragments:
            start = self._payload_start(frag)
            end = start + len(self._payload(frag))
            if end > start:
                ranges.append((start, end))
        if not ranges:
            return False

        ranges.sort()
        covered = 0
        for start, end in ranges:
            if start > covered:
                return False
            covered = max(covered, end)
            if covered >= self.total_payload_len:
                return True
        return False

    def reassemble(self) -> Optional[ParsedPacket]:
        if not self.is_complete():
            return None

        first = min(self.fragments, key=lambda p: p.ip_frag)
        if first.ip_frag != 0:
            return None

        payload = bytearray(self.total_payload_len or 0)
        for frag in self.fragments:
            start = self._payload_start(frag)
            data = self._payload(frag)
            payload[start:start + len(data)] = data

        raw_data = self._build_packet(first, bytes(payload))
        rebuilt = ParsedPacket(
            no=first.no,
            timestamp=first.timestamp,
            raw_data=raw_data,
            length=len(raw_data),
            summary=first.summary,
        )
        rebuilt = ParserChain.parse(rebuilt)
        rebuilt.info = f"[Reassembled {len(self.fragments)} fragments] {rebuilt.info or first.info}"
        rebuilt.add_layer("IP Reassembly", {
            "Fragment Count": len(self.fragments),
            "Reassembled Payload Length": len(payload),
            "Original Offsets": ", ".join(str(f.ip_frag) for f in sorted(self.fragments, key=lambda p: p.ip_frag)),
        })
        return rebuilt

    @staticmethod
    def _payload_start(packet: ParsedPacket) -> int:
        return packet.ip_frag * 8

    @staticmethod
    def _payload(packet: ParsedPacket) -> bytes:
        ip_end = packet.network_offset + packet.ip_len if packet.ip_len else len(packet.raw_data)
        ip_end = min(ip_end, len(packet.raw_data))
        return packet.raw_data[packet.transport_offset:ip_end]

    @staticmethod
    def _build_packet(first: ParsedPacket, payload: bytes) -> bytes:
        ip_offset = first.network_offset
        header_len = max(20, first.transport_offset - first.network_offset)
        ip_header = bytearray(first.raw_data[ip_offset:ip_offset + header_len])

        total_len = header_len + len(payload)
        ip_header[2:4] = total_len.to_bytes(2, "big")
        ip_header[6:8] = b"\x00\x00"
        ip_header[10:12] = b"\x00\x00"
        checksum = _ipv4_checksum(bytes(ip_header))
        ip_header[10:12] = checksum.to_bytes(2, "big")

        prefix = first.raw_data[:ip_offset]
        return prefix + bytes(ip_header) + payload

    @property
    def age(self) -> float:
        return time.time() - self.created_at


class FragmentReassembler:
    """Cache and reassemble IPv4 fragments."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._table: Dict[FragmentKey, _FragmentGroup] = {}
        self._completed_count = 0
        self._expired_count = 0

    @property
    def pending_groups(self) -> int:
        return len(self._table)

    @property
    def completed_count(self) -> int:
        return self._completed_count

    @property
    def expired_count(self) -> int:
        return self._expired_count

    def process(self, packet: ParsedPacket) -> Optional[ParsedPacket]:
        if packet is None:
            return None
        mf_flag = (packet.ip_flags & 0x01) != 0
        frag_offset = packet.ip_frag
        if not mf_flag and frag_offset == 0:
            return packet

        if not packet.ip_src or not packet.ip_dst:
            return packet

        self._cleanup_expired()
        key = (packet.ip_src, packet.ip_dst, packet.ip_id, packet.ip_proto)
        group = self._table.setdefault(key, _FragmentGroup(key))
        group.add(packet)

        if group.is_complete():
            del self._table[key]
            self._completed_count += 1
            return group.reassemble()
        return None

    def _cleanup_expired(self) -> None:
        expired_keys = [
            key for key, group in self._table.items()
            if group.age > self.timeout
        ]
        for key in expired_keys:
            del self._table[key]
            self._expired_count += 1

    def get_stats(self) -> dict:
        return {
            "pending_groups": self.pending_groups,
            "completed_count": self.completed_count,
            "expired_count": self.expired_count,
            "timeout": self.timeout,
        }
