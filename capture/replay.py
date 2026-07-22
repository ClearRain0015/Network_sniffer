#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Packet replay and injection helpers."""

from typing import Callable, Dict, Optional

from protocols.base import ParsedPacket


def bytes_from_hex(text: str) -> bytes:
    cleaned = "".join(ch for ch in text if ch in "0123456789abcdefABCDEF")
    if not cleaned:
        raise ValueError("十六进制数据为空")
    if len(cleaned) % 2:
        raise ValueError("十六进制字符数量必须为偶数")
    return bytes.fromhex(cleaned)


def _looks_like_raw_ip(raw_data: bytes) -> bool:
    return bool(raw_data) and ((raw_data[0] >> 4) in (4, 6))


def replay_bytes(
    raw_data: bytes,
    iface: Optional[str] = None,
    count: int = 1,
    interval: float = 0.0,
    dry_run: bool = False,
    sender: Optional[Callable[..., object]] = None,
) -> Dict[str, object]:
    if not raw_data:
        raise ValueError("没有可发送的数据")
    if count < 1:
        raise ValueError("发送次数必须 >= 1")
    if interval < 0:
        raise ValueError("发送间隔不能为负数")

    mode = "L3" if _looks_like_raw_ip(raw_data) else "L2"
    result = {
        "bytes": len(raw_data),
        "count": count,
        "interval": interval,
        "iface": iface or "",
        "mode": mode,
        "sent": False,
    }
    if dry_run:
        return result

    if sender is None:
        from scapy.all import Ether, IP, send, sendp
        if mode == "L3":
            scapy_packet = IP(raw_data)
            sender = send
        else:
            scapy_packet = Ether(raw_data)
            sender = sendp
    else:
        scapy_packet = raw_data

    kwargs = {"count": count, "inter": interval, "verbose": False}
    if iface and mode == "L2":
        kwargs["iface"] = iface
    sender(scapy_packet, **kwargs)
    result["sent"] = True
    return result


def replay_packet(
    packet: ParsedPacket,
    iface: Optional[str] = None,
    count: int = 1,
    interval: float = 0.0,
    dry_run: bool = False,
    sender: Optional[Callable[..., object]] = None,
) -> Dict[str, object]:
    if packet is None:
        raise ValueError("请先选择一个数据包")
    return replay_bytes(packet.raw_data, iface, count, interval, dry_run, sender)


def inject_hex_packet(
    hex_text: str,
    iface: Optional[str] = None,
    count: int = 1,
    interval: float = 0.0,
    dry_run: bool = False,
    sender: Optional[Callable[..., object]] = None,
) -> Dict[str, object]:
    return replay_bytes(bytes_from_hex(hex_text), iface, count, interval, dry_run, sender)
