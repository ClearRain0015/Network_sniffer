#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP request/response pairing."""

from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from protocols.base import ParsedPacket

FlowKey = Tuple[str, str, int, int]


def _http_layer(packet: Optional[ParsedPacket]):
    return packet.get_layer("HTTP") if packet else None


def _flow_key(packet: ParsedPacket) -> FlowKey:
    return (packet.ip_src, packet.ip_dst, packet.src_port, packet.dst_port)


def _reverse_flow_key(packet: ParsedPacket) -> FlowKey:
    return (packet.ip_dst, packet.ip_src, packet.dst_port, packet.src_port)


def _is_request(packet: ParsedPacket) -> bool:
    layer = _http_layer(packet)
    return bool(layer and "Method" in layer.fields)


def _is_response(packet: ParsedPacket) -> bool:
    layer = _http_layer(packet)
    return bool(layer and ("Status Line" in layer.fields or "Status Code" in layer.fields))


def build_http_pairs(packets: Iterable[ParsedPacket]) -> List[Dict[str, object]]:
    """Pair HTTP responses with the earliest pending request in each TCP flow."""
    pending: Dict[FlowKey, Deque[ParsedPacket]] = defaultdict(deque)
    pairs: List[Dict[str, object]] = []

    for packet in packets:
        if not packet or not packet.has_layer("HTTP"):
            continue

        if _is_request(packet):
            pending[_flow_key(packet)].append(packet)
            continue

        if not _is_response(packet):
            continue

        queue = pending.get(_reverse_flow_key(packet))
        request: Optional[ParsedPacket] = queue.popleft() if queue else None
        request_layer = _http_layer(request)
        response_layer = _http_layer(packet)
        latency_ms = None
        if request is not None:
            latency_ms = max(0.0, (packet.timestamp - request.timestamp) * 1000)

        pairs.append({
            "request_no": request.no if request else None,
            "response_no": packet.no,
            "client": request.ip_src if request else packet.ip_dst,
            "server": request.ip_dst if request else packet.ip_src,
            "method": request_layer.fields.get("Method", "") if request_layer else "",
            "uri": request_layer.fields.get("URI", "") if request_layer else "",
            "host": request_layer.fields.get("Host", "") if request_layer else "",
            "status_code": response_layer.fields.get("Status Code", "") if response_layer else "",
            "status_line": response_layer.fields.get("Status Line", "") if response_layer else "",
            "latency_ms": latency_ms,
        })

    return pairs


def format_http_pairs(pairs: List[Dict[str, object]], lang: str = "zh") -> str:
    if not pairs:
        return "未找到 HTTP 请求/响应配对。" if lang == "zh" else "No HTTP request/response pairs found."

    title = "HTTP 请求 / 响应配对" if lang == "zh" else "HTTP Request / Response Pairs"
    lines = [title, "=" * 28]
    for index, pair in enumerate(pairs, 1):
        latency = pair.get("latency_ms")
        latency_text = "-" if latency is None else f"{latency:.1f} ms"
        request = f"{pair.get('method', '')} {pair.get('host', '')}{pair.get('uri', '')}".strip()
        response = f"{pair.get('status_code', '')} {pair.get('status_line', '')}".strip()
        request_label = "请求" if lang == "zh" else "Request"
        response_label = "响应" if lang == "zh" else "Response"
        client_label = "客户端" if lang == "zh" else "Client"
        server_label = "服务器" if lang == "zh" else "Server"
        latency_label = "延迟" if lang == "zh" else "Latency"
        lines.extend([
            f"{index}. {request_label} #{pair.get('request_no') or '-'} -> {response_label} #{pair.get('response_no')}",
            f"   {client_label}: {pair.get('client')}  {server_label}: {pair.get('server')}",
            f"   {request_label}: {request or '-'}",
            f"   {response_label}: {response or '-'}",
            f"   {latency_label}: {latency_text}",
        ])
    return "\n".join(lines)
