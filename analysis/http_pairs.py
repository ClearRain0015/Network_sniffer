#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP request/response pairing utilities."""

from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from protocols.base import ParsedPacket

FlowKey = Tuple[str, str, int, int]


def _http_layer(packet: ParsedPacket):
    return packet.get_layer("HTTP") if packet else None


def _flow_key(packet: ParsedPacket) -> FlowKey:
    return (packet.ip_src, packet.ip_dst, packet.src_port, packet.dst_port)


def _reverse_flow_key(packet: ParsedPacket) -> FlowKey:
    return (packet.ip_dst, packet.ip_src, packet.dst_port, packet.src_port)


def _request_summary(packet: ParsedPacket) -> str:
    layer = _http_layer(packet)
    fields = layer.fields if layer else {}
    method = fields.get("Method", "")
    uri = fields.get("URI", "")
    host = fields.get("Host", "")
    target = f"{host}{uri}" if host else uri
    return f"{method} {target}".strip()


def _response_summary(packet: ParsedPacket) -> str:
    layer = _http_layer(packet)
    fields = layer.fields if layer else {}
    status = fields.get("Status Code", "")
    line = fields.get("Status Line", "")
    return f"{status} {line}".strip()


def _is_http_request(packet: ParsedPacket) -> bool:
    layer = _http_layer(packet)
    return bool(layer and "Method" in layer.fields)


def _is_http_response(packet: ParsedPacket) -> bool:
    layer = _http_layer(packet)
    return bool(layer and ("Status Code" in layer.fields or "Status Line" in layer.fields))


def build_http_pairs(packets: Iterable[ParsedPacket]) -> List[Dict[str, object]]:
    """Pair HTTP responses with the earliest pending request in a TCP flow."""
    pending: Dict[FlowKey, Deque[ParsedPacket]] = defaultdict(deque)
    pairs: List[Dict[str, object]] = []

    for packet in packets:
        if not packet or not packet.has_layer("HTTP"):
            continue

        if _is_http_request(packet):
            pending[_flow_key(packet)].append(packet)
            continue

        if not _is_http_response(packet):
            continue

        request_queue = pending.get(_reverse_flow_key(packet))
        request: Optional[ParsedPacket] = request_queue.popleft() if request_queue else None
        latency_ms = None
        if request is not None:
            latency_ms = max(0.0, (packet.timestamp - request.timestamp) * 1000)

        req_layer = _http_layer(request) if request else None
        resp_layer = _http_layer(packet)
        pairs.append({
            "request_no": request.no if request else None,
            "response_no": packet.no,
            "client": request.ip_src if request else packet.ip_dst,
            "server": request.ip_dst if request else packet.ip_src,
            "method": req_layer.fields.get("Method", "") if req_layer else "",
            "uri": req_layer.fields.get("URI", "") if req_layer else "",
            "host": req_layer.fields.get("Host", "") if req_layer else "",
            "status_code": resp_layer.fields.get("Status Code", "") if resp_layer else "",
            "latency_ms": latency_ms,
            "request": _request_summary(request) if request else "(unmatched request)",
            "response": _response_summary(packet),
        })

    return pairs


def format_http_pairs(pairs: List[Dict[str, object]]) -> str:
    """Format paired HTTP exchanges for the GUI."""
    if not pairs:
        return "No HTTP request/response pairs found."

    lines = ["HTTP Request / Response Pairs", "=" * 32]
    for idx, pair in enumerate(pairs, 1):
        latency = pair.get("latency_ms")
        latency_text = "-" if latency is None else f"{latency:.1f} ms"
        lines.extend([
            f"{idx}. Request #{pair.get('request_no') or '-'} -> Response #{pair.get('response_no')}",
            f"   Client: {pair.get('client')}  Server: {pair.get('server')}",
            f"   Request: {pair.get('request')}",
            f"   Response: {pair.get('response')}",
            f"   Latency: {latency_text}",
        ])
    return "\n".join(lines)
