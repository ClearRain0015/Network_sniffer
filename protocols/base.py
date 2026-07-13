#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser/base.py — 解析器基础数据结构
==================================
定义所有解析器共用的 ParsedPacket 和 ProtocolLayer。
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import time


@dataclass
class ProtocolLayer:
    """
    单个协议层信息
    -------------
    例如：Ethernet / IPv4 / TCP 各对应一个 ProtocolLayer。
    每层解析完成后插入 ParsedPacket.layers。
    """
    name: str                        # 协议名（"Ethernet", "IPv4", "TCP" …）
    fields: Dict[str, Any] = field(default_factory=dict)  # 键值对字段
    raw_bytes: bytes = b""           # 该层的原始字节


@dataclass
class ParsedPacket:
    """
    统一数据包结构
    ==============
    贯穿整个管线（抓包 → 解析 → 过滤 → 重组 → GUI）的标准表示。

    链路层字段
    ---------
    """
    no: int                          # 数据包序号
    timestamp: float                 # 时间戳（秒）
    raw_data: bytes                  # 完整原始字节
    length: int                      # 总长度

    # ── 链路层 ──────────────────────────────
    eth_src: str = ""
    eth_dst: str = ""
    eth_type: int = 0

    # ── 网络层概要 ──────────────────────────
    ip_src: str = ""
    ip_dst: str = ""
    ip_proto: int = 0
    ip_len: int = 0
    ip_id: int = 0
    ip_flags: int = 0
    ip_frag: int = 0
    ip_ttl: int = 0

    # ── 传输层概要 ──────────────────────────
    proto_name: str = ""             # 协议名（"TCP","UDP","ICMP","ARP"…）
    src_port: int = 0
    dst_port: int = 0

    # ── TCP 特定 ────────────────────────────
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0

    # ── 摘要 ────────────────────────────────
    summary: str = ""                # 一行描述
    info: str = ""                   # 附加信息

    # ── 已解析的协议层列表 ───────────────────
    layers: List[ProtocolLayer] = field(default_factory=list)

    # ── 便捷方法 ────────────────────────────

    @property
    def timestamp_str(self) -> str:
        """格式化的时间字符串"""
        return time.strftime(
            "%H:%M:%S.",
            time.localtime(self.timestamp),
        ) + f"{int((self.timestamp % 1) * 1_000_000):06d}"

    @property
    def src_str(self) -> str:
        """源地址（优先 IP，否则 MAC）"""
        return self.ip_src or self.eth_src or "—"

    @property
    def dst_str(self) -> str:
        """目的地址"""
        return self.ip_dst or self.eth_dst or "—"

    @property
    def length_str(self) -> str:
        return str(self.length)

    def add_layer(self, name: str, fields: Dict[str, Any], raw: bytes = b"") -> ProtocolLayer:
        """向包中添加一个协议层"""
        layer = ProtocolLayer(name=name, fields=fields, raw_bytes=raw)
        self.layers.append(layer)
        return layer

    def get_layer(self, name: str) -> Optional[ProtocolLayer]:
        """获取指定名称的第一个协议层"""
        for layer in self.layers:
            if layer.name == name:
                return layer
        return None

    def has_layer(self, name: str) -> bool:
        return self.get_layer(name) is not None
