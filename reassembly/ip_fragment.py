#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reassembly/ip_fragment.py — IP 分片重组模块
===========================================
课程设计重点模块，面试/答辩高频问题。

实现思路：
  1. 维护一个 fragment_table
  2. key = (src_ip, dst_ip, identification)
  3. 收到分片 → 加入缓存
  4. 所有分片到齐（MF=0 且 Offset 覆盖完整）→ 排序 → 拼接 → 输出完整 IP 包

超时淘汰：超过 30 秒未完成重组 → 丢弃该分片组
"""

import time
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

from protocols.base import ParsedPacket


# 分片组 key: (src_ip, dst_ip, identification)
FragmentKey = Tuple[str, str, int]


class _FragmentGroup:
    """单个 IP 包的分片缓存"""

    def __init__(self, key: FragmentKey):
        self.key = key
        self.fragments: List[ParsedPacket] = []
        self.created_at = time.time()
        self.total_len = 0          # 预计总长度（从最后一个分片得出）
        self.has_last = False       # 是否收到 MF=0 的分片
        self._sorted = False

    def add(self, packet: ParsedPacket) -> None:
        """添加一个分片"""
        self.fragments.append(packet)
        self._sorted = False

        # 检查是否为最后一个分片
        mf_flag = (packet.ip_flags & 0x01) != 0
        if not mf_flag and packet.ip_frag > 0:
            # MF=0 且 offset>0 → 这是最后一个分片
            self.has_last = True
            # total = offset*8 + payload长度（ip_len 减去 IP 头 20 字节）
            self.total_len = packet.ip_frag * 8 + (packet.ip_len - 20)

    def is_complete(self) -> bool:
        """
        判断是否所有分片到齐
        -------------------
        条件：
          1. 收到了最后一个分片（MF=0, Offset>0）
          2. 所有分片按 Offset 排序后连续覆盖 [0, total_len)
        """
        if not self.has_last or len(self.fragments) < 2:
            # 没有最后一个分片，或只有一个分片（不是分片包）
            return False

        # 排序
        sorted_frags = sorted(self.fragments, key=lambda p: p.ip_frag)

        # 检查连续性
        expected_offset = 0
        for frag in sorted_frags:
            frag_offset = frag.ip_frag * 8  # Offset 单位是 8 字节
            if frag_offset != expected_offset:
                return False  # 有缺口
            # 注意：ip_len 包含 IP 头部，需要减去头部得到数据长度
            expected_offset += (frag.ip_len - 20)  # 假设 20 字节 IP 头

        # 如果 MF=0 的分片覆盖到了预期总长度，说明完整
        return True

    def reassemble(self) -> Optional[ParsedPacket]:
        """
        重组分片
        -------
        按 Offset 排序后拼接 payload，
        用第一个分片的头部信息作为新包的头部。
        """
        if not self.is_complete():
            return None

        sorted_frags = sorted(self.fragments, key=lambda p: p.ip_frag)

        # 以第一个分片为基础
        base = sorted_frags[0]

        # 拼接所有分片的 payload（跳过各分片的 IP 头）
        combined_payload = b""
        for frag in sorted_frags:
            ip_header_len = 20  # 简化：假设固定 20 字节 IP 头
            payload = frag.raw_data[14 + ip_header_len:]  # 14=以太网头
            combined_payload += payload

        # 构造重组后的完整 IP 包（保留第一个分片的 IP 头）
        ip_header = sorted_frags[0].raw_data[14:34]  # 14 字节以太网头 + 20 字节 IP 头

        # 修改 IP 头中的 Total Length 和清除 Flags/Fragment Offset
        new_ip_header = bytearray(ip_header)
        new_total_len = 20 + len(combined_payload)
        new_ip_header[2:4] = new_total_len.to_bytes(2, "big")
        new_ip_header[6:8] = b"\x00\x00"  # 清除 Flags + Fragment Offset

        # 构造完整的重组原始数据
        eth_header = base.raw_data[:14]
        raw_data = eth_header + bytes(new_ip_header) + combined_payload

        # 更新 ParsedPacket 信息
        base.raw_data = raw_data
        base.length = len(raw_data)
        base.ip_len = new_total_len
        base.ip_flags = 0
        base.ip_frag = 0
        base.info = f"[重组] {base.info}"

        base.add_layer("IP Reassembly", {
            "Fragment Count": len(sorted_frags),
            "Reassembled Length": len(combined_payload),
            "Original Fragments": ", ".join(
                f"Offset={f.ip_frag}" for f in sorted_frags
            ),
        })

        return base

    @property
    def age(self) -> float:
        """分片组存活时间（秒）"""
        return time.time() - self.created_at


class FragmentReassembler:
    """
    IP 分片重组器

    用法:
        reassembler = FragmentReassembler(timeout=30)
        result = reassembler.process(parsed_packet)

    如果数据包不是分片，直接返回原包。
    如果是分片且重组完成，返回重组后的包。
    如果是分片但还未完成，返回 None（不显示，等待后续分片）。
    """

    def __init__(self, timeout: float = 30.0):
        """
        timeout: 分片超时时间（秒）
                 超过此时间未完成重组的分片组将被丢弃。
        """
        self.timeout = timeout
        self._table: Dict[FragmentKey, _FragmentGroup] = {}
        self._completed_count = 0

    @property
    def pending_groups(self) -> int:
        """待重组的分片组数量"""
        return len(self._table)

    @property
    def completed_count(self) -> int:
        """已完成的重组次数"""
        return self._completed_count

    def process(self, packet: ParsedPacket) -> Optional[ParsedPacket]:
        """
        处理一个数据包
        -------------
        如果不是分片 → 直接返回
        如果是分片 → 加入缓存，如果重组完成则返回完整包，否则返回 None
        """
        # ── 判断是否为分片 ───────────────────
        mf_flag = (packet.ip_flags & 0x01) != 0
        frag_offset = packet.ip_frag

        if not mf_flag and frag_offset == 0:
            # 不是分片包（MF=0 且 Offset=0）
            return packet

        # ── 是分片包，加入缓存 ───────────────
        key = (packet.ip_src, packet.ip_dst, packet.ip_id)

        # 定期清理过期分片
        self._cleanup_expired()

        if key not in self._table:
            self._table[key] = _FragmentGroup(key)

        group = self._table[key]
        group.add(packet)

        # ── 检查是否可重组 ───────────────────
        if group.is_complete():
            del self._table[key]
            self._completed_count += 1
            result = group.reassemble()
            if result:
                # 重新解析重组后的包，让传输层提取 payload
                from protocols.parser_chain import ParserChain
                result = ParserChain.parse(result)
            return result

        # 还在等待其他分片
        return None  # 暂不显示

    def _cleanup_expired(self) -> None:
        """清理过期的分片组"""
        expired_keys = [
            key for key, group in self._table.items()
            if group.age > self.timeout
        ]
        for key in expired_keys:
            del self._table[key]

    def get_stats(self) -> dict:
        """获取重组器统计信息"""
        return {
            "pending_groups": self.pending_groups,
            "completed_count": self._completed_count,
            "timeout": self.timeout,
        }
