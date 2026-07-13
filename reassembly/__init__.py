"""
reassembly/ — IP 分片重组模块（课程重点）
=======================================
老师要求的数据报文重组功能。

核心数据结构：
  fragment_table = {
    (src_ip, dst_ip, id): [fragment1, fragment2, fragment3, ...]
  }

重组判断依据：
  - MF=0 表示最后一个分片
  - 所有分片按 Offset 排序后连续覆盖 → 重组完成
"""

from .ip_fragment import FragmentReassembler

__all__ = ["FragmentReassembler"]
