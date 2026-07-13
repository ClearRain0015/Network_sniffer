"""
save/ — 保存模块
================
支持三种格式：
  1. PCAP  — Wireshark 可直接打开
  2. TXT   — 可读文本格式
  3. CSV   — Excel 可打开
"""

from .pcap_save import save_packets, save_as_pcap, save_as_txt, save_as_csv

__all__ = ["save_packets", "save_as_pcap", "save_as_txt", "save_as_csv"]
