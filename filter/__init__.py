"""
filter/ — 包过滤模块
====================
支持 BPF（Berkeley Packet Filter）语法过滤。

支持的过滤表达式：
  tcp          — 只显示 TCP 包
  udp          — 只显示 UDP 包
  icmp         — 只显示 ICMP 包
  arp          — 只显示 ARP 包
  host x.x.x.x — 按 IP 过滤
  port 80      — 按端口过滤
  tcp port 443 — 组合过滤
  ip           — 只显示 IP 包
"""

from .bpf_filter import BPFFilter

__all__ = ["BPFFilter"]
