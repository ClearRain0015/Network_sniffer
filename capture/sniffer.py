#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture/sniffer.py — 数据捕获模块
================================
职责：
  1. 在选定网卡上持续监听数据包
  2. 将每个收到数据包交给解析器
  3. 通知 GUI 刷新显示

核心循环（流水线）：
  while True:
      packet = 下一帧
      → Parser.parse(packet)
      → 过滤
      → IP 重组
      → GUI 更新
"""

import threading
import time
from typing import Optional, Callable

from protocols.base import ParsedPacket


class Sniffer:
    """
    抓包器 — 管理与 scapy/pcap 交互的核心类

    使用方式:
        sniffer = Sniffer(interface="eth0")
        sniffer.start()
        ...
        sniffer.stop()
    """

    def __init__(self, interface: str = "eth0", bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.print_packets = True
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0

        # 回调：收到新包时调用
        self.on_packet: Optional[Callable[[ParsedPacket], None]] = None

    # ── 属性 ──────────────────────────────────

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def is_running(self) -> bool:
        return self._running

    # ── 公共方法 ──────────────────────────────

    def start(self) -> None:
        """
        开始抓包
        -------
        后台线程中执行 sniff()，避免阻塞 GUI
        """
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="sniff-thread",
        )
        self._thread.start()

    def stop(self) -> None:
        """停止抓包"""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def set_filter(self, bpf: str) -> None:
        """动态更新 BPF 过滤器"""
        self.bpf_filter = bpf

    # ── 内部实现 ──────────────────────────────

    def _sniff_loop(self) -> None:
        """
        抓包主循环
        ---------
        优先使用 scapy.sniff 做持续性捕获；
        scapy 不可用/缺 Npcap 时，用原始 socket 兜底。
        """
        try:
            self._sniff_with_scapy()
        except (ImportError, OSError, RuntimeError) as e:
            print(f"[!] scapy 抓包失败: {e}")
            print("[*] Windows 用户请安装 Npcap: https://npcap.com/dist/npcap-1.80.exe")
            print("[*] 安装时勾选 'Install Npcap in WinPcap API-compatible Mode'")
            print("[*] 现在尝试 socket 回退模式（需管理员权限）...")
            self._sniff_with_socket()

    def _sniff_with_scapy(self) -> None:
        """使用 scapy 抓包（推荐）"""
        from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether

        # 构造 BPF 过滤字符串
        filt = self.bpf_filter if self.bpf_filter else None

        def process_packet(pkt):
            """scapy 回调：每收到一个包就调用"""
            if not self._running:
                # 返回 True 终止 sniff
                return True

            self._packet_count += 1

            # 解析为 ParsedPacket 并回调
            parsed = self._scapy_to_parsed(pkt, self._packet_count)
            self._print_packet_summary(parsed)
            if self.on_packet and parsed:
                self.on_packet(parsed)

        # 在独立线程中持续监听
        sniff(
            iface=self.interface,
            prn=process_packet,
            filter=filt,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def _sniff_with_socket(self) -> None:
        """
        使用原始 socket 兜底捕获
        -----------------------
        Windows 需要管理员权限，且只能抓到 IP 层。
        """
        import socket

        try:
            # Windows: 绑定到本机 IP 抓 IP 包
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_IP,
            )
            sock.bind(("0.0.0.0", 0))
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_HDRINCL,
                1,
            )
            # 启用混杂模式（Windows）
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except (OSError, AttributeError):
                pass

            sock.settimeout(0.5)

            while self._running:
                try:
                    raw = sock.recvfrom(65535)[0]
                    self._packet_count += 1
                    # 将原始字节包装为 ParsedPacket
                    parsed = ParsedPacket(
                        no=self._packet_count,
                        timestamp=time.time(),
                        raw_data=raw,
                        length=len(raw),
                        proto_name="IPv4",
                        summary=f"Raw IPv4 packet len={len(raw)}",
                    )
                    self._print_packet_summary(parsed)
                    if self.on_packet:
                        self.on_packet(parsed)
                except socket.timeout:
                    continue
                except OSError:
                    break

        except (OSError, ImportError) as e:
            print(f"[!] socket 抓包也失败了: {e}")
            print("[*] 请以管理员/root 权限运行本程序")
        finally:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _scapy_to_parsed(pkt, packet_no: int) -> "ParsedPacket":
        """
        将 scapy 原始包转为统一 ParsedPacket 结构
        -----------------------------------------
        ParsedPacket 是解析器管线中使用的标准格式。
        """
        from scapy.all import raw as scapy_raw

        raw = bytes(pkt)
        parsed = ParsedPacket(
            no=packet_no,
            timestamp=pkt.time if hasattr(pkt, "time") else time.time(),
            raw_data=raw,
            length=len(raw),
        )

        # 填充链路层信息
        if pkt.haslayer("Ether"):
            eth = pkt["Ether"]
            parsed.eth_src = eth.src
            parsed.eth_dst = eth.dst
            parsed.eth_type = eth.type

        # 填充网络层概要
        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            parsed.ip_src = ip.src
            parsed.ip_dst = ip.dst
            parsed.ip_proto = ip.proto
            parsed.ip_len = ip.len
            parsed.ip_id = ip.id
            parsed.ip_flags = ip.flags
            parsed.ip_frag = ip.frag
            parsed.ip_ttl = ip.ttl

        # 高层协议标记
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            parsed.proto_name = "TCP"
            parsed.src_port = tcp.sport
            parsed.dst_port = tcp.dport
            parsed.tcp_flags = tcp.flags
            parsed.tcp_seq = tcp.seq
            parsed.tcp_ack = tcp.ack
        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            parsed.proto_name = "UDP"
            parsed.src_port = udp.sport
            parsed.dst_port = udp.dport
        elif pkt.haslayer("ICMP"):
            parsed.proto_name = "ICMP"
        elif pkt.haslayer("ARP"):
            parsed.proto_name = "ARP"
        else:
            parsed.proto_name = "Other"

        # 简要信息摘要
        parsed.summary = pkt.summary() if hasattr(pkt, "summary") else ""
        return parsed

    def _print_packet_summary(self, packet: ParsedPacket) -> None:
        """Print one-line packet information for terminal-mode verification."""
        if not self.print_packets:
            return
        info = packet.info or packet.summary
        if len(info) > 100:
            info = info[:97] + "..."
        print(
            f"[{packet.no:05d}] {packet.timestamp_str} "
            f"{packet.src_str} -> {packet.dst_str} "
            f"{packet.proto_name or 'Other'} len={packet.length} {info}",
            flush=True,
        )


class SniffWorker:
    """
    抓包工作线程包装器
    -----------------
    用于 PyQt5 的 QThread 环境中，支持信号/槽通知。
    """

    def __init__(self, interface: str, bpf_filter: str = ""):
        self.sniffer = Sniffer(interface, bpf_filter)

    def run(self):
        """启动抓包（阻塞，应在子线程中运行）"""
        self.sniffer.start()

    def stop(self):
        """停止抓包"""
        self.sniffer.stop()
