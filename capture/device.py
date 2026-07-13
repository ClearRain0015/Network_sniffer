#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture/device.py — 网卡管理模块
===============================
职责：
  1. 列出本机所有可用网卡
  2. 提供网卡选择接口
  3. 记录当前监听的网卡信息

Python 可直接调用 scapy.get_if_list() 获取：
  Ethernet / WLAN / VMware / Loopback 等
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class InterfaceInfo:
    """网卡信息"""
    name: str          # 网卡名称，如 "eth0", "WLAN 1"
    ip: str            # IP 地址
    mac: str           # MAC 地址
    description: str   # 描述/友好名称
    is_loopback: bool  # 是否为回环网卡


def list_interfaces() -> List[InterfaceInfo]:
    """
    枚举本机所有可用网卡
    --------------------
    优先使用 scapy 获取网卡信息，
    不可用则回退到标准库 socket。
    """
    interfaces = []

    # ── 方案1：scapy ──────────────────────────
    try:
        from scapy.all import get_if_list, get_if_hwaddr

        for iface_name in get_if_list():
            try:
                mac_addr = get_if_hwaddr(iface_name) if iface_name else "N/A"
                is_lo = iface_name.lower().startswith("lo") or iface_name == "lo"

                interfaces.append(InterfaceInfo(
                    name=iface_name,
                    ip="N/A",
                    mac=mac_addr,
                    description=iface_name,
                    is_loopback=is_lo,
                ))
            except Exception:
                continue

        if interfaces:
            return interfaces
    except ImportError:
        pass

    # ── 方案2：标准库 socket（回退方案） ─────────
    import socket
    import uuid

    # 尝试获取本机实际的 IP 和网卡信息
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip = "127.0.0.1"

    # 使用 scapy 的 conf.iface 作为默认网卡名（如果可用）
    iface_name = "default"
    try:
        from scapy.config import conf
        iface_name = conf.iface.name if conf.iface else iface_name
    except Exception:
        pass

    interfaces.append(InterfaceInfo(
        name=iface_name,
        ip=ip,
        mac=hex(uuid.getnode())[2:],
        description=f"默认网卡 ({hostname})",
        is_loopback=False,
    ))

    # 回环
    interfaces.append(InterfaceInfo(
        name="loopback",
        ip="127.0.0.1",
        mac="00:00:00:00:00:00",
        description="Loopback",
        is_loopback=True,
    ))

    return interfaces


def select_interface(name: str) -> Optional[InterfaceInfo]:
    """根据网卡名选择一个网卡"""
    for iface in list_interfaces():
        if iface.name == name:
            return iface
    return None
