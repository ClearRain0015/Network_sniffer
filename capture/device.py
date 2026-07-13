#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture/device.py — 网卡管理模块
===============================
职责：
  1. 列出本机所有可用网卡
  2. 提供网卡选择接口
  3. 记录当前监听的网卡信息

优先使用 scapy 的 conf.ifaces 获取 Windows 友好名称，
不可用则回退到标准库 socket。
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class InterfaceInfo:
    """网卡信息"""
    name: str                   # 显示名称（友好名，如 "WLAN"）
    ip: str                     # IP 地址
    mac: str                    # MAC 地址
    description: str            # 描述
    is_loopback: bool           # 是否为回环网卡
    scapy_name: str = ""        # 传给 scapy sniff() 的名称（NPF 路径）


def list_interfaces() -> List[InterfaceInfo]:
    """
    枚举本机所有可用网卡
    --------------------
    优先使用 scapy conf.ifaces 获取完整信息，
    不可用则回退到标准库 socket。

    返回 InterfaceInfo 列表供 GUI 展示。
    """
    interfaces = []

    # ── 方案1：scapy conf.ifaces（推荐） ────
    try:
        from scapy.all import conf

        # 强制重新加载接口列表（scapy 2.7 需要手动 reload）
        conf.ifaces.reload()

        for iface in conf.ifaces.values():
            name = iface.name or iface.network_name or "Unknown"
            scapy_name = iface.network_name or iface.name or name
            ip = iface.ip or "N/A"
            mac = iface.mac or "N/A"
            desc = iface.description or name

            # 跳过没有 IP 且看起来不活跃的虚拟适配器
            # (WAN Miniport 等通常抓不到有用流量)

            interfaces.append(InterfaceInfo(
                name=name,
                ip=ip,
                mac=mac,
                description=desc,
                is_loopback=("loopback" in name.lower()),
                scapy_name=scapy_name,
            ))

        if interfaces:
            return interfaces
    except ImportError:
        pass

    # ── 方案2：标准库 socket（回退方案） ────
    import socket
    import uuid

    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip = "127.0.0.1"

    interfaces.append(InterfaceInfo(
        name="Loopback",
        ip="127.0.0.1",
        mac="00:00:00:00:00:00",
        description="Loopback",
        is_loopback=True,
        scapy_name="loopback",
    ))

    return interfaces


def select_interface(name: str) -> Optional[InterfaceInfo]:
    """根据网卡名选择一个网卡"""
    for iface in list_interfaces():
        if iface.name == name:
            return iface
    return None
