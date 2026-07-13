#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture/device.py — 网卡管理模块
===============================
职责：
  1. 列出本机所有可用网卡（显示友好名称和 IP）
  2. 提供网卡选择接口
  3. 记录当前监听的网卡信息
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class InterfaceInfo:
    """网卡信息"""
    name: str          # 网卡路径（UUID，供 scapy 抓包用）
    ip: str            # IP 地址
    mac: str           # MAC 地址
    description: str   # 友好名称（如 "Intel Wi-Fi 6E"）
    is_loopback: bool  # 是否为回环网卡
    display: str       # GUI 显示名 "描述 (IP)"


def _is_auto_ip(ip: str) -> bool:
    """判断是否为自动配置的无效 IP（169.254.x.x）"""
    return ip.startswith("169.254.") or ip.startswith("0.0.0.0")


def list_interfaces() -> List[InterfaceInfo]:
    """
    枚举本机所有可用网卡
    --------------------
    使用 scapy 的 IFACES 获取友好名称和 IP，
    按优先级排序：有真实 IP 的排前面。
    """
    interfaces = []

    try:
        from scapy.all import IFACES, get_if_hwaddr

        for name, iface in IFACES.items():
            try:
                desc = iface.description or name
                ip = iface.ip or "N/A"
                is_lo = "loopback" in name.lower() or ip == "127.0.0.1"

                # MAC
                try:
                    mac = get_if_hwaddr(name)
                except Exception:
                    mac = "N/A"

                # 显示名：描述 + IP
                display = f"{desc} ({ip})"

                interfaces.append(InterfaceInfo(
                    name=name,
                    ip=ip,
                    mac=mac,
                    description=desc,
                    is_loopback=is_lo,
                    display=display,
                ))
            except Exception:
                continue

        # 排序：有真实 IP 的排前面
        if interfaces:
            interfaces.sort(key=lambda i: (
                _is_auto_ip(i.ip),   # 自动 IP 排后面
                i.is_loopback,        # 回环排后面
            ))

        if interfaces:
            return interfaces

    except ImportError:
        pass

    # ── 回退方案：标准库 ──────────────────────
    import socket
    import uuid

    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip = "127.0.0.1"

    interfaces.append(InterfaceInfo(
        name="default",
        ip=ip,
        mac=hex(uuid.getnode())[2:],
        description=f"默认网卡 ({hostname})",
        is_loopback=False,
        display=f"默认网卡 ({hostname}) - {ip}",
    ))

    interfaces.append(InterfaceInfo(
        name="loopback",
        ip="127.0.0.1",
        mac="00:00:00:00:00:00",
        description="Loopback",
        is_loopback=True,
        display="Loopback (127.0.0.1)",
    ))

    return interfaces


def select_interface(name: str) -> Optional[InterfaceInfo]:
    """根据网卡名选择一个网卡"""
    for iface in list_interfaces():
        if iface.name == name:
            return iface
    return None
