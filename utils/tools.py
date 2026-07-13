#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
utils/tools.py — 通用工具函数
=============================
"""

import time
import sys
import ctypes
import os


def format_mac(addr_bytes: bytes) -> str:
    """将 6 字节 MAC 地址格式化为 'aa:bb:cc:dd:ee:ff'"""
    return ":".join(f"{b:02x}" for b in addr_bytes)


def format_ip(addr_bytes: bytes) -> str:
    """将 4 字节 IPv4 地址格式化为 'x.x.x.x'"""
    return ".".join(str(b) for b in addr_bytes)


def timestamp_to_str(ts: float) -> str:
    """将时间戳转为格式化字符串 'HH:MM:SS.microseconds'"""
    return time.strftime("%H:%M:%S.", time.localtime(ts)) + \
           f"{int((ts % 1) * 1_000_000):06d}"


def bytes_to_hexstr(data: bytes, max_len: int = 256) -> str:
    """
    将字节数据转为十六进制字符串

    返回格式:
      0000  aa bb cc dd ee ff 00 11  22 33 44 55 66 77 88 99  ..........3DUfw..
    """
    if len(data) > max_len:
        data = data[:max_len]

    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = ""
        ascii_part = ""

        for i in range(16):
            if i < len(chunk):
                b = chunk[i]
                hex_part += f"{b:02x} "
                if i == 7:
                    hex_part += " "
                if 32 <= b < 127:
                    ascii_part += chr(b)
                else:
                    ascii_part += "."
            else:
                hex_part += "   "
                if i == 7:
                    hex_part += " "

        hex_part = hex_part.ljust(50)
        lines.append(f"{offset:04x}  {hex_part} {ascii_part}")

    return "\n".join(lines)


def format_hex(data: bytes, bytes_per_line: int = 16) -> str:
    """格式化为纯十六进制字符串（无 ASCII 对照）"""
    return " ".join(f"{b:02x}" for b in data)


def is_admin() -> bool:
    """
    检查是否以管理员/root 权限运行

    抓包通常需要管理员权限。
    """
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False
