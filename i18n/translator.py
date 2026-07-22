#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal Chinese/English labels for the GUI."""

LANGUAGES = {
    "zh": "中文",
    "en": "English",
}

_TEXT = {
    "window_title": {"zh": "Sniffer — 网络数据包分析器", "en": "Sniffer - Network Packet Analyzer"},
    "search": {"zh": "搜索", "en": "Search"},
    "prev": {"zh": "上一个", "en": "Prev"},
    "next": {"zh": "下一个", "en": "Next"},
    "dark": {"zh": "暗色", "en": "Dark"},
    "light": {"zh": "亮色", "en": "Light"},
    "http_pairs": {"zh": "HTTP配对", "en": "HTTP Pairs"},
    "replay": {"zh": "重放", "en": "Replay"},
    "inject": {"zh": "注入", "en": "Inject"},
    "language": {"zh": "语言", "en": "Lang"},
    "no_packets": {"zh": "没有数据包", "en": "No packets"},
    "no_match": {"zh": "没有匹配项", "en": "No matches"},
    "ready": {"zh": "就绪", "en": "Ready"},
}


def t(key: str, lang: str = "zh") -> str:
    item = _TEXT.get(key)
    if not item:
        return key
    return item.get(lang) or item.get("zh") or key
