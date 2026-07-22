"""
protocols/ — 协议解析模块（项目重点）
===============================
解析树：
  Ethernet
    ├── ARP
    ├── IPv4
    │   ├── ICMP
    │   ├── TCP  → HTTP / HTTPS / FTP
    │   └── UDP  → DNS  / DHCP
    └── IPv6（可选）

解析顺序：
  Ethernet → 判断 Type → ARP? / IPv4? → 读取 Protocol → TCP? / UDP? / ICMP?
  每层只负责解析自己的协议。
"""

from .base import ParsedPacket, ProtocolLayer
from .ethernet import EthernetParser
from .arp import ARPParser
from .ip import IPv4Parser
from .ipv6 import IPv6Parser
from .tcp import TCPParser
from .udp import UDPParser
from .icmp import ICMPParser
from .http import HTTPParser
from .tls import TLSParser
from .dns import DNSParser
from .dhcp import DHCPParser
from .parser_chain import ParserChain

__all__ = [
    "ParsedPacket",
    "ProtocolLayer",
    "EthernetParser",
    "ARPParser",
    "IPv4Parser",
    "IPv6Parser",
    "TCPParser",
    "UDPParser",
    "ICMPParser",
    "HTTPParser",
    "TLSParser",
    "DNSParser",
    "DHCPParser",
    "ParserChain",
]
