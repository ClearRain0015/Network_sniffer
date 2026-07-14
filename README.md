# Sniffer — 网络数据包嗅探器

基于 Python 的模块化网络数据包分析工具，功能和界面模仿 Wireshark。

## 功能特性

- **网卡枚举** — 自动识别所有网卡，显示友好名称+IP，活跃网卡优先
- **实时抓包** — Scapy 主模式 + Raw Socket 回退（缺 Npcap 时自动降级）
- **协议解析** — 12 种协议全覆盖
- **IP 分片重组** — Fragment Table 缓存 + Offset 排序拼接 + 30s 超时淘汰
- **BPF 过滤** — `tcp` / `udp port 80` / `host 192.168.1.1` / `tcp port 443` 等
- **Payload 面板** — 显示应用层可读文本（HTTP 请求/响应、DNS 查询等）
- **PCAP 保存** — `.pcap`（Wireshark 可打开）、TXT、CSV 三种格式
- **流量统计** — 协议分布、Top IP/端口、包大小分布、pps 速率、饼图
- **双 GUI 后端** — PyQt5（推荐，接近 Wireshark）+ Tkinter（回退）
- **单元测试** — 协议解析 + 高级功能测试覆盖

## 协议支持

```
Ethernet
├── ARP
├── IPv4
│   ├── ICMP（Ping Echo Request/Reply）
│   ├── TCP → HTTP
│   └── UDP → DNS / DHCP
└── IPv6
```

## 项目结构

```
Sniffer/
├── main.py                     # 程序入口
├── requirements.txt            # 依赖清单
├── capture/                    # 网卡管理 + 数据捕获
│   ├── device.py               #   网卡枚举（友好名称显示）
│   └── sniffer.py              #   抓包启停（Scapy + socket 回退）
├── protocols/                  # 协议解析器链（核心）
│   ├── base.py                 #   ParsedPacket 统一数据结构
│   ├── parser_chain.py         #   责任链调度
│   ├── ethernet.py / arp.py    #   链路层
│   ├── ip.py / ipv6.py         #   网络层
│   ├── tcp.py / udp.py         #   传输层
│   ├── icmp.py                 #   网络诊断
│   ├── http.py / dns.py        #   应用层
│   └── dhcp.py                 #   应用层
├── gui/                        # 图形界面
│   ├── main_window.py          #   主窗口（Wireshark 风格）
│   ├── packet_table.py         #   数据包列表（QTableView）
│   └── packet_detail.py        #   协议树 + 十六进制 + Payload
├── reassembly/                 # IP 分片重组
│   └── ip_fragment.py
├── filter/                     # BPF 过滤器
│   └── bpf_filter.py
├── save/                       # 保存模块
│   └── pcap_save.py            #   PCAP / TXT / CSV
├── statistics/                 # 流量统计 + 图表
│   └── flow_statistics.py
├── utils/                      # 工具函数
│   └── tools.py
└── tests/                      # 单元测试
    ├── test_protocol_parsers.py
    └── test_advanced_features.py
```

## 快速开始

### 环境要求

- Python 3.8+
- **管理员/root 权限**（抓包必需）

### 安装

```bash
# 1. Python 依赖
pip install -r requirements.txt

# 2. Windows 用户安装 Npcap（可选，强烈推荐）
#    下载：https://npcap.com/dist/npcap-1.80.exe
#    安装时勾选 "Install Npcap in WinPcap API-compatible Mode"
#    macOS/Linux 自带 libpcap，无需额外安装
```

> 没有 Npcap 也能用：程序自动回退 socket 模式，但**必须管理员权限**。

### 运行

```bash
# Windows：以管理员身份打开终端
python main.py

# macOS/Linux：
sudo python main.py
```

### 运行测试

```bash
pytest tests/ -v
```

## 界面布局

```
┌──────────────────────────────────────────────────────────┐
│ 网卡: [Intel Wi-Fi 6E (10.181.61.240) ▼]                 │
│ ▶ 开始抓包  ⏹ 停止  💾 保存PCAP  🗑 清空               │
│ 过滤: [tcp port 80                  ]  [应用]  📊 统计    │
├──────────────────────────────────────────────────────────┤
│ No │ Time         │ Source         │ Dest   │ Proto      │
│  1 │ 12:34:56.123 │ 192.168.1.1    │ 1.2.3.4│ TCP        │
│  2 │ 12:34:56.456 │ 192.168.1.1    │ 1.2.3.4│ HTTP       │
├──────────────────────────────────────────────────────────┤
│ ▼ Ethernet                        │  ▲ 协议字段树        │
│   Destination MAC : aa:bb:...     │                      │
│ ▼ IPv4                            │                      │
│   Source IP : 192.168.1.1         │                      │
│ ▼ TCP                             │                      │
│   Flags : [SYN · ACK]             │                      │
├──────────────────────────────────────────────────────────┤
│ 0000  aa bb cc dd ee ff 11 22  33 44 55 66 08 00 ...     │
├──────────────────────────────────────────────────────────┤
│ GET /index.html HTTP/1.1           ▲ Payload 可读文本     │
│ Host: www.example.com              │                      │
└──────────────────────────────────────────────────────────┘
```

## 架构设计

```
GUI (PyQt5 / Tkinter)
        │
        ▼
Controller（控制层）
  开始/停止抓包 → 过滤 → 保存 → IP 重组
        │
        ▼
Packet Capture（Scapy / socket）
        │
        ▼
Protocol Parser（协议解析链）
  Ethernet → ARP / IPv4 / IPv6 → TCP / UDP / ICMP → HTTP / DNS / DHCP
        │
        ▼
Data Processing（IP 分片重组 + 统计）
        │
        ▼
Save Module（PCAP / TXT / CSV）
```

## 开发阶段

| 阶段 | 内容 | 状态 |
|------|------|------|
| 一 | 抓包基础：网卡枚举、启停抓包、终端打印 | ✅ 完成 |
| 二 | 协议解析：12 种协议全覆盖 | ✅ 完成 |
| 三 | GUI：包列表 + 协议树 + 十六进制 + Payload 面板 | ✅ 完成 |
| 四 | 高级功能：BPF 过滤、IP 分片重组、PCAP 保存、流量统计 | ✅ 完成 |
| 五 | 扩展加分：HTTP/DNS/DHCP 解析、IPv6、流量图表、单元测试 | ✅ 完成 |

## 技术栈

| 类别 | 推荐 | 备选 |
|------|------|------|
| 语言 | Python 3 | — |
| 抓包 | Scapy（需 Npcap） | Raw Socket |
| GUI | PyQt5 | Tkinter |
| 数据处理 | 标准库 `struct` + `collections` | — |
| 保存 | Scapy `wrpcap()` | dpkt |
| 测试 | pytest | — |
| 图表 | Matplotlib | — |

## 依赖

| 包 | 用途 | 必需 |
|---|---|---|
| `scapy` | 抓包、协议解析、PCAP 读写 | ✅ |
| `PyQt5` | GUI 界面 | ✅ |
| `dpkt` | PCAP 读写备选 | ✅ |
| `matplotlib` | 流量图表 | ✅ |
| `pytest` | 单元测试 | ✅ |

## 注意事项

1. **必须以管理员权限运行**
2. Windows 安装 Npcap 时勾选 WinPcap 兼容模式
3. Python 3.12+ 可能与某些旧版 Scapy 不兼容，建议 Python 3.8 ~ 3.11
4. 虚拟机 NAT 模式下抓包受限，建议使用桥接模式
5. 抓取大量数据包时注意内存占用，可配合 BPF 过滤器使用

## License

仅用于课程设计学习。
