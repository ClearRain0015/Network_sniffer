# Sniffer — 网络数据包嗅探器

基于 Python 的模块化网络数据包分析工具，功能和界面模仿 Wireshark。

## 功能特性

- **网卡枚举** — 自动列出所有可用网卡（Ethernet / WLAN / Loopback）
- **实时抓包** — 基于 Scapy 捕获数据包，支持原始 socket 回退
- **协议解析** — 逐层解析 Ethernet → ARP / IPv4 → TCP / UDP / ICMP → HTTP / DNS
- **IP 分片重组** — Fragment Table 缓存 + 超时淘汰，完整拼接后输出
- **BPF 过滤** — 支持 `tcp`、`udp port 80`、`host 192.168.1.1` 等表达式
- **PCAP 保存** — 导出为 `.pcap`（Wireshark 可打开）、TXT、CSV
- **流量统计** — 协议分布、Top IP / 端口、包速率
- **双 GUI 后端** — PyQt5（推荐，接近 Wireshark）和 Tkinter（回退）

## 项目结构

```
Sniffer/
├── main.py                 # 程序入口
├── requirements.txt        # 依赖清单
├── capture/                # 网卡管理 + 数据捕获
├── parser/                 # 协议解析器链（核心）
├── gui/                    # 图形界面
├── reassembly/             # IP 分片重组
├── filter/                 # BPF 过滤器
├── save/                   # PCAP/TXT/CSV 保存
├── statistics/             # 流量统计 + 图表
└── utils/                  # 工具函数
```

## 快速开始

### 环境要求

- Python 3.8+
- **管理员/root 权限**（抓包必需）

### 安装

```bash
# 完整安装（推荐）
pip install -r requirements.txt

# 最小安装（仅基础功能）
pip install scapy
```

### 运行

```bash
python main.py
```

## 界面布局

```
┌──────────────────────────────────────────────────────┐
│ 网卡: [eth0 ▼]   ▶ 开始抓包  ⏹ 停止  💾 保存  🗑 清空 │
│ 过滤: [tcp port 80              ]  [应用]  📊 统计   │
├──────────────────────────────────────────────────────┤
│ No │ Time         │ Source        │ Dest   │ Proto   │
│  1 │ 12:34:56.123 │ 192.168.1.1   │ 1.2.3.4│ TCP     │
│  2 │ 12:34:56.456 │ 192.168.1.1   │ 1.2.3.4│ HTTP    │
├──────────────────────────────────────────────────────┤
│ ▼ Ethernet                                           │
│   Destination MAC : aa:bb:cc:dd:ee:ff               │
│   Source MAC      : 11:22:33:44:55:66               │
│ ▼ IPv4                                               │
│   Source IP       : 192.168.1.1                      │
│   TTL             : 128                               │
│ ▼ TCP                                                │
│   Source Port     : 54321                             │
│   Flags           : [SYN · ACK]                      │
├──────────────────────────────────────────────────────┤
│ 0000  aa bb cc dd ee ff 11 22  33 44 55 66 08 00 ... │
└──────────────────────────────────────────────────────┘
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
  Ethernet → ARP/IPv4 → TCP/UDP/ICMP → HTTP/DNS
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
| 一 | 抓包基础：网卡枚举、启停抓包、终端打印 | ✅ 框架 |
| 二 | 协议解析：Ethernet → IPv4 → TCP/UDP/ICMP/ARP | ✅ 框架 |
| 三 | GUI：包列表 + 协议树 + 十六进制面板 | ✅ 框架 |
| 四 | 高级功能：BPF 过滤、IP 分片重组、PCAP 保存、流量统计 | ✅ 框架 |
| 五 | 扩展加分：HTTP 头解析、DNS 解析、流量图表 | ✅ 框架 |

## 技术栈

- **语言**：Python 3
- **抓包**：Scapy（主）+ Raw Socket（回退）
- **GUI**：PyQt5（主）+ Tkinter（回退）
- **数据处理**：标准库 `struct` + `collections`
- **保存**：Scapy `wrpcap()` / dpkt
- **图表（可选）**：Matplotlib

## 依赖

| 包 | 用途 | 必需 |
|---|---|---|
| `scapy` | 抓包、协议解析、PCAP 读写 | ✅ 是 |
| `PyQt5` | GUI 界面（推荐） | 二选一 |
| `dpkt` | PCAP 读写备选 | ❌ 否 |
| `matplotlib` | 流量图表 | ❌ 否 |

## 注意事项

1. **必须以管理员权限运行** — Windows 下右键"以管理员身份运行"，Linux/Mac 使用 `sudo`
2. Python 3.12+ 可能与某些旧版 Scapy 不兼容，建议使用 Python 3.8 ~ 3.11
3. 虚拟机 NAT 模式下抓包可能受限，建议使用桥接模式
4. 抓取大量数据包时注意内存占用，可配合 BPF 过滤器使用
