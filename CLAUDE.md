# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sniffer — a modular Python network packet analyzer inspired by Wireshark. Captures live traffic, parses protocols layer-by-layer, and displays results in a GUI.

## Commands

```bash
# Run the application (requires admin/root)
python main.py                        # Windows: run as Administrator
sudo python main.py                   # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Run all tests
python -m pytest tests/ -v
python -m unittest tests/test_protocol_parsers.py
python -m unittest tests/test_advanced_features.py

# Run a single test
python -m unittest tests.test_protocol_parsers.ProtocolParserTests.test_tcp_payload_is_parsed_from_ethernet_ipv4
```

## Architecture

Data flows through a unidirectional pipeline:

```
Capture (Scapy/socket) → ParserChain → FragmentReassembler → BPFFilter → GUI display / Save
```

### Core data structure

[ParsedPacket](protocols/base.py) is the universal data object that flows through every stage. It holds raw bytes, parsed layer info (`layers: List[ProtocolLayer]`), and offset markers (`network_offset`, `transport_offset`, `payload_offset`) so each parser stage operates on the right byte range without assuming a specific encapsulation. All protocol parsers read from and write to the same `ParsedPacket` instance.

### Protocol parsing — Chain of Responsibility

[ParserChain](protocols/parser_chain.py) registers parsers in a fixed order: `Ethernet → ARP → IPv4 → ICMP → TCP → UDP → HTTP → DNS`. Each parser exposes two static methods:

- `can_parse(packet)` — inspects the packet to decide if this layer applies (e.g., `IPv4Parser` checks `eth_type == 0x0800` or that the first nibble is `0x4`)
- `parse(packet)` — extracts fields from raw bytes using `struct`, populates `packet.layers`, sets offset markers, and returns the same packet

A parser failure in one layer does not break the chain — the exception is caught and recorded in `packet.info`.

### Capture module

[Sniffer](capture/sniffer.py) runs in a background daemon thread. It tries Scapy's `sniff()` first; if Scapy is missing or Npcap is unavailable (Windows), it falls back to raw sockets (`SOCK_RAW` with `IPPROTO_IP`). Raw packets are converted to `ParsedPacket` via `_scapy_to_parsed()` and pushed through a callback (`on_packet`).

### Dual GUI backends

The GUI supports both PyQt5 (primary) and Tkinter (fallback). [main_window.py](gui/main_window.py) detects PyQt5 availability at import time via a module-level `_HAS_PYQT5` flag. Both backends share the same logical flow: a toolbar for interface selection/start/stop/filter/save, a packet table, a protocol detail tree, and a hex dump panel. The PyQt5 version uses `QThread` + `pyqtSignal` for thread-safe packet delivery with a 100ms flush timer; the Tkinter version uses `threading` + `root.after()` polling.

The filter is applied **post-capture** at the application level (not passed to the driver) because Windows/Npcap BPF can silently drop valid ICMP packets. This means all packets are captured and then matched against `BPFFilter` after parsing.

### IP fragment reassembly

[FragmentReassembler](reassembly/ip_fragment.py) caches fragments keyed by `(src_ip, dst_ip, ip_id, protocol)`. When `process()` sees a fragment (MF=1 or offset>0), it buffers it in a `_FragmentGroup`. Once the final fragment (MF=0) arrives and the byte range is contiguous, it rebuilds a complete packet with a recalculated IPv4 header checksum and re-parses it through `ParserChain`. Expired groups (>30s) are evicted. Non-fragmented packets pass through unchanged.

### BPF filter

[BPFFilter](filter/bpf_filter.py) implements a subset of BPF expression syntax at the application level — it operates on already-parsed `ParsedPacket` objects, not raw bytes. Supports `and`/`or`/`not` combinators, protocol keywords (`tcp`, `udp`, `icmp`, `arp`, `http`, `dns`), `host`, `port`, `src`/`dst` direction qualifiers, and `portrange`.

### Save module

[save/pcap_save.py](save/pcap_save.py) writes standard libpcap-format files using only the stdlib `struct` module (no Scapy dependency). It auto-detects link type (Ethernet vs raw IP) and writes the global pcap header + per-packet records. Also supports TXT and CSV export.

### Statistics & alerts

[flow_statistics.py](statistics/flow_statistics.py) computes protocol distribution, top IPs/ports, packet size buckets, and time-bucketed traffic trends (for Matplotlib charts). [alerts.py](statistics/alerts.py) implements a sliding-window SYN flood detector using `collections.deque`.

## Key conventions

- Protocol parsers are stateless — all state lives on `ParsedPacket`
- Offset fields (`network_offset`, `transport_offset`, `payload_offset`) are set by lower-layer parsers and consumed by upper-layer parsers, so the chain works whether capture starts at Ethernet or raw IPv4
- The capture filter in the GUI is intentionally broad (`""`); filtering happens post-parse to avoid driver-level BPF issues on Windows
- Packets are batched through a pending queue and flushed on a timer to keep the GUI responsive
- Npcap must be installed in "WinPcap API-compatible Mode" on Windows for Scapy capture; otherwise the raw socket fallback captures only IP-layer data
