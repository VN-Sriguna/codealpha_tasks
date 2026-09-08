# CodeAlpha_NetworkSniffer

**CodeAlpha Cyber Security Internship — Task 1: Basic Network Sniffer**

A Python packet sniffer that captures network traffic, walks common protocol layers, and prints the fields you need to understand how data moves across a network: source and destination addresses, protocol, and payload.

Use this only on networks you own or have permission to monitor.

## What it shows

Each packet is broken into the layers you meet in a typical capture:

| Layer | What you learn |
| --- | --- |
| Ethernet | MAC addresses and frame type |
| IPv4 / IPv6 | Source/destination IP, TTL, protocol number |
| TCP / UDP / ICMP | Ports, flags, sequence numbers, ICMP type/code |
| Application hints | HTTP requests, DNS queries when present |
| Payload | Hex and printable ASCII preview |

At the end of a session it prints a short summary: packet count, bytes, protocol mix, and top source IPs.

## Setup

```bash
cd CodeAlpha_NetworkSniffer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Live capture needs administrator privileges because the OS will not hand raw frames to a normal user process.

## Usage

**Try the analyzer without capturing live traffic** (good first run):

```bash
python3 sniffer.py --demo -v
```

**List interfaces:**

```bash
python3 sniffer.py --list-interfaces
```

**Capture 20 packets on macOS Wi-Fi (`en0`) and print full layer details:**

```bash
sudo python3 sniffer.py -i en0 -c 20 -v
```

**Filter with BPF** (only HTTP or only ICMP):

```bash
sudo python3 sniffer.py -i en0 -f "tcp port 80" -c 30 -v
sudo python3 sniffer.py -i en0 -f icmp -c 10
```

**Save a pcap, then analyze it later without sudo:**

```bash
sudo python3 sniffer.py -i en0 -c 50 -w capture.pcap
python3 sniffer.py -r capture.pcap -v
```

### Common flags

| Flag | Meaning |
| --- | --- |
| `-i`, `--iface` | Interface to sniff |
| `-c`, `--count` | Stop after N packets (`0` = until Ctrl+C) |
| `-f`, `--filter` | BPF filter string |
| `-r`, `--read` | Read packets from a `.pcap` file |
| `-w`, `--write` | Write captured packets to a `.pcap` file |
| `-v`, `--verbose` | Print Ethernet / IP / TCP fields |
| `--demo` | Analyze crafted sample packets |
| `--list-interfaces` | Print local interface names |

## How packet flow is represented

Traffic is stacked. Ethernet carries IP, IP carries TCP or UDP (or ICMP), and those carry application data:

```
Ethernet  →  IP  →  TCP/UDP/ICMP  →  payload (HTTP, DNS, …)
```

The sniffer prints that path as `layers` in verbose mode so you can map a line of output back to this model.

## Project layout

```
sniffer.py            CLI: live capture, pcap replay, demo packets
packet_analyzer.py    Dissection: IPs, ports, protocol, payload, stats
requirements.txt      Python dependencies (Scapy)
```

## Internship notes

- Repository name follows CodeAlpha guidance: `CodeAlpha_NetworkSniffer`.
- Libraries used: [Scapy](https://scapy.net/) for capture and layer decoding.
- This is a learning tool, not a covert monitor. Do not run it against networks or people who have not agreed to be captured.

## Author

Venkata Naga Sriguna Bhasuru  
CodeAlpha Cyber Security Intern — Sep 10 to Oct 10, 2026  
Student ID: CA/DF1/269988
