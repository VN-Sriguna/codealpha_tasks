#!/usr/bin/env python3
"""Basic Network Sniffer — CodeAlpha Cyber Security Internship (Task 1).

Captures packets from a network interface (or a pcap file), then prints
source/destination addresses, protocol, and payload previews so you can see
how traffic is structured.

Use this only on networks you own or have permission to monitor.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from scapy.all import get_if_list, rdpcap, sniff, wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packet_analyzer import CaptureStats, analyze_packet, format_summary


BANNER = """
==============================================================
  CodeAlpha | Basic Network Sniffer
  Capture packets, inspect layers, learn how data moves
==============================================================
  Authorized use only. Sniff traffic on networks you own
  or have explicit permission to monitor.
==============================================================
"""

ETHICAL_NOTICE = (
    "This tool is for learning packet structure and authorized lab use. "
    "Capturing other people's traffic without permission can be illegal."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Educational packet sniffer for the CodeAlpha internship.",
        epilog=ETHICAL_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--iface",
        help="Network interface to sniff (example: en0 on macOS, eth0 on Linux).",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Stop after N packets. 0 means keep capturing until Ctrl+C.",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default="",
        help='BPF filter, for example: "tcp port 80" or "icmp".',
    )
    parser.add_argument(
        "-r",
        "--read",
        metavar="PCAP",
        help="Analyze packets from an existing .pcap file instead of live capture.",
    )
    parser.add_argument(
        "-w",
        "--write",
        metavar="PCAP",
        help="Save captured packets to a .pcap file.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print layer-by-layer fields (Ethernet, IP, TCP/UDP/ICMP).",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Show available network interfaces and exit.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Analyze a few crafted sample packets (no root / live capture needed).",
    )
    return parser


def list_interfaces() -> None:
    print("Available interfaces:")
    for name in get_if_list():
        print(f"  - {name}")
    print("\nTip: on macOS Wi-Fi is often en0. Live capture usually needs sudo.")


def demo_packets():
    """Craft a handful of packets so the analyzer can be tried without sniffing."""
    http = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="192.168.1.10", dst="93.184.216.34", ttl=64)
        / TCP(sport=51234, dport=80, flags="PA", seq=1000, ack=1)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    dns = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:03")
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    ping = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:04")
        / IP(src="10.0.0.5", dst="10.0.0.1")
        / ICMP(type=8, code=0)
        / Raw(load=b"ping-payload")
    )
    syn = (
        Ether(src="aa:bb:cc:dd:ee:05", dst="aa:bb:cc:dd:ee:01")
        / IP(src="203.0.113.50", dst="192.168.1.10")
        / TCP(sport=443, dport=443, flags="S", seq=42)
    )
    for packet in (http, dns, ping, syn):
        packet.time = 0
    return [http, dns, ping, syn]


def print_packet(packet, index: int, stats: CaptureStats, verbose: bool) -> None:
    if float(getattr(packet, "time", 0) or 0) == 0:
        import time

        packet.time = time.time()
    summary = analyze_packet(packet, index)
    stats.add(summary)
    print(format_summary(summary, verbose=verbose))
    print()


def run_pcap(path: str, verbose: bool, count: int) -> None:
    packets = rdpcap(path)
    stats = CaptureStats()
    limit = count if count > 0 else len(packets)
    print(f"Reading {min(limit, len(packets))} packet(s) from {path}\n")
    for index, packet in enumerate(packets[:limit], start=1):
        print_packet(packet, index, stats, verbose)
    print("\n".join(stats.report_lines()))


def run_demo(verbose: bool) -> None:
    print("Demo mode: analyzing crafted sample packets (nothing is sent on the wire).\n")
    stats = CaptureStats()
    for index, packet in enumerate(demo_packets(), start=1):
        print_packet(packet, index, stats, verbose)
    print("\n".join(stats.report_lines()))


def run_live(iface: str | None, count: int, bpf: str, write_path: str | None, verbose: bool) -> None:
    if os.geteuid() != 0:
        print(
            "Live capture usually needs administrator privileges.\n"
            "Re-run with:  sudo python3 sniffer.py -i <interface> -c 20 -v\n"
            "Or try a pcap / demo:  python3 sniffer.py --demo -v\n",
            file=sys.stderr,
        )

    captured = []
    stats = CaptureStats()
    counter = {"n": 0}

    def on_packet(packet) -> None:
        counter["n"] += 1
        captured.append(packet)
        print_packet(packet, counter["n"], stats, verbose)

    print(f"Sniffing on {iface or 'default interface'}  filter={bpf or '(none)'}")
    print("Press Ctrl+C to stop.\n")
    try:
        sniff(
            iface=iface,
            filter=bpf or None,
            prn=on_packet,
            count=count if count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print("Permission denied. Use sudo, or run --demo / -r file.pcap instead.", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"Could not open the interface: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped by user.")

    if write_path and captured:
        wrpcap(write_path, captured)
        print(f"\nSaved {len(captured)} packet(s) to {write_path}")
    print("\n".join(stats.report_lines()))


def main() -> None:
    args = build_parser().parse_args()
    print(BANNER)

    if args.list_interfaces:
        list_interfaces()
        return
    if args.demo:
        run_demo(args.verbose)
        return
    if args.read:
        pcap = Path(args.read)
        if not pcap.exists():
            print(f"pcap not found: {pcap}", file=sys.stderr)
            sys.exit(1)
        run_pcap(str(pcap), args.verbose, args.count)
        return

    run_live(args.iface, args.count, args.filter, args.write, args.verbose)


if __name__ == "__main__":
    main()
