#!/usr/bin/env python3
"""Network Intrusion Detection System — CodeAlpha Cyber Security Internship (Task 4).

Monitors authorized network traffic (live interface or pcap), matches Snort-style
rules, raises behavioural alerts, and records response actions.

Use this only on networks you own or have permission to monitor.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from scapy.all import get_if_list, rdpcap, sniff
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from detector import Detector, Thresholds
from responder import Responder
from ruleset import load_rules


ROOT = Path(__file__).resolve().parent
DEFAULT_RULES = ROOT / "rules" / "local.rules"
DEFAULT_LOGS = ROOT / "logs"

BANNER = """
==============================================================
  CodeAlpha | Network Intrusion Detection System
  Signatures + anomalies + alerts + local response
==============================================================
  Authorized use only. Monitor networks you own
  or have explicit permission to watch.
==============================================================
"""

ETHICAL_NOTICE = (
    "This IDS is for learning detection and authorized lab use. "
    "Watching other people's traffic without permission can be illegal."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Educational network IDS for the CodeAlpha internship.",
        epilog=ETHICAL_NOTICE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--iface", help="Interface to monitor (example: en0).")
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Stop after N packets. 0 means run until Ctrl+C.",
    )
    parser.add_argument("-f", "--filter", default="", help="BPF filter, for example: tcp or icmp.")
    parser.add_argument("-r", "--read", metavar="PCAP", help="Read packets from a .pcap file.")
    parser.add_argument(
        "--rules",
        default=str(DEFAULT_RULES),
        help="Path to a local.rules file (Snort-style subset).",
    )
    parser.add_argument("--log-dir", default=str(DEFAULT_LOGS), help="Directory for alerts and blocklist.")
    parser.add_argument("--no-block", action="store_true", help="Log alerts only; do not update the blocklist.")
    parser.add_argument(
        "--apply-firewall",
        action="store_true",
        help="Also add a local drop rule for blocklisted IPs (opt-in, needs privileges).",
    )
    parser.add_argument("--webhook", help="Optional HTTP URL that receives JSON alerts.")
    parser.add_argument("--list-interfaces", action="store_true", help="Show interfaces and exit.")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the detector against synthetic lab packets (nothing is sent on the wire).",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Start the local visualization dashboard (http://127.0.0.1:5050).",
    )
    parser.add_argument("--port", type=int, default=5050, help="Dashboard port.")
    return parser


def list_interfaces() -> None:
    print("Available interfaces:")
    for name in get_if_list():
        print(f"  - {name}")
    print("\nTip: on macOS Wi-Fi is often en0. Live capture usually needs sudo.")


def demo_packets():
    """Craft local sample packets that should fire rules / anomalies. Not transmitted."""
    packets = []
    attacker = "203.0.113.80"
    victim = "192.168.1.50"
    src_mac = "aa:bb:cc:dd:ee:01"
    dst_mac = "aa:bb:cc:dd:ee:02"

    def eth() -> Ether:
        return Ether(src=src_mac, dst=dst_mac)

    sqli = (
        eth()
        / IP(src=attacker, dst=victim)
        / TCP(sport=40001, dport=80, flags="PA")
        / Raw(load=b"GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: lab.local\r\n\r\n")
    )
    traversal = (
        eth()
        / IP(src=attacker, dst=victim)
        / TCP(sport=40002, dport=80, flags="PA")
        / Raw(load=b"GET /../../etc/passwd HTTP/1.1\r\nHost: lab.local\r\n\r\n")
    )
    xmas = eth() / IP(src=attacker, dst=victim) / TCP(sport=40003, dport=22, flags="FPU")
    null = eth() / IP(src=attacker, dst=victim) / TCP(sport=40004, dport=80, flags=0)
    land = eth() / IP(src=victim, dst=victim) / TCP(sport=80, dport=80, flags="S")
    onion = (
        eth()
        / IP(src=attacker, dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="longname.example.onion"))
    )
    long_dns = (
        eth()
        / IP(src=attacker, dst="8.8.8.8")
        / UDP(sport=53001, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=("a" * 60) + ".lab.local"))
    )
    arp_one = eth() / ARP(op=2, psrc=victim, hwsrc="aa:aa:aa:aa:aa:01", pdst=attacker)
    arp_two = eth() / ARP(op=2, psrc=victim, hwsrc="bb:bb:bb:bb:bb:02", pdst=attacker)
    packets.extend([sqli, traversal, xmas, null, land, onion, long_dns, arp_one, arp_two])

    for port in range(20, 40):
        packets.append(
            eth() / IP(src=attacker, dst=victim) / TCP(sport=50000 + port, dport=port, flags="S")
        )
    for index in range(10):
        packets.append(
            eth() / IP(src=attacker, dst=victim) / TCP(sport=22000 + index, dport=22, flags="S")
        )
    for index in range(32):
        packets.append(
            eth()
            / IP(src=attacker, dst=f"10.0.0.{index + 1}")
            / ICMP(type=8, code=0)
            / Raw(load=b"lab-ping")
        )

    now = time.time()
    for packet in packets:
        packet.time = now
    return packets


def make_engine(args) -> tuple[Detector, Responder]:
    rules_path = Path(args.rules)
    if not rules_path.exists():
        print(f"Rules file not found: {rules_path}", file=sys.stderr)
        sys.exit(1)
    signatures = load_rules(rules_path)
    print(f"Loaded {len(signatures)} signature(s) from {rules_path}")
    detector = Detector(signatures, Thresholds())
    responder = Responder(
        log_dir=Path(args.log_dir),
        auto_block=not args.no_block,
        apply_firewall=args.apply_firewall,
        webhook=args.webhook,
    )
    print(f"Alerts will be written to {responder.log_dir}")
    return detector, responder


def process_packet(packet, detector: Detector, responder: Responder, counter: dict) -> None:
    counter["n"] += 1
    if float(getattr(packet, "time", 0) or 0) == 0:
        packet.time = time.time()
    for alert in detector.inspect(packet):
        responder.handle(alert)


def print_session_summary(responder: Responder) -> None:
    stats = responder.stats()
    print("\n" + "=" * 72)
    print(" NIDS session summary")
    print("=" * 72)
    print(f" Alerts      : {stats['total_alerts']}")
    print(f" Blocked IPs : {len(stats['blocked_ips'])}")
    if stats["blocked_ips"]:
        for ip in stats["blocked_ips"]:
            print(f"   - {ip}")
    print(" By severity:")
    for name, count in stats["by_severity"].items():
        print(f"   {name:<8} {count}")
    if stats["by_classtype"]:
        print(" By class:")
        for name, count in sorted(stats["by_classtype"].items(), key=lambda item: -item[1]):
            print(f"   {name:<22} {count}")
    print("=" * 72)
    print(f" JSON log : {responder.jsonl_path}")
    print(f" Text log : {responder.text_path}")
    print(" Open the dashboard:  python3 nids.py --dashboard")
    print("=" * 72)


def run_demo(args) -> None:
    print("Demo mode: inspecting synthetic lab packets (nothing is sent on the wire).\n")
    detector, responder = make_engine(args)
    counter = {"n": 0}
    for packet in demo_packets():
        process_packet(packet, detector, responder, counter)
    print(f"\nInspected {counter['n']} packet(s).")
    print_session_summary(responder)


def run_pcap(args) -> None:
    packets = rdpcap(args.read)
    detector, responder = make_engine(args)
    counter = {"n": 0}
    limit = args.count if args.count > 0 else len(packets)
    print(f"Reading {min(limit, len(packets))} packet(s) from {args.read}\n")
    for packet in packets[:limit]:
        process_packet(packet, detector, responder, counter)
    print_session_summary(responder)


def run_live(args) -> None:
    if os.geteuid() != 0:
        print(
            "Live capture usually needs administrator privileges.\n"
            "Re-run with:  sudo python3 nids.py -i <interface>\n"
            "Or try demo mode:  python3 nids.py --demo\n",
            file=sys.stderr,
        )
    detector, responder = make_engine(args)
    counter = {"n": 0}

    def on_packet(packet) -> None:
        process_packet(packet, detector, responder, counter)
        if counter["n"] % 50 == 0:
            print(f"  ... {counter['n']} packets inspected, {len(responder.alerts)} alerts")

    print(f"Monitoring {args.iface or 'default interface'}  filter={args.filter or '(none)'}")
    print("Press Ctrl+C to stop.\n")
    try:
        sniff(
            iface=args.iface,
            filter=args.filter or None,
            prn=on_packet,
            count=args.count if args.count > 0 else 0,
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
    print(f"\nInspected {counter['n']} packet(s).")
    print_session_summary(responder)


def main() -> None:
    args = build_parser().parse_args()
    print(BANNER)

    if args.list_interfaces:
        list_interfaces()
        return
    if args.dashboard:
        from dashboard import run_dashboard

        run_dashboard(Path(args.log_dir), args.port)
        return
    if args.demo:
        run_demo(args)
        return
    if args.read:
        pcap = Path(args.read)
        if not pcap.exists():
            print(f"pcap not found: {pcap}", file=sys.stderr)
            sys.exit(1)
        run_pcap(args)
        return
    run_live(args)


if __name__ == "__main__":
    main()
