"""Educational packet dissection for the CodeAlpha Basic Network Sniffer.

Turns a captured packet into a structured summary: Ethernet, IP, transport
layer (TCP/UDP/ICMP), and a short payload preview. The goal is to show how
data is layered on a network, not to hide or exploit traffic.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw


PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}

TCP_FLAG_LABELS = (
    ("FIN", 0x01),
    ("SYN", 0x02),
    ("RST", 0x04),
    ("PSH", 0x08),
    ("ACK", 0x10),
    ("URG", 0x20),
    ("ECE", 0x40),
    ("CWR", 0x80),
)


@dataclass
class PacketSummary:
    """Human-readable snapshot of one captured packet."""

    index: int
    timestamp: str
    length: int
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: str = ""
    dst_port: str = ""
    protocol: str = "UNKNOWN"
    info: str = ""
    payload_hex: str = ""
    payload_ascii: str = ""
    layers: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def endpoint_line(self) -> str:
        src = self.src_ip or self.src_mac or "?"
        dst = self.dst_ip or self.dst_mac or "?"
        if self.src_port:
            src = f"{src}:{self.src_port}"
        if self.dst_port:
            dst = f"{dst}:{self.dst_port}"
        return f"{src}  ->  {dst}"


class CaptureStats:
    """Running totals shown at the end of a sniffing session."""

    def __init__(self) -> None:
        self.total = 0
        self.bytes = 0
        self.protocols: Counter[str] = Counter()
        self.talkers: Counter[str] = Counter()

    def add(self, summary: PacketSummary) -> None:
        self.total += 1
        self.bytes += summary.length
        self.protocols[summary.protocol] += 1
        if summary.src_ip:
            self.talkers[summary.src_ip] += 1

    def report_lines(self) -> list[str]:
        lines = [
            "",
            "=" * 72,
            " Capture summary",
            "=" * 72,
            f" Packets : {self.total}",
            f" Bytes   : {self.bytes}",
        ]
        if self.protocols:
            lines.append(" Protocols:")
            for name, count in self.protocols.most_common():
                lines.append(f"   {name:<10} {count}")
        if self.talkers:
            lines.append(" Top source IPs:")
            for ip, count in self.talkers.most_common(5):
                lines.append(f"   {ip:<40} {count}")
        lines.append("=" * 72)
        return lines


def tcp_flags(flags: int) -> str:
    names = [label for label, bit in TCP_FLAG_LABELS if flags & bit]
    return " ".join(names) if names else str(flags)


def preview_payload(payload: bytes, limit: int = 64) -> tuple[str, str]:
    chunk = payload[:limit]
    hex_view = " ".join(f"{byte:02x}" for byte in chunk)
    ascii_view = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
    if len(payload) > limit:
        hex_view += " ..."
        ascii_view += "..."
    return hex_view, ascii_view


def analyze_packet(packet: Packet, index: int) -> PacketSummary:
    """Walk common protocol layers and extract internship-required fields."""
    summary = PacketSummary(
        index=index,
        timestamp=datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3],
        length=len(packet),
        layers=[getattr(layer, "__name__", str(layer)) for layer in packet.layers()],
    )

    if packet.haslayer(Ether):
        ether = packet[Ether]
        summary.src_mac = ether.src
        summary.dst_mac = ether.dst
        summary.details["ethernet"] = {
            "src": ether.src,
            "dst": ether.dst,
            "type": hex(ether.type),
        }

    if packet.haslayer(ARP):
        arp = packet[ARP]
        summary.protocol = "ARP"
        summary.src_ip = arp.psrc
        summary.dst_ip = arp.pdst
        op = "who-has" if arp.op == 1 else "is-at"
        summary.info = f"{op} {arp.pdst}  (sender {arp.psrc})"
        summary.details["arp"] = {"op": op, "psrc": arp.psrc, "pdst": arp.pdst}
        _attach_payload(packet, summary)
        return summary

    if packet.haslayer(IP):
        ip = packet[IP]
        summary.src_ip = ip.src
        summary.dst_ip = ip.dst
        summary.protocol = PROTOCOL_NAMES.get(ip.proto, f"IP-{ip.proto}")
        summary.details["ip"] = {
            "version": ip.version,
            "src": ip.src,
            "dst": ip.dst,
            "ttl": ip.ttl,
            "proto": ip.proto,
            "len": ip.len,
        }
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        summary.src_ip = ip6.src
        summary.dst_ip = ip6.dst
        summary.protocol = PROTOCOL_NAMES.get(ip6.nh, f"IPv6-{ip6.nh}")
        summary.details["ipv6"] = {
            "src": ip6.src,
            "dst": ip6.dst,
            "nh": ip6.nh,
            "hlim": ip6.hlim,
        }

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        summary.protocol = "TCP"
        summary.src_port = str(tcp.sport)
        summary.dst_port = str(tcp.dport)
        flags = tcp_flags(int(tcp.flags))
        summary.info = f"flags=[{flags}] seq={tcp.seq} ack={tcp.ack} win={tcp.window}"
        summary.details["tcp"] = {
            "sport": tcp.sport,
            "dport": tcp.dport,
            "flags": flags,
            "seq": tcp.seq,
            "ack": tcp.ack,
        }
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            method = http.Method.decode(errors="replace") if http.Method else "HTTP"
            host = http.Host.decode(errors="replace") if http.Host else ""
            path = http.Path.decode(errors="replace") if http.Path else ""
            summary.protocol = "HTTP"
            summary.info = f"{method} {host}{path}"
        elif packet.haslayer(HTTPResponse):
            http = packet[HTTPResponse]
            status = http.Status_Code.decode(errors="replace") if http.Status_Code else ""
            reason = http.Reason_Phrase.decode(errors="replace") if http.Reason_Phrase else ""
            summary.protocol = "HTTP"
            summary.info = f"HTTP {status} {reason}".strip()
        elif packet.haslayer(Raw):
            first_line = bytes(packet[Raw].load).split(b"\r\n", 1)[0].decode(errors="replace")
            if first_line.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/")):
                summary.protocol = "HTTP"
                summary.info = f"{first_line}  |  {summary.info}"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        summary.protocol = "UDP"
        summary.src_port = str(udp.sport)
        summary.dst_port = str(udp.dport)
        summary.info = f"len={udp.len}"
        summary.details["udp"] = {"sport": udp.sport, "dport": udp.dport, "len": udp.len}
        if packet.haslayer(DNS) and packet[DNS].qd:
            dns = packet[DNS]
            qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            kind = "query" if dns.qr == 0 else "response"
            summary.protocol = "DNS"
            summary.info = f"{kind} {qname}"
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        summary.protocol = "ICMP"
        summary.info = f"type={icmp.type} code={icmp.code}"
        summary.details["icmp"] = {"type": icmp.type, "code": icmp.code}

    _attach_payload(packet, summary)
    return summary


def _attach_payload(packet: Packet, summary: PacketSummary) -> None:
    if packet.haslayer(Raw):
        data = bytes(packet[Raw].load)
        summary.payload_hex, summary.payload_ascii = preview_payload(data)
        summary.details["payload_bytes"] = len(data)


def format_summary(summary: PacketSummary, verbose: bool = False) -> str:
    header = (
        f"[{summary.index:>4}] {summary.timestamp}  "
        f"{summary.protocol:<6}  {summary.endpoint_line()}  "
        f"{summary.length} bytes"
    )
    lines = [header]
    if summary.info:
        lines.append(f"       {summary.info}")
    if summary.payload_ascii:
        lines.append(f"       payload ascii : {summary.payload_ascii}")
        lines.append(f"       payload hex   : {summary.payload_hex}")
    if verbose:
        lines.append(f"       layers        : {' / '.join(summary.layers)}")
        for layer_name, fields in summary.details.items():
            if layer_name == "payload_bytes":
                lines.append(f"       payload size  : {fields} bytes")
                continue
            pretty = ", ".join(f"{key}={value}" for key, value in fields.items())
            lines.append(f"       {layer_name:<13}: {pretty}")
    return "\n".join(lines)
