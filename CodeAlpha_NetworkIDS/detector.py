"""Detection engine: Snort-like signatures plus behavioural anomaly checks.

Looks at traffic you capture (live, pcap, or synthetic demo packets).
It does not generate attacks or send packets onto the network.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Iterable

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from responder import Alert, now_ts
from ruleset import Signature


@dataclass
class Thresholds:
    window_seconds: float = 10.0
    port_scan_ports: int = 12
    syn_flood_count: int = 25
    icmp_flood_count: int = 30
    ping_sweep_hosts: int = 12
    ssh_syn_count: int = 8
    dns_label_length: int = 50


class SlidingWindow:
    def __init__(self, window: float) -> None:
        self.window = window
        self.events: dict[str, Deque[tuple[float, object]]] = defaultdict(deque)

    def add(self, key: str, timestamp: float, value: object) -> None:
        bucket = self.events[key]
        bucket.append((timestamp, value))
        self._expire(bucket, timestamp)

    def values(self, key: str, timestamp: float) -> list[object]:
        bucket = self.events[key]
        self._expire(bucket, timestamp)
        return [item for _, item in bucket]

    def _expire(self, bucket: Deque[tuple[float, object]], timestamp: float) -> None:
        cutoff = timestamp - self.window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()


class Detector:
    def __init__(self, signatures: list[Signature], thresholds: Thresholds | None = None) -> None:
        self.signatures = signatures
        self.thresholds = thresholds or Thresholds()
        self.window = SlidingWindow(self.thresholds.window_seconds)
        self.arp_map: dict[str, set[str]] = defaultdict(set)
        self.seen_keys: set[str] = set()

    def inspect(self, packet: Packet) -> list[Alert]:
        ctx = _packet_context(packet)
        alerts: list[Alert] = []
        alerts.extend(self._match_signatures(packet, ctx))
        alerts.extend(self._behavioural(packet, ctx))
        return alerts

    def _match_signatures(self, packet: Packet, ctx: dict) -> list[Alert]:
        alerts: list[Alert] = []
        payload = ctx["payload"]
        for rule in self.signatures:
            if not _proto_ok(rule.proto, ctx["protocol"], packet):
                continue
            if not _addr_ok(rule.src, ctx["src_ip"]):
                continue
            if not _addr_ok(rule.dst, ctx["dst_ip"]):
                continue
            if not _port_ok(rule.sport, ctx["src_port"]):
                continue
            if not _port_ok(rule.dport, ctx["dst_port"]):
                continue
            if rule.flags is not None:
                mask = rule.flag_mask()
                if ctx["tcp_flags"] is None or mask is None:
                    continue
                if int(ctx["tcp_flags"]) != mask:
                    continue
            if rule.content:
                haystack = payload
                needle = rule.content.encode("utf-8", errors="ignore")
                if rule.nocase:
                    if needle.lower() not in haystack.lower():
                        continue
                elif needle not in haystack:
                    continue
            dedupe = f"sig:{rule.sid}:{ctx['src_ip']}:{ctx['dst_ip']}:{ctx['dst_port']}:{ctx['payload'][:40]!r}"
            if not self._once(dedupe, behavioural=False):
                continue
            alerts.append(
                _alert(
                    sid=rule.sid,
                    name=rule.msg,
                    classtype=rule.classtype,
                    priority=rule.priority,
                    ctx=ctx,
                    detail=f"signature match sid={rule.sid}",
                )
            )
        return alerts

    def _behavioural(self, packet: Packet, ctx: dict) -> list[Alert]:
        alerts: list[Alert] = []
        ts = ctx["time"]
        src = ctx["src_ip"]
        dst = ctx["dst_ip"]
        if not src:
            return alerts

        if src and dst and src == dst:
            key = f"land:{src}"
            if self._once(key):
                alerts.append(
                    _alert(
                        900001,
                        "Land-style packet (source IP equals destination IP)",
                        "bad-unknown",
                        1,
                        ctx,
                        "src and dst are the same",
                        extra={"skip_block": True},
                    )
                )

        if packet.haslayer(TCP) and ctx["tcp_flags"] is not None:
            flags = int(ctx["tcp_flags"])
            syn_only = flags & 0x02 and not (flags & 0x10)
            if syn_only:
                self.window.add(f"ports:{src}", ts, ctx["dst_port"])
                ports = {p for p in self.window.values(f"ports:{src}", ts) if p}
                if len(ports) >= self.thresholds.port_scan_ports:
                    key = f"ps:{src}"
                    if self._once(key):
                        alerts.append(
                            _alert(
                                900010,
                                "Possible TCP port scan",
                                "recon",
                                1,
                                ctx,
                                f"{len(ports)} unique destination ports in {self.thresholds.window_seconds:.0f}s",
                            )
                        )
                self.window.add(f"syn:{dst}", ts, src)
                syns = self.window.values(f"syn:{dst}", ts)
                if len(syns) >= self.thresholds.syn_flood_count:
                    key = f"synf:{dst}"
                    if self._once(key):
                        alerts.append(
                            _alert(
                                900011,
                                "Possible SYN flood",
                                "denial-of-service",
                                1,
                                ctx,
                                f"{len(syns)} SYN packets to {dst} in {self.thresholds.window_seconds:.0f}s",
                            )
                        )
                if ctx["dst_port"] == "22":
                    self.window.add(f"ssh:{src}:{dst}", ts, 1)
                    n = len(self.window.values(f"ssh:{src}:{dst}", ts))
                    if n >= self.thresholds.ssh_syn_count:
                        key = f"ssh:{src}:{dst}"
                        if self._once(key):
                            alerts.append(
                                _alert(
                                    900014,
                                    "Repeated SSH connection attempts",
                                    "attempted-login",
                                    1,
                                    ctx,
                                    f"{n} SYNs to port 22 in {self.thresholds.window_seconds:.0f}s",
                                )
                            )

        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            self.window.add(f"icmp:{src}", ts, dst)
            dests = self.window.values(f"icmp:{src}", ts)
            if len(dests) >= self.thresholds.icmp_flood_count:
                key = f"icmpf:{src}"
                if self._once(key):
                    alerts.append(
                        _alert(
                            900012,
                            "Possible ICMP flood",
                            "denial-of-service",
                            1,
                            ctx,
                            f"{len(dests)} echo requests in {self.thresholds.window_seconds:.0f}s",
                        )
                    )
            unique_hosts = set(dests)
            if len(unique_hosts) >= self.thresholds.ping_sweep_hosts:
                key = f"sweep:{src}"
                if self._once(key):
                    alerts.append(
                        _alert(
                            900013,
                            "Possible ICMP ping sweep",
                            "recon",
                            1,
                            ctx,
                            f"{len(unique_hosts)} unique targets in {self.thresholds.window_seconds:.0f}s",
                        )
                    )

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            labels = qname.split(".")
            long_label = max((len(label) for label in labels), default=0)
            if long_label >= self.thresholds.dns_label_length:
                key = f"dns:{src}:{qname[:40]}"
                if self._once(key):
                    alerts.append(
                        _alert(
                            900015,
                            "Suspicious long DNS label (tunneling heuristic)",
                            "policy-violation",
                            2,
                            ctx,
                            f"qname length={len(qname)} longest_label={long_label}",
                        )
                    )

        if packet.haslayer(ARP) and packet[ARP].op == 2:
            ip_addr = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            self.arp_map[ip_addr].add(mac)
            if len(self.arp_map[ip_addr]) >= 2:
                key = f"arp:{ip_addr}"
                if self._once(key):
                    macs = ", ".join(sorted(self.arp_map[ip_addr]))
                    alerts.append(
                        _alert(
                            900016,
                            "Possible ARP spoofing (IP claimed by multiple MACs)",
                            "bad-unknown",
                            1,
                            ctx,
                            f"{ip_addr} seen with MACs {macs}",
                            extra={"skip_block": True},
                        )
                    )

        return alerts

    def _once(self, key: str, behavioural: bool = True) -> bool:
        if key in self.seen_keys:
            return False
        self.seen_keys.add(key)
        return True


def _packet_context(packet: Packet) -> dict:
    src_ip = dst_ip = ""
    src_port = dst_port = ""
    protocol = "OTHER"
    tcp_flags = None
    if packet.haslayer(IP):
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        protocol = "IP"
    elif packet.haslayer(IPv6):
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
        protocol = "IPv6"
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port, dst_port = str(packet[TCP].sport), str(packet[TCP].dport)
        tcp_flags = int(packet[TCP].flags)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port, dst_port = str(packet[UDP].sport), str(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(ARP):
        protocol = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
    payload = b""
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
    elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
        payload = packet[DNSQR].qname
    timestamp = float(getattr(packet, "time", 0) or 0)
    src_mac = ""
    if packet.haslayer(Ether):
        try:
            src_mac = packet[Ether].src or ""
        except (ValueError, OSError):
            src_mac = ""
    return {
        "time": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "tcp_flags": tcp_flags,
        "payload": payload,
        "src_mac": src_mac,
    }


def _alert(
    sid: int,
    name: str,
    classtype: str,
    priority: int,
    ctx: dict,
    detail: str,
    extra: dict | None = None,
) -> Alert:
    return Alert(
        timestamp=now_ts(),
        sid=sid,
        name=name,
        classtype=classtype,
        priority=priority,
        src_ip=ctx["src_ip"],
        dst_ip=ctx["dst_ip"],
        src_port=ctx["src_port"],
        dst_port=ctx["dst_port"],
        protocol=ctx["protocol"],
        detail=detail,
        extra=extra or {},
    )


def _proto_ok(rule_proto: str, packet_proto: str, packet: Packet) -> bool:
    if rule_proto in ("ip", "any"):
        return packet.haslayer(IP) or packet.haslayer(IPv6)
    if rule_proto == "tcp":
        return packet.haslayer(TCP)
    if rule_proto == "udp":
        return packet.haslayer(UDP)
    if rule_proto == "icmp":
        return packet.haslayer(ICMP)
    return rule_proto == packet_proto.lower()


def _addr_ok(rule_addr: str, value: str) -> bool:
    return rule_addr in ("any", "$HOME_NET", "$EXTERNAL_NET") or rule_addr == value


def _port_ok(rule_port: str, value: str) -> bool:
    if rule_port == "any":
        return True
    return rule_port == value


def inspect_packets(detector: Detector, packets: Iterable[Packet]) -> list[Alert]:
    found: list[Alert] = []
    for packet in packets:
        found.extend(detector.inspect(packet))
    return found
