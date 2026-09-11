"""Response actions for NIDS alerts: log, persist, blocklist, optional webhook.

Default behaviour is defensive and local: write alerts and remember source IPs.
Firewall commands are never applied unless --apply-firewall is set, and even
then they only add a local block (macOS pf / Linux iptables) for the alerted IP.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


PRIORITY_NAME = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}


@dataclass
class Alert:
    timestamp: str
    sid: int
    name: str
    classtype: str
    priority: int
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    protocol: str
    detail: str
    action: str = "logged"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        return PRIORITY_NAME.get(self.priority, "MEDIUM")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity
        return data


class Responder:
    """Persist alerts and apply configured responses."""

    def __init__(
        self,
        log_dir: Path,
        auto_block: bool = True,
        apply_firewall: bool = False,
        webhook: str | None = None,
        high_priority_only_block: bool = True,
    ) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.log_dir / "alerts.jsonl"
        self.text_path = self.log_dir / "alerts.log"
        self.blocklist_path = self.log_dir / "blocklist.txt"
        self.auto_block = auto_block
        self.apply_firewall = apply_firewall
        self.webhook = webhook
        self.high_priority_only_block = high_priority_only_block
        self.alerts: list[Alert] = []
        self.blocked: set[str] = set()
        if self.blocklist_path.exists():
            self.blocked = {
                line.strip()
                for line in self.blocklist_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }

    def handle(self, alert: Alert) -> Alert:
        should_block = (
            self.auto_block
            and alert.src_ip
            and not alert.extra.get("skip_block")
            and (not self.high_priority_only_block or alert.priority <= 1)
        )
        if should_block:
            alert.action = "blocklisted"
            self._block(alert.src_ip)
        else:
            alert.action = "logged"

        self.alerts.append(alert)
        self._write_files(alert)
        self._notify_webhook(alert)
        self._print(alert)
        return alert

    def _block(self, ip: str) -> None:
        if ip in self.blocked:
            return
        self.blocked.add(ip)
        if not self.blocklist_path.exists():
            self.blocklist_path.write_text(
                "# Local NIDS blocklist — source IPs that triggered high-severity alerts.\n"
                "# Review before applying at a firewall.\n",
                encoding="utf-8",
            )
        with self.blocklist_path.open("a", encoding="utf-8") as handle:
            handle.write(ip + "\n")
        if self.apply_firewall:
            self._apply_os_block(ip)

    def _apply_os_block(self, ip: str) -> None:
        """Best-effort local drop rule. Opt-in only."""
        if sys.platform == "darwin":
            table = "nids_block"
            commands = [
                ["pfctl", "-t", table, "-T", "add", ip],
            ]
        else:
            commands = [
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            ]
        for cmd in commands:
            try:
                if cmd[0] == "iptables" and cmd[1] == "-C":
                    check = subprocess.run(cmd, capture_output=True, text=True)
                    if check.returncode == 0:
                        return
                    subprocess.run(
                        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    return
                subprocess.run(cmd, capture_output=True, text=True, check=False)
            except OSError:
                print(f"  [response] could not apply firewall rule for {ip}", file=sys.stderr)

    def _write_files(self, alert: Alert) -> None:
        with self.jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert.to_dict()) + "\n")
        line = (
            f"{alert.timestamp}  [{alert.severity:<6}] sid={alert.sid}  "
            f"{alert.name}  {alert.src_ip}:{alert.src_port} -> "
            f"{alert.dst_ip}:{alert.dst_port}  {alert.detail}  action={alert.action}\n"
        )
        with self.text_path.open("a", encoding="utf-8") as handle:
            handle.write(line)

    def _notify_webhook(self, alert: Alert) -> None:
        if not self.webhook:
            return
        payload = json.dumps(alert.to_dict()).encode("utf-8")
        request = urllib.request.Request(
            self.webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=3)
        except OSError as exc:
            print(f"  [response] webhook failed: {exc}", file=sys.stderr)

    def _print(self, alert: Alert) -> None:
        color = {1: "\033[91m", 2: "\033[93m", 3: "\033[96m"}.get(alert.priority, "")
        reset = "\033[0m" if sys.stdout.isatty() else ""
        color = color if sys.stdout.isatty() else ""
        print(
            f"{color}[ALERT {alert.severity}]{reset} {alert.timestamp}  "
            f"{alert.name}  {alert.src_ip} -> {alert.dst_ip}  "
            f"{alert.detail}  [{alert.action}]"
        )

    def stats(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_class: dict[str, int] = {}
        for alert in self.alerts:
            by_sev[alert.severity] = by_sev.get(alert.severity, 0) + 1
            by_class[alert.classtype] = by_class.get(alert.classtype, 0) + 1
        return {
            "total_alerts": len(self.alerts),
            "blocked_ips": sorted(self.blocked),
            "by_severity": by_sev,
            "by_classtype": by_class,
        }


def load_alerts(jsonl_path: Path) -> list[dict[str, Any]]:
    if not jsonl_path.exists():
        return []
    rows = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
