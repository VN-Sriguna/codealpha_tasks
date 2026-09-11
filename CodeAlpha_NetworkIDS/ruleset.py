"""Snort-style rule loader for the CodeAlpha Network IDS.

Supports a small, educational subset:
  alert <proto> <src> <sport> -> <dst> <dport> (key:value; ...)

Understood options: msg, content, nocase, flags, sid, classtype, priority, rev.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


HEADER_RE = re.compile(
    r"^(alert)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.*)\)\s*$"
)
OPTION_RE = re.compile(r"(\w+)\s*:\s*([^;]*);")

FLAG_BITS = {
    "F": 0x01,
    "S": 0x02,
    "R": 0x04,
    "P": 0x08,
    "A": 0x10,
    "U": 0x20,
    "E": 0x40,
    "C": 0x80,
}


@dataclass
class Signature:
    action: str
    proto: str
    src: str
    sport: str
    dst: str
    dport: str
    msg: str
    sid: int
    classtype: str = "misc-activity"
    priority: int = 2
    content: str = ""
    nocase: bool = False
    flags: str | None = None
    rev: int = 1

    def flag_mask(self) -> int | None:
        if self.flags is None:
            return None
        if self.flags.strip() == "0":
            return 0
        mask = 0
        for char in self.flags.upper():
            if char in FLAG_BITS:
                mask |= FLAG_BITS[char]
        return mask


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_rule_line(line: str) -> Signature | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = HEADER_RE.match(stripped)
    if not match:
        return None
    action, proto, src, sport, dst, dport, options = match.groups()
    fields: dict[str, str] = {}
    nocase = False
    for key, raw in OPTION_RE.findall(options):
        key = key.lower()
        if key == "nocase":
            nocase = True
            continue
        fields[key] = _unquote(raw)
    if "nocase" in options.lower() and "nocase;" in options.lower().replace(" ", ""):
        nocase = True

    sid = int(fields.get("sid", "0") or 0)
    priority = int(fields.get("priority", "2") or 2)
    rev = int(fields.get("rev", "1") or 1)
    return Signature(
        action=action,
        proto=proto.lower(),
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        msg=fields.get("msg", "unnamed signature"),
        sid=sid,
        classtype=fields.get("classtype", "misc-activity"),
        priority=priority,
        content=fields.get("content", ""),
        nocase=nocase,
        flags=fields.get("flags"),
        rev=rev,
    )


def load_rules(path: str | Path) -> list[Signature]:
    rules: list[Signature] = []
    text = Path(path).read_text(encoding="utf-8")
    for line in text.splitlines():
        rule = parse_rule_line(line)
        if rule:
            rules.append(rule)
    return rules
