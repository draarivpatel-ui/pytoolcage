"""Strict IP parsing and non-public network classification."""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional

_DEC = re.compile(r"^\d+$")
_HEX = re.compile(r"^0[xX][0-9a-fA-F]+$")
_OCT = re.compile(r"^0[oO][0-7]+$")
_LEGACY_OCT = re.compile(r"^0[0-7]+$")
_BIN = re.compile(r"^0[bB][01]+$")


def _from_int(value: int) -> str:
    return "%d.%d.%d.%d" % ((value >> 24) & 255, (value >> 16) & 255, (value >> 8) & 255, value & 255)


def _parse_part(token: str) -> Optional[int]:
    if not token or len(token) > 16:
        return None
    base = 10
    body = token
    if _HEX.match(token):
        base, body = 16, token[2:]
    elif _OCT.match(token):
        base, body = 8, token[2:]
    elif _LEGACY_OCT.match(token):
        base, body = 8, token[1:]
    elif _BIN.match(token):
        base, body = 2, token[2:]
    elif not _DEC.match(token):
        return None
    if not body or len(body) > 16:
        return None
    try:
        value = int(body, base)
    except ValueError:
        return None
    if value < 0 or value > 0xFFFFFF:
        return None
    return value


def parse_ipv4(host: str) -> Optional[str]:
    """Parse dotted, integer, hex, octal, binary and shorthand IPv4 forms."""
    if not isinstance(host, str) or not host or len(host) > 64 or "%" in host:
        return None
    if _DEC.match(host) or _HEX.match(host) or _OCT.match(host) or _BIN.match(host) or _LEGACY_OCT.match(host):
        try:
            if _HEX.match(host):
                value = int(host[2:], 16)
            elif _OCT.match(host):
                value = int(host[2:], 8)
            elif _BIN.match(host):
                value = int(host[2:], 2)
            elif _LEGACY_OCT.match(host):
                value = int(host[1:], 8)
            else:
                value = int(host, 10)
        except ValueError:
            return None
        if 0 <= value <= 0xFFFFFFFF:
            return _from_int(value)
        return None
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for part in parts:
        parsed = _parse_part(part)
        if parsed is None:
            return None
        values.append(parsed)
    if len(values) == 4 and all(v <= 255 for v in values):
        return _from_int((values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3])
    if len(values) == 3 and values[0] <= 255 and values[1] <= 255 and values[2] <= 0xFFFF:
        return _from_int((values[0] << 24) | (values[1] << 16) | values[2])
    if len(values) == 2 and values[0] <= 255 and values[1] <= 0xFFFFFF:
        return _from_int((values[0] << 24) | values[1])
    if len(values) == 1 and values[0] <= 0xFFFFFFFF:
        return _from_int(values[0])
    return None


def parse_ipv6(host: str) -> Optional[List[int]]:
    """Parse IPv6 text and return eight sixteen-bit groups."""
    if not isinstance(host, str) or not host or len(host) > 128:
        return None
    text = host.split("%", 1)[0]
    try:
        address = ipaddress.IPv6Address(text)
    except ValueError:
        return None
    packed = address.packed
    return [(packed[index] << 8) | packed[index + 1] for index in range(0, 16, 2)]


def _ipv4_parts(ip: str) -> Optional[List[int]]:
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        values = [int(part, 10) for part in parts]
    except ValueError:
        return None
    if any(part != str(value) for part, value in zip(parts, values)) or any(value < 0 or value > 255 for value in values):
        return None
    return values


def classify_ipv4(ip: str) -> str:
    parts = _ipv4_parts(ip)
    if parts is None:
        return "invalid"
    a, b = parts[0], parts[1]
    if a == 0:
        return "reserved"
    if a == 10:
        return "private"
    if a == 100 and 64 <= b <= 127:
        return "carrier-grade-nat"
    if a == 127:
        return "loopback"
    if a == 169 and b == 254:
        return "link-local"
    if a == 172 and 16 <= b <= 31:
        return "private"
    if a == 192 and b == 168:
        return "private"
    if a == 192 and b == 0:
        return "reserved"
    if a == 192 and b == 2:
        return "documentation"
    if a == 198 and b in (18, 19):
        return "benchmark"
    if a == 198 and b == 51:
        return "documentation"
    if a == 203 and b == 0:
        return "documentation"
    if 224 <= a <= 239:
        return "multicast"
    if a >= 240:
        return "reserved"
    return "public"


def classify_ipv6(host: str) -> str:
    groups = parse_ipv6(host)
    if groups is None:
        return "invalid"
    if groups[:5] == [0, 0, 0, 0, 0] and groups[5] == 0xFFFF:
        mapped = _from_int((groups[6] << 16) | groups[7])
        return classify_ipv4(mapped)
    if all(group == 0 for group in groups):
        return "reserved"
    if groups[:7] == [0] * 7 and groups[7] == 1:
        return "loopback"
    if groups[0] & 0xFFC0 == 0xFE80:
        return "link-local"
    if groups[0] & 0xFE00 == 0xFC00:
        return "private"
    if groups[0] & 0xFF00 == 0xFF00:
        return "multicast"
    if groups[0] == 0x2001 and groups[1] == 0x0DB8:
        return "documentation"
    if groups[0] == 0x2002:
        return "transition"
    if groups[0] & 0xFF00 == 0x2000 and groups[1] == 0 and groups[2] == 0:
        return "transition"
    return "public"


def normalize_ip(host: str) -> Optional[str]:
    ipv4 = parse_ipv4(host)
    if ipv4 is not None:
        return ipv4
    groups = parse_ipv6(host)
    if groups is None:
        return None
    if groups[:5] == [0, 0, 0, 0, 0] and groups[5] == 0xFFFF:
        return _from_int((groups[6] << 16) | groups[7])
    return ":".join(format(group, "x") for group in groups)


def classify_ip(host: str) -> str:
    ipv4 = parse_ipv4(host)
    if ipv4 is not None:
        return classify_ipv4(ipv4)
    return classify_ipv6(host)


def is_public_ip(host: str) -> bool:
    return classify_ip(host) == "public"
