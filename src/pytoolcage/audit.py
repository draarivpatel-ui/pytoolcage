"""Tamper-evident append-only audit trail."""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Callable, Dict, Optional, Tuple

from .canonical import sha256_text, stable_stringify

GENESIS = "0" * 64


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return {key: _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


def _primitive_details(details: Any) -> Dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    output = {}
    for key in sorted(details):
        value = details[key]
        if value is None or isinstance(value, (str, int, float, bool)):
            output[key] = value
        elif isinstance(value, list) and all(item is None or isinstance(item, (str, int, float, bool)) for item in value):
            output[key] = list(value)
    return output


class AuditTrail:
    """Append-only hash-chained audit log."""

    def __init__(self, now: Optional[Callable[[], float]] = None) -> None:
        self._now = now or (lambda: __import__("time").time_ns() // 1_000_000)
        self._entries = []

    def append(self, event: str, fields: Optional[Dict[str, Any]] = None) -> MappingProxyType:
        source = fields if isinstance(fields, dict) else {}
        sequence = len(self._entries)
        previous_hash = GENESIS if sequence == 0 else self._entries[sequence - 1]["hash"]
        import datetime
        timestamp = datetime.datetime.fromtimestamp(float(self._now()) / 1000.0, tz=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        body = {
            "sequence": sequence,
            "timestamp": timestamp,
            "event": str(event),
            "tool": source.get("tool") if isinstance(source.get("tool"), str) else None,
            "decision": source.get("decision") if isinstance(source.get("decision"), str) else None,
            "inputHash": source.get("inputHash") if isinstance(source.get("inputHash"), str) else None,
            "bytes": source.get("bytes") if isinstance(source.get("bytes"), int) and not isinstance(source.get("bytes"), bool) else 0,
            "durationMs": max(0, source.get("durationMs", 0)) if isinstance(source.get("durationMs", 0), (int, float)) else 0,
            "details": _primitive_details(source.get("details")),
            "previousHash": previous_hash,
        }
        body["hash"] = sha256_text(stable_stringify(body))
        frozen = _freeze(body)
        self._entries.append(frozen)
        return frozen

    def entries(self) -> Tuple[MappingProxyType, ...]:
        return tuple(self._entries)

    def verify(self) -> bool:
        previous = GENESIS
        for index, entry in enumerate(self._entries):
            if entry["sequence"] != index or entry["previousHash"] != previous:
                return False
            plain = {key: _thaw(value) for key, value in entry.items() if key != "hash"}
            if sha256_text(stable_stringify(plain)) != entry["hash"]:
                return False
            previous = entry["hash"]
        return True

    def digest(self) -> str:
        return GENESIS if not self._entries else self._entries[-1]["hash"]

    def statistics(self) -> MappingProxyType:
        counts: Dict[str, int] = {}
        byte_count = 0
        for entry in self._entries:
            counts[entry["event"]] = counts.get(entry["event"], 0) + 1
            byte_count += entry["bytes"]
        return _freeze({"entries": len(self._entries), "bytes": byte_count, "events": counts, "digest": self.digest()})


AUDIT_GENESIS_HASH = GENESIS
