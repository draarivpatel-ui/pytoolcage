"""Capability budgets, sliding windows and duplicate-call loop detection."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional


def _denial(code: str, message: str) -> Dict[str, Any]:
    return {"ok": False, "code": code, "message": message}


class CapabilityBudget:
    def __init__(self, config: Optional[Dict[str, int]] = None, now: Optional[Callable[[], float]] = None) -> None:
        self.config = {
            "maxCalls": 1000,
            "maxBytes": 1048576,
            "windowMs": 60000,
            "windowMaxCalls": 120,
            "duplicateWindowMs": 10000,
            "maxDuplicates": 4,
        }
        if config:
            self.config.update(config)
        self._now = now or (lambda: __import__("time").time_ns() // 1_000_000)
        self.calls = 0
        self.bytes = 0
        self.session_times = []
        self.tool_calls: Dict[str, int] = {}
        self.tool_times: Dict[str, list] = {}
        self.duplicates: Dict[str, list] = {}

    @staticmethod
    def _prune(values: list, cutoff: float) -> None:
        while values and values[0] <= cutoff:
            values.pop(0)

    def admit(self, tool_name: str, tool_policy: Dict[str, Any], input_hash: str, input_bytes: int) -> Dict[str, Any]:
        now = self._now()
        cfg = self.config
        self._prune(self.session_times, now - cfg["windowMs"])
        calls = self.tool_calls.get(tool_name, 0)
        times = self.tool_times.setdefault(tool_name, [])
        rate = tool_policy.get("rateLimit") if isinstance(tool_policy, dict) else None
        if rate:
            self._prune(times, now - rate["windowMs"])
        if self.calls >= cfg["maxCalls"]:
            return _denial("SESSION_CALL_LIMIT", "session call budget exhausted")
        if isinstance(tool_policy, dict) and isinstance(tool_policy.get("maxCalls"), int) and calls >= tool_policy["maxCalls"]:
            return _denial("TOOL_CALL_LIMIT", "per-tool call budget exhausted")
        if len(self.session_times) >= cfg["windowMaxCalls"]:
            return _denial("RATE_LIMIT", "session sliding-window rate limit exceeded")
        if rate and len(times) >= rate["maxCalls"]:
            return _denial("RATE_LIMIT", "tool sliding-window rate limit exceeded")
        if self.bytes + input_bytes > cfg["maxBytes"]:
            return _denial("BYTE_BUDGET", "cumulative byte budget exhausted")
        duplicate_key = tool_name + ":" + input_hash
        duplicate_times = self.duplicates.setdefault(duplicate_key, [])
        self._prune(duplicate_times, now - cfg["duplicateWindowMs"])
        if len(duplicate_times) >= cfg["maxDuplicates"]:
            return _denial("DUPLICATE_CALL_LOOP", "identical tool call loop detected")
        self.calls += 1
        self.bytes += input_bytes
        self.session_times.append(now)
        self.tool_calls[tool_name] = calls + 1
        if rate:
            times.append(now)
        duplicate_times.append(now)
        return {"ok": True, "admittedAt": now, "inputBytes": input_bytes, "inputHash": input_hash, "toolName": tool_name}

    def complete(self, tool_name: str, output_bytes: int) -> Dict[str, Any]:
        self.bytes += max(0, int(output_bytes))
        if self.bytes > self.config["maxBytes"]:
            return _denial("BYTE_BUDGET", "cumulative byte budget exhausted by tool output")
        return {"ok": True}

    def snapshot(self) -> Dict[str, Any]:
        return {
            "calls": self.calls,
            "bytes": self.bytes,
            "remainingCalls": max(0, self.config["maxCalls"] - self.calls),
            "remainingBytes": max(0, self.config["maxBytes"] - self.bytes),
            "perTool": dict(self.tool_calls),
        }
