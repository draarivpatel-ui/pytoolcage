"""Canonical JSON, measurement and hashing helpers."""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Set


def _check_json_value(value: Any, seen: Set[int]) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("non-finite number cannot be canonicalized")
        return
    ident = id(value)
    if isinstance(value, list):
        if ident in seen:
            raise TypeError("cyclic value cannot be canonicalized")
        seen.add(ident)
        try:
            for item in value:
                _check_json_value(item, seen)
        finally:
            seen.remove(ident)
        return
    if type(value) is dict:
        if ident in seen:
            raise TypeError("cyclic value cannot be canonicalized")
        seen.add(ident)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("object keys must be strings")
                _check_json_value(item, seen)
        finally:
            seen.remove(ident)
        return
    raise TypeError(type(value).__name__ + " values cannot be canonicalized")


def stable_stringify(value: Any) -> str:
    """Return deterministic JSON with sorted keys and no insignificant whitespace."""
    _check_json_value(value, set())
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256_text(stable_stringify(value))


def utf8_bytes(text: str) -> int:
    return len(text.encode("utf-8"))


def measured_json_bytes(value: Any) -> int:
    return utf8_bytes(stable_stringify(value))


def max_depth_of(value: Any) -> int:
    seen = set()

    def visit(node: Any, depth: int) -> int:
        if not isinstance(node, (list, dict)) or type(node) is not dict and not isinstance(node, list):
            return depth
        ident = id(node)
        if ident in seen:
            raise TypeError("cyclic value has no finite depth")
        seen.add(ident)
        try:
            best = depth
            children = node if isinstance(node, list) else node.values()
            for child in children:
                best = max(best, visit(child, depth + 1))
            return best
        finally:
            seen.remove(ident)

    return visit(value, 0)
