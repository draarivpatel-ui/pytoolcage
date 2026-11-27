"""Canonical JSON, measurement and hashing helpers."""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, Set

MAX_JSON_GRAPH_DEPTH = 128


def analyze_json_graph(value: Any, maximum_depth: int = MAX_JSON_GRAPH_DEPTH) -> Dict[str, Any]:
    """Inspect object-graph shape iteratively before recursive canonical code runs."""
    seen = set()
    active = set()
    depth = 0
    stack = [(value, 0, True)]
    while stack:
        node, current_depth, enter = stack.pop()
        if not isinstance(node, (list, dict)):
            if current_depth > maximum_depth:
                return {"ok": False, "reason": "depth", "depth": current_depth}
            depth = max(depth, current_depth)
            continue
        if not enter:
            active.discard(id(node))
            continue
        ident = id(node)
        if ident in active:
            return {"ok": False, "reason": "cyclic", "depth": current_depth}
        if ident in seen:
            return {"ok": False, "reason": "shared", "depth": current_depth}
        if current_depth > maximum_depth:
            return {"ok": False, "reason": "depth", "depth": current_depth}
        seen.add(ident)
        active.add(ident)
        depth = max(depth, current_depth)
        stack.append((node, current_depth, False))
        children = node if isinstance(node, list) else node.values()
        for child in children:
            stack.append((child, current_depth + 1, True))
    return {"ok": True, "depth": depth}


def _graph_error(reason: str) -> TypeError:
    if reason == "cyclic":
        return TypeError("cyclic value cannot be canonicalized")
    if reason == "shared":
        return TypeError("shared object references cannot be canonicalized safely")
    return TypeError("json value exceeds maximum safe structural depth %s" % MAX_JSON_GRAPH_DEPTH)


def _assert_safe_graph(value: Any) -> Dict[str, Any]:
    graph = analyze_json_graph(value)
    if not graph["ok"]:
        raise _graph_error(graph["reason"])
    return graph


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
    _assert_safe_graph(value)
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
    return int(_assert_safe_graph(value)["depth"])
