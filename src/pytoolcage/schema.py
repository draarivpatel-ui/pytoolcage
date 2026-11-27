"""Strict JSON-schema-like validation for agent tool arguments."""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Set

from .canonical import max_depth_of, measured_json_bytes, stable_stringify, utf8_bytes
from .errors import failure
from .guards import guard_value_by_kind

PARAM_TYPES = {"any", "string", "number", "integer", "boolean", "object", "array", "path", "url", "command", "null"}
DEFAULT_MAX_DEPTH = 12
DEFAULT_MAX_BYTES = 16384
DANGEROUS_KEYS = {"__proto__", "constructor", "prototype"}
_DUNDER_RE = re.compile(r"^__.*__$")


def _error(errors: List[Dict[str, str]], code: str, message: str, path: str) -> None:
    errors.append(failure(code, message, path))


def _is_json_scalar(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, int) and not isinstance(value, bool):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _scan_json_like(value: Any, path: str, errors: List[Dict[str, str]], seen: Set[int]) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _error(errors, "NON_FINITE_NUMBER", "numbers must be finite", path)
        return
    if isinstance(value, list):
        ident = id(value)
        if ident in seen:
            _error(errors, "CYCLIC_ARGUMENT", "cyclic values are not valid tool arguments", path)
            return
        seen.add(ident)
        for index, child in enumerate(value):
            _scan_json_like(child, "%s[%d]" % (path, index), errors, seen)
        seen.remove(ident)
        return
    if type(value) is dict:
        ident = id(value)
        if ident in seen:
            _error(errors, "CYCLIC_ARGUMENT", "cyclic values are not valid tool arguments", path)
            return
        seen.add(ident)
        for key, child in value.items():
            child_path = path + "." + str(key)
            if not isinstance(key, str):
                _error(errors, "NON_STRING_KEY", "object keys must be strings", child_path)
                continue
            lower = key.lower()
            if lower in DANGEROUS_KEYS or _DUNDER_RE.match(key):
                _error(errors, "PROTOTYPE_POLLUTION_KEY", "object key can mutate or confuse object internals", child_path)
                continue
            _scan_json_like(child, child_path, errors, seen)
        seen.remove(ident)
        return
    _error(errors, "UNSUPPORTED_JSON_TYPE", type(value).__name__ + " values are not valid tool arguments", path)


def inspect_tool_arguments(args: Any) -> Dict[str, Any]:
    errors: List[Dict[str, str]] = []
    if type(args) is not dict:
        _error(errors, "ARGUMENTS_NOT_OBJECT", "tool arguments must be a plain dictionary", "$")
        return {"ok": False, "errors": errors}
    _scan_json_like(args, "$", errors, set())
    if errors:
        return {"ok": False, "errors": errors}
    try:
        byte_count = measured_json_bytes(args)
        depth = max(0, max_depth_of(args) - 1)
    except (TypeError, ValueError) as caught:
        _error(errors, "MEASUREMENT_FAILED", str(caught), "$")
        return {"ok": False, "errors": errors}
    return {"ok": True, "errors": [], "bytes": byte_count, "depth": depth}


def _compile_pattern(pattern: Any):
    if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _enum_contains(options: Any, value: Any) -> bool:
    if not isinstance(options, list):
        return False
    try:
        canonical = stable_stringify(value)
    except (TypeError, ValueError):
        return False
    for option in options:
        try:
            if stable_stringify(option) == canonical:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _validate_string(value: Any, spec: Dict[str, Any], path: str, errors: List[Dict[str, str]]) -> None:
    if not isinstance(value, str):
        _error(errors, "TYPE_MISMATCH", "expected " + str(spec.get("type")), path)
        return
    if isinstance(spec.get("minLength"), int) and len(value) < spec["minLength"]:
        _error(errors, "STRING_TOO_SHORT", "string is shorter than %s characters" % spec["minLength"], path)
    if isinstance(spec.get("maxLength"), int) and len(value) > spec["maxLength"]:
        _error(errors, "STRING_TOO_LONG", "string is longer than %s characters" % spec["maxLength"], path)
    if isinstance(spec.get("maxBytes"), int) and utf8_bytes(value) > spec["maxBytes"]:
        _error(errors, "STRING_TOO_LARGE", "string is larger than %s bytes" % spec["maxBytes"], path)
    if "pattern" in spec:
        regex = _compile_pattern(spec.get("pattern"))
        if regex is None:
            _error(errors, "INVALID_POLICY_PATTERN", "parameter regular expression is invalid", path)
        elif regex.search(value) is None:
            _error(errors, "PATTERN_MISMATCH", "string does not match the required pattern", path)


def _validate_number(value: Any, spec: Dict[str, Any], path: str, errors: List[Dict[str, str]], integer: bool) -> None:
    valid = False
    if integer:
        valid = isinstance(value, int) and not isinstance(value, bool)
    else:
        valid = (isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value))
    if not valid:
        _error(errors, "TYPE_MISMATCH", "expected " + ("integer" if integer else "number"), path)
        return
    if isinstance(spec.get("min"), (int, float)) and value < spec["min"]:
        _error(errors, "NUMBER_TOO_SMALL", "number is below minimum %s" % spec["min"], path)
    if isinstance(spec.get("max"), (int, float)) and value > spec["max"]:
        _error(errors, "NUMBER_TOO_LARGE", "number is above maximum %s" % spec["max"], path)
    multiple = spec.get("multipleOf")
    if isinstance(multiple, (int, float)) and multiple > 0:
        quotient = value / multiple
        if abs(quotient - round(quotient)) > 1e-10:
            _error(errors, "NUMBER_MULTIPLE_MISMATCH", "number is not a multiple of %s" % multiple, path)


def _validate_array(value: Any, spec: Dict[str, Any], path: str, errors: List[Dict[str, str]], depth: int) -> None:
    if not isinstance(value, list):
        _error(errors, "TYPE_MISMATCH", "expected array", path)
        return
    if isinstance(spec.get("minItems"), int) and len(value) < spec["minItems"]:
        _error(errors, "ARRAY_TOO_SHORT", "array has fewer than %s items" % spec["minItems"], path)
    if isinstance(spec.get("maxItems"), int) and len(value) > spec["maxItems"]:
        _error(errors, "ARRAY_TOO_LONG", "array has more than %s items" % spec["maxItems"], path)
    if spec.get("uniqueItems") is True:
        seen = set()
        for entry in value:
            try:
                key = stable_stringify(entry)
            except (TypeError, ValueError):
                key = "<unmeasurable>"
            if key in seen:
                _error(errors, "ARRAY_ITEMS_NOT_UNIQUE", "array items must be unique", path)
                break
            seen.add(key)
    if isinstance(spec.get("items"), dict):
        for index, child in enumerate(value):
            _validate_value(child, spec["items"], "%s[%d]" % (path, index), errors, depth + 1)


def _validate_object(value: Any, spec: Dict[str, Any], path: str, errors: List[Dict[str, str]], depth: int) -> None:
    if type(value) is not dict:
        _error(errors, "TYPE_MISMATCH", "expected object", path)
        return
    properties = spec.get("properties") if isinstance(spec.get("properties"), dict) else {}
    if isinstance(spec.get("maxProperties"), int) and len(value) > spec["maxProperties"]:
        _error(errors, "OBJECT_TOO_MANY_PROPERTIES", "object has more than %s properties" % spec["maxProperties"], path)
    for key, child in value.items():
        if key not in properties:
            if spec.get("additionalProperties") is not True:
                _error(errors, "UNKNOWN_ARGUMENT_KEY", "unknown object key " + key, path + "." + key)
            continue
        _validate_value(child, properties[key], path + "." + key, errors, depth + 1)
    for key, child_spec in properties.items():
        if isinstance(child_spec, dict) and child_spec.get("required") is True and key not in value:
            _error(errors, "REQUIRED_ARGUMENT_MISSING", "required object key " + key + " is missing", path + "." + key)


def _validate_value(value: Any, spec: Any, path: str, errors: List[Dict[str, str]], depth: int) -> None:
    if not isinstance(spec, dict):
        _error(errors, "INVALID_POLICY", "parameter specification must be an object", path)
        return
    if value is None:
        if "enum" in spec or spec.get("type") == "null" or spec.get("nullable") is True:
            return
        _error(errors, "TYPE_MISMATCH", "expected " + str(spec.get("type")), path)
        return
    if "enum" in spec and not _enum_contains(spec.get("enum"), value):
        _error(errors, "ENUM_MISMATCH", "value is not one of the allowed values", path)
        return
    if isinstance(spec.get("maxDepth"), int) and depth > spec["maxDepth"]:
        _error(errors, "DEPTH_EXCEEDED", "value exceeds maximum depth %s" % spec["maxDepth"], path)
        return
    kind = spec.get("type")
    if kind == "any":
        return
    if kind in ("string", "path", "url", "command"):
        _validate_string(value, spec, path, errors)
        if isinstance(value, str):
            errors.extend(guard_value_by_kind(value, spec, path))
        return
    if kind == "number":
        _validate_number(value, spec, path, errors, False)
        return
    if kind == "integer":
        _validate_number(value, spec, path, errors, True)
        return
    if kind == "boolean":
        if not isinstance(value, bool):
            _error(errors, "TYPE_MISMATCH", "expected boolean", path)
        return
    if kind == "array":
        _validate_array(value, spec, path, errors, depth)
        return
    if kind == "object":
        _validate_object(value, spec, path, errors, depth)
        return
    if kind == "null":
        _error(errors, "TYPE_MISMATCH", "expected null", path)
        return
    _error(errors, "INVALID_POLICY_TYPE", "unknown parameter type " + str(kind), path)


def _clone_json(value: Any) -> Any:
    if isinstance(value, list):
        return [_clone_json(entry) for entry in value]
    if type(value) is dict:
        return {key: _clone_json(child) for key, child in value.items()}
    return value


def validate_tool_arguments(args: Any, tool_spec: Dict[str, Any]) -> Dict[str, Any]:
    inspected = inspect_tool_arguments(args)
    if not inspected["ok"]:
        return {"ok": False, "errors": inspected["errors"]}
    errors: List[Dict[str, str]] = []
    parameters = tool_spec.get("parameters") if isinstance(tool_spec.get("parameters"), dict) else {}
    max_depth = tool_spec.get("maxDepth") if isinstance(tool_spec.get("maxDepth"), int) else DEFAULT_MAX_DEPTH
    max_bytes = tool_spec.get("maxBytes") if isinstance(tool_spec.get("maxBytes"), int) else DEFAULT_MAX_BYTES
    if inspected["depth"] > max_depth:
        _error(errors, "DEPTH_EXCEEDED", "arguments exceed maximum depth %s" % max_depth, "$")
    if inspected["bytes"] > max_bytes:
        _error(errors, "ARGUMENTS_TOO_LARGE", "arguments exceed maximum size %s bytes" % max_bytes, "$")
    for key in args:
        if key not in parameters:
            _error(errors, "UNKNOWN_ARGUMENT_KEY", "unknown argument key " + key, "$." + key)
    for key, spec in parameters.items():
        present = key in args
        if not present and isinstance(spec, dict) and spec.get("required") is True:
            _error(errors, "REQUIRED_ARGUMENT_MISSING", "required argument " + key + " is missing", "$." + key)
            continue
        if present:
            _validate_value(args[key], spec, "$." + key, errors, 1)
    if errors:
        return {"ok": False, "errors": errors, "bytes": inspected["bytes"], "depth": inspected["depth"]}
    return {
        "ok": True,
        "errors": [],
        "normalizedArguments": _clone_json(args),
        "bytes": inspected["bytes"],
        "depth": inspected["depth"],
    }
