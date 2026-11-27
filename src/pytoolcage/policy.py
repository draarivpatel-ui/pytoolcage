"""Policy validation, normalization and static audit."""
from __future__ import annotations

import copy
import math
import re
from typing import Any, Dict, List

from .errors import ToolCageError
from .schema import PARAM_TYPES

TOP_LEVEL_KEYS = {"version", "tools", "allowedTools", "deniedTools", "allowUnknownTools", "budget", "sanitizer", "metadata"}
TOOL_KEYS = {"description", "enabled", "parameters", "maxCalls", "rateLimit", "maxBytes", "maxDepth", "result", "metadata"}
PARAM_KEYS = {
    "type", "required", "nullable", "enum", "minLength", "maxLength", "maxBytes", "pattern",
    "min", "max", "multipleOf", "properties", "additionalProperties", "items", "minItems", "maxItems",
    "uniqueItems", "maxProperties", "maxDepth", "allowAbsolute", "allowParentTraversal",
    "allowUnicodeNormalizationBypass", "allowShellOperators", "allowPrivateNetworks", "allowedSchemes",
    "allowedPorts", "hostPolicy", "metadata",
}
BUDGET_KEYS = {"maxCalls", "maxBytes", "windowMs", "windowMaxCalls", "duplicateWindowMs", "maxDuplicates"}
RATE_KEYS = {"windowMs", "maxCalls"}
RESULT_KEYS = {"maxBytes", "maxDepth", "blockOnInstruction", "redactSecrets", "removeHiddenUnicode", "sensitiveKeys", "customSecretPatterns"}
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def _issue(kind: str, code: str, message: str, path: str) -> Dict[str, str]:
    return {"kind": kind, "code": code, "message": message, "path": path}


def _plain(value: Any) -> bool:
    return type(value) is dict


def _check_unknown_keys(value: Dict[str, Any], allowed: set, path: str, errors: List[Dict[str, str]]) -> None:
    for key in value:
        if key not in allowed:
            errors.append(_issue("error", "POLICY_UNKNOWN_KEY", "unknown policy key " + key, path + "." + key))


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_rate_limit(value: Any, path: str, errors: List[Dict[str, str]]) -> None:
    if value is None:
        return
    if not _plain(value):
        errors.append(_issue("error", "POLICY_RATE_INVALID", "rateLimit must be an object", path))
        return
    _check_unknown_keys(value, RATE_KEYS, path, errors)
    if not _positive_int(value.get("maxCalls")) or value.get("maxCalls") < 1:
        errors.append(_issue("error", "POLICY_RATE_INVALID", "rateLimit.maxCalls must be a positive integer", path + ".maxCalls"))
    if not _positive_int(value.get("windowMs")) or value.get("windowMs") < 1:
        errors.append(_issue("error", "POLICY_RATE_INVALID", "rateLimit.windowMs must be a positive integer", path + ".windowMs"))


def _validate_host_policy(value: Any, path: str, errors: List[Dict[str, str]]) -> None:
    if value is None:
        return
    if not _plain(value):
        errors.append(_issue("error", "POLICY_HOST_INVALID", "hostPolicy must be an object", path))
        return
    for key in value:
        if key not in ("allow", "deny"):
            errors.append(_issue("error", "POLICY_UNKNOWN_KEY", "unknown hostPolicy key " + key, path + "." + key))
    for key in ("allow", "deny"):
        if key in value and (not isinstance(value[key], list) or any(not isinstance(entry, str) for entry in value[key])):
            errors.append(_issue("error", "POLICY_HOST_INVALID", "hostPolicy." + key + " must be an array of strings", path + "." + key))


def _validate_param_spec(spec: Any, path: str, errors: List[Dict[str, str]], warnings: List[Dict[str, str]], depth: int) -> None:
    if not _plain(spec):
        errors.append(_issue("error", "POLICY_PARAM_INVALID", "parameter specification must be an object", path))
        return
    _check_unknown_keys(spec, PARAM_KEYS, path, errors)
    if spec.get("type") not in PARAM_TYPES:
        errors.append(_issue("error", "POLICY_PARAM_TYPE", "unsupported parameter type " + str(spec.get("type")), path + ".type"))
    if "pattern" in spec:
        pattern = spec.get("pattern")
        if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
            errors.append(_issue("error", "POLICY_PATTERN_INVALID", "pattern must be a string of 1 to 512 characters", path + ".pattern"))
        else:
            try:
                re.compile(pattern)
            except re.error:
                errors.append(_issue("error", "POLICY_PATTERN_INVALID", "pattern does not compile", path + ".pattern"))
    for key in ("minLength", "maxLength", "maxBytes", "minItems", "maxItems", "maxProperties", "maxDepth"):
        if key in spec and not _positive_int(spec[key]):
            errors.append(_issue("error", "POLICY_NUMBER_INVALID", key + " must be a nonnegative integer", path + "." + key))
    for key in ("min", "max", "multipleOf"):
        if key in spec and (not isinstance(spec[key], (int, float)) or isinstance(spec[key], bool) or not math.isfinite(spec[key])):
            errors.append(_issue("error", "POLICY_NUMBER_INVALID", key + " must be finite", path + "." + key))
    if isinstance(spec.get("minLength"), int) and isinstance(spec.get("maxLength"), int) and spec["minLength"] > spec["maxLength"]:
        errors.append(_issue("error", "POLICY_RANGE_INVALID", "minLength exceeds maxLength", path))
    if isinstance(spec.get("min"), (int, float)) and isinstance(spec.get("max"), (int, float)) and spec["min"] > spec["max"]:
        errors.append(_issue("error", "POLICY_RANGE_INVALID", "min exceeds max", path))
    if isinstance(spec.get("minItems"), int) and isinstance(spec.get("maxItems"), int) and spec["minItems"] > spec["maxItems"]:
        errors.append(_issue("error", "POLICY_RANGE_INVALID", "minItems exceeds maxItems", path))
    if spec.get("type") == "object":
        properties = spec.get("properties")
        if properties is not None:
            if not _plain(properties):
                errors.append(_issue("error", "POLICY_PROPERTIES_INVALID", "properties must be an object", path + ".properties"))
            elif depth < 16:
                for key, child in properties.items():
                    _validate_param_spec(child, path + ".properties." + key, errors, warnings, depth + 1)
        if spec.get("additionalProperties") is True:
            warnings.append(_issue("warning", "POLICY_OPEN_OBJECT", "object allows additional nested properties", path + ".additionalProperties"))
    if spec.get("type") == "array" and "items" in spec:
        _validate_param_spec(spec["items"], path + ".items", errors, warnings, depth + 1)
    if spec.get("type") == "path":
        if spec.get("allowAbsolute") is True:
            warnings.append(_issue("warning", "POLICY_ABSOLUTE_PATH", "path parameter allows absolute paths", path + ".allowAbsolute"))
        if spec.get("allowParentTraversal") is True:
            warnings.append(_issue("warning", "POLICY_PARENT_TRAVERSAL", "path parameter allows parent traversal", path + ".allowParentTraversal"))
    if spec.get("type") == "url":
        if spec.get("allowPrivateNetworks") is True:
            warnings.append(_issue("warning", "POLICY_PRIVATE_NETWORK", "URL parameter allows private network targets", path + ".allowPrivateNetworks"))
        if "allowedSchemes" in spec and (not isinstance(spec["allowedSchemes"], list) or any(not isinstance(entry, str) for entry in spec["allowedSchemes"])):
            errors.append(_issue("error", "POLICY_SCHEME_INVALID", "allowedSchemes must be an array of strings", path + ".allowedSchemes"))
        ports = spec.get("allowedPorts")
        if "allowedPorts" in spec and ports not in ("any", "default-only") and (not isinstance(ports, list) or any(not _positive_int(port) or port < 1 or port > 65535 for port in ports)):
            errors.append(_issue("error", "POLICY_PORT_INVALID", "allowedPorts must be default-only, any, or an array of valid ports", path + ".allowedPorts"))
        _validate_host_policy(spec.get("hostPolicy"), path + ".hostPolicy", errors)
    if spec.get("type") == "command" and spec.get("allowShellOperators") is True:
        warnings.append(_issue("warning", "POLICY_SHELL_OPERATORS", "command parameter allows shell operators", path + ".allowShellOperators"))


def _validate_budget(budget: Any, path: str, errors: List[Dict[str, str]]) -> None:
    if budget is None:
        return
    if not _plain(budget):
        errors.append(_issue("error", "POLICY_BUDGET_INVALID", "budget must be an object", path))
        return
    _check_unknown_keys(budget, BUDGET_KEYS, path, errors)
    for key, value in budget.items():
        if not _positive_int(value) or value < 1:
            errors.append(_issue("error", "POLICY_BUDGET_INVALID", "budget." + key + " must be a positive integer", path + "." + key))


def _validate_result_policy(result: Any, path: str, errors: List[Dict[str, str]]) -> None:
    if result is None:
        return
    if not _plain(result):
        errors.append(_issue("error", "POLICY_RESULT_INVALID", "result policy must be an object", path))
        return
    _check_unknown_keys(result, RESULT_KEYS, path, errors)
    if "maxBytes" in result and (not _positive_int(result["maxBytes"]) or result["maxBytes"] < 1):
        errors.append(_issue("error", "POLICY_RESULT_INVALID", "result.maxBytes must be positive", path + ".maxBytes"))
    if "maxDepth" in result and not _positive_int(result["maxDepth"]):
        errors.append(_issue("error", "POLICY_RESULT_INVALID", "result.maxDepth must be nonnegative", path + ".maxDepth"))
    if "sensitiveKeys" in result and (not isinstance(result["sensitiveKeys"], list) or any(not isinstance(entry, str) for entry in result["sensitiveKeys"])):
        errors.append(_issue("error", "POLICY_RESULT_INVALID", "result.sensitiveKeys must be a string array", path + ".sensitiveKeys"))
    if "customSecretPatterns" in result and (not isinstance(result["customSecretPatterns"], list) or any(not isinstance(entry, str) for entry in result["customSecretPatterns"])):
        errors.append(_issue("error", "POLICY_RESULT_INVALID", "result.customSecretPatterns must be a string array", path + ".customSecretPatterns"))


def audit_policy(policy: Any) -> Dict[str, Any]:
    errors: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []
    if not _plain(policy):
        errors.append(_issue("error", "POLICY_NOT_OBJECT", "policy must be a plain object", "$"))
        return {"ok": False, "errors": errors, "warnings": warnings, "summary": {"tools": 0, "parameters": 0, "errors": 1, "warnings": 0}}
    _check_unknown_keys(policy, TOP_LEVEL_KEYS, "$", errors)
    if "version" in policy and policy["version"] != 1:
        errors.append(_issue("error", "POLICY_VERSION", "policy version must be 1", "$.version"))
    for key in ("allowedTools", "deniedTools"):
        if key in policy and (not isinstance(policy[key], list) or any(not isinstance(entry, str) or TOOL_NAME_RE.match(entry) is None for entry in policy[key])):
            errors.append(_issue("error", "POLICY_TOOL_LIST_INVALID", key + " must contain valid tool names", "$." + key))
    if policy.get("allowUnknownTools") is True:
        warnings.append(_issue("warning", "POLICY_UNKNOWN_TOOLS_OPEN", "unknown tools are allowed", "$.allowUnknownTools"))
    _validate_budget(policy.get("budget"), "$.budget", errors)
    _validate_result_policy(policy.get("sanitizer"), "$.sanitizer", errors)
    tools = policy.get("tools")
    if not _plain(tools):
        errors.append(_issue("error", "POLICY_TOOLS_INVALID", "tools must be an object", "$.tools"))
        tools = {}
    for name, tool in tools.items():
        path = "$.tools." + name
        if not isinstance(name, str) or TOOL_NAME_RE.match(name) is None:
            errors.append(_issue("error", "POLICY_TOOL_NAME_INVALID", "tool name contains unsafe characters", path))
        if not _plain(tool):
            errors.append(_issue("error", "POLICY_TOOL_INVALID", "tool policy must be an object", path))
            continue
        _check_unknown_keys(tool, TOOL_KEYS, path, errors)
        if "enabled" in tool and not isinstance(tool["enabled"], bool):
            errors.append(_issue("error", "POLICY_TOOL_INVALID", "enabled must be boolean", path + ".enabled"))
        if "maxCalls" in tool and (not _positive_int(tool["maxCalls"]) or tool["maxCalls"] < 1):
            errors.append(_issue("error", "POLICY_BUDGET_INVALID", "maxCalls must be positive", path + ".maxCalls"))
        _validate_rate_limit(tool.get("rateLimit"), path + ".rateLimit", errors)
        if "maxBytes" in tool and (not _positive_int(tool["maxBytes"]) or tool["maxBytes"] < 1):
            errors.append(_issue("error", "POLICY_BUDGET_INVALID", "maxBytes must be positive", path + ".maxBytes"))
        if "maxDepth" in tool and not _positive_int(tool["maxDepth"]):
            errors.append(_issue("error", "POLICY_BUDGET_INVALID", "maxDepth must be nonnegative", path + ".maxDepth"))
        _validate_result_policy(tool.get("result"), path + ".result", errors)
        if "parameters" in tool:
            if not _plain(tool["parameters"]):
                errors.append(_issue("error", "POLICY_PARAMETERS_INVALID", "parameters must be an object", path + ".parameters"))
            else:
                for key, child in tool["parameters"].items():
                    _validate_param_spec(child, path + ".parameters." + key, errors, warnings, 0)
        if tool.get("enabled", True) is not False and policy.get("allowUnknownTools") is not True and not tool.get("parameters"):
            warnings.append(_issue("warning", "POLICY_TOOL_HAS_NO_PARAMETERS", "enabled tool declares no parameters", path + ".parameters"))
    parameter_count = sum(len(tool.get("parameters", {})) for tool in tools.values() if _plain(tool) and _plain(tool.get("parameters", {})))
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": {"tools": len(tools), "parameters": parameter_count, "errors": len(errors), "warnings": len(warnings)},
    }


def normalize_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    audit = audit_policy(policy)
    if not audit["ok"]:
        first = audit["errors"][0]
        raise ToolCageError("INVALID_POLICY", "invalid tool policy: " + first["code"] + " at " + first["path"], audit)
    output = copy.deepcopy(policy)
    output["version"] = 1
    output["allowUnknownTools"] = output.get("allowUnknownTools") is True
    output["allowedTools"] = sorted(set(output.get("allowedTools", [])))
    output["deniedTools"] = sorted(set(output.get("deniedTools", [])))
    budget = {
        "maxCalls": 1000,
        "maxBytes": 1048576,
        "windowMs": 60000,
        "windowMaxCalls": 120,
        "duplicateWindowMs": 10000,
        "maxDuplicates": 4,
    }
    budget.update(output.get("budget", {}))
    output["budget"] = budget
    sanitizer = {
        "maxBytes": 65536,
        "maxDepth": 12,
        "blockOnInstruction": True,
        "redactSecrets": True,
        "removeHiddenUnicode": True,
    }
    sanitizer.update(output.get("sanitizer", {}))
    output["sanitizer"] = sanitizer
    output.setdefault("tools", {})
    for tool in output["tools"].values():
        tool["enabled"] = tool.get("enabled") is not False
        if "rateLimit" in tool:
            rate = {"windowMs": 1000, "maxCalls": 5}
            rate.update(tool["rateLimit"])
            tool["rateLimit"] = rate
    return output
