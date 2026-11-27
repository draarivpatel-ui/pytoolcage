"""Sanitize untrusted tool output before it is returned to a model."""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Set

from .canonical import max_depth_of, measured_json_bytes

REDACTED_SECRET = "[REDACTED_SECRET]"
REDACTED_BLOCK = "[REDACTED_PRIVATE_KEY_BLOCK]"

_SECRET_ASSIGNMENT_RE = re.compile(r"\b(api[_\s-]?key|access[_\s-]?token|refresh[_\s-]?token|session[_\s-]?token|client[_\s-]?secret|secret|password|passwd|private[_\s-]?key|auth[_\s-]?token)(\s*[:=]\s*)([\"']?)([^\s\"',\]}]{8,})\3", re.IGNORECASE)
_BEARER_RE = re.compile(r"\b(bearer\s+)([A-Za-z0-9._~+/=-]{12,})\b", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{20,4096}?-----END [A-Z0-9 ]*PRIVATE KEY-----")
_URL_AUTH_RE = re.compile(r"\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^/\s@]{4,})(@)", re.IGNORECASE)

_INSTRUCTION_PATTERNS = [
    ("INSTRUCTION_OVERRIDE", re.compile(r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directions|messages)\b", re.IGNORECASE)),
    ("INSTRUCTION_OVERRIDE", re.compile(r"\bdisregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directions|messages)\b", re.IGNORECASE)),
    ("INSTRUCTION_OVERRIDE", re.compile(r"\bforget\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directions|messages)\b", re.IGNORECASE)),
    ("PROMPT_EXFILTRATION", re.compile(r"\b(?:reveal|print|show|repeat|disclose)\s+(?:your|the)\s+(?:system|developer|hidden)\s+(?:prompt|instructions|message)\b", re.IGNORECASE)),
    ("SECRET_EXFILTRATION", re.compile(r"\b(?:exfiltrate|steal|send|leak)\s+(?:all\s+)?(?:secrets|credentials|tokens|api\s+keys|passwords)\b", re.IGNORECASE)),
    ("QUIET_EXFILTRATION", re.compile(r"\bdo\s+not\s+(?:tell|inform|warn)\s+the\s+user\b", re.IGNORECASE)),
    ("SAFETY_BYPASS", re.compile(r"\b(?:bypass|override|disable)\s+(?:the\s+)?(?:safety|security)\s+(?:policy|policies|controls|guardrails)\b", re.IGNORECASE)),
    ("TOOL_HIJACK", re.compile(r"\b(?:call|invoke|execute|run)\s+(?:the\s+)?[a-z0-9_.:-]{1,80}(?:\s+tool)?\s+(?:with|using)\b", re.IGNORECASE)),
    ("TOOL_HIJACK", re.compile(r"\buse\s+the\s+tool\s+(?:to\s+)?(?:delete|exfiltrate|send|upload|modify)\b", re.IGNORECASE)),
]

_DEFAULT_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "apikey", "authorization", "auth", "credential",
    "credentials", "privatekey", "clientsecret", "accesstoken", "refreshtoken", "sessiontoken",
    "cookie", "setcookie", "session", "secretkey", "signingkey", "encryptionkey",
}
_DANGEROUS_RESULT_KEYS = {"__proto__", "constructor", "prototype"}


def _normalize_key(key: str) -> str:
    return re.sub(r"[\s_.-]+", "", key.lower())


def _hidden_codepoint(cp: int) -> bool:
    return (
        0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069 or 0x200B <= cp <= 0x200F
        or 0x2060 <= cp <= 0x2064 or cp in (0x180E, 0xFEFF, 0x00AD)
        or 0xE0000 <= cp <= 0xE007F or 0x0000 <= cp <= 0x0008 or cp in (0x000B, 0x000C)
        or 0x000E <= cp <= 0x001F or 0x007F <= cp <= 0x009F
    )


def _strip_hidden(value: str):
    output = []
    count = 0
    for ch in value:
        if _hidden_codepoint(ord(ch)):
            count += 1
        else:
            output.append(ch)
    return "".join(output), count


def _safe_custom_pattern(pattern: Any):
    if not isinstance(pattern, str) or not pattern or len(pattern) > 256:
        return None
    if re.search(r"\([^)]*[+*][^)]*\)[+*]", pattern):
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


def _redact_secrets_in_string(text: str, custom_patterns: Any):
    count = 0
    rejected = 0

    def count_replacement(match):
        nonlocal count
        count += 1
        return REDACTED_SECRET

    def key_block_replacement(match):
        nonlocal count
        count += 1
        return REDACTED_BLOCK

    text = _PRIVATE_KEY_RE.sub(key_block_replacement, text)

    def assignment(match):
        nonlocal count
        count += 1
        return match.group(1) + match.group(2) + match.group(3) + REDACTED_SECRET + match.group(3)

    text = _SECRET_ASSIGNMENT_RE.sub(assignment, text)

    def bearer(match):
        nonlocal count
        count += 1
        return match.group(1) + REDACTED_SECRET

    text = _BEARER_RE.sub(bearer, text)
    text = _JWT_RE.sub(count_replacement, text)

    def url_auth(match):
        nonlocal count
        count += 1
        return match.group(1) + REDACTED_SECRET + match.group(3)

    text = _URL_AUTH_RE.sub(url_auth, text)
    if isinstance(custom_patterns, list):
        for source in custom_patterns:
            regex = _safe_custom_pattern(source)
            if regex is None:
                rejected += 1
                continue
            text = regex.sub(count_replacement, text)
    return text, count, rejected


def _instruction_findings(text: str, path: str) -> List[Dict[str, str]]:
    return [
        {"code": code, "path": path, "message": "high-confidence prompt-injection marker detected"}
        for code, regex in _INSTRUCTION_PATTERNS
        if regex.search(text)
    ]


def _json_supported(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, int) and not isinstance(value, bool):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _structure_ok(value: Any) -> bool:
    seen: Set[int] = set()

    def visit(node: Any) -> bool:
        if _json_supported(node):
            return True
        if isinstance(node, list):
            ident = id(node)
            if ident in seen:
                return False
            seen.add(ident)
            ok = all(visit(child) for child in node)
            seen.remove(ident)
            return ok
        if type(node) is dict:
            ident = id(node)
            if ident in seen:
                return False
            seen.add(ident)
            ok = all(isinstance(key, str) and visit(child) for key, child in node.items())
            seen.remove(ident)
            return ok
        return False

    return visit(value)


def sanitize_tool_result(result: Any, options: Dict[str, Any] = None) -> Dict[str, Any]:
    opts = {
        "maxBytes": 65536,
        "maxDepth": 12,
        "blockOnInstruction": True,
        "redactSecrets": True,
        "removeHiddenUnicode": True,
        "sensitiveKeys": [],
        "customSecretPatterns": [],
    }
    if options:
        opts.update(options)
    findings: List[Dict[str, str]] = []
    removed_hidden = 0
    redacted_secrets = 0
    if not _structure_ok(result):
        findings.append({"code": "RESULT_NOT_JSON", "path": "$", "message": "result must be finite JSON-compatible data"})
        return {"action": "blocked", "ok": False, "value": None, "findings": findings, "removedHidden": 0, "redactedSecrets": 0, "bytes": 0}
    try:
        input_bytes = measured_json_bytes(result)
        input_depth = max_depth_of(result)
    except (TypeError, ValueError):
        findings.append({"code": "RESULT_NOT_JSON", "path": "$", "message": "result must be finite JSON-compatible data"})
        return {"action": "blocked", "ok": False, "value": None, "findings": findings, "removedHidden": 0, "redactedSecrets": 0, "bytes": 0}
    if input_bytes > opts["maxBytes"]:
        findings.append({"code": "RESULT_TOO_LARGE", "path": "$", "message": "result exceeds %s bytes" % opts["maxBytes"]})
        return {"action": "blocked", "ok": False, "value": None, "findings": findings, "removedHidden": 0, "redactedSecrets": 0, "bytes": input_bytes}
    if input_depth > opts["maxDepth"]:
        findings.append({"code": "RESULT_TOO_DEEP", "path": "$", "message": "result exceeds depth %s" % opts["maxDepth"]})
        return {"action": "blocked", "ok": False, "value": None, "findings": findings, "removedHidden": 0, "redactedSecrets": 0, "bytes": input_bytes}
    sensitive = set(_DEFAULT_SENSITIVE_KEYS)
    sensitive.update(_normalize_key(key) for key in opts.get("sensitiveKeys", []) if isinstance(key, str))

    def sanitize_string(value: str, path: str):
        nonlocal removed_hidden, redacted_secrets
        text = value
        changed = False
        if opts.get("removeHiddenUnicode") is not False:
            text, removed = _strip_hidden(text)
            if removed:
                removed_hidden += removed
                findings.append({"code": "HIDDEN_UNICODE_REMOVED", "path": path, "message": "hidden or bidirectional control characters removed"})
                changed = True
        if opts.get("redactSecrets") is not False:
            text, redacted, rejected = _redact_secrets_in_string(text, opts.get("customSecretPatterns"))
            if rejected:
                findings.append({"code": "CUSTOM_PATTERN_REJECTED", "path": path, "message": "unsafe custom secret pattern rejected"})
            if redacted:
                redacted_secrets += redacted
                findings.append({"code": "SECRET_REDACTED", "path": path, "message": "secret-like material redacted"})
                changed = True
        injection = _instruction_findings(text, path)
        findings.extend(injection)
        return text, changed, bool(injection)

    def visit(value: Any, path: str):
        nonlocal redacted_secrets
        if _json_supported(value):
            if not isinstance(value, str):
                return value, False, False
            text, changed, blocked = sanitize_string(value, path)
            return text, changed, blocked and opts.get("blockOnInstruction") is not False
        if isinstance(value, list):
            changed = False
            blocked = False
            output = []
            for index, child in enumerate(value):
                new_child, child_changed, child_blocked = visit(child, "%s[%d]" % (path, index))
                output.append(new_child)
                changed = changed or child_changed
                blocked = blocked or child_blocked
            return output, changed, blocked
        output = {}
        changed = False
        blocked = False
        for key, child in value.items():
            child_path = path + "." + key
            if key.lower() in _DANGEROUS_RESULT_KEYS:
                findings.append({"code": "UNSAFE_RESULT_KEY", "path": child_path, "message": "result key is unsafe for structured consumers"})
                blocked = True
                continue
            if _normalize_key(key) in sensitive:
                output[key] = REDACTED_SECRET
                redacted_secrets += 1
                findings.append({"code": "SECRET_REDACTED", "path": child_path, "message": "sensitive structured field redacted"})
                changed = True
                continue
            new_child, child_changed, child_blocked = visit(child, child_path)
            output[key] = new_child
            changed = changed or child_changed
            blocked = blocked or child_blocked
        return output, changed, blocked

    value, changed, blocked = visit(result, "$")
    if blocked:
        code = "UNSAFE_RESULT_STRUCTURE" if any(item["code"] == "UNSAFE_RESULT_KEY" for item in findings) else "PROMPT_INJECTION_DETECTED"
        findings.append({"code": code, "path": "$", "message": "tool result blocked before model exposure"})
        return {"action": "blocked", "ok": False, "value": None, "findings": findings, "removedHidden": removed_hidden, "redactedSecrets": redacted_secrets, "bytes": input_bytes}
    output_bytes = measured_json_bytes(value)
    if output_bytes > opts["maxBytes"]:
        findings.append({"code": "RESULT_TOO_LARGE", "path": "$", "message": "sanitized result exceeds %s bytes" % opts["maxBytes"]})
        return {"action": "blocked", "ok": False, "value": None, "findings": findings, "removedHidden": removed_hidden, "redactedSecrets": redacted_secrets, "bytes": output_bytes}
    return {"action": "sanitized" if changed else "allow", "ok": True, "value": value, "findings": findings, "removedHidden": removed_hidden, "redactedSecrets": redacted_secrets, "bytes": output_bytes}


def result_looks_dangerous(result: Any) -> bool:
    return sanitize_tool_result(result, {"redactSecrets": False, "removeHiddenUnicode": False})["action"] == "blocked"
