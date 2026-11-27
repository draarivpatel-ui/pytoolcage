"""Dangerous argument guards for command, path and URL parameters."""
from __future__ import annotations

import re
import shlex
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from .errors import failure
from .ip import classify_ip, normalize_ip

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SHELL_OPERATOR_PATTERNS = [
    ("COMMAND_SUBSTITUTION", re.compile(r"\$\{")),
    ("COMMAND_SUBSTITUTION", re.compile(r"\$\(")),
    ("COMMAND_SUBSTITUTION", re.compile(r"`")),
    ("PROCESS_SUBSTITUTION", re.compile(r"[<>]\(")),
    ("SHELL_OPERATOR", re.compile(r"&&|\|\||;;")),
    ("SHELL_OPERATOR", re.compile(r"[;&|<>*?\[\]]")),
    ("SHELL_EXPANSION", re.compile(r"\$[A-Za-z_{(]")),
]
_GIT_ENV_RE = re.compile(r"(?:^|\s)GIT_(?:SSH_COMMAND|SSH|ASKPASS)=(?:\"[^\"]*\"|'[^']*'|\S+)", re.IGNORECASE)
_DANGEROUS_GIT_LONG_FLAGS = {
    "--upload-pack",
    "--exec-path",
    "--config",
    "--config-env",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
}
_LOCAL_HOSTNAMES = {"localhost", "ip6-localhost", "ip6-loopback"}
_LOCAL_HOST_SUFFIXES = (".localhost", ".local", ".lan", ".home", ".internal", ".intranet", ".corp")
_WINDOWS_DRIVE_RE = re.compile(r"^[a-zA-Z]:[\\/]")
_CONTROL_PERCENT_RE = re.compile(r"%(?:0[0-9a-f]|1[f]|7[f])", re.IGNORECASE)
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _err(code: str, message: str, path: str) -> Dict[str, str]:
    return failure(code, message, path)


def split_command_words(command: str) -> Optional[List[str]]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return None


def _is_git_executable(word: str) -> bool:
    base = word.split("/")[-1].split("\\")[-1].lower()
    return base in ("git", "git.exe")


def guard_command(value: str, spec: Dict[str, object], path: str = "$") -> List[Dict[str, str]]:
    errors = []
    if _CONTROL_RE.search(value):
        errors.append(_err("CONTROL_CHARACTER", "command contains a control character", path))
    if "\x00" in value:
        errors.append(_err("NULL_BYTE", "command contains a null byte", path))
    if spec.get("allowShellOperators") is not True:
        for code, regex in _SHELL_OPERATOR_PATTERNS:
            if regex.search(value):
                errors.append(_err(code, "command contains shell syntax that is not allowed", path))
                break
    if _GIT_ENV_RE.search(value):
        errors.append(_err("GIT_COMMAND_INJECTION", "git process execution environment override is not allowed", path))
    words = split_command_words(value)
    if words is None:
        errors.append(_err("UNBALANCED_QUOTE", "command quoting is unbalanced", path))
        return errors
    git_mode = False
    for word in words:
        lower = word.lower()
        if _is_git_executable(word):
            git_mode = True
        if not git_mode:
            continue
        if lower in ("-c", "--config", "--config-env"):
            errors.append(_err("GIT_CONFIG_INJECTION", "git command-line configuration injection is not allowed", path))
            continue
        flag = lower.split("=", 1)[0]
        if flag in _DANGEROUS_GIT_LONG_FLAGS:
            errors.append(_err("GIT_FLAG_BLOCKED", "git flag " + flag + " is not allowed", path))
        if "core.sshcommand" in lower or "core.sshvariant" in lower or "ssh.command" in lower:
            errors.append(_err("GIT_COMMAND_INJECTION", "git ssh command override is not allowed", path))
    return errors


def _percent_decode_repeated(value: str) -> str:
    text = value
    hex_digits = set("0123456789abcdefABCDEF")
    for _round in range(4):
        output = []
        changed = False
        index = 0
        while index < len(text):
            if text[index] == "%" and index + 2 < len(text) and all(ch in hex_digits for ch in text[index + 1:index + 3]):
                output.append(chr(int(text[index + 1:index + 3], 16)))
                index += 3
                changed = True
            else:
                output.append(text[index])
                index += 1
        text = "".join(output)
        if not changed:
            break
    return text


def guard_path(value: str, spec: Dict[str, object], path: str = "$") -> List[Dict[str, str]]:
    errors = []
    decoded = _percent_decode_repeated(value).replace("\\", "/")
    if _CONTROL_RE.search(value) or _CONTROL_PERCENT_RE.search(value) or _CONTROL_RE.search(decoded):
        errors.append(_err("CONTROL_CHARACTER", "path contains a control character", path))
    if "\x00" in value:
        errors.append(_err("NULL_BYTE", "path contains a null byte", path))
    if "\x00" in decoded:
        errors.append(_err("NULL_BYTE", "encoded path contains a null byte", path))
    if _WINDOWS_DRIVE_RE.match(decoded) or decoded.startswith("/") or decoded.startswith("//"):
        if spec.get("allowAbsolute") is not True:
            errors.append(_err("ABSOLUTE_PATH", "absolute paths are not allowed", path))
    if re.match(r"^~(?:/|$)", decoded):
        errors.append(_err("HOME_EXPANSION", "home-directory expansion is not allowed", path))
    segments = [segment for segment in decoded.split("/") if segment and segment != "."]
    if spec.get("allowParentTraversal") is not True and ".." in segments:
        errors.append(_err("PATH_TRAVERSAL", "parent directory traversal is not allowed", path))
    if "..../" in decoded or "....//" in decoded:
        errors.append(_err("PATH_TRAVERSAL", "ambiguous parent traversal sequence is not allowed", path))
    if spec.get("allowUnicodeNormalizationBypass") is not True and re.search(r"(?:%u202e|%e0%80%ae)", value, re.IGNORECASE):
        errors.append(_err("PATH_OBFUSCATION", "encoded direction override or overlong path sequence is not allowed", path))
    return errors


def _strip_trailing_dots(host: str) -> str:
    return host.rstrip(".")


def _host_pattern_matches(host: str, pattern: object) -> bool:
    if not isinstance(pattern, str) or not pattern:
        return False
    normalized = _strip_trailing_dots(pattern.strip().lower())
    if normalized.startswith("*."):
        normalized = normalized[2:]
    if normalized.startswith("."):
        normalized = normalized[1:]
    if not normalized:
        return False
    return host == normalized or host.endswith("." + normalized)


def _hostname_looks_local(host: str) -> bool:
    return host in _LOCAL_HOSTNAMES or any(host.endswith(suffix) for suffix in _LOCAL_HOST_SUFFIXES)


def _valid_hostname_shape(host: str) -> bool:
    if not host or len(host) > 253 or ".." in host:
        return False
    return all(0 < len(label) <= 63 and _LABEL_RE.match(label) is not None for label in host.split("."))


def _port_is_allowed(parsed: object, spec: Dict[str, object]) -> bool:
    try:
        port = parsed.port
    except ValueError:
        return False
    if port is None:
        return True
    if port < 1 or port > 65535:
        return False
    allowed = spec.get("allowedPorts")
    if isinstance(allowed, list):
        return port in allowed
    if allowed == "any":
        return True
    return (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)


def guard_url(value: str, spec: Dict[str, object], path: str = "$") -> List[Dict[str, str]]:
    errors = []

    def push(code: str, message: str) -> None:
        errors.append(_err(code, message, path))

    if _CONTROL_RE.search(value):
        push("CONTROL_CHARACTER", "URL contains a control character")
    if any(ch.isspace() for ch in value):
        push("URL_WHITESPACE", "URL contains whitespace")
    if "\x00" in value:
        push("NULL_BYTE", "URL contains a null byte")
    if "\\" in value:
        push("URL_BACKSLASH", "URL contains a backslash")
    if value.startswith("//"):
        push("SCHEME_RELATIVE_URL", "scheme-relative URLs are not allowed")
    if errors:
        return errors
    try:
        parsed = urlsplit(value)
    except ValueError:
        push("INVALID_URL", "URL cannot be parsed")
        return errors
    schemes_raw = spec.get("allowedSchemes")
    schemes = [str(scheme).lower().rstrip(":") for scheme in schemes_raw] if isinstance(schemes_raw, list) and schemes_raw else ["http", "https"]
    if parsed.scheme.lower() not in schemes:
        push("UNSAFE_URL_SCHEME", "URL scheme " + parsed.scheme + ": is not allowed")
    if parsed.username is not None or parsed.password is not None:
        push("URL_USERINFO", "URL userinfo is not allowed")
    if not _port_is_allowed(parsed, spec):
        push("URL_PORT_BLOCKED", "URL port is not allowed")
    host = parsed.hostname or ""
    host = _strip_trailing_dots(host.lower())
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        push("INVALID_URL", "URL host is empty")
    if "%" in host:
        push("INVALID_URL", "URL host contains percent encoding")
    normalized_ip = normalize_ip(host) if host else None
    if normalized_ip is not None:
        classification = classify_ip(normalized_ip)
        if classification != "public" and spec.get("allowPrivateNetworks") is not True:
            push("SSRF_PRIVATE_NETWORK", "URL resolves to a " + classification + " network literal")
    elif host:
        if not _valid_hostname_shape(host):
            push("INVALID_HOSTNAME", "URL hostname is not a valid DNS name")
        if _hostname_looks_local(host) and spec.get("allowPrivateNetworks") is not True:
            push("SSRF_LOCAL_HOSTNAME", "URL hostname is reserved for local networks")
    host_policy = spec.get("hostPolicy") if isinstance(spec.get("hostPolicy"), dict) else {}
    deny = host_policy.get("deny") if isinstance(host_policy.get("deny"), list) else []
    allow = host_policy.get("allow") if isinstance(host_policy.get("allow"), list) else []
    for pattern in deny:
        if _host_pattern_matches(host, pattern):
            push("HOST_DENIED", "URL host is denied by policy")
            break
    if allow and not any(_host_pattern_matches(host, pattern) for pattern in allow):
        push("HOST_NOT_ALLOWED", "URL host is not on the allow list")
    return errors


def guard_value_by_kind(value: str, spec: Dict[str, object], path: str) -> List[Dict[str, str]]:
    kind = spec.get("type")
    if kind == "command":
        return guard_command(value, spec, path)
    if kind == "path":
        return guard_path(value, spec, path)
    if kind == "url":
        return guard_url(value, spec, path)
    return []
