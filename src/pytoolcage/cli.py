"""Command-line interface for pytoolcage."""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from . import VERSION
from .policy import audit_policy
from .firewall import create_firewall
from .sanitizer import sanitize_tool_result


def _usage() -> str:
    return "\n".join([
        "pytoolcage " + VERSION,
        "",
        "Usage:",
        "  python3 -m pytoolcage audit-policy --policy policy.json [--json]",
        "  python3 -m pytoolcage validate --policy policy.json --tool NAME (--arguments JSON | --arguments-file FILE) [--show-arguments] [--json]",
        "  python3 -m pytoolcage sanitize [--input FILE | --text TEXT] [--json-input] [--json]",
        "  python3 -m pytoolcage --version",
    ])


def _parse(argv: List[str]) -> Dict[str, Any]:
    options: Dict[str, Any] = {"_": []}
    index = 0
    booleans = {"--json", "--show-arguments", "--json-input", "--input-json"}
    while index < len(argv):
        arg = argv[index]
        if not arg.startswith("--"):
            options["_"].append(arg)
        elif arg in booleans:
            options[arg[2:]] = True
        else:
            if index + 1 >= len(argv):
                raise ValueError("missing value for " + arg)
            options[arg[2:]] = argv[index + 1]
            index += 1
        index += 1
    return options


def _read_json_file(path: str, label: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as caught:
        raise ValueError("cannot read " + label + ": " + str(caught))


def _print(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: List[str] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--version" in args or "-v" in args:
        print("pytoolcage " + VERSION)
        return 0
    if not args:
        print(_usage())
        return 2
    if "--help" in args or "-h" in args:
        print(_usage())
        return 0
    command = args[0]
    try:
        options = _parse(args[1:])
        if command == "audit-policy":
            if "policy" not in options:
                raise ValueError("audit-policy requires --policy")
            audit = audit_policy(_read_json_file(options["policy"], "policy"))
            _print(audit)
            return 0 if audit["ok"] else 1
        if command == "validate":
            if "policy" not in options:
                raise ValueError("validate requires --policy")
            if "tool" not in options:
                raise ValueError("validate requires --tool")
            if "arguments" in options and "arguments-file" in options:
                raise ValueError("use only one argument input")
            tool_args: Any = {}
            if "arguments" in options:
                tool_args = json.loads(options["arguments"])
            elif "arguments-file" in options:
                tool_args = _read_json_file(options["arguments-file"], "arguments")
            firewall = create_firewall(_read_json_file(options["policy"], "policy"))
            result = firewall.validate_call(options["tool"], tool_args)
            if not options.get("show-arguments") and "normalizedArguments" in result:
                result = dict(result)
                keys = sorted(result.pop("normalizedArguments").keys())
                result["argumentKeys"] = keys
                result["argumentBytes"] = result.get("bytes", 0)
            _print(result)
            return 0 if result.get("ok") else 1
        if command == "sanitize":
            if "text" in options:
                raw = options["text"]
            elif "input" in options:
                with open(options["input"], "r", encoding="utf-8") as handle:
                    raw = handle.read()
            else:
                raw = sys.stdin.read()
            value = json.loads(raw) if options.get("json-input") or options.get("input-json") else raw
            result = sanitize_tool_result(value)
            if options.get("json"):
                _print(result)
            elif isinstance(result["value"], str):
                print(result["value"])
            else:
                print(json.dumps(result["value"], sort_keys=True))
            return 0 if result["ok"] else 1
        raise ValueError("unknown command " + command)
    except (ValueError, json.JSONDecodeError) as caught:
        print("pytoolcage: " + str(caught), file=sys.stderr)
        print(_usage(), file=sys.stderr)
        return 2
