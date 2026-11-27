# pytoolcage

Zero-dependency AI-agent and MCP tool-call security firewall for Python 3.9 through 3.13.

`pytoolcage` sits between a model and real tools. It validates tool names and arguments before execution, blocks dangerous command, path and URL inputs, enforces capability budgets, stops duplicate runaway loops, writes a tamper-evident audit trail, and sanitizes untrusted tool output before the output goes back to a model.

- Zero runtime dependencies
- Typed package with `py.typed`
- Synchronous and asynchronous execution wrappers
- No network access and no hidden process, file or environment side effects

## Install

```sh
python3 -m pip install pytoolcage
```

This repository is prepared for independent audit before publication. Do not treat a local checkout as proof that the package is available on PyPI.

## Quick start

```python
from pytoolcage import create_firewall

firewall = create_firewall({
    "version": 1,
    "tools": {
        "read_file": {
            "parameters": {
                "path": {"type": "path", "required": True, "maxLength": 1024},
            },
            "maxCalls": 10,
            "rateLimit": {"windowMs": 1000, "maxCalls": 3},
        },
    },
    "budget": {
        "maxCalls": 100,
        "maxBytes": 1000000,
        "windowMs": 60000,
        "windowMaxCalls": 30,
        "duplicateWindowMs": 10000,
        "maxDuplicates": 4,
    },
})

result = firewall.execute(
    "read_file",
    {"path": "notes/today.txt"},
    lambda args: {"path": args["path"], "bytes": 42},
)

if result["ok"]:
    print(result["value"])
else:
    print(result.get("error") or result.get("errors"))
```

## Controls

### Tool policy and argument firewall

Every enabled tool is declared in policy. Unknown tools are denied by default. Arguments must be plain JSON-compatible dictionaries. Unknown argument keys are rejected fail closed, including unknown nested keys unless `additionalProperties` is explicitly true. Dunder keys, prototype-confusion keys, non-string keys, cyclic values, nonplain objects and non-finite numbers are rejected. Size and depth limits apply globally, per tool and per parameter.

### Dangerous argument guards

- `command`: shell operators, substitution, process substitution, expansion, control characters, unbalanced quoting, dangerous git flags and git SSH command overrides.
- `path`: parent traversal, encoded traversal, absolute paths, Windows drive paths, UNC paths, home expansion, null bytes and control characters.
- `url`: unsafe schemes, userinfo, whitespace and backslash ambiguity, non-default ports, local hostnames, direct private or reserved IP literals, IPv4 spelling obfuscation, IPv4-mapped IPv6, host allowlists and host denylists.

### Capability budgets and audit

`CapabilityBudget` supports per-session and per-tool maximum calls, session and per-tool sliding-window rate limits, cumulative byte budgets and duplicate identical-call loop detection. Every execution decision appends a hash-chained frozen entry to `AuditTrail`. Entries contain metadata and hashes, never raw arguments or results.

### Output sanitization

`sanitize_tool_result` removes Trojan Source bidirectional controls, zero-width characters, Unicode Tag characters and unsafe control characters. It detects high-confidence instruction-override, prompt-exfiltration, secret-exfiltration, safety-bypass and tool-hijack markers. It redacts structured sensitive fields and common secret-shaped strings without echoing secrets into findings.

## Public API

- `create_firewall(policy, now=None)` and `ToolCage`
- `firewall.validate_call(tool_name, args)`
- `firewall.execute(tool_name, args, handler)` for synchronous handlers
- `firewall.execute_async(tool_name, args, handler)` for asynchronous handlers
- `firewall.wrap_tool`, `wrap_tool_async`, `wrap_tools`
- `validate_tool_arguments`, `inspect_tool_arguments`
- `audit_policy`, `normalize_policy`
- `guard_command`, `guard_path`, `guard_url`, `split_command_words`
- `sanitize_tool_result`, `result_looks_dangerous`
- `AuditTrail`, `CapabilityBudget`
- `parse_ipv4`, `parse_ipv6`, `normalize_ip`, `classify_ip`, `is_public_ip`

## CLI

```sh
python3 -m pytoolcage audit-policy --policy policy.json --json
python3 -m pytoolcage validate --policy policy.json --tool read_file --arguments-file args.json --json
python3 -m pytoolcage sanitize --input untrusted.txt --json
```

Validation output hides argument values by default. Pass `--show-arguments` only when the values are safe to print.

## Examples

```sh
PYTHONPATH=src python3 examples/mcp_tool_wrapper.py
PYTHONPATH=src python3 examples/policy_audit.py
PYTHONPATH=src python3 examples/result_sanitizer.py
```

## Threat model and boundaries

In scope: untrusted model-selected tool names, malformed or hostile arguments, dangerous command/path/URL values, runaway automation loops, oversized outputs, hidden Unicode in tool output, high-confidence indirect prompt injection and accidental secret exposure.

Out of scope: compromise of the host process itself, malicious policy authors, side-channel-free execution, network pinning after a URL is validated, full natural-language injection detection, and safety of the underlying tool implementation. A permissive policy can weaken every control here. Treat policy changes as security-sensitive code changes.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m build
python3 scripts/check_dist.py dist
```

The package has zero runtime dependencies. Building distributions requires the standard `build` frontend in the development environment only.

## License

MIT
