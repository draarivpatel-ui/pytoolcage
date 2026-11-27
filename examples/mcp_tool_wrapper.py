"""Wrap an MCP-style tool handler with policy validation, budgets and output sanitization."""
from pytoolcage import create_firewall

policy = {
    "version": 1,
    "tools": {
        "read_file": {
            "parameters": {"path": {"type": "path", "required": True, "maxLength": 1024}},
            "maxCalls": 5,
            "rateLimit": {"windowMs": 1000, "maxCalls": 2},
        },
    },
}

firewall = create_firewall(policy)

def read_file_tool(args):
    return {"path": args["path"], "bytes": 128, "preview": "safe example content"}

safe_read_file = firewall.wrap_tool("read_file", read_file_tool)
allowed = safe_read_file({"path": "notes/readme.txt"})
rejected = safe_read_file({"path": "../outside.txt"})
print({"allowed": allowed["ok"], "rejected": not rejected["ok"], "auditDigest": firewall.audit_digest()})
