"""Statically audit a tool policy before putting it into production."""
from pytoolcage import audit_policy

policy = {
    "version": 1,
    "allowUnknownTools": True,
    "tools": {
        "fetch_url": {
            "parameters": {"url": {"type": "url", "required": True, "allowPrivateNetworks": True}},
        },
    },
}
audit = audit_policy(policy)
print({"ok": audit["ok"], "errors": len(audit["errors"]), "warnings": [item["code"] for item in audit["warnings"]]})
