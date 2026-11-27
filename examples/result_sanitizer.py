"""Inspect and sanitize untrusted tool output before giving it to a model."""
from pytoolcage import sanitize_tool_result

untrusted = {
    "title": "search result",
    "body": "useful text\u202e",
    "credentialNote": "password = synthetic-example-value",
}
result = sanitize_tool_result(untrusted)
print({"action": result["action"], "value": result["value"], "findings": [item["code"] for item in result["findings"]]})
