"""Runtime firewall combining policy validation, budgets, audit and sanitization."""
from __future__ import annotations

import inspect
import re
from typing import Any, Callable, Dict, Optional

from .audit import AuditTrail
from .budget import CapabilityBudget
from .canonical import canonical_hash, stable_stringify
from .policy import normalize_policy
from .sanitizer import sanitize_tool_result
from .schema import inspect_tool_arguments, validate_tool_arguments

_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def _failure(code: str, message: str) -> Dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message}}


class ToolCage:
    def __init__(self, policy: Dict[str, Any], now: Optional[Callable[[], float]] = None) -> None:
        self.policy = normalize_policy(policy)
        self._now = now or (lambda: __import__("time").time_ns() // 1_000_000)
        self.audit = AuditTrail(self._now)
        self.budget = CapabilityBudget(self.policy["budget"], self._now)

    def resolve_tool(self, tool_name: str) -> Dict[str, Any]:
        if not isinstance(tool_name, str) or _TOOL_NAME_RE.match(tool_name) is None:
            return {"allowed": False, "code": "TOOL_NAME_INVALID", "message": "tool name is invalid"}
        if tool_name in self.policy["deniedTools"]:
            return {"allowed": False, "code": "TOOL_DENIED", "message": "tool is denied by policy"}
        if self.policy["allowedTools"] and tool_name not in self.policy["allowedTools"]:
            return {"allowed": False, "code": "TOOL_NOT_ALLOWLISTED", "message": "tool is not on the allowlist"}
        spec = self.policy["tools"].get(tool_name)
        if spec is None:
            if self.policy["allowUnknownTools"] is not True:
                return {"allowed": False, "code": "TOOL_NOT_ALLOWLISTED", "message": "tool is not declared by policy"}
            return {"allowed": True, "spec": None, "unknown": True}
        if spec.get("enabled") is not True:
            return {"allowed": False, "code": "TOOL_DISABLED", "message": "tool is disabled by policy"}
        return {"allowed": True, "spec": spec, "unknown": False}

    def validate_call(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        resolution = self.resolve_tool(tool_name)
        if not resolution["allowed"]:
            return _failure(resolution["code"], resolution["message"])
        if resolution["unknown"]:
            inspected = inspect_tool_arguments(args)
            if not inspected["ok"]:
                return {"ok": False, "errors": inspected["errors"]}
            return {"ok": True, "tool": tool_name, "normalizedArguments": __import__("json").loads(stable_stringify(args)), "bytes": inspected["bytes"], "depth": inspected["depth"], "unknownTool": True}
        validated = validate_tool_arguments(args, resolution["spec"])
        if not validated["ok"]:
            return validated
        validated["tool"] = tool_name
        validated["unknownTool"] = False
        return validated

    def _prepare(self, tool_name: str, args: Dict[str, Any], started: float) -> Dict[str, Any]:
        resolution = self.resolve_tool(tool_name)
        if not resolution["allowed"]:
            entry = self.audit.append("policy_denied", {"tool": str(tool_name or ""), "decision": "deny", "details": {"code": resolution["code"]}})
            return {**_failure(resolution["code"], resolution["message"]), "auditHash": entry["hash"]}
        if resolution["unknown"]:
            inspected = inspect_tool_arguments(args)
            if inspected["ok"]:
                validated = {"ok": True, "normalizedArguments": __import__("json").loads(stable_stringify(args)), "bytes": inspected["bytes"], "depth": inspected["depth"]}
            else:
                validated = {"ok": False, "errors": inspected["errors"]}
        else:
            validated = validate_tool_arguments(args, resolution["spec"])
        if not validated["ok"]:
            first = validated["errors"][0]["code"] if validated["errors"] else "INVALID"
            entry = self.audit.append("validation_failed", {"tool": tool_name, "decision": "deny", "bytes": validated.get("bytes", 0), "details": {"firstCode": first, "errorCount": len(validated["errors"])}})
            return {"ok": False, "errors": validated["errors"], "auditHash": entry["hash"]}
        normalized = validated["normalizedArguments"]
        input_hash = canonical_hash(normalized)
        admission = self.budget.admit(tool_name, resolution["spec"] or {}, input_hash, validated["bytes"])
        if not admission["ok"]:
            entry = self.audit.append("budget_denied", {"tool": tool_name, "decision": "deny", "inputHash": input_hash, "bytes": validated["bytes"], "details": {"code": admission["code"]}})
            return {**_failure(admission["code"], admission["message"]), "auditHash": entry["hash"]}
        return {"prepared": True, "resolution": resolution, "normalized": normalized, "validated": validated, "inputHash": input_hash}

    def _finish(self, tool_name: str, prepared: Dict[str, Any], raw: Any, started: float) -> Dict[str, Any]:
        resolution = prepared["resolution"]
        validated = prepared["validated"]
        input_hash = prepared["inputHash"]
        sanitizer_options = dict(self.policy.get("sanitizer", {}))
        if resolution["spec"] and isinstance(resolution["spec"].get("result"), dict):
            sanitizer_options.update(resolution["spec"]["result"])
        sanitized = sanitize_tool_result(raw, sanitizer_options)
        completion = self.budget.complete(tool_name, sanitized.get("bytes", 0))
        duration = self._now() - started
        if not completion["ok"]:
            entry = self.audit.append("budget_denied", {"tool": tool_name, "decision": "deny", "inputHash": input_hash, "bytes": validated["bytes"] + sanitized.get("bytes", 0), "durationMs": duration, "details": {"code": completion["code"], "phase": "output"}})
            return {**_failure(completion["code"], completion["message"]), "auditHash": entry["hash"]}
        if not sanitized["ok"]:
            entry = self.audit.append("result_blocked", {"tool": tool_name, "decision": "deny", "inputHash": input_hash, "bytes": validated["bytes"] + sanitized.get("bytes", 0), "durationMs": duration, "details": {"findingCount": len(sanitized["findings"]), "action": sanitized["action"]}})
            return {**_failure("RESULT_BLOCKED", "tool result was blocked by the output sanitizer"), "findings": sanitized["findings"], "auditHash": entry["hash"]}
        entry = self.audit.append("call_completed", {"tool": tool_name, "decision": "sanitize" if sanitized["action"] == "sanitized" else "allow", "inputHash": input_hash, "bytes": validated["bytes"] + sanitized["bytes"], "durationMs": duration, "details": {"findingCount": len(sanitized["findings"]), "action": sanitized["action"], "redactions": sanitized["redactedSecrets"], "hiddenRemoved": sanitized["removedHidden"]}})
        return {"ok": True, "value": sanitized["value"], "action": sanitized["action"], "findings": sanitized["findings"], "bytes": validated["bytes"] + sanitized["bytes"], "inputHash": input_hash, "auditHash": entry["hash"]}

    def _tool_error(self, tool_name: str, prepared: Dict[str, Any], started: float, caught: BaseException) -> Dict[str, Any]:
        entry = self.audit.append("tool_error", {"tool": tool_name, "decision": "error", "inputHash": prepared["inputHash"], "bytes": prepared["validated"]["bytes"], "durationMs": self._now() - started, "details": {"errorName": type(caught).__name__}})
        return {**_failure("TOOL_ERROR", "tool handler failed"), "auditHash": entry["hash"]}

    def execute(self, tool_name: str, args: Dict[str, Any], handler: Callable[[Dict[str, Any]], Any]) -> Dict[str, Any]:
        started = self._now()
        if not callable(handler):
            entry = self.audit.append("execution_rejected", {"tool": str(tool_name or ""), "decision": "deny", "details": {"reason": "handler_missing"}})
            return {**_failure("HANDLER_MISSING", "execute requires a tool handler function"), "auditHash": entry["hash"]}
        prepared = self._prepare(tool_name, args, started)
        if not prepared.get("prepared"):
            return prepared
        try:
            raw = handler(prepared["normalized"])
            if inspect.isawaitable(raw):
                close = getattr(raw, "close", None)
                if callable(close):
                    close()
                raise TypeError("async handler requires execute_async")
        except BaseException as caught:
            return self._tool_error(tool_name, prepared, started, caught)
        return self._finish(tool_name, prepared, raw, started)

    async def execute_async(self, tool_name: str, args: Dict[str, Any], handler: Callable[[Dict[str, Any]], Any]) -> Dict[str, Any]:
        started = self._now()
        if not callable(handler):
            entry = self.audit.append("execution_rejected", {"tool": str(tool_name or ""), "decision": "deny", "details": {"reason": "handler_missing"}})
            return {**_failure("HANDLER_MISSING", "execute requires a tool handler function"), "auditHash": entry["hash"]}
        prepared = self._prepare(tool_name, args, started)
        if not prepared.get("prepared"):
            return prepared
        try:
            raw = handler(prepared["normalized"])
            if inspect.isawaitable(raw):
                raw = await raw
        except BaseException as caught:
            return self._tool_error(tool_name, prepared, started, caught)
        return self._finish(tool_name, prepared, raw, started)

    def wrap_tool(self, tool_name: str, handler: Callable[[Dict[str, Any]], Any]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        def wrapped(args: Dict[str, Any]) -> Dict[str, Any]:
            return self.execute(tool_name, args, handler)
        return wrapped

    def wrap_tool_async(self, tool_name: str, handler: Callable[[Dict[str, Any]], Any]) -> Callable[[Dict[str, Any]], Any]:
        async def wrapped(args: Dict[str, Any]) -> Dict[str, Any]:
            return await self.execute_async(tool_name, args, handler)
        return wrapped

    def wrap_tools(self, handlers: Dict[str, Callable[[Dict[str, Any]], Any]]) -> Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]]:
        return {name: self.wrap_tool(name, handler) for name, handler in handlers.items()}

    def sanitize_result(self, value: Any, tool_name: Optional[str] = None) -> Dict[str, Any]:
        options = dict(self.policy.get("sanitizer", {}))
        spec = self.policy["tools"].get(tool_name) if isinstance(tool_name, str) else None
        if spec and isinstance(spec.get("result"), dict):
            options.update(spec["result"])
        return sanitize_tool_result(value, options)

    def audit_entries(self):
        return self.audit.entries()

    def verify_audit(self) -> bool:
        return self.audit.verify()

    def audit_digest(self) -> str:
        return self.audit.digest()

    def budget_snapshot(self) -> Dict[str, Any]:
        return self.budget.snapshot()


def create_firewall(policy: Dict[str, Any], now: Optional[Callable[[], float]] = None) -> ToolCage:
    return ToolCage(policy, now)


def wrap_tool(policy: Dict[str, Any], tool_name: str, handler: Callable[[Dict[str, Any]], Any], now: Optional[Callable[[], float]] = None):
    return create_firewall(policy, now).wrap_tool(tool_name, handler)
