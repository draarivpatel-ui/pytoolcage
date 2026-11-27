"""Zero-dependency AI-agent and MCP tool-call security firewall."""
from .audit import AUDIT_GENESIS_HASH, AuditTrail
from .budget import CapabilityBudget
from .canonical import canonical_hash, max_depth_of, measured_json_bytes, sha256_text, stable_stringify
from .errors import ToolCageError
from .firewall import ToolCage, create_firewall, wrap_tool
from .guards import guard_command, guard_path, guard_url, split_command_words
from .ip import classify_ip, classify_ipv4, classify_ipv6, is_public_ip, normalize_ip, parse_ipv4, parse_ipv6
from .policy import audit_policy, normalize_policy
from .sanitizer import REDACTED_BLOCK, REDACTED_SECRET, result_looks_dangerous, sanitize_tool_result
from .schema import inspect_tool_arguments, validate_tool_arguments

VERSION = "1.0.0"

__all__ = [
    "AUDIT_GENESIS_HASH", "AuditTrail", "CapabilityBudget", "REDACTED_BLOCK", "REDACTED_SECRET",
    "ToolCage", "ToolCageError", "VERSION", "audit_policy", "canonical_hash", "classify_ip",
    "classify_ipv4", "classify_ipv6", "create_firewall", "guard_command", "guard_path", "guard_url",
    "inspect_tool_arguments", "is_public_ip", "max_depth_of", "measured_json_bytes", "normalize_ip",
    "normalize_policy", "parse_ipv4", "parse_ipv6", "result_looks_dangerous", "sanitize_tool_result",
    "sha256_text", "split_command_words", "stable_stringify", "validate_tool_arguments", "wrap_tool",
]
