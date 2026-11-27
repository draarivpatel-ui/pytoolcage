"""Typed errors and validation issue helpers."""
from __future__ import annotations

from typing import Any, Dict, Optional


class ToolCageError(Exception):
    """Machine-coded error raised for invalid firewall configuration."""

    def __init__(self, code: str, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details


def failure(code: str, message: str, path: str = "$") -> Dict[str, str]:
    return {"code": code, "message": message, "path": path}
