"""Content-addressed hashing for MCP tool definitions.

Produces a deterministic SHA-256 hash of a tool's canonical JSON
representation. Any change to the tool definition — even whitespace in a
description — produces a different hash, forcing re-verification.

Usage:
    from toolvet import tool_hash

    h = tool_hash({"name": "foo", "tools": [...]})
    # => "sha256:ab12cd..."
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _canonicalize(obj: Any) -> Any:
    """Recursively sort dict keys and normalize types for deterministic JSON."""
    if isinstance(obj, dict):
        return {k: _canonicalize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(item) for item in obj]
    if isinstance(obj, float):
        return float(f"{obj:.10g}")
    return obj


def tool_hash(tool_definition: dict) -> str:
    """Compute a content-addressed hash of a tool definition.

    The hash covers the fields that define the tool's behavior:
    name, version, description, tools, permissions.

    Returns:
        String in the format "sha256:<hex-digest>".
    """
    canonical = {
        "name": tool_definition.get("name", ""),
        "version": tool_definition.get("version", ""),
        "description": tool_definition.get("description", ""),
        "tools": tool_definition.get("tools", []),
        "permissions": tool_definition.get("permissions", []),
    }
    canonical = _canonicalize(canonical)
    payload = json.dumps(canonical, separators=(",", ":"), ensure_ascii=True).encode()
    digest = hashlib.sha256(payload).hexdigest()
    return f"sha256:{digest}"
