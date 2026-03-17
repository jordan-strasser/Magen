"""Tool loader: parse MCP server definitions from various sources.

Supports:
- JSON/YAML config files
- package.json with MCP configuration
- Directory scanning for MCP server projects
"""

import json
from pathlib import Path
from typing import Optional

import yaml

from toolvet.models import MCPToolDefinition


class LoadError(Exception):
    """Failed to load tool definition."""
    pass


def load_tool(source: str) -> MCPToolDefinition:
    """Load an MCP tool definition from a file path or directory.

    Args:
        source: Path to a config file, directory, or URL.

    Returns:
        Parsed MCPToolDefinition.
    """
    path = Path(source).resolve()

    if not path.exists():
        raise LoadError(f"Source not found: {source}")

    if path.is_file():
        return _load_from_file(path)
    elif path.is_dir():
        return _load_from_directory(path)
    else:
        raise LoadError(f"Unsupported source type: {source}")


def _load_from_file(path: Path) -> MCPToolDefinition:
    """Load from a single config file."""
    content = path.read_text()

    if path.suffix in {".json", ".jsonc"}:
        data = json.loads(content)
    elif path.suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(content)
    else:
        raise LoadError(f"Unsupported file type: {path.suffix}")

    return MCPToolDefinition.from_dict(data, source_path=str(path.parent))


def _load_from_directory(path: Path) -> MCPToolDefinition:
    """Scan a directory for MCP server configuration.

    Priority order:
    1. mcp.json / mcp.yaml
    2. magen.json / magen.yaml (our own config format)
    3. package.json with "mcp" key
    4. pyproject.toml with [tool.mcp] section
    """
    # Check for dedicated MCP config
    for name in ["mcp.json", "mcp.yaml", "mcp.yml", "magen.json", "magen.yaml"]:
        config_path = path / name
        if config_path.exists():
            tool = _load_from_file(config_path)
            tool.source_path = str(path)
            return tool

    # Check package.json
    pkg_json = path / "package.json"
    if pkg_json.exists():
        data = json.loads(pkg_json.read_text())
        if "mcp" in data:
            tool = MCPToolDefinition.from_dict(
                {**data.get("mcp", {}), "name": data.get("name", "unknown"), "version": data.get("version", "0.0.0")},
                source_path=str(path),
            )
            return tool

        # Also extract from standard MCP server patterns
        if "bin" in data or data.get("name", "").endswith("-mcp-server"):
            return MCPToolDefinition(
                name=data.get("name", "unknown"),
                version=data.get("version", "0.0.0"),
                description=data.get("description", ""),
                source_path=str(path),
                raw_config=data,
            )

    # Check pyproject.toml
    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore

        with open(pyproject, "rb") as f:
            data = tomllib.load(f)

        project = data.get("project", {})
        mcp_config = data.get("tool", {}).get("mcp", {})

        if mcp_config or "mcp" in project.get("keywords", []):
            return MCPToolDefinition(
                name=project.get("name", "unknown"),
                version=project.get("version", "0.0.0"),
                description=project.get("description", ""),
                source_path=str(path),
                raw_config={**project, **mcp_config},
            )

    raise LoadError(
        f"No MCP configuration found in {path}. "
        f"Expected one of: mcp.json, mcp.yaml, package.json (with 'mcp' key), "
        f"or pyproject.toml (with [tool.mcp] section)."
    )
