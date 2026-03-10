"""Tool loader: parse MCP server definitions from various sources.

Supports:
- JSON/YAML config files
- package.json with MCP configuration
- Directory scanning for MCP server projects
- MCP Registry API (registry.modelcontextprotocol.io)
- Live MCP servers via Streamable HTTP (tools/list)
"""

import json
from pathlib import Path
from typing import Optional
from urllib.parse import quote as urlquote

import httpx
import yaml

from magen.models import MCPToolDefinition

REGISTRY_BASE = "https://registry.modelcontextprotocol.io/v0.1"


class LoadError(Exception):
    """Failed to load tool definition."""
    pass


def load_tool(source: str) -> MCPToolDefinition:
    """Load an MCP tool definition from a file path, directory, registry name, or URL.

    Args:
        source: One of:
            - File path to a JSON/YAML config
            - Directory containing an MCP server project
            - Registry name (e.g. "io.github.user/my-server")
            - URL to a Streamable HTTP MCP server

    Returns:
        Parsed MCPToolDefinition.
    """
    # URL — connect to live MCP server
    if source.startswith(("http://", "https://")):
        return load_from_mcp_url(source)

    # Local path
    path = Path(source).resolve()
    if path.exists():
        if path.is_file():
            return _load_from_file(path)
        elif path.is_dir():
            return _load_from_directory(path)

    # Try as a registry name (contains "/" but isn't a path)
    if "/" in source and not path.exists():
        return load_from_registry(source)

    raise LoadError(f"Source not found: {source}")


def load_from_registry(name: str, version: str = "latest") -> MCPToolDefinition:
    """Fetch a server definition from the MCP Registry API.

    Retrieves server metadata and, if a Streamable HTTP remote is available,
    connects to the live server to pull actual tool definitions.
    """
    encoded = urlquote(name, safe="")
    try:
        resp = httpx.get(
            f"{REGISTRY_BASE}/servers/{encoded}/versions/{version}",
            timeout=15,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise LoadError(f"Server '{name}' not found in registry")
        raise LoadError(f"Registry returned {e.response.status_code}")
    except httpx.HTTPError as e:
        raise LoadError(f"Failed to reach registry: {e}")

    data = resp.json()
    server = data.get("server", data)

    tool_def = MCPToolDefinition(
        name=server.get("name", name),
        version=server.get("version", "0.0.0"),
        description=server.get("description", ""),
        raw_config=server,
    )

    # Try to connect to a live remote to get actual tool definitions
    remotes = server.get("remotes", [])
    for remote in remotes:
        rtype = remote.get("type", "")
        url = remote.get("url", "")
        if rtype in ("streamable-http", "sse") and url:
            try:
                tools = _fetch_tools_list(url)
                tool_def.tools = tools
                break
            except Exception:
                continue  # Try next remote, or fall back to metadata-only

    return tool_def


def load_from_mcp_url(url: str) -> MCPToolDefinition:
    """Connect to a live MCP server and pull tool definitions via tools/list."""
    try:
        tools = _fetch_tools_list(url)
    except Exception as e:
        raise LoadError(f"Failed to connect to MCP server at {url}: {e}")

    # Derive name from URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    name = parsed.hostname or "unknown"

    return MCPToolDefinition(
        name=name,
        description=f"Live MCP server at {url}",
        tools=tools,
        raw_config={"url": url, "tools": tools},
    )


def _fetch_tools_list(url: str) -> list[dict]:
    """Call tools/list on a Streamable HTTP MCP server via JSON-RPC."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    }

    resp = httpx.post(
        url,
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        timeout=15,
    )
    resp.raise_for_status()

    content_type = resp.headers.get("content-type", "")

    # Streamable HTTP may return JSON directly or SSE
    if "text/event-stream" in content_type:
        return _parse_sse_tools_response(resp.text)

    data = resp.json()
    result = data.get("result", {})
    return result.get("tools", [])


def _parse_sse_tools_response(sse_text: str) -> list[dict]:
    """Parse an SSE stream to extract the tools/list result."""
    for line in sse_text.splitlines():
        if line.startswith("data:"):
            data_str = line[len("data:"):].strip()
            if not data_str:
                continue
            try:
                msg = json.loads(data_str)
                result = msg.get("result", {})
                tools = result.get("tools", [])
                if tools:
                    return tools
            except (json.JSONDecodeError, AttributeError):
                continue
    return []


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
