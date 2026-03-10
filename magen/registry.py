"""Registry client: fetch MCP server definitions from the MCP registry."""

from urllib.parse import quote as urlquote

import httpx

from magen.models import MCPToolDefinition

REGISTRY_BASE = "https://registry.modelcontextprotocol.io/v0.1"


class RegistryError(Exception):
    """Failed to fetch from the MCP registry."""
    pass


def fetch_server(name: str) -> dict:
    """Fetch server metadata from the MCP registry by name.

    Args:
        name: Server name as it appears in the registry
              (e.g. 'io.github.user/my-server').

    Returns:
        Raw server dict from the registry response.
    """
    encoded = urlquote(name, safe="")
    try:
        resp = httpx.get(
            f"{REGISTRY_BASE}/servers/{encoded}/versions/latest",
            timeout=15,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise RegistryError(f"Server '{name}' not found in registry")
        raise RegistryError(f"Registry returned {e.response.status_code}")
    except httpx.HTTPError as e:
        raise RegistryError(f"Failed to reach registry: {e}")

    data = resp.json()
    return data.get("server", data)


def server_to_tool(server: dict) -> MCPToolDefinition:
    """Convert a registry server response dict to an MCPToolDefinition."""
    packages = server.get("packages", [])
    remotes = server.get("remotes", [])

    # Include package names in description corpus so scanners can analyse them
    pkg_names = [p.get("name", "") for p in packages if p.get("name")]
    description = server.get("description", "")
    if pkg_names:
        description = description + "\n\nPackages: " + ", ".join(pkg_names)

    raw_config = {
        "name": server.get("name", "unknown"),
        "version": server.get("version", "0.0.0"),
        "description": server.get("description", ""),
        "title": server.get("title", ""),
        "packages": packages,
        "remotes": remotes,
        "repository": server.get("repository", {}),
    }

    return MCPToolDefinition(
        name=server.get("name", "unknown"),
        version=server.get("version", "0.0.0"),
        description=description,
        tools=server.get("tools", []),
        permissions=server.get("permissions", []),
        raw_config=raw_config,
    )


def fetch_and_load(name: str) -> MCPToolDefinition:
    """Fetch a server from the registry and return as MCPToolDefinition.

    Args:
        name: Registry server name (e.g. 'io.github.user/my-server').

    Returns:
        MCPToolDefinition ready to pass into the Pipeline.
    """
    server = fetch_server(name)
    return server_to_tool(server)
