"""Integration tests: verify magen against real MCP servers from the registry.

These tests hit the live MCP Registry API and optionally connect to
live MCP servers. They require network access and are marked with
pytest.mark.integration so they can be skipped in offline CI.

Run with:
    pytest tests/test_integration.py -v
    pytest tests/test_integration.py -v -k "not live_server"  # registry only
"""

import pytest

from magen.loader import load_from_registry, LoadError
from magen.models import Verdict
from magen.pipeline import Pipeline


def _has_network():
    """Check if we can reach the registry."""
    try:
        import httpx
        resp = httpx.get("https://registry.modelcontextprotocol.io/v0.1/version", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _has_network(), reason="No network access to registry")


class TestRegistryFetch:
    """Test that we can fetch server definitions from the real MCP registry."""

    def test_fetch_known_server(self):
        """Fetch a well-known server and verify we get valid metadata."""
        # Search for any server — we just need one that exists
        import httpx
        resp = httpx.get(
            "https://registry.modelcontextprotocol.io/v0.1/servers",
            params={"limit": 1, "version": "latest"},
            timeout=15,
        )
        resp.raise_for_status()
        servers = resp.json().get("servers", [])
        assert len(servers) > 0

        name = servers[0]["server"]["name"]
        tool = load_from_registry(name)

        assert tool.name == name
        assert tool.version
        assert tool.description

    def test_fetch_nonexistent_server(self):
        """Fetching a nonexistent server raises LoadError."""
        with pytest.raises(LoadError, match="not found"):
            load_from_registry("com.nonexistent/does-not-exist-12345")

    def test_verify_registry_server(self):
        """Fetch a server from the registry and run the full verification pipeline."""
        import httpx
        resp = httpx.get(
            "https://registry.modelcontextprotocol.io/v0.1/servers",
            params={"limit": 3, "version": "latest"},
            timeout=15,
        )
        resp.raise_for_status()
        servers = resp.json().get("servers", [])
        assert len(servers) > 0

        pipeline = Pipeline()
        verified_count = 0

        for entry in servers:
            name = entry["server"]["name"]
            try:
                tool = load_from_registry(name)
            except LoadError:
                continue

            score = pipeline.verify(tool)

            # Score should be a valid number
            assert 0 <= score.score <= 100
            # Verdict should be one of the valid values
            assert score.verdict in (Verdict.PASS, Verdict.WARN, Verdict.CAUTION, Verdict.FAIL)
            # Should have run both layers
            assert len(score.scan_results) == 2
            layers = [r.layer for r in score.scan_results]
            assert "static" in layers
            assert "behavioral" in layers

            verified_count += 1

        assert verified_count > 0, "Should have verified at least one server"


class TestRegistrySearch:
    """Test registry search via the loader."""

    def test_search_returns_results(self):
        """Search for a common term and verify results come back."""
        import httpx
        resp = httpx.get(
            "https://registry.modelcontextprotocol.io/v0.1/servers",
            params={"search": "github", "limit": 5, "version": "latest"},
            timeout=15,
        )
        resp.raise_for_status()
        servers = resp.json().get("servers", [])
        # "github" is common enough that there should be results
        assert len(servers) > 0


class TestLiveServerConnection:
    """Test connecting to a live MCP server and pulling tool definitions.

    These tests connect to actual MCP servers, so they may be flaky
    if the server is down.
    """

    def _find_server_with_remote(self):
        """Find a server in the registry that has a streamable-http remote."""
        import httpx
        resp = httpx.get(
            "https://registry.modelcontextprotocol.io/v0.1/servers",
            params={"limit": 50, "version": "latest"},
            timeout=15,
        )
        resp.raise_for_status()

        for entry in resp.json().get("servers", []):
            server = entry.get("server", {})
            for remote in server.get("remotes", []):
                if remote.get("type") in ("streamable-http",) and remote.get("url"):
                    return server["name"], remote["url"]
        return None, None

    def test_fetch_tools_from_live_server(self):
        """Connect to a live MCP server and verify we get tool definitions."""
        name, url = self._find_server_with_remote()
        if not url:
            pytest.skip("No server with streamable-http remote found in registry")

        tool = load_from_registry(name)

        # If we got tools from the live server, verify their structure
        if tool.tools:
            for t in tool.tools:
                assert "name" in t, f"Tool missing 'name' field: {t}"
            # Run verification on the live tools
            pipeline = Pipeline()
            score = pipeline.verify(tool)
            assert 0 <= score.score <= 100

    def test_verify_live_server_end_to_end(self):
        """Full end-to-end: registry → live server → verify → trust score."""
        name, url = self._find_server_with_remote()
        if not url:
            pytest.skip("No server with streamable-http remote found in registry")

        tool = load_from_registry(name)
        pipeline = Pipeline()
        score = pipeline.verify(tool)

        # We got a real score
        assert 0 <= score.score <= 100
        assert score.verdict in (Verdict.PASS, Verdict.WARN, Verdict.CAUTION, Verdict.FAIL)
        assert score.tool_name == name


class TestCLIEndToEnd:
    """Test the CLI commands work end-to-end."""

    def test_verify_from_registry_name(self):
        """Test that `magen verify <registry-name>` works via the loader."""
        import httpx
        resp = httpx.get(
            "https://registry.modelcontextprotocol.io/v0.1/servers",
            params={"limit": 1, "version": "latest"},
            timeout=15,
        )
        resp.raise_for_status()
        servers = resp.json().get("servers", [])
        assert len(servers) > 0

        name = servers[0]["server"]["name"]

        # This is what the CLI does internally
        from magen.loader import load_tool
        tool = load_tool(name)
        pipeline = Pipeline()
        score = pipeline.verify(tool)

        assert 0 <= score.score <= 100
        assert score.tool_name == name
