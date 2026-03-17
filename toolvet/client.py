"""HTTP client for the ToolVet verification registry.

This is what an autonomous agent would ``pip install toolvet`` and use to
check whether a tool has been verified before installing it.

Usage:
    from toolvet import ToolVetClient, tool_hash

    client = ToolVetClient("https://api.toolvet.dev")
    h = tool_hash(tool_def)
    att = client.check(h)
    if att and att["score"] >= 70:
        print("Tool verified")
"""

from __future__ import annotations

from typing import Any

import httpx

from toolvet.hash import tool_hash as compute_hash
from toolvet.verify import Attestation, Verifier


class ToolVetClient:
    """Lightweight HTTP client for the ToolVet registry API."""

    def __init__(self, base_url: str = "https://api.toolvet.dev", timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    # -- local helpers --------------------------------------------------------

    def hash_tool(self, tool_definition: dict[str, Any]) -> str:
        """Compute the content-addressed hash for a tool definition (local, no network)."""
        return compute_hash(tool_definition)

    # -- query endpoints ------------------------------------------------------

    def check(self, tool_hash: str) -> dict[str, Any] | None:
        """Query the registry for an attestation by hash.

        Returns the attestation dict if found, None if the hash is unknown.
        """
        resp = httpx.get(
            f"{self._base}/api/v1/registry/verify/{tool_hash}",
            timeout=self._timeout,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def lookup(self, tool_name: str) -> list[dict[str, Any]]:
        """Look up all attestations for a tool by name.

        Returns an empty list if no attestations exist.
        """
        resp = httpx.get(
            f"{self._base}/api/v1/registry/lookup/{tool_name}",
            timeout=self._timeout,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json()

    def fetch_public_key(self) -> bytes:
        """Download ToolVet's Ed25519 public key (PEM-encoded bytes)."""
        resp = httpx.get(
            f"{self._base}/api/v1/registry/public-key",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        pem_str = resp.json()["public_key"]
        return pem_str.encode("ascii")

    def submit(self, tool_definition: dict[str, Any]) -> dict[str, Any]:
        """Submit a tool definition for hashing (returns the hash for tracking).

        This is a convenience for tool developers who want to register their
        tool's hash before requesting verification.
        """
        resp = httpx.post(
            f"{self._base}/api/v1/registry/hash",
            json=tool_definition,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # -- offline verification -------------------------------------------------

    def verify_offline(self, attestation_dict: dict[str, Any], public_key_pem: bytes) -> bool:
        """Verify an attestation signature offline using a cached public key.

        Args:
            attestation_dict: An attestation as returned by ``check()`` or ``lookup()``.
            public_key_pem: PEM-encoded Ed25519 public key (from ``fetch_public_key()``).

        Returns:
            True if the signature is valid, False otherwise.
        """
        att = Attestation.from_dict(attestation_dict)
        verifier = Verifier.from_pem(public_key_pem)
        return att.verify_signature(verifier)
