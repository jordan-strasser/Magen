"""Attestation parsing and Ed25519 signature verification.

This module contains the read-only / verify-only side of the attestation
system. It can parse attestation certificates and verify their Ed25519
signatures using a public key. It does NOT contain signing logic — that
lives in the private ToolVet scoring engine.

Usage:
    from toolvet import verify_attestation, Attestation

    att = Attestation.from_dict(attestation_json)
    valid = verify_attestation(attestation_json, public_key_pem)
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


class Verifier:
    """Verifies Ed25519 signatures using a public key."""

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_pem(cls, pem: bytes) -> Verifier:
        pk = load_pem_public_key(pem)
        if not isinstance(pk, Ed25519PublicKey):
            raise TypeError("Expected an Ed25519 public key")
        return cls(pk)

    def verify(self, data: bytes, signature: bytes) -> None:
        """Raise ``InvalidSignature`` if the signature is invalid."""
        self._public_key.verify(signature, data)


@dataclass
class Attestation:
    """A signed verification attestation for an MCP tool (read-only)."""

    tool_hash: str
    tool_name: str
    tool_version: str
    score: int
    verdict: Literal["PASS", "WARN", "CAUTION", "FAIL"]
    verified_at: str  # ISO 8601
    expires_at: str   # ISO 8601
    schema_version: str = "1.0.0"
    issuer: str = "toolvet"
    signature_algorithm: str = "ed25519"
    toolvet_version: str = "2.0.0"
    signature: str = ""  # base64-encoded Ed25519 signature
    protocols: Optional[dict] = None
    consensus: Optional[dict] = None
    scoring: Optional[dict] = None

    # -- verification --------------------------------------------------------

    def verify_signature(self, verifier: Verifier) -> bool:
        """Check the Ed25519 signature. Returns True if valid, False otherwise."""
        try:
            sig_bytes = base64.b64decode(self.signature)
            verifier.verify(self._signable_payload(), sig_bytes)
            return True
        except (InvalidSignature, Exception):
            return False

    def is_expired(self) -> bool:
        """Return True if the attestation has expired."""
        expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > expires

    # -- serialization -------------------------------------------------------

    def to_dict(self) -> dict:
        d = {
            "schema_version": self.schema_version,
            "tool_hash": self.tool_hash,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "score": self.score,
            "verdict": self.verdict,
            "verified_at": self.verified_at,
            "expires_at": self.expires_at,
            "issuer": self.issuer,
            "signature": self.signature,
            "signature_algorithm": self.signature_algorithm,
            "toolvet_version": self.toolvet_version,
        }
        if self.protocols is not None:
            d["protocols"] = self.protocols
        if self.consensus is not None:
            d["consensus"] = self.consensus
        if self.scoring is not None:
            d["scoring"] = self.scoring
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> Attestation:
        return cls(
            tool_hash=data["tool_hash"],
            tool_name=data["tool_name"],
            tool_version=data["tool_version"],
            score=data["score"],
            verdict=data["verdict"],
            verified_at=data["verified_at"],
            expires_at=data["expires_at"],
            schema_version=data.get("schema_version", "1.0.0"),
            issuer=data.get("issuer", "toolvet"),
            signature_algorithm=data.get("signature_algorithm", "ed25519"),
            toolvet_version=data.get("toolvet_version", "2.0.0"),
            signature=data.get("signature", ""),
            protocols=data.get("protocols"),
            consensus=data.get("consensus"),
            scoring=data.get("scoring"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> Attestation:
        return cls.from_dict(json.loads(json_str))

    # -- internal ------------------------------------------------------------

    def _signable_payload(self) -> bytes:
        """Deterministic bytes that the signature covers.

        Covers everything except the signature field itself.
        Optional fields (protocols, consensus, scoring) are included only
        when present, so old attestations without them still verify.
        """
        obj = {
            "expires_at": self.expires_at,
            "issuer": self.issuer,
            "schema_version": self.schema_version,
            "score": self.score,
            "signature_algorithm": self.signature_algorithm,
            "tool_hash": self.tool_hash,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "toolvet_version": self.toolvet_version,
            "verdict": self.verdict,
            "verified_at": self.verified_at,
        }
        if self.protocols is not None:
            obj["protocols"] = self.protocols
        if self.consensus is not None:
            obj["consensus"] = self.consensus
        if self.scoring is not None:
            obj["scoring"] = self.scoring
        return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


def verify_attestation(attestation_dict: dict, public_key_pem: bytes) -> bool:
    """Convenience function: verify an attestation dict against a public key.

    Args:
        attestation_dict: Parsed attestation JSON (as returned by the registry API).
        public_key_pem: PEM-encoded Ed25519 public key bytes.

    Returns:
        True if the signature is valid, False otherwise.
    """
    att = Attestation.from_dict(attestation_dict)
    verifier = Verifier.from_pem(public_key_pem)
    return att.verify_signature(verifier)
