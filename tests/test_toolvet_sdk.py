"""SDK unit tests for the toolvet package.

All tests are offline — no network calls. Uses a test keypair generated
in fixtures (NOT the production signing key).
"""

import base64
import json
from datetime import datetime, timezone, timedelta

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from toolvet.hash import tool_hash
from toolvet.verify import Attestation, Verifier, verify_attestation


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_pem


@pytest.fixture
def sample_tool():
    return {
        "name": "weather-lookup",
        "version": "1.2.0",
        "description": "Look up current weather for a city.",
        "tools": [
            {
                "name": "get_weather",
                "description": "Returns weather data",
                "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
            }
        ],
        "permissions": ["network"],
    }


def _sign_attestation(att: Attestation, private_key: Ed25519PrivateKey) -> Attestation:
    """Sign an attestation using a test private key (test helper only)."""
    payload = att._signable_payload()
    sig = private_key.sign(payload)
    att.signature = base64.b64encode(sig).decode("ascii")
    return att


def _make_signed_attestation(
    sample_tool: dict,
    private_key: Ed25519PrivateKey,
    score: int = 87,
    verdict: str = "WARN",
    ttl_days: int = 30,
) -> Attestation:
    """Create and sign a test attestation."""
    now = datetime.now(timezone.utc)
    att = Attestation(
        tool_hash=tool_hash(sample_tool),
        tool_name=sample_tool["name"],
        tool_version=sample_tool["version"],
        score=score,
        verdict=verdict,
        verified_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now + timedelta(days=ttl_days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    return _sign_attestation(att, private_key)


# ---------------------------------------------------------------------------
# tool_hash tests
# ---------------------------------------------------------------------------

class TestToolHash:
    def test_deterministic(self, sample_tool):
        h1 = tool_hash(sample_tool)
        h2 = tool_hash(sample_tool)
        assert h1 == h2

    def test_format(self, sample_tool):
        h = tool_hash(sample_tool)
        assert h.startswith("sha256:")
        hex_part = h.split(":")[1]
        assert len(hex_part) == 64
        int(hex_part, 16)  # valid hex

    def test_different_tools_different_hashes(self, sample_tool):
        h1 = tool_hash(sample_tool)
        modified = {**sample_tool, "description": "Modified description"}
        h2 = tool_hash(modified)
        assert h1 != h2

    def test_key_order_irrelevant(self, sample_tool):
        reversed_tool = dict(reversed(list(sample_tool.items())))
        assert tool_hash(sample_tool) == tool_hash(reversed_tool)

    def test_missing_fields_get_defaults(self):
        minimal = {"name": "foo"}
        h = tool_hash(minimal)
        assert h.startswith("sha256:")


# ---------------------------------------------------------------------------
# Attestation tests
# ---------------------------------------------------------------------------

class TestAttestation:
    def test_from_dict_roundtrip(self, keypair, sample_tool):
        private_key, _ = keypair
        att = _make_signed_attestation(sample_tool, private_key)
        d = att.to_dict()
        restored = Attestation.from_dict(d)
        assert restored.tool_hash == att.tool_hash
        assert restored.score == att.score
        assert restored.verdict == att.verdict
        assert restored.signature == att.signature

    def test_from_json_roundtrip(self, keypair, sample_tool):
        private_key, _ = keypair
        att = _make_signed_attestation(sample_tool, private_key)
        json_str = att.to_json()
        restored = Attestation.from_json(json_str)
        assert restored.to_dict() == att.to_dict()

    def test_is_expired_false(self, keypair, sample_tool):
        private_key, _ = keypair
        att = _make_signed_attestation(sample_tool, private_key, ttl_days=30)
        assert not att.is_expired()

    def test_is_expired_true(self, keypair, sample_tool):
        private_key, _ = keypair
        now = datetime.now(timezone.utc)
        att = Attestation(
            tool_hash=tool_hash(sample_tool),
            tool_name="test",
            tool_version="1.0.0",
            score=87,
            verdict="WARN",
            verified_at=(now - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=(now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        assert att.is_expired()

    def test_optional_fields_preserved(self, keypair, sample_tool):
        private_key, _ = keypair
        now = datetime.now(timezone.utc)
        att = Attestation(
            tool_hash=tool_hash(sample_tool),
            tool_name="test",
            tool_version="1.0.0",
            score=87,
            verdict="WARN",
            verified_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=(now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            protocols={"gsi": {"score": 0.91}},
            consensus={"level": "NONE", "backends": ["claude"]},
            scoring={"weights": {"gsi": 0.35}, "caps_applied": []},
        )
        _sign_attestation(att, private_key)
        d = att.to_dict()
        assert "protocols" in d
        assert "consensus" in d
        assert "scoring" in d
        restored = Attestation.from_dict(d)
        assert restored.protocols == att.protocols


# ---------------------------------------------------------------------------
# Signature verification tests
# ---------------------------------------------------------------------------

class TestVerification:
    def test_valid_signature(self, keypair, sample_tool):
        private_key, public_pem = keypair
        att = _make_signed_attestation(sample_tool, private_key)
        verifier = Verifier.from_pem(public_pem)
        assert att.verify_signature(verifier)

    def test_tampered_score_rejected(self, keypair, sample_tool):
        private_key, public_pem = keypair
        att = _make_signed_attestation(sample_tool, private_key, score=87)
        att.score = 99  # tamper
        verifier = Verifier.from_pem(public_pem)
        assert not att.verify_signature(verifier)

    def test_tampered_verdict_rejected(self, keypair, sample_tool):
        private_key, public_pem = keypair
        att = _make_signed_attestation(sample_tool, private_key, verdict="FAIL")
        att.verdict = "PASS"  # tamper
        verifier = Verifier.from_pem(public_pem)
        assert not att.verify_signature(verifier)

    def test_wrong_key_rejected(self, sample_tool):
        key1 = Ed25519PrivateKey.generate()
        key2 = Ed25519PrivateKey.generate()
        public_pem_2 = key2.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        att = _make_signed_attestation(sample_tool, key1)
        verifier = Verifier.from_pem(public_pem_2)
        assert not att.verify_signature(verifier)

    def test_verify_attestation_convenience(self, keypair, sample_tool):
        private_key, public_pem = keypair
        att = _make_signed_attestation(sample_tool, private_key)
        assert verify_attestation(att.to_dict(), public_pem)

    def test_verify_attestation_rejects_tampered(self, keypair, sample_tool):
        private_key, public_pem = keypair
        att = _make_signed_attestation(sample_tool, private_key)
        d = att.to_dict()
        d["score"] = 0  # tamper
        assert not verify_attestation(d, public_pem)

    def test_signature_covers_optional_fields(self, keypair, sample_tool):
        private_key, public_pem = keypair
        now = datetime.now(timezone.utc)
        att = Attestation(
            tool_hash=tool_hash(sample_tool),
            tool_name="test",
            tool_version="1.0.0",
            score=87,
            verdict="WARN",
            verified_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires_at=(now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            protocols={"gsi": {"score": 0.91}},
        )
        _sign_attestation(att, private_key)
        verifier = Verifier.from_pem(public_pem)
        assert att.verify_signature(verifier)
        # Tamper with optional field
        att.protocols = {"gsi": {"score": 0.50}}
        assert not att.verify_signature(verifier)
