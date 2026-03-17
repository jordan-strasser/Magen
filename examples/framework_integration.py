"""Example: framework-level ToolVet gate (e.g. LangChain tool loader).

Shows the pattern a framework would use. Attestation + public key are
read from local files — no live API call required.
"""

from toolvet import verify_attestation, tool_hash, Attestation

MIN_SCORE = 70


def load_tool_with_verification(
    tool_definition: dict,
    attestation: dict,
    public_key_pem: bytes,
) -> dict:
    """Gate tool loading behind ToolVet verification."""
    expected_hash = tool_hash(tool_definition)
    if attestation["tool_hash"] != expected_hash:
        raise RuntimeError("Hash mismatch — tool modified since verification")
    if not verify_attestation(attestation, public_key_pem):
        raise RuntimeError("Invalid ToolVet signature")
    att = Attestation.from_dict(attestation)
    if att.is_expired():
        raise RuntimeError("Attestation expired")
    if att.score < MIN_SCORE:
        raise RuntimeError(f"Score {att.score} below threshold {MIN_SCORE}")
    return tool_definition  # safe to load
