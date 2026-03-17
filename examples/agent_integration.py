"""Verify a ToolVet attestation embedded in a tool's manifest."""

import json

from toolvet import verify_attestation, tool_hash, Attestation

# Tool developer ships their tool with an attestation baked in
tool_def = json.load(open("tool_manifest.json"))
attestation = tool_def.get("toolvet_attestation")
public_key = open("toolvet_public_key.pem", "rb").read()

# Agent verifies: hash matches, signature valid, not expired, score OK
expected_hash = tool_hash(tool_def)
if attestation["tool_hash"] != expected_hash:
    raise RuntimeError("Attestation hash doesn't match tool definition")
if not verify_attestation(attestation, public_key):
    raise RuntimeError("Invalid ToolVet signature")

att = Attestation.from_dict(attestation)
if att.is_expired():
    raise RuntimeError("Attestation expired — request re-verification")
if att.score < 70:
    raise RuntimeError(f"Tool scored {att.score}, below safety threshold")

print(f"Tool verified: {att.verdict} (score={att.score})")
