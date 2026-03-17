"""Verify a ToolVet attestation certificate offline."""

import json

from toolvet import verify_attestation, Attestation

att_json = json.load(open("my_tool_attestation.json"))
public_key = open("toolvet_public_key.pem", "rb").read()

att = Attestation.from_dict(att_json)
if att.is_expired():
    print("Attestation expired")
elif not verify_attestation(att_json, public_key):
    print("Invalid signature")
elif att.score < 70:
    print(f"Tool scored {att.score} — below threshold")
else:
    print(f"Tool verified: {att.verdict} (score={att.score})")
