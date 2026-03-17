"""toolvet — Immune system for AI agents.

Public API:
    # SDK — attestation verification
    from toolvet import ToolVetClient, verify_attestation, Attestation, tool_hash

    # Scanning engine
    from toolvet.pipeline import Pipeline
    from toolvet.loader import load_tool
    from toolvet.models import TrustScore, Verdict
"""

__version__ = "1.0.0"

from toolvet.client import ToolVetClient
from toolvet.verify import verify_attestation, Attestation
from toolvet.hash import tool_hash

__all__ = ["ToolVetClient", "verify_attestation", "Attestation", "tool_hash"]
