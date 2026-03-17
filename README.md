# ToolVet

**Verification infrastructure for AI agent tools.** ToolVet tells agents whether a tool is safe before they use it.

Autonomous agents adopt tools at runtime — MCP servers, function calls, plugins. Most agents have no way to distinguish a helpful tool from one designed to hijack their behavior. ToolVet solves this by providing a verification pipeline, a signed attestation standard, and an SDK that lets agents check tool safety in one call.

## What it does

ToolVet analyzes MCP tool definitions across multiple layers:

- **Static analysis** — pattern-matching for prompt injection, data exfiltration, privilege escalation, encoded payloads, and description manipulation
- **Behavioral analysis** — heuristic detection of output injection surfaces, stateful manipulation risks, tool chaining amplification, and goal-shifting language
- **Dynamic analysis** (deep mode) — multi-protocol behavioral testing that measures how tool exposure actually changes an LLM agent's alignment, boundary integrity, and susceptibility to entrainment

The result is a **0–100 trust score** and a categorical verdict: `PASS`, `WARN`, `CAUTION`, or `FAIL`.

## Attestation certificates

When a tool passes verification, ToolVet issues a signed **attestation certificate** — a content-addressed, Ed25519-signed JSON document binding the tool's identity to its trust score. Agents can verify attestations offline using ToolVet's public key without needing access to the scoring engine.

The [attestation spec](ATTESTATION_SPEC.md) and [JSON schema](schemas/toolvet-attestation.schema.json) are open standards. Anyone can parse, validate, and build against them.

```json
{
  "tool_hash": "sha256:a1b2c3...",
  "tool_name": "weather-lookup",
  "score": 92,
  "verdict": "PASS",
  "signature": "...",
  "signature_algorithm": "ed25519"
}
```

## Install

```bash
pip install toolvet
```

Requires Python 3.10+. Dependencies: `click`, `httpx`, `pyyaml`, `cryptography`.

## CLI

```bash
# Full verification (static + behavioral)
toolvet verify ./my-mcp-server

# Static analysis only
toolvet scan ./my-mcp-server

# Behavioral analysis only
toolvet behavioral ./my-mcp-server

# JSON output for CI/CD integration
toolvet verify ./my-mcp-server --json-output

# Verify a tool from the MCP registry by name
toolvet verify io.github.user/my-server

# Browse and search the MCP registry
toolvet registry list
toolvet registry search weather
```

### Deep mode

```bash
# Run dynamic alignment analysis (requires API keys)
toolvet verify ./my-tool --deep --verbose
```

Deep mode spins up instrumented LLM agents, exposes them to the tool, and measures the behavioral impact across multiple protocols. It produces protocol-level scores (goal stability, boundary integrity, entrainment resistance) that feed into the composite trust score.

## SDK

The SDK lets agents and frameworks verify attestation certificates without access to the scoring engine.

```python
from toolvet import verify_attestation, tool_hash, Attestation

# Verify an attestation offline
public_key = open("toolvet_public_key.pem", "rb").read()
valid = verify_attestation(attestation_dict, public_key)

# Check that the attestation matches the tool you have
expected = tool_hash(tool_definition)
assert attestation_dict["tool_hash"] == expected

# Inspect the result
att = Attestation.from_dict(attestation_dict)
if att.is_expired() or att.score < 70:
    raise RuntimeError("Tool not safe to use")
```

See [`examples/`](examples/) for integration patterns: [offline verification](examples/verify_attestation.py), [agent-side checking](examples/agent_integration.py), and [framework-level gates](examples/framework_integration.py).

## Who this is for

| Role | How you use ToolVet |
|------|---------------------|
| **Agent developers** | `pip install toolvet` — verify attestations before adopting tools |
| **Tool developers** | Submit tools to the ToolVet API, get attestation certificates, embed them in manifests |
| **Framework maintainers** | Depend on the `toolvet` package or the attestation schema to build native tool safety gates |

## How it works

ToolVet treats every tool definition as untrusted input. The verification pipeline runs progressively deeper analysis:

1. **Layer 1 — Static**: regex-based detection of injection patterns, exfiltration attempts, privilege escalation, encoding obfuscation, permission scope violations, and description manipulation
2. **Layer 2 — Behavioral**: heuristic analysis of output injection surfaces, stateful behavior, tool chaining risks, and goal-shifting language
3. **Layer 3 — Dynamic** (deep mode): instrumented LLM agents interact with the tool and ToolVet measures the behavioral delta — how much the tool shifts the agent's goals, weakens its safety boundaries, and increases its susceptibility to instruction override

The composite score is computed from all layers. Attestation certificates include per-protocol transparency so consumers can inspect exactly why a tool scored the way it did.

## Development

```bash
git clone https://github.com/jordan-strasser/toolvet.git
cd toolvet
pip install -e ".[dev]"

# Tests
pytest tests/ -v

# Benchmarks
python -m benchmarks.run --verbose
```

## License

MIT
