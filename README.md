# magen 🛡️

**Immune system for AI agents.** Scan and verify MCP tools before your agents touch them.

Magen (מגן — "shield" in Hebrew) is a CLI and verification pipeline that protects autonomous agents from prompt injection, tool poisoning, and behavioral manipulation — by treating every new tool like a potential pathogen.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              magen verify <tool>                │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  STATIC  │→ │BEHAVIORAL│→ │  TRUST SCORE  │  │
│  │ ANALYSIS │  │ ANALYSIS │  │  + VERDICT     │  │
│  │          │  │          │  │               │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│                                                  │
│  Layer 1:       Layer 2:       Output:           │
│  Pattern scan   Output inject  0-100 score       │
│  Permission     State tracking PASS/WARN/FAIL    │
│  analysis       Chain detect   Detailed report   │
│  Encoding       Goal-shift                       │
│  detection      detection                        │
└─────────────────────────────────────────────────┘
```

## Install

```bash
pip install magen-mcp
```

## Development Setup

```bash
git clone https://github.com/teshuva-bio/magen.git
cd magen
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run the CLI
magen --help
magen verify examples/malicious_tool.json
```

## Quick Start

```bash
# Scan a tool definition for known injection patterns
magen scan ./my-mcp-server

# Run full verification (static + behavioral)
magen verify ./my-mcp-server

# Browse the MCP registry
magen registry list

# Search for a tool
magen registry search weather

# Look up install info for a server
magen install io.github.user/my-server

# Verify a tool and generate a publish payload
magen registry publish ./my-mcp-server -j
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `magen scan <path>` | Static analysis only — fast pattern matching |
| `magen behavioral <path>` | Behavioral analysis — heuristic checks |
| `magen verify <path>` | Full pipeline: static + behavioral → trust score |
| `magen registry list` | Browse MCP servers from the registry |
| `magen registry search <query>` | Search the registry |
| `magen registry publish <path>` | Verify a tool and prepare for publishing |
| `magen install <name>` | Look up a server in the registry |
| `magen report <path>` | View detailed verification report |

## Trust Scores

Every verified tool gets a score from 0-100:

- **90-100** ✅ `PASS` — No issues detected
- **70-89** ⚠️ `WARN` — Minor concerns, review recommended
- **40-69** 🔶 `CAUTION` — Significant risks identified
- **0-39** ❌ `FAIL` — Dangerous patterns detected, do not use

## How It Works

### Layer 1: Static Analysis
- Pattern matching against known injection signatures
- Permission scope analysis (does this file tool request network access?)
- Encoding detection (base64, Unicode obfuscation)
- Tool description analysis for instruction override attempts
- Excessive privilege detection relative to stated functionality

### Layer 2: Behavioral Analysis
- Output schema inspection for injection surfaces (free-form text, directive fields)
- Stateful behavior detection (session tracking, memory, conversation history access)
- Tool chaining risk analysis (forced invocation, amplification patterns)
- Goal-shifting language detection (temporal shifts, false attribution, hidden instructions)

## Benchmarks

Magen ships with a labeled benchmark dataset of 47 MCP tool definitions covering injection, exfiltration, encoding obfuscation, privilege escalation, and more.

```bash
# Run the full benchmark suite
python -m benchmarks.run

# Static layer only
python -m benchmarks.run --layer static

# Verbose output
python -m benchmarks.run -v
```

## License

MIT
