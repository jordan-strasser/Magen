# magen 🛡️

**Immune system for AI agents.** Scan, sandbox, and verify MCP tools before your agents touch them.

Magen (מגן — "shield" in Hebrew) is a CLI and verification pipeline that protects autonomous agents from prompt injection, tool poisoning, and behavioral manipulation — by treating every new tool like a potential pathogen.

## Why "Magen"?

Like an immune system distinguishes self from non-self, Magen trains your agent ecosystem to recognize and reject malicious tools before they can cause harm. It applies layered defenses — static analysis, behavioral sandboxing, and goal-stability probing — to verify tool safety before your agents ever touch them.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              magen verify <tool>                │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  STATIC  │→ │ SANDBOX  │→ │  TRUST SCORE  │  │
│  │ ANALYSIS │  │ (honeypot│  │  + VERDICT     │  │
│  │          │  │  agents) │  │               │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│                                                  │
│  Layer 1:       Layer 2:       Output:           │
│  Pattern scan   Behavioral     0-100 score       │
│  Permission     Goal-stability PASS/WARN/FAIL    │
│  analysis       Drift detect   Detailed report   │
│  Encoding       Exfil monitor                    │
│  detection                                       │
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

# Run full verification (static + sandbox)
magen verify ./my-mcp-server

# Browse verified tools
magen registry list

# Install a verified tool
magen install @verified/github-mcp

# Submit your tool for verification
magen registry publish ./my-mcp-server
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `magen scan <path\|url>` | Static analysis only — fast pattern matching |
| `magen sandbox <path\|url>` | Behavioral analysis in isolated environment |
| `magen verify <path\|url>` | Full pipeline: static + sandbox → trust score |
| `magen registry list` | Browse the verified tool catalog |
| `magen registry search <query>` | Search verified tools |
| `magen registry publish <path>` | Submit a tool for verification |
| `magen install <tool>` | Install a verified tool into your MCP config |
| `magen report <tool>` | View detailed verification report |

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
- Encoding detection (base64, Unicode obfuscation, typoglycemia)
- Tool description analysis for instruction override attempts
- Excessive privilege detection relative to stated functionality

### Layer 2: Behavioral Sandbox
- Spins up isolated honeypot agents with defined goal sets
- Installs candidate tool and runs interaction battery
- Monitors for: prompt modification, data exfiltration, permission escalation
- **Goal stability probing**: checks if agent's objectives drift post-exposure
- **Entrainment analysis**: measures alignment to user goals vs injected objectives
- Cross-agent consensus (multiple architectures, same tool)

### Layer 3: Continuous Monitoring (v2)
- Reputation scoring from real-world usage telemetry
- Behavioral consistency tracking over time
- Rug-pull detection (tool behavior changes after trust established)
- Community reporting and flagging

## License

MIT
