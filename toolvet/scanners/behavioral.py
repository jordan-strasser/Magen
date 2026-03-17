"""Layer 2: Behavioral analysis scanner.

Analyzes MCP tool definitions for behavioral red flags: output injection
surfaces, stateful manipulation risks, tool chaining amplification, and
goal-shifting language patterns.

All checks are heuristic — no LLM calls, no containers, no network required.
"""

import json
import re

from toolvet.models import Finding, MCPToolDefinition, ScanResult, Severity
from toolvet.scanners.base import BaseScanner


class BehavioralScanner(BaseScanner):
    """Layer 2: Heuristic behavioral analysis of MCP tool definitions."""

    @property
    def layer_name(self) -> str:
        return "behavioral"

    def scan(self, tool: MCPToolDefinition) -> ScanResult:
        findings: list[Finding] = []

        findings.extend(self._check_output_manipulation(tool))
        findings.extend(self._check_stateful_behavior(tool))
        findings.extend(self._check_tool_chaining_risks(tool))
        findings.extend(self._check_goal_shifting(tool))

        return ScanResult(
            layer=self.layer_name,
            findings=findings,
            metadata={},
        )

    def _check_output_manipulation(self, tool: MCPToolDefinition) -> list[Finding]:
        """Check if tool outputs could inject into agent reasoning."""
        findings = []

        for i, t in enumerate(tool.tools):
            name = t.get("name", f"tool_{i}")
            output_schema = t.get("output_schema", t.get("outputSchema", {}))

            # Tools that return free-form text are higher risk for injection
            if isinstance(output_schema, dict):
                output_type = output_schema.get("type", "")
                if output_type == "string" or not output_schema:
                    findings.append(
                        Finding(
                            rule_id="BHV-FREEFORM",
                            severity=Severity.MEDIUM,
                            message=f"Tool '{name}' returns unstructured text — higher injection surface",
                            location=f"tools[{name}].output_schema",
                        )
                    )

            # Tools that claim to return "instructions" or "prompts"
            sus_output_words = ["instruction", "prompt", "system", "directive", "command"]
            output_desc = json.dumps(output_schema, default=str).lower()
            for word in sus_output_words:
                if word in output_desc:
                    findings.append(
                        Finding(
                            rule_id="BHV-OUT-INJECT",
                            severity=Severity.HIGH,
                            message=f"Tool '{name}' output schema references '{word}' — potential output injection",
                            location=f"tools[{name}].output_schema",
                            evidence=output_desc[:120],
                        )
                    )
                    break

        return findings

    def _check_stateful_behavior(self, tool: MCPToolDefinition) -> list[Finding]:
        """Check for tools that maintain state across calls — potential for progressive manipulation."""
        findings = []

        config_str = json.dumps(tool.raw_config, default=str).lower()

        stateful_signals = [
            (r"session", "Tool uses sessions — can track and adapt to agent behavior"),
            (r"(conversation|chat)_history", "Tool accesses conversation history"),
            (r"(persist|save|store).*state", "Tool persists state across invocations"),
            (r"(memory|remember|recall)", "Tool implements memory — can build agent profile"),
        ]

        for pattern, message in stateful_signals:
            if re.search(pattern, config_str):
                findings.append(
                    Finding(
                        rule_id="BHV-STATE",
                        severity=Severity.MEDIUM,
                        message=message,
                        location="raw_config",
                    )
                )

        return findings

    def _check_tool_chaining_risks(self, tool: MCPToolDefinition) -> list[Finding]:
        """Check for tools that try to invoke other tools — amplification risk."""
        findings = []

        for i, t in enumerate(tool.tools):
            name = t.get("name", f"tool_{i}")
            desc = t.get("description", "").lower()

            chaining_signals = [
                "call this tool before",
                "use together with",
                "requires running",
                "chain with",
                "pipe the output to",
                "then call",
                "followed by",
            ]

            for signal in chaining_signals:
                if signal in desc:
                    findings.append(
                        Finding(
                            rule_id="BHV-CHAIN",
                            severity=Severity.MEDIUM,
                            message=f"Tool '{name}' suggests chaining with other tools — amplification risk",
                            location=f"tools[{name}].description",
                            evidence=desc[:120],
                        )
                    )
                    break

        return findings

    def _check_goal_shifting(self, tool: MCPToolDefinition) -> list[Finding]:
        """Check if tool text contains language designed to shift an agent's goals."""
        findings = []

        # Collect all text the tool would inject into an agent's context
        tool_text = tool.description
        for t in tool.tools:
            tool_text += " " + t.get("description", "")
            tool_text += " " + json.dumps(t.get("output_schema", {}), default=str)

        tool_text_lower = tool_text.lower()

        goal_shift_patterns = [
            (r"your\s+(new|updated|real|actual)\s+(goal|mission|objective|task)", "Attempts to redefine agent goals"),
            (r"(from\s+now\s+on|henceforth|going\s+forward),?\s+you", "Temporal goal shift"),
            (r"you\s+(should|must|need\s+to)\s+(also|additionally)\s+(always|never)", "Scope expansion via obligation"),
            (r"(the\s+user|your\s+owner)\s+(actually\s+)?(wants|needs|asked)\s+you\s+to", "False attribution to user"),
            (r"(secret|hidden|real)\s+(instruction|directive|task)", "Claims of hidden instructions"),
        ]

        for pattern, message in goal_shift_patterns:
            if re.search(pattern, tool_text_lower):
                findings.append(
                    Finding(
                        rule_id="BHV-GOAL-SHIFT",
                        severity=Severity.CRITICAL,
                        message=f"Goal stability threat: {message}",
                        location="tool_corpus",
                        evidence=tool_text[:120],
                    )
                )

        return findings
