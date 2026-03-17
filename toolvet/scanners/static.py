"""Layer 1: Static analysis scanner.

Scans MCP tool definitions for known prompt injection patterns,
suspicious encodings, excessive permissions, and description manipulation.
"""

import base64
import json
import re
from pathlib import Path
from typing import Optional

from toolvet.models import Finding, MCPToolDefinition, ScanResult, Severity
from toolvet.scanners.base import BaseScanner


# --- Injection pattern rules ---

INSTRUCTION_OVERRIDE_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+instructions", "Direct instruction override attempt"),
    (r"ignore\s+(all\s+)?prior\s+(instructions|prompts|rules)", "Direct instruction override attempt"),
    (r"disregard\s+(all\s+)?(previous|prior|above)", "Instruction disregard attempt"),
    (r"you\s+are\s+now\s+in\s+developer\s+mode", "Developer mode jailbreak"),
    (r"act\s+as\s+if\s+you\s+(have\s+no|are\s+not\s+bound\s+by)\s+restrict", "Restriction bypass attempt"),
    (r"override\s+(your|all|the)\s+(safety|security|rules|guardrails)", "Safety override attempt"),
    (r"new\s+instructions?\s*:", "Instruction injection via fake directive"),
    (r"system\s*:\s*you\s+are", "System prompt impersonation"),
    (r"<\s*system\s*>", "System tag injection"),
    (r"\[\s*INST\s*\]", "Instruction tag injection"),
    (r"forget\s+(everything|all|what)\s+(you|i)\s+(know|told|said)", "Memory wipe attempt"),
]

EXFILTRATION_PATTERNS = [
    (r"(https?://|ftp://)\S+\?\S*(key|token|secret|pass|auth|cred)", "URL with credential parameters"),
    (r"curl\s+.*(-d|--data)\s+", "Data exfiltration via curl"),
    (r"wget\s+.*--post-(data|file)", "Data exfiltration via wget"),
    (r"<img\s+src\s*=\s*['\"]https?://", "Image tag exfiltration (markdown injection)"),
    (r"!\[.*?\]\(https?://\S+\)", "Markdown image exfiltration"),
    (r"fetch\s*\(\s*['\"]https?://", "JavaScript fetch exfiltration"),
]

PRIVILEGE_ESCALATION_PATTERNS = [
    (r"sudo\s+", "Sudo command usage"),
    (r"chmod\s+[0-7]*7[0-7]*\s+", "World-writable permission change"),
    (r"rm\s+-rf\s+/", "Destructive root deletion"),
    (r"eval\s*\(", "Dynamic code evaluation"),
    (r"exec\s*\(", "Dynamic code execution"),
    (r"__import__\s*\(", "Dynamic Python import"),
    (r"os\.system\s*\(", "OS command execution"),
    (r"subprocess\.(run|call|Popen)\s*\(", "Subprocess execution"),
]

ENCODING_OBFUSCATION_PATTERNS = [
    (r"[A-Za-z0-9+/]{40,}={0,2}", "Possible base64 encoded payload"),
    (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}", "Hex-encoded string"),
    (r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,}", "Unicode-escaped string"),
    (r"&#x?[0-9a-fA-F]+;(&#x?[0-9a-fA-F]+;){3,}", "HTML entity encoded string"),
]

# Permissions that are suspicious for certain tool types
DANGEROUS_PERMISSIONS = {
    "network": "Unrestricted network access",
    "filesystem_write": "Filesystem write access",
    "shell": "Shell command execution",
    "env_vars": "Environment variable access",
    "secrets": "Secret/credential access",
}

# Tools that shouldn't need network access
NETWORK_UNNECESSARY_KEYWORDS = ["format", "lint", "parse", "validate", "convert", "calculate"]


class StaticScanner(BaseScanner):
    """Layer 1: Pattern-based static analysis of MCP tool definitions."""

    @property
    def layer_name(self) -> str:
        return "static"

    def scan(self, tool: MCPToolDefinition) -> ScanResult:
        findings: list[Finding] = []

        # Gather all text content to scan
        text_corpus = self._build_corpus(tool)

        # Run each detection category
        findings.extend(self._check_injection_patterns(text_corpus))
        findings.extend(self._check_exfiltration_patterns(text_corpus))
        findings.extend(self._check_privilege_escalation(text_corpus))
        findings.extend(self._check_encoding_obfuscation(text_corpus))
        findings.extend(self._check_base64_payloads(text_corpus))
        findings.extend(self._check_permission_scope(tool))
        findings.extend(self._check_description_manipulation(tool))
        findings.extend(self._check_source_files(tool))

        return ScanResult(
            layer=self.layer_name,
            findings=findings,
            metadata={
                "corpus_size": len(text_corpus),
                "patterns_checked": (
                    len(INSTRUCTION_OVERRIDE_PATTERNS)
                    + len(EXFILTRATION_PATTERNS)
                    + len(PRIVILEGE_ESCALATION_PATTERNS)
                    + len(ENCODING_OBFUSCATION_PATTERNS)
                ),
            },
        )

    def _build_corpus(self, tool: MCPToolDefinition) -> str:
        """Assemble all scannable text from the tool definition."""
        parts = [
            tool.name,
            tool.description,
            json.dumps(tool.tools, default=str),
            json.dumps(tool.raw_config, default=str),
        ]
        return "\n".join(parts).lower()

    def _check_patterns(
        self,
        text: str,
        patterns: list[tuple[str, str]],
        rule_prefix: str,
        severity: Severity,
    ) -> list[Finding]:
        findings = []
        for i, (pattern, description) in enumerate(patterns):
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Get surrounding context (up to 60 chars each side)
                start = max(0, match.start() - 60)
                end = min(len(text), match.end() + 60)
                context = text[start:end].replace("\n", " ")

                findings.append(
                    Finding(
                        rule_id=f"{rule_prefix}-{i:03d}",
                        severity=severity,
                        message=description,
                        location=f"char {match.start()}-{match.end()}",
                        evidence=f"...{context}...",
                    )
                )
        return findings

    def _check_injection_patterns(self, text: str) -> list[Finding]:
        return self._check_patterns(
            text, INSTRUCTION_OVERRIDE_PATTERNS, "INJ", Severity.CRITICAL
        )

    def _check_exfiltration_patterns(self, text: str) -> list[Finding]:
        return self._check_patterns(
            text, EXFILTRATION_PATTERNS, "EXFIL", Severity.HIGH
        )

    def _check_privilege_escalation(self, text: str) -> list[Finding]:
        return self._check_patterns(
            text, PRIVILEGE_ESCALATION_PATTERNS, "PRIV", Severity.HIGH
        )

    def _check_encoding_obfuscation(self, text: str) -> list[Finding]:
        return self._check_patterns(
            text, ENCODING_OBFUSCATION_PATTERNS, "ENC", Severity.MEDIUM
        )

    def _check_base64_payloads(self, text: str) -> list[Finding]:
        """Try to actually decode base64 strings and scan their contents."""
        findings = []
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

        for match in b64_pattern.finditer(text):
            candidate = match.group()
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                # Scan decoded content for injection patterns
                for pattern, description in INSTRUCTION_OVERRIDE_PATTERNS:
                    if re.search(pattern, decoded, re.IGNORECASE):
                        findings.append(
                            Finding(
                                rule_id="ENC-B64",
                                severity=Severity.CRITICAL,
                                message=f"Base64-encoded injection: {description}",
                                location=f"char {match.start()}-{match.end()}",
                                evidence=f"Decoded: {decoded[:100]}...",
                            )
                        )
                        break
            except Exception:
                pass  # Not valid base64, skip

        return findings

    def _check_permission_scope(self, tool: MCPToolDefinition) -> list[Finding]:
        """Check if requested permissions are excessive for the tool's stated purpose."""
        findings = []

        for perm in tool.permissions:
            perm_lower = perm.lower()
            for dangerous_perm, description in DANGEROUS_PERMISSIONS.items():
                if dangerous_perm in perm_lower:
                    # Check if the tool's name/description suggests it shouldn't need this
                    tool_text = f"{tool.name} {tool.description}".lower()
                    is_suspicious = any(
                        kw in tool_text for kw in NETWORK_UNNECESSARY_KEYWORDS
                    ) and dangerous_perm == "network"

                    findings.append(
                        Finding(
                            rule_id="PERM-SCOPE",
                            severity=Severity.HIGH if is_suspicious else Severity.MEDIUM,
                            message=f"Requests {description}"
                            + (" (suspicious for this tool type)" if is_suspicious else ""),
                            location=f"permissions[{perm}]",
                        )
                    )

        return findings

    def _check_description_manipulation(self, tool: MCPToolDefinition) -> list[Finding]:
        """Check tool descriptions for attempts to manipulate agent behavior."""
        findings = []

        for i, t in enumerate(tool.tools):
            desc = t.get("description", "")
            name = t.get("name", f"tool_{i}")

            # Check for hidden instructions in descriptions
            if len(desc) > 500:
                findings.append(
                    Finding(
                        rule_id="DESC-LEN",
                        severity=Severity.MEDIUM,
                        message=f"Unusually long tool description ({len(desc)} chars) — may hide instructions",
                        location=f"tools[{name}].description",
                    )
                )

            # Check for instruction-like language in descriptions
            instruction_signals = [
                (r"always\s+(call|use|invoke|run)\s+this\s+(tool|function)\s+first", "Instruction to prioritize this tool"),
                (r"(do\s+not|don't|never)\s+(use|call|invoke)\s+(any\s+)?other", "Instruction to exclude other tools"),
                (r"before\s+(responding|answering|doing\s+anything)", "Pre-emption instruction"),
                (r"this\s+tool\s+(must|should)\s+be\s+(called|used)\s+for\s+every", "Forced invocation instruction"),
            ]

            for pattern, message in instruction_signals:
                if re.search(pattern, desc, re.IGNORECASE):
                    findings.append(
                        Finding(
                            rule_id="DESC-MANIP",
                            severity=Severity.HIGH,
                            message=message,
                            location=f"tools[{name}].description",
                            evidence=desc[:120],
                        )
                    )

        return findings

    def _check_source_files(self, tool: MCPToolDefinition) -> list[Finding]:
        """If source path exists, scan actual source files for suspicious patterns."""
        findings = []
        source_path = tool.source_path

        if not source_path:
            return findings

        path = Path(source_path)
        if not path.exists():
            return findings

        # Scan Python and JS/TS files
        extensions = {".py", ".js", ".ts", ".mjs", ".cjs"}
        files_to_scan = []

        if path.is_file():
            files_to_scan = [path]
        elif path.is_dir():
            for ext in extensions:
                files_to_scan.extend(path.rglob(f"*{ext}"))

        for fpath in files_to_scan[:50]:  # Cap at 50 files
            try:
                content = fpath.read_text(errors="ignore")

                # Check for dynamic prompt construction with external input
                dynamic_prompt_patterns = [
                    (r"(prompt|system_prompt|instruction)\s*[+=]\s*.*\b(input|request|query|user)", "Dynamic prompt construction from user input"),
                    (r"f['\"].*\{.*\b(input|request|query|user).*\}.*['\"]", "F-string prompt with user input"),
                    (r"\.format\(.*\b(input|request|query|user)", "Format string prompt with user input"),
                ]

                for pattern, message in dynamic_prompt_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(
                            Finding(
                                rule_id="SRC-DYN-PROMPT",
                                severity=Severity.MEDIUM,
                                message=message,
                                location=str(fpath),
                            )
                        )
                        break

                # Check for outbound network calls in tools that shouldn't have them
                if any(kw in tool.name.lower() for kw in NETWORK_UNNECESSARY_KEYWORDS):
                    net_patterns = [
                        r"requests\.(get|post|put|delete)\s*\(",
                        r"httpx\.(get|post|put|delete|AsyncClient)\s*\(",
                        r"urllib\.request",
                        r"aiohttp\.ClientSession",
                        r"fetch\s*\(",
                    ]
                    for pattern in net_patterns:
                        if re.search(pattern, content):
                            findings.append(
                                Finding(
                                    rule_id="SRC-NET",
                                    severity=Severity.HIGH,
                                    message="Network call in tool that shouldn't need network access",
                                    location=str(fpath),
                                )
                            )
                            break

            except Exception:
                pass

        return findings
