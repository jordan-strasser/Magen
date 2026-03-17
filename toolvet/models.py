"""Core data models for toolvet verification pipeline."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Verdict(Enum):
    PASS = "PASS"
    WARN = "WARN"
    CAUTION = "CAUTION"
    FAIL = "FAIL"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single issue found during scanning."""

    rule_id: str
    severity: Severity
    message: str
    location: Optional[str] = None
    evidence: Optional[str] = None

    @property
    def score_penalty(self) -> int:
        penalties = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 15,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }
        return penalties[self.severity]


@dataclass
class ScanResult:
    """Result from a single scan layer."""

    layer: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    @property
    def total_penalty(self) -> int:
        return sum(f.score_penalty for f in self.findings)


@dataclass
class TrustScore:
    """Final verification output."""

    score: int  # 0-100
    verdict: Verdict
    scan_results: list[ScanResult] = field(default_factory=list)
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None

    @classmethod
    def compute(cls, scan_results: list[ScanResult], tool_name: str = "", tool_version: str = "") -> "TrustScore":
        total_penalty = sum(r.total_penalty for r in scan_results)
        score = max(0, 100 - total_penalty)

        if score >= 90:
            verdict = Verdict.PASS
        elif score >= 70:
            verdict = Verdict.WARN
        elif score >= 40:
            verdict = Verdict.CAUTION
        else:
            verdict = Verdict.FAIL

        return cls(
            score=score,
            verdict=verdict,
            scan_results=scan_results,
            tool_name=tool_name,
            tool_version=tool_version,
        )

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for result in self.scan_results:
            findings.extend(result.findings)
        return findings


@dataclass
class MCPToolDefinition:
    """Parsed MCP tool/server definition."""

    name: str
    version: str = "0.0.0"
    description: str = ""
    tools: list[dict] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    source_path: Optional[str] = None
    raw_config: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict, source_path: str = "") -> "MCPToolDefinition":
        return cls(
            name=data.get("name", "unknown"),
            version=data.get("version", "0.0.0"),
            description=data.get("description", ""),
            tools=data.get("tools", []),
            permissions=data.get("permissions", []),
            source_path=source_path,
            raw_config=data,
        )
