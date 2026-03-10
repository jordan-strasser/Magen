"""Verification pipeline: orchestrates scan layers into a TrustScore."""

from magen.loader import load_tool
from magen.models import MCPToolDefinition, ScanResult, TrustScore
from magen.scanners.static import StaticScanner
from magen.scanners.behavioral import BehavioralScanner


class Pipeline:
    """Verification pipeline that runs tools through layered analysis."""

    def __init__(self, layers: list[str] | None = None):
        self.scanners = []

        enabled = layers or ["static", "behavioral"]

        if "static" in enabled:
            self.scanners.append(StaticScanner())
        if "behavioral" in enabled:
            self.scanners.append(BehavioralScanner())

    def verify(self, tool: MCPToolDefinition) -> TrustScore:
        """Run all enabled scan layers and compute trust score."""
        results: list[ScanResult] = []

        for scanner in self.scanners:
            result = scanner.scan(tool)
            results.append(result)

        return TrustScore.compute(
            scan_results=results,
            tool_name=tool.name,
            tool_version=tool.version,
        )

    def verify_from_source(self, source: str) -> TrustScore:
        """Load a tool from source path and verify it."""
        tool = load_tool(source)
        return self.verify(tool)
