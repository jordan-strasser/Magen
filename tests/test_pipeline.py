"""Tests for magen verification pipeline."""

import json
from pathlib import Path

from magen.loader import load_tool
from magen.models import Verdict, Severity
from magen.pipeline import Pipeline

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


class TestCleanTool:
    def test_clean_tool_passes(self):
        tool = load_tool(str(EXAMPLES_DIR / "clean_tool.json"))
        pipeline = Pipeline()
        score = pipeline.verify(tool)

        assert score.verdict in (Verdict.PASS, Verdict.WARN)
        assert score.score >= 70

    def test_clean_tool_name(self):
        tool = load_tool(str(EXAMPLES_DIR / "clean_tool.json"))
        assert tool.name == "weather-mcp"


class TestMaliciousTool:
    def test_malicious_tool_fails(self):
        tool = load_tool(str(EXAMPLES_DIR / "malicious_tool.json"))
        pipeline = Pipeline()
        score = pipeline.verify(tool)

        assert score.verdict == Verdict.FAIL
        assert score.score < 40

    def test_detects_injection(self):
        tool = load_tool(str(EXAMPLES_DIR / "malicious_tool.json"))
        pipeline = Pipeline(layers=["static"])
        score = pipeline.verify(tool)

        rule_ids = [f.rule_id for f in score.all_findings]
        # Should detect instruction override
        assert any(r.startswith("INJ") for r in rule_ids)

    def test_detects_exfiltration(self):
        tool = load_tool(str(EXAMPLES_DIR / "malicious_tool.json"))
        pipeline = Pipeline(layers=["static"])
        score = pipeline.verify(tool)

        rule_ids = [f.rule_id for f in score.all_findings]
        assert any(r.startswith("EXFIL") for r in rule_ids)

    def test_detects_description_manipulation(self):
        tool = load_tool(str(EXAMPLES_DIR / "malicious_tool.json"))
        pipeline = Pipeline(layers=["static"])
        score = pipeline.verify(tool)

        rule_ids = [f.rule_id for f in score.all_findings]
        assert any(r.startswith("DESC") for r in rule_ids)

    def test_detects_excessive_permissions(self):
        tool = load_tool(str(EXAMPLES_DIR / "malicious_tool.json"))
        pipeline = Pipeline(layers=["static"])
        score = pipeline.verify(tool)

        rule_ids = [f.rule_id for f in score.all_findings]
        assert any(r.startswith("PERM") for r in rule_ids)


class TestSneakyTool:
    def test_sneaky_tool_flagged(self):
        tool = load_tool(str(EXAMPLES_DIR / "sneaky_tool.json"))
        pipeline = Pipeline()
        score = pipeline.verify(tool)

        # Should at least be WARN or worse
        assert score.verdict != Verdict.PASS
        assert score.score < 90

    def test_detects_base64_in_field_names(self):
        tool = load_tool(str(EXAMPLES_DIR / "sneaky_tool.json"))
        pipeline = Pipeline(layers=["static"])
        score = pipeline.verify(tool)

        # The base64 field name "SWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM"
        # decodes to "Ignore all previous instructions"
        has_encoding = any(f.rule_id.startswith("ENC") for f in score.all_findings)
        assert has_encoding

    def test_detects_output_injection_risk(self):
        tool = load_tool(str(EXAMPLES_DIR / "sneaky_tool.json"))
        pipeline = Pipeline(layers=["behavioral"])
        score = pipeline.verify(tool)

        rule_ids = [f.rule_id for f in score.all_findings]
        assert any(r.startswith("BHV") for r in rule_ids)


class TestPipeline:
    def test_static_only(self):
        tool = load_tool(str(EXAMPLES_DIR / "clean_tool.json"))
        pipeline = Pipeline(layers=["static"])
        score = pipeline.verify(tool)
        assert len(score.scan_results) == 1
        assert score.scan_results[0].layer == "static"

    def test_behavioral_only(self):
        tool = load_tool(str(EXAMPLES_DIR / "clean_tool.json"))
        pipeline = Pipeline(layers=["behavioral"])
        score = pipeline.verify(tool)
        assert len(score.scan_results) == 1
        assert score.scan_results[0].layer == "behavioral"

    def test_full_pipeline(self):
        tool = load_tool(str(EXAMPLES_DIR / "clean_tool.json"))
        pipeline = Pipeline()
        score = pipeline.verify(tool)
        assert len(score.scan_results) == 2
        layers = [r.layer for r in score.scan_results]
        assert "static" in layers
        assert "behavioral" in layers

    def test_json_output_structure(self):
        tool = load_tool(str(EXAMPLES_DIR / "malicious_tool.json"))
        pipeline = Pipeline()
        score = pipeline.verify(tool)

        # Verify all findings have required fields
        for finding in score.all_findings:
            assert finding.rule_id
            assert finding.severity
            assert finding.message
