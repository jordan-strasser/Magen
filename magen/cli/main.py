"""magen CLI — Immune system for AI agents."""

import json
import sys

import click

from magen import __version__
from magen.loader import LoadError, load_tool
from magen.models import Severity, TrustScore, Verdict
from magen.pipeline import Pipeline

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

VERDICT_LABELS = {
    Verdict.PASS: "✅ PASS",
    Verdict.WARN: "⚠️  WARN",
    Verdict.CAUTION: "🔶 CAUTION",
    Verdict.FAIL: "❌ FAIL",
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.INFO: "INFO",
}


def render_trust_score(score: TrustScore) -> None:
    """Render a TrustScore to terminal."""
    verdict_text = VERDICT_LABELS[score.verdict]

    # Header
    click.echo("")
    click.echo("╔══════════════════════════════════════════════════╗")
    click.echo("║  🛡️  magen verification                         ║")
    click.echo("╠══════════════════════════════════════════════════╣")
    click.echo(f"║  Tool:    {score.tool_name:<39}║")
    if score.tool_version:
        click.echo(f"║  Version: {score.tool_version:<39}║")
    click.echo(f"║  Verdict: {verdict_text:<39}║")
    click.echo(f"║  Score:   {score.score}/100{' ':>34}║")
    click.echo("╚══════════════════════════════════════════════════╝")

    # Findings
    all_findings = score.all_findings
    if not all_findings:
        click.echo("  No issues found. ✅\n")
        return

    click.echo("")
    click.echo(f"  {'SEV':<6} {'RULE':<16} {'MESSAGE'}")
    click.echo(f"  {'─'*5}  {'─'*14}  {'─'*40}")

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    sorted_findings = sorted(all_findings, key=lambda f: severity_order.get(f.severity, 5))

    for finding in sorted_findings:
        sev_label = SEVERITY_LABELS[finding.severity]
        click.echo(f"  {sev_label:<6} {finding.rule_id:<16} {finding.message}")
        if finding.location:
            click.echo(f"  {'':6} {'':16} └─ {finding.location}")

    # Summary
    click.echo("")
    by_severity: dict = {}
    for f in all_findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = by_severity.get(sev, 0)
        if count > 0:
            parts.append(f"{count} {SEVERITY_LABELS[sev].strip()}")

    click.echo(f"  Summary: {' · '.join(parts)}")
    click.echo("")


@click.group()
@click.version_option(__version__, prog_name="magen")
def cli():
    """🛡️ magen — Immune system for AI agents.

    Scan, sandbox, and verify MCP tools before your agents touch them.
    """
    pass


@cli.command()
@click.argument("source")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def scan(source: str, json_output: bool):
    """Run static analysis on an MCP tool definition.

    SOURCE can be a file path or directory containing an MCP server.
    """
    try:
        tool = load_tool(source)
    except LoadError as e:
        click.echo(f"Error: {e}")
        sys.exit(1)

    pipeline = Pipeline(layers=["static"])
    score = pipeline.verify(tool)

    if json_output:
        _output_json(score)
    else:
        render_trust_score(score)

    sys.exit(0 if score.verdict in (Verdict.PASS, Verdict.WARN) else 1)


@cli.command()
@click.argument("source")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def sandbox(source: str, json_output: bool):
    """Run behavioral sandbox analysis on an MCP tool.

    SOURCE can be a file path or directory containing an MCP server.
    """
    try:
        tool = load_tool(source)
    except LoadError as e:
        click.echo(f"Error: {e}")
        sys.exit(1)

    pipeline = Pipeline(layers=["sandbox"])
    score = pipeline.verify(tool)

    if json_output:
        _output_json(score)
    else:
        render_trust_score(score)

    sys.exit(0 if score.verdict in (Verdict.PASS, Verdict.WARN) else 1)


@cli.command()
@click.argument("source")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@click.option("--strict", is_flag=True, help="Fail on WARN (default: only CAUTION/FAIL)")
def verify(source: str, json_output: bool, strict: bool):
    """Full verification: static analysis + behavioral sandbox.

    SOURCE can be a file path or directory containing an MCP server.
    Returns exit code 0 for PASS/WARN, 1 for CAUTION/FAIL.
    Use --strict to also fail on WARN.
    """
    try:
        tool = load_tool(source)
    except LoadError as e:
        click.echo(f"Error: {e}")
        sys.exit(1)

    pipeline = Pipeline(layers=["static", "sandbox"])
    score = pipeline.verify(tool)

    if json_output:
        _output_json(score)
    else:
        render_trust_score(score)

    if strict:
        sys.exit(0 if score.verdict == Verdict.PASS else 1)
    else:
        sys.exit(0 if score.verdict in (Verdict.PASS, Verdict.WARN) else 1)


@cli.group()
def registry():
    """Browse and manage the verified tool registry."""
    pass


@registry.command("list")
@click.option("--category", "-c", help="Filter by category")
def registry_list(category: str):
    """List verified tools in the registry."""
    click.echo(
        "\n📋 Registry\n"
        "  Registry coming in v0.2 — will connect to the magen hosted catalog.\n"
        "  For now, use `magen verify` to scan local tools.\n"
    )


@registry.command("publish")
@click.argument("source")
def registry_publish(source: str):
    """Submit a tool for verification and listing."""
    click.echo(
        "\n📤 Publish\n"
        "  Publishing coming in v0.2.\n"
        "  For now, use `magen verify` to test your tool locally.\n"
    )


def _output_json(score: TrustScore) -> None:
    """Output TrustScore as JSON to stdout."""
    output = {
        "tool": score.tool_name,
        "version": score.tool_version,
        "score": score.score,
        "verdict": score.verdict.value,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "location": f.location,
                "evidence": f.evidence,
            }
            for f in score.all_findings
        ],
        "layers": [
            {
                "layer": r.layer,
                "finding_count": len(r.findings),
                "total_penalty": r.total_penalty,
                "metadata": r.metadata,
            }
            for r in score.scan_results
        ],
    }
    click.echo(json.dumps(output, indent=2))


if __name__ == "__main__":
    cli()
