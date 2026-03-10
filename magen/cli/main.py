"""magen CLI — Immune system for AI agents."""

import json
import sys
from pathlib import Path
from urllib.parse import quote as urlquote

import click
import httpx

from magen import __version__
from magen.loader import LoadError, load_tool
from magen.models import MCPToolDefinition, Severity, TrustScore, Verdict
from magen.pipeline import Pipeline
from magen.registry import RegistryError, fetch_and_load

REGISTRY_BASE = "https://registry.modelcontextprotocol.io/v0.1"

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


def _load_source(source: str) -> MCPToolDefinition:
    """Load a tool from a local path or fall back to the MCP registry.

    Args:
        source: File path, directory path, or registry server name.

    Returns:
        Parsed MCPToolDefinition.

    Raises:
        click.ClickException on failure.
    """
    if Path(source).exists():
        try:
            return load_tool(source)
        except LoadError as e:
            raise click.ClickException(str(e))

    # Not a local path — try registry
    click.echo(f"  Fetching '{source}' from MCP registry...", err=True)
    try:
        return fetch_and_load(source)
    except RegistryError as e:
        raise click.ClickException(str(e))


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

    Scan and verify MCP tools before your agents touch them.
    """
    pass


@cli.command()
@click.argument("source")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def scan(source: str, json_output: bool):
    """Run static analysis on an MCP tool definition.

    SOURCE can be a file path, directory, or registry server name
    (e.g. 'io.github.user/my-server').
    """
    tool = _load_source(source)
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
def behavioral(source: str, json_output: bool):
    """Run behavioral analysis on an MCP tool.

    SOURCE can be a file path, directory, or registry server name
    (e.g. 'io.github.user/my-server').
    """
    tool = _load_source(source)
    pipeline = Pipeline(layers=["behavioral"])
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
    """Full verification: static + behavioral analysis.

    SOURCE can be a file path, directory, or registry server name
    (e.g. 'io.github.user/my-server').
    Returns exit code 0 for PASS/WARN, 1 for CAUTION/FAIL.
    Use --strict to also fail on WARN.
    """
    tool = _load_source(source)
    pipeline = Pipeline(layers=["static", "behavioral"])
    score = pipeline.verify(tool)

    if json_output:
        _output_json(score)
    else:
        render_trust_score(score)

    if strict:
        sys.exit(0 if score.verdict == Verdict.PASS else 1)
    else:
        sys.exit(0 if score.verdict in (Verdict.PASS, Verdict.WARN) else 1)


# ---------------------------------------------------------------------------
# Registry commands
# ---------------------------------------------------------------------------


@cli.group()
def registry():
    """Browse and search the MCP tool registry."""
    pass


@registry.command("list")
@click.option("--limit", "-n", default=20, help="Max results to show")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def registry_list(limit: int, json_output: bool):
    """List MCP servers from the registry."""
    try:
        resp = httpx.get(
            f"{REGISTRY_BASE}/servers",
            params={"limit": limit, "version": "latest"},
            timeout=15,
        )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        click.echo(f"Error: failed to reach registry — {e}")
        sys.exit(1)

    data = resp.json()
    servers = data.get("servers", [])

    if json_output:
        click.echo(json.dumps(servers, indent=2))
        return

    if not servers:
        click.echo("\n  No servers found.\n")
        return

    click.echo("")
    click.echo(f"  {'NAME':<40} {'VERSION':<12} {'DESCRIPTION'}")
    click.echo(f"  {'─'*39}  {'─'*11}  {'─'*40}")
    for entry in servers:
        server = entry.get("server", entry)
        name = server.get("name", "?")
        version = server.get("version", "?")
        desc = server.get("description", "")
        if len(desc) > 50:
            desc = desc[:47] + "..."
        click.echo(f"  {name:<40} {version:<12} {desc}")
    click.echo("")


@registry.command("search")
@click.argument("query")
@click.option("--limit", "-n", default=20, help="Max results to show")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def registry_search(query: str, limit: int, json_output: bool):
    """Search for MCP servers in the registry."""
    try:
        resp = httpx.get(
            f"{REGISTRY_BASE}/servers",
            params={"search": query, "limit": limit, "version": "latest"},
            timeout=15,
        )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        click.echo(f"Error: failed to reach registry — {e}")
        sys.exit(1)

    data = resp.json()
    servers = data.get("servers", [])

    if json_output:
        click.echo(json.dumps(servers, indent=2))
        return

    if not servers:
        click.echo(f"\n  No servers matching '{query}'.\n")
        return

    click.echo(f"\n  Results for '{query}':\n")
    click.echo(f"  {'NAME':<40} {'VERSION':<12} {'DESCRIPTION'}")
    click.echo(f"  {'─'*39}  {'─'*11}  {'─'*40}")
    for entry in servers:
        server = entry.get("server", entry)
        name = server.get("name", "?")
        version = server.get("version", "?")
        desc = server.get("description", "")
        if len(desc) > 50:
            desc = desc[:47] + "..."
        click.echo(f"  {name:<40} {version:<12} {desc}")
    click.echo("")


@registry.command("publish")
@click.argument("source")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def registry_publish(source: str, json_output: bool):
    """Verify a tool locally and show its trust score for publishing.

    Runs the full magen verification pipeline and outputs the result
    in a format suitable for submission to the MCP registry. The actual
    POST to the registry requires authentication — use the MCP registry
    CLI or API directly with the JSON output from this command.

    SOURCE can be a file path or directory containing an MCP server.
    """
    tool = _load_source(source)
    pipeline = Pipeline(layers=["static", "behavioral"])
    score = pipeline.verify(tool)

    publish_payload = {
        "name": tool.name,
        "version": tool.version,
        "description": tool.description,
        "magen": {
            "score": score.score,
            "verdict": score.verdict.value,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                }
                for f in score.all_findings
            ],
        },
    }

    if json_output:
        click.echo(json.dumps(publish_payload, indent=2))
    else:
        render_trust_score(score)
        click.echo("  To publish, pass --json-output and submit to the MCP registry:")
        click.echo("    magen registry publish ./my-server -j | curl -X POST \\")
        click.echo(f"      {REGISTRY_BASE}/publish \\")
        click.echo("      -H 'Content-Type: application/json' \\")
        click.echo("      -H 'Authorization: Bearer <token>' \\")
        click.echo("      -d @-")
        click.echo("")

    sys.exit(0 if score.verdict in (Verdict.PASS, Verdict.WARN) else 1)


# ---------------------------------------------------------------------------
# Install command
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("name")
@click.option("--json-output", "-j", is_flag=True, help="Output server config as JSON")
def install(name: str, json_output: bool):
    """Look up an MCP server in the registry and show install info.

    NAME is the server name (e.g. 'io.github.user/my-server').
    """
    encoded = urlquote(name, safe="")
    try:
        resp = httpx.get(
            f"{REGISTRY_BASE}/servers/{encoded}/versions/latest",
            timeout=15,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            click.echo(f"Error: server '{name}' not found in registry.")
        else:
            click.echo(f"Error: registry returned {e.response.status_code}")
        sys.exit(1)
    except httpx.HTTPError as e:
        click.echo(f"Error: failed to reach registry — {e}")
        sys.exit(1)

    data = resp.json()
    server = data.get("server", data)

    if json_output:
        click.echo(json.dumps(server, indent=2))
        return

    click.echo("")
    click.echo(f"  🛡️  {server.get('name', name)}")
    if server.get("title"):
        click.echo(f"  {server['title']}")
    click.echo(f"  Version: {server.get('version', '?')}")
    click.echo(f"  {server.get('description', '')}")

    # Show packages
    packages = server.get("packages", [])
    if packages:
        click.echo("\n  Packages:")
        for pkg in packages:
            registry_name = pkg.get("registry_name", pkg.get("registryName", "?"))
            pkg_name = pkg.get("name", "?")
            click.echo(f"    {registry_name}: {pkg_name}")

    # Show remotes
    remotes = server.get("remotes", [])
    if remotes:
        click.echo("\n  Remotes:")
        for remote in remotes:
            rtype = remote.get("type", "?")
            url = remote.get("url", "?")
            click.echo(f"    [{rtype}] {url}")

    # Show repo
    repo = server.get("repository", {})
    if repo and repo.get("url"):
        click.echo(f"\n  Repository: {repo['url']}")

    click.echo("")


# ---------------------------------------------------------------------------
# Report command
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("source")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def report(source: str, json_output: bool):
    """Show a detailed verification report for a tool.

    SOURCE can be a file path, directory, or registry server name
    (e.g. 'io.github.user/my-server').
    """
    tool = _load_source(source)
    pipeline = Pipeline(layers=["static", "behavioral"])
    score = pipeline.verify(tool)

    if json_output:
        _output_json(score)
    else:
        render_trust_score(score)


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
