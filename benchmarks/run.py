"""magen benchmark harness.

Runs the verification pipeline against a labeled dataset of MCP tools
and computes detection metrics (precision, recall, F1, confusion matrix).

Usage:
  python -m benchmarks.run
  python -m benchmarks.run --layer static
  python -m benchmarks.run --layer sandbox
  python -m benchmarks.run --verbose
"""

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from magen.loader import load_tool, LoadError
from magen.models import Verdict
from magen.pipeline import Pipeline


# --- Labeled dataset structure ---
# Each tool in benchmarks/dataset/ should have a companion .label.json:
#
#   {
#     "expected_verdict": "FAIL",       // PASS, WARN, CAUTION, FAIL
#     "expected_min_findings": 1,        // at least this many findings
#     "attack_category": "injection",    // category for analysis
#     "attack_technique": "direct_override", // specific technique
#     "description": "Blunt 'ignore all previous instructions' in tool description"
#   }


@dataclass
class BenchmarkResult:
    tool_name: str
    tool_file: str
    expected_verdict: str
    actual_verdict: str
    actual_score: int
    expected_malicious: bool  # True if expected CAUTION or FAIL
    detected_malicious: bool  # True if actual CAUTION or FAIL
    finding_count: int
    attack_category: str = ""
    attack_technique: str = ""
    elapsed_ms: float = 0
    error: str = ""


@dataclass
class BenchmarkReport:
    results: list[BenchmarkResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def true_positives(self) -> int:
        return sum(1 for r in self.results if r.expected_malicious and r.detected_malicious)

    @property
    def false_positives(self) -> int:
        return sum(1 for r in self.results if not r.expected_malicious and r.detected_malicious)

    @property
    def true_negatives(self) -> int:
        return sum(1 for r in self.results if not r.expected_malicious and not r.detected_malicious)

    @property
    def false_negatives(self) -> int:
        return sum(1 for r in self.results if r.expected_malicious and not r.detected_malicious)

    @property
    def precision(self) -> float:
        tp = self.true_positives
        fp = self.false_positives
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        tp = self.true_positives
        fn = self.false_negatives
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def by_category(self) -> dict[str, "BenchmarkReport"]:
        """Break down results by attack category."""
        categories: dict[str, list[BenchmarkResult]] = {}
        for r in self.results:
            cat = r.attack_category or "uncategorized"
            categories.setdefault(cat, []).append(r)
        return {cat: BenchmarkReport(results=rs) for cat, rs in categories.items()}

    def by_technique(self) -> dict[str, "BenchmarkReport"]:
        """Break down results by attack technique."""
        techniques: dict[str, list[BenchmarkResult]] = {}
        for r in self.results:
            tech = r.attack_technique or "uncategorized"
            techniques.setdefault(tech, []).append(r)
        return {tech: BenchmarkReport(results=rs) for tech, rs in techniques.items()}

    def print_report(self, verbose: bool = False) -> None:
        print("\n" + "=" * 60)
        print("  🛡️  magen benchmark report")
        print("=" * 60)

        print(f"\n  Total tools tested:  {self.total}")
        print(f"  True positives:      {self.true_positives}")
        print(f"  False positives:     {self.false_positives}")
        print(f"  True negatives:      {self.true_negatives}")
        print(f"  False negatives:     {self.false_negatives}")
        print(f"\n  Precision:           {self.precision:.3f}")
        print(f"  Recall:              {self.recall:.3f}")
        print(f"  F1 Score:            {self.f1:.3f}")

        # Confusion matrix
        print(f"\n  {'':20} {'Predicted':>20}")
        print(f"  {'':20} {'Safe':>10} {'Malicious':>10}")
        print(f"  {'Actual Safe':<20} {self.true_negatives:>10} {self.false_positives:>10}")
        print(f"  {'Actual Malicious':<20} {self.false_negatives:>10} {self.true_positives:>10}")

        # Per-category breakdown
        categories = self.by_category()
        if len(categories) > 1:
            print(f"\n  {'Category':<25} {'Recall':>8} {'Count':>8}")
            print(f"  {'─' * 25} {'─' * 8} {'─' * 8}")
            for cat, report in sorted(categories.items()):
                print(f"  {cat:<25} {report.recall:>8.3f} {report.total:>8}")

        # Per-technique breakdown
        techniques = self.by_technique()
        if len(techniques) > 1:
            print(f"\n  {'Technique':<30} {'Recall':>8} {'Count':>8}")
            print(f"  {'─' * 30} {'─' * 8} {'─' * 8}")
            for tech, report in sorted(techniques.items()):
                print(f"  {tech:<30} {report.recall:>8.3f} {report.total:>8}")

        # False negatives (most important to review)
        fn = [r for r in self.results if r.expected_malicious and not r.detected_malicious]
        if fn:
            print(f"\n  ⚠️  FALSE NEGATIVES (missed attacks):")
            for r in fn:
                print(f"    - {r.tool_file}: expected {r.expected_verdict}, got {r.actual_verdict} (score={r.actual_score})")
                if r.attack_technique:
                    print(f"      technique: {r.attack_technique}")

        # False positives (important for usability)
        fp = [r for r in self.results if not r.expected_malicious and r.detected_malicious]
        if fp:
            print(f"\n  ⚠️  FALSE POSITIVES (wrongly flagged):")
            for r in fp:
                print(f"    - {r.tool_file}: expected {r.expected_verdict}, got {r.actual_verdict} (score={r.actual_score}, findings={r.finding_count})")

        if verbose:
            print(f"\n  ALL RESULTS:")
            print(f"  {'File':<35} {'Expected':>8} {'Actual':>8} {'Score':>6} {'Findings':>9} {'ms':>6}")
            print(f"  {'─' * 35} {'─' * 8} {'─' * 8} {'─' * 6} {'─' * 9} {'─' * 6}")
            for r in self.results:
                marker = ""
                if r.expected_malicious and not r.detected_malicious:
                    marker = " ← MISS"
                elif not r.expected_malicious and r.detected_malicious:
                    marker = " ← FP"
                print(
                    f"  {r.tool_file:<35} {r.expected_verdict:>8} {r.actual_verdict:>8} "
                    f"{r.actual_score:>6} {r.finding_count:>9} {r.elapsed_ms:>6.0f}{marker}"
                )

        print("")


def load_dataset(dataset_dir: str) -> list[tuple[Path, dict]]:
    """Load all tool definitions and their labels from the dataset directory."""
    dataset_path = Path(dataset_dir)
    if not dataset_path.exists():
        print(f"Error: dataset directory not found: {dataset_dir}")
        sys.exit(1)

    entries = []
    for label_file in sorted(dataset_path.glob("*.label.json")):
        tool_stem = label_file.name.replace(".label.json", "")

        # Find corresponding tool file
        tool_file = None
        for ext in [".json", ".yaml", ".yml"]:
            candidate = dataset_path / f"{tool_stem}{ext}"
            if candidate.exists():
                tool_file = candidate
                break

        if tool_file is None:
            print(f"  Warning: no tool file found for {label_file.name}, skipping")
            continue

        label = json.loads(label_file.read_text())
        entries.append((tool_file, label))

    return entries


def run_benchmark(
    dataset_dir: str = "benchmarks/dataset",
    layers: list[str] | None = None,
    verbose: bool = False,
) -> BenchmarkReport:
    """Run the full benchmark suite."""
    pipeline = Pipeline(layers=layers)
    entries = load_dataset(dataset_dir)

    if not entries:
        print("No benchmark entries found.")
        sys.exit(1)

    print(f"\n  Running magen benchmark on {len(entries)} tools...")
    print(f"  Layers: {layers or ['static', 'behavioral']}\n")

    report = BenchmarkReport()

    for tool_file, label in entries:
        expected_verdict = label["expected_verdict"]
        expected_malicious = expected_verdict in ("CAUTION", "FAIL")

        start = time.time()
        try:
            tool = load_tool(str(tool_file))
            score = pipeline.verify(tool)
            elapsed = (time.time() - start) * 1000

            actual_verdict = score.verdict.value
            detected_malicious = score.verdict in (Verdict.CAUTION, Verdict.FAIL)

            result = BenchmarkResult(
                tool_name=tool.name,
                tool_file=tool_file.name,
                expected_verdict=expected_verdict,
                actual_verdict=actual_verdict,
                actual_score=score.score,
                expected_malicious=expected_malicious,
                detected_malicious=detected_malicious,
                finding_count=len(score.all_findings),
                attack_category=label.get("attack_category", ""),
                attack_technique=label.get("attack_technique", ""),
                elapsed_ms=elapsed,
            )
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            result = BenchmarkResult(
                tool_name=tool_file.stem,
                tool_file=tool_file.name,
                expected_verdict=expected_verdict,
                actual_verdict="ERROR",
                actual_score=-1,
                expected_malicious=expected_malicious,
                detected_malicious=False,
                finding_count=0,
                attack_category=label.get("attack_category", ""),
                attack_technique=label.get("attack_technique", ""),
                elapsed_ms=elapsed,
                error=str(e),
            )

        status = "✅" if (result.expected_malicious == result.detected_malicious) else "❌"
        print(f"  {status} {tool_file.name}")

        report.results.append(result)

    report.print_report(verbose=verbose)
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="magen benchmark harness")
    parser.add_argument("--dataset", default="benchmarks/dataset", help="Path to dataset directory")
    parser.add_argument("--layer", choices=["static", "behavioral"], help="Run single layer only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all results")
    args = parser.parse_args()

    layers = [args.layer] if args.layer else None
    run_benchmark(dataset_dir=args.dataset, layers=layers, verbose=args.verbose)
