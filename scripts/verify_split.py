#!/usr/bin/env python3
"""Verify that the public toolvet/ package contains no proprietary code.

Run from the repo root:
    python scripts/verify_split.py
"""

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLVET_DIR = REPO_ROOT / "toolvet"
SCHEMA_FILE = REPO_ROOT / "schemas" / "toolvet-attestation.schema.json"

FAIL = False


def check(label: str, pattern: str, directory: str = "toolvet/", exclude_files: list[str] | None = None) -> None:
    global FAIL
    result = subprocess.run(
        ["grep", "-r", pattern, directory],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    lines = result.stdout.strip()
    if lines and exclude_files:
        filtered = [
            line for line in lines.splitlines()
            if not any(line.startswith(ef) for ef in exclude_files)
        ]
        lines = "\n".join(filtered)
    if lines:
        print(f"FAIL: {label}")
        print(f"  Found matches:\n{lines}")
        FAIL = True
    else:
        print(f"OK:   {label}")


def main() -> None:
    global FAIL

    print("=== ToolVet Public/Private Split Verification ===\n")

    # 1. No proprietary imports (magen_v2 — the private scoring engine)
    # cli/main.py has lazy magen_v2 imports in the --deep code path (local dev only) — excluded
    check("No magen_v2 imports (excl cli/main.py --deep)", r"magen_v2",
          exclude_files=["toolvet/cli/main.py"])

    # 2. No signing logic in SDK files
    check("No Signer class in SDK", r"Signer", "toolvet/verify.py")
    check("No Signer class in hash", r"Signer", "toolvet/hash.py")
    check("No Signer class in client", r"Signer", "toolvet/client.py")
    check("No private_key in SDK", r"private_key", "toolvet/verify.py")

    # 3. Schema validates as JSON
    print()
    try:
        with open(SCHEMA_FILE) as f:
            json.load(f)
        print(f"OK:   Schema file is valid JSON ({SCHEMA_FILE.name})")
    except Exception as e:
        print(f"FAIL: Schema file invalid: {e}")
        FAIL = True

    # 4. Basic import check
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from toolvet import ToolVetClient, verify_attestation, tool_hash, Attestation
        print("OK:   Public SDK imports work")
    except Exception as e:
        print(f"FAIL: SDK import error: {e}")
        FAIL = True

    # 5. CLI imports work
    try:
        from toolvet.pipeline import Pipeline
        from toolvet.loader import load_tool
        from toolvet.models import TrustScore, Verdict
        print("OK:   Pipeline/CLI imports work")
    except Exception as e:
        print(f"FAIL: Pipeline import error: {e}")
        FAIL = True

    # 6. tool_hash is deterministic
    try:
        from toolvet.hash import tool_hash as th
        h1 = th({"name": "test", "tools": [{"name": "a"}]})
        h2 = th({"name": "test", "tools": [{"name": "a"}]})
        assert h1 == h2, "Hash not deterministic"
        assert h1.startswith("sha256:"), f"Hash format wrong: {h1}"
        print("OK:   tool_hash() is deterministic and correctly formatted")
    except Exception as e:
        print(f"FAIL: tool_hash check: {e}")
        FAIL = True

    print()
    if FAIL:
        print("FAILED — issues detected")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
