"""
ShieldNet Automated Test Suite Runner
Runs unit and integration tests across the shared engine and Windows components.
"""

import sys
import subprocess
from pathlib import Path


def main():
    repo_root = Path(__file__).resolve().parent.parent
    print("=" * 60)
    print("ShieldNet Automated Test Suite Runner")
    print(f"Target Directory: {repo_root}")
    print("=" * 60)

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(repo_root / "shared" / "tests"),
        str(repo_root / "windows" / "tests"),
        "-v",
        "--tb=short",
    ]

    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=repo_root)

    print("=" * 60)
    if result.returncode == 0:
        print("ALL TESTS PASSED SUCCESSFULLY.")
    else:
        print(f"TEST FAILURES DETECTED (Exit code: {result.returncode})")
    print("=" * 60)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
