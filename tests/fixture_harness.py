"""Rule-fixture loader for the test suite. The implementation lives in the
package (``agentguard.rules_dev``) because `agentguard rules test` uses it too."""

from __future__ import annotations

from pathlib import Path

from agentguard.rules_dev import CONTROL_FILES, Case, check_case, iter_cases, load_case, missing_native
from agentguard.rules_dev import detector_dir as _detector_dir

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures" / "rules"


def detector_dir(key: str) -> Path:
    return _detector_dir(key, FIXTURES)


__all__ = ["CONTROL_FILES", "FIXTURES", "REPO", "Case", "check_case", "detector_dir", "iter_cases", "load_case",
           "missing_native"]
