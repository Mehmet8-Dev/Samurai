from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Dict, Optional


def run_unittest_discover(
    *,
    start_dir: str,
    pattern: str = "test_*.py",
    top_level_dir: Optional[str] = None,
    verbosity: int = 2,
) -> Dict[str, Any]:
    """Run unittest discovery and return a structured summary.

    This is intended for safe self-diagnostics and CI-style reporting.
    """
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=start_dir, pattern=pattern, top_level_dir=top_level_dir)

    buf = io.StringIO()
    runner = unittest.TextTestRunner(stream=buf, verbosity=verbosity)

    # Capture both unittest runner output and incidental prints from tests.
    with redirect_stdout(buf), redirect_stderr(buf):
        result = runner.run(suite)

    out = buf.getvalue()

    # unittest result lists contain (testcase, traceback_str)
    failures = list(result.failures or [])
    errors = list(result.errors or [])
    skipped = list(getattr(result, "skipped", []) or [])

    return {
        "tests_run": int(getattr(result, "testsRun", 0) or 0),
        "failures": len(failures),
        "errors": len(errors),
        "skipped": len(skipped),
        "successful": bool(result.wasSuccessful()),
        "output": out,
    }

