"""Fails the test suite if vuln answer-key content has leaked into the repo.

Wraps tests/check_no_vuln_leak.py. Works in CI without the private repo
(structural detector runs); on a maintainer machine the narrative detector
runs too. Either way a clean repo exits 0.
"""
import os
import subprocess
import sys


def test_no_vuln_info_leak():
    root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"]
    ).decode().strip()
    result = subprocess.run(
        [sys.executable, os.path.join(root, "tests", "check_no_vuln_leak.py")]
    )
    assert result.returncode == 0, (
        "vuln answer-key content detected in the repo — see output above"
    )
