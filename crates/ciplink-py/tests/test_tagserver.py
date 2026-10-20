"""
The ciplink-tagserver test suite (a sibling checkout) with the Rust-backed wheel installed instead of ciplink 0.2.
Set CIPLINK_WHEEL to the wheel built by maturin; skipped without it or without the checkout.  The tagserver repo
is not modified: its tests run in an isolated uv environment from its own directory.
"""

import os
import shutil
import subprocess

import pytest

from conftest import REPO

TAGSERVER = os.environ.get("CIPLINK_TAGSERVER", os.path.join(os.path.dirname(REPO), "ciplink-tagserver"))
WHEEL = os.environ.get("CIPLINK_WHEEL")


@pytest.mark.skipif(not WHEEL or not os.path.isdir(TAGSERVER) or not shutil.which("uv"),
                    reason="needs CIPLINK_WHEEL, the ciplink-tagserver checkout and uv")
def test_tagserver_suite_passes_with_the_wheel():
    check = subprocess.run(["uv", "run", "--isolated", "--with", WHEEL, "--with", "pytest", "python", "-c",
                            "import ciplink; print(hasattr(ciplink, '_core'))"],
                           cwd=TAGSERVER, capture_output=True, text=True)
    assert check.stdout.strip().endswith("True"), check.stdout + check.stderr
    result = subprocess.run(["uv", "run", "--isolated", "--with", WHEEL, "--with", "pytest", "python", "-m",
                             "pytest", "-q", "-p", "no:cacheprovider"], cwd=TAGSERVER, capture_output=True, text=True)
    print(result.stdout[-2000:])
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
