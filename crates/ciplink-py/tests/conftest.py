"""
Tests of the Rust-backed ciplink package (python/ciplink and its extension module ciplink._core).  Run them from
the repo root with the package installed (the wheel, or ``maturin develop``), e.g.::

    uv run --no-project --isolated --python 3.12 --with <wheel> --with pytest python -m pytest crates/ciplink-py/tests

The parity tests run the reference driver (tools/reference) in a subprocess, never in this interpreter.
"""

import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

import ciplink  # noqa: E402

assert hasattr(ciplink, "_core"), f"ciplink._core is missing: {ciplink.__file__} is not the built package"


def run_pytest(cwd, *args, env=None):
    """pytest in a subprocess with this interpreter, the package under test importable as installed"""
    import subprocess

    env = {**os.environ, **(env or {})}  # a PYTHONPATH to the package under test is kept
    return subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *args], cwd=cwd, env=env,
                          capture_output=True, text=True)
