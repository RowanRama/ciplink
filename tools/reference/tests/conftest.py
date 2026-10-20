"""
The reference driver's own offline tests (verbatim, apart from the examples/ path in test_misc.py).  They run
against the reference package, loaded as ``ciplink`` before any test module imports it; the repo's examples/ are
importable for the tests that exercise them.  The fixture generators import their helpers too.  Run from the repo
root::

    uv run --no-project --isolated --python 3.12 --with pytest python -m pytest tools/reference/tests -q
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REFERENCE = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(REFERENCE))

sys.path.insert(0, REFERENCE)
sys.path.append(REPO)  # examples/, after tools/reference so ``tests`` stays this package

import reference  # noqa: E402

reference.load()
