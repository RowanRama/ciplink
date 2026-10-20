"""
The Rust-backed LogixDriver against the reference driver on the same simulated controller: the tag definitions
(type classes included), data types, info and the other dicts users read must be identical.
"""

import json
import os
import subprocess
import sys

import pytest

from conftest import REPO
from dump_driver import dump

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import Sim  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import LogixDriver  # noqa: E402


@pytest.fixture(scope="module")
def dumps():
    with Sim("example_controller.json") as sim:
        new = dump(LogixDriver, sim.address)
        ref = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "dump_driver.py"),
                              os.path.join(REPO, "tools", "reference"), sim.address], capture_output=True, text=True, cwd=REPO)
        assert ref.returncode == 0, ref.stderr
    ref = json.loads(ref.stdout)
    assert new["rust_core"] and not ref["rust_core"]
    return new, ref


KEYS = ["tags", "data_types", "shared", "tags_json", "info", "str", "repr", "name", "revision_major", "tag_info",
        "tag_info_is_tag", "tag_list", "plc_time", "module_info", "plc_info", "generic"]


@pytest.mark.parametrize("key", KEYS)
def test_same_as_reference(dumps, key):
    new, ref = dumps
    new = json.loads(json.dumps(new[key]))  # the reference's went through JSON too
    assert new == ref[key]
