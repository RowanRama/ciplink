"""
Bit strings (BYTE, WORD, DWORD, LWORD) and BOOL arrays through ciplink.LogixDriver, against the simulator: a
scalar bit string is a value of its own (one bool per bit), a DWORD with dimensions a BOOL array.
"""

import os
import sys

import pytest

from conftest import REPO

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import Sim  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import ErrorKind, LogixDriver  # noqa: E402


def bits(n, word):
    return [bool(word >> i & 1) for i in range(n)]


def word_of(bools):
    return sum(1 << i for i, b in enumerate(bools) if b)


@pytest.fixture
def sim():
    with Sim("example_controller.json") as sim:
        yield sim


@pytest.fixture
def plc(sim):
    with LogixDriver(sim.address) as plc:
        yield plc


def test_scalar_bit_strings_read_whole(plc):
    cases = [
        ("byte1", "BYTE", 8, 0xA5),
        ("word1", "WORD", 16, 0x8001),
        ("dword1", "DWORD", 32, 0x8000_0005),
        ("lword1", "LWORD", 64, 0x8000_0000_0000_0003),
        ("bits_udt.dw", "DWORD", 32, 4),
    ]
    results = plc.read(*[c[0] for c in cases])
    for (tag, type_name, n, word), result in zip(cases, results):
        assert (result.value, result.type, result.error) == (bits(n, word), type_name, None), tag


def test_scalar_bit_string_bits_read_as_bool(plc):
    cases = {"byte1.7": True, "byte1.1": False, "word1.15": True, "dword1.2": True, "dword1.1": False,
             "dword1.31": True, "lword1.63": True, "bits_udt.dw.2": True, "word_ary[2].15": True}
    results = plc.read(*cases)
    for (tag, set_), result in zip(cases.items(), results):
        assert (result.tag, result.value, result.type, result.error) == (tag, set_, "BOOL", None)


def test_bits_outside_a_bit_string_are_refused(plc):
    for result in plc.read("byte1.8", "word1.16", "dword1.32", "lword1.64"):
        assert result.error_kind is ErrorKind.BAD_REQUEST
        assert "Bit index is outside the tag's data type" in str(result.error)


def test_bit_writes_change_only_their_bits(sim, plc):
    results = plc.write(("dword1.4", True), ("dword1.0", False), ("word1.8", True), ("lword1.40", True),
                        ("bits_udt.dw.9", True))
    assert [r.error for r in results] == [None] * 5
    assert word_of(sim.cmd("value", path="dword1")) == 0x8000_0014
    assert word_of(sim.cmd("value", path="word1")) == 0x8101
    assert word_of(sim.cmd("value", path="lword1")) == 0x8000_0100_0000_0003
    assert word_of(sim.cmd("value", path="bits_udt.dw")) == 0x204
    assert plc.read("dword1.4").value is True


def test_whole_writes_take_lists_of_bools(sim, plc):
    assert plc.write("word1", bits(16, 0x1234)).error is None
    assert word_of(sim.cmd("value", path="word1")) == 0x1234
    assert plc.read("word1").value == bits(16, 0x1234)


def test_bool_arrays_are_unchanged(sim, plc):
    five, slice_ = plc.read("bool_ary[5]", "bool_ary[31]{3}")
    assert (five.value, five.type) == (True, "BOOL")
    assert (slice_.value, slice_.type) == ([True, True, False], "BOOL[3]")
    assert plc.write("bool_ary[40]", True).error is None
    assert sim.cmd("value", path="bool_ary")[40] is True
    assert plc.read("bool_ary[40]").value is True
