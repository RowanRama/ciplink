"""Write values that do not fit the tag's type are rejected by the type's encoder (DataError)."""

import pytest

from ciplink import (
    BOOL, DINT, DWORD, INT, LINT, LREAL, REAL, SINT, UDINT, UINT, ULINT, USINT, DataError, StructTag,
)


UDT = StructTag((DINT("x"), 0), (SINT("ZZZhost"), 4), bit_members={"flag": (4, 0)}, private_members={"ZZZhost"},
                struct_size=8)


def test_struct_read_value_round_trips():
    value = UDT.decode(bytes(UDT.encode({"x": 7, "flag": True})))
    assert value == {"x": 7, "flag": True}
    assert UDT.decode(bytes(UDT.encode(value))) == value


@pytest.mark.parametrize("typ", [SINT, INT, DINT, LINT, USINT, UINT, UDINT, ULINT, REAL, LREAL])
def test_numeric_types_reject_bools(typ):
    for value in (True, False):
        with pytest.raises(DataError):
            typ.encode(value)
    assert typ.decode(typ.encode(1)) == 1


@pytest.mark.parametrize("value", [2, -1, 1.0, 0.0, "1", None])
def test_bool_accepts_only_bools_and_0_1(value):
    with pytest.raises(DataError):
        BOOL.encode(value)
    with pytest.raises(DataError):
        DWORD.encode([value] + [False] * 31)


def test_nested_struct_read_value_round_trips():
    outer = StructTag((UDT("inner"), 0), (DINT("y"), 8), (SINT("__pad"), 12), bit_members={},
                      private_members={"__pad"}, struct_size=16)
    value = outer.decode(bytes(outer.encode({"inner": {"x": 7, "flag": True}, "y": 3})))
    assert value == {"inner": {"x": 7, "flag": True}, "y": 3}
    assert outer.decode(bytes(outer.encode(value))) == value
    with pytest.raises(DataError):
        outer.encode({"inner": {"x": 7, "flag": True, "z": 1}, "y": 3})


def test_slc_word_writes_reject_bools():
    from ciplink.exceptions import RequestError
    from ciplink.slc_driver import writeable_value
    tag = {"file_type": "N", "tag": "N7:0"}
    assert writeable_value(tag, 1) == b"\xff\xff\x01\x00"
    with pytest.raises(RequestError):
        writeable_value(tag, True)
    bit = {"file_type": "B", "tag": "B3:0/1", "address_field": 3, "sub_element": 1}
    assert writeable_value(bit, True) == b"\x02\x00\x02\x00"
