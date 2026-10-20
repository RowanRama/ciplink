"""Write values that do not fit the tag's type are rejected per tag (BAD_VALUE), nothing is sent for that tag."""
from unittest import mock

import pytest

from ciplink import (
    BOOL, DINT, DWORD, INT, LINT, LREAL, REAL, SINT, UDINT, UINT, ULINT, USINT, DataError, ErrorKind,
    FixedSizeString, StructTag,
)
from ciplink.cip_driver import CIPDriver
from ciplink.packets import WriteTagRequestPacket

from .test_logix_transfers import Controller, definition, driver

UDT = StructTag((DINT("x"), 0), (SINT("ZZZhost"), 4), bit_members={"flag": (4, 0)}, private_members={"ZZZhost"},
                struct_size=8)


def struct_definition(name, type_class, size):
    data_type = {"name": "UDT", "internal_tags": {}, "attributes": [],
                 "template": {"structure_size": size, "structure_handle": 0x1234}}
    return {"tag_name": name, "tag_type": "struct", "data_type": data_type, "data_type_name": "UDT",
            "instance_id": None, "dim": 0, "dimensions": [0, 0, 0], "type_class": type_class}


def plc_and_controller():
    plc = driver(
        definition("a"), definition("arr", DINT, 3), definition("big", DINT, 70000), definition("b", BOOL),
        definition("r", REAL), definition("flags", DWORD, 3), struct_definition("s", UDT, 8),
        struct_definition("text", FixedSizeString(84, max_len_=82), 88),
    )
    return plc, Controller({f"flags[{i}]": 0 for i in range(3)} | {"a": 0})


def write(*tags_values):
    plc, controller = plc_and_controller()
    with mock.patch.object(CIPDriver, "send", side_effect=controller.send):
        return plc.write(*tags_values), controller


@pytest.mark.parametrize("tag,value", [
    # more values than elements, they were truncated
    ("arr{3}", [1, 2, 3, 4]), ("arr", [1, 2]), ("flags[0]{32}", [True] * 33), ("flags[1]{3}", [True] * 4),
    ("big{70000}", [1] * 70001),
    # BOOL: only a bool or 0/1
    ("b", 2), ("b", 1.0), ("b", "True"), ("b", None), ("a.3", 2), ("a.3", 0.5), ("flags[1]", 2),
    ("flags[1]{2}", [True, 2]), ("flags[0]{32}", [True] * 31 + [2]),
    # no bools for numbers, no floats for integers
    ("a", True), ("r", False), ("arr{2}", [1, True]), ("a", 5.0),
    # structures: unknown or missing members, BOOL members
    ("s", {"x": 1, "flag": True, "y": 2}), ("s", {"flag": True}), ("s", {"x": 1, "flag": 2}),
    ("text", "x" * 83),
])
def test_rejected_values_send_nothing(tag, value):
    plc, _ = plc_and_controller()
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.write(tag, value)
    assert not result and result.error_kind is ErrorKind.BAD_VALUE, result.error
    send.assert_not_called()


@pytest.mark.parametrize("tag,value", [
    ("arr{3}", [1, 2, 3]), ("arr", [5]), ("arr", 5), ("flags[0]{32}", [True] * 32), ("flags[1]{3}", [1, 0, True]),
    ("b", True), ("b", 0), ("a.3", 1), ("a.3", False), ("r", 5), ("r", 2.5),
    ("s", {"x": 1, "flag": True}), ("s", {"x": 1, "flag": 0, "ZZZhost": 0}), ("text", "x" * 82),
])
def test_values_that_fit_are_written(tag, value):
    result, _ = write(tag, value)
    assert result and result.error is None


def test_other_tags_of_the_write_still_go():
    (bad, good), controller = write(("arr{3}", [1, 2, 3, 4]), ("a", 5))
    assert bad.error_kind is ErrorKind.BAD_VALUE and "Too many values" in bad.error
    assert good.error is None
    assert [r.tag for r in controller.sent if isinstance(r, WriteTagRequestPacket)] == ["a"]


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
