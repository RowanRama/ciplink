from collections import defaultdict

import pytest

from pycomm3.exceptions import BufferEmptyError, DataError
from pycomm3.cip.data_types import (
    BOOL,
    BYTE,
    DATE_AND_TIME,
    DWORD,
    LWORD,
    PADDED_EPATH,
    SHORT_STRING,
    SINT,
    STRING,
    STRING2,
    STRINGI,
    STRINGN,
    TIME32,
    UDINT,
    UINT,
    USINT,
    WORD,
    Array,
    ConstructedDataTypeSegment,
    DataSegment,
    DataTypes,
    ElementaryDataTypeSegment,
    LogicalSegment,
    NetworkSegment,
    PortSegment,
    Struct,
    SymbolicSegment,
    n_bytes,
)
from pycomm3.custom_types import FixedSizeString, StructTag
from pycomm3.map import EnumMap
from pycomm3.packets.util import tag_request_path


# BOOL encoders must not treat strings / None as truthy
@pytest.mark.parametrize("value", ["False", "0", "", b"\x00", None])
def test_bool_encode_rejects_non_bool(value):
    with pytest.raises(DataError):
        BOOL.encode(value)


def test_bool_encode_accepts_bools_and_ints():
    assert BOOL.encode(False) == b"\x00"
    assert BOOL.encode(True) == b"\xff"
    assert BOOL.encode(1) == b"\xff"
    assert BOOL.encode(0) == b"\x00"


def test_bit_array_encode_rejects_strings():
    with pytest.raises(DataError):
        DWORD.encode(["1"] + [False] * 31)
    assert DWORD.encode([1] + [False] * 31) == b"\x01\x00\x00\x00"


def test_struct_tag_bit_member_rejects_strings():
    udt = StructTag(
        (SINT("host"), 0),
        bit_members={"flag": (0, 0)},
        private_members={"host"},
        struct_size=1,
    )
    with pytest.raises(DataError):
        udt.encode({"flag": "False"})
    assert udt.encode({"flag": True}) == b"\x01"
    assert udt.encode({"flag": False}) == b"\x00"


# STRING2 length counts 2-byte characters
def test_string2_round_trip():
    assert STRING2.encode("ab") == b"\x02\x00a\x00b\x00"
    assert STRING2.decode(STRING2.encode("ab")) == "ab"


def test_string2_in_struct_keeps_stream_aligned():
    s = Struct(STRING2("s"), USINT("n"))
    assert s.decode(s.encode({"s": "ab", "n": 7})) == {"s": "ab", "n": 7}


def test_string_encoding_unchanged():
    assert STRING.encode("ab") == b"\x02\x00ab"
    assert STRING.decode(b"\x02\x00ab") == "ab"


# STRINGN empty strings and multi-byte utf-8 characters
def test_stringn_empty():
    assert STRINGN.decode(STRINGN.encode("")) == ""


def test_stringn_empty_in_unbounded_array():
    data = STRINGN.encode("a") + STRINGN.encode("") + STRINGN.encode("b")
    assert Array(None, STRINGN).decode(data) == ["a", "", "b"]


def test_stringn_counts_encoded_characters():
    assert STRINGN.decode(STRINGN.encode("é")) == "é"
    assert STRINGN.encode("ab", 2) == b"\x02\x00\x02\x00a\x00b\x00"
    assert STRINGN.decode(STRINGN.encode("ab", 2)) == "ab"


# DATE_AND_TIME takes one (time, date) value and is 6 bytes
def test_date_and_time_in_struct():
    expected = UDINT.encode(1) + UINT.encode(2)
    assert Struct(DATE_AND_TIME("dt")).encode({"dt": (1, 2)}) == expected


def test_date_and_time_encode_forms():
    expected = UDINT.encode(1) + UINT.encode(2)
    assert DATE_AND_TIME.encode((1, 2)) == expected
    assert DATE_AND_TIME.encode(1, 2) == expected
    assert DATE_AND_TIME.size == 6
    assert DATE_AND_TIME.decode(DATE_AND_TIME.encode((1, 2))) == (1, 2)
    with pytest.raises(DataError):
        DATE_AND_TIME.encode("bad")


# short reads raise instead of returning truncated data
def test_short_string_data_raises():
    with pytest.raises(DataError):
        STRING.decode(b"\x05\x00ab")


def test_short_bytes_raises():
    with pytest.raises(DataError):
        n_bytes(4).decode(b"ab")
    assert n_bytes(-1).decode(b"ab") == b"ab"


# TIME32 is a signed microsecond duration
def test_time32_is_signed():
    assert TIME32.decode(b"\xff\xff\xff\xff") == -1
    assert TIME32.encode(-1) == b"\xff\xff\xff\xff"
    assert DataTypes.get(0xD6) == "FTIME"


# bit array decode is bit order LSB first, encode needs exactly 8 * size values
def test_bit_array_decode_lsb_first():
    assert DWORD.decode(b"\x01\x00\x00\x80") == [True] + [False] * 30 + [True]
    assert BYTE.decode(b"\x00") == [False] * 8


@pytest.mark.parametrize("typ", [BYTE, WORD, DWORD, LWORD])
def test_bit_array_round_trip(typ):
    bits = [i % 3 == 0 for i in range(typ.size * 8)]
    assert typ.decode(typ.encode(bits)) == bits


def test_bit_array_encode_wrong_count_message():
    with pytest.raises(DataError) as exc:
        DWORD.encode([True] * 3)
    assert str(exc.value.__cause__) == "DWORD needs exactly 32 values, got 3"


# STRINGI decode behaviour (round trip and error wrapping)
def test_stringi_round_trip():
    data = STRINGI.encode(("hello", STRING, "eng", 4), ("ab", SHORT_STRING, "fra", 4))
    assert STRINGI.decode(data) == (["hello", "ab"], ["eng", "fra"], [4, 4])


def test_stringi_decode_errors():
    with pytest.raises(DataError, match="as STRINGI"):
        STRINGI.decode(b"\x01eng\x99\x04\x00")  # unknown string type code
    with pytest.raises(BufferEmptyError):
        STRINGI.decode(b"")


# StructTag encode copies into a plain dict, so a defaultdict missing a member still raises
def test_struct_tag_encode_defaultdict_missing_member_raises():
    udt = StructTag(
        (SINT("host"), 0),
        (SINT("x"), 1),
        bit_members={"flag": (0, 0)},
        private_members={"host"},
        struct_size=2,
    )
    with pytest.raises(DataError):
        udt.encode(defaultdict(int, {"x": 1}))
    values = defaultdict(int, {"x": 1, "flag": True})
    assert udt.encode(values) == b"\x01\x01"
    assert dict(values) == {"x": 1, "flag": True}


# 32-bit logical segments use logical format 0b10
def test_logical_segment_32bit_format():
    assert PADDED_EPATH.encode([LogicalSegment(70000, "instance_id")]) == b"\x26\x00\x70\x11\x01\x00"
    assert PADDED_EPATH.encode([LogicalSegment(70000, "member_id")]) == b"\x2a\x00\x70\x11\x01\x00"
    assert tag_request_path("big[70000]", {}, False) == bytes.fromhex("069103626967002a0070110100")
    # 8/16-bit unchanged
    assert PADDED_EPATH.encode([LogicalSegment(5, "member_id")]) == b"\x28\x05"
    assert PADDED_EPATH.encode([LogicalSegment(300, "member_id")]) == b"\x29\x00\x2c\x01"


# arrays with a DataType length (class or instance)
def test_array_decode_derived_length():
    assert SINT[SINT].decode(b"\x05\x01\x02\x03\x04\x05\x00\x00\x00") == [1, 2, 3, 4, 5]
    assert Array(UINT, USINT).decode(b"\x03\x00\x0a\x0b\x0c") == [10, 11, 12]
    assert Array(UINT("n"), USINT).decode(b"\x03\x00\x0a\x0b\x0c") == [10, 11, 12]
    assert Array(UINT, Struct(USINT("a"), USINT("b"))).decode(b"\x01\x00\x01\x02") == [{"a": 1, "b": 2}]


def test_unbound_bit_array_decode_is_flat():
    data = b"\x01\x00\x00\x80\x03\x00\x00\x00"
    assert DWORD[None].decode(data) == DWORD[2].decode(data)
    assert len(DWORD[None].decode(data)) == 64


# bit array encode must not drop a partial trailing chunk
def test_bit_array_encode_partial_chunk():
    with pytest.raises(DataError):
        DWORD[2].encode([True] * 40)
    assert DWORD[2].encode([True] * 64) == b"\xff" * 8


# port numbers above 14 use the extended port field
def test_port_segment_extended_port():
    assert PortSegment.encode(PortSegment(16, 1)) == b"\x0f\x10\x00\x01"
    assert PortSegment.encode(PortSegment(18, "10.0.0.1")) == b"\x1f\x08\x12\x00" + b"10.0.0.1"
    assert PortSegment.encode(PortSegment("bp", 0)) == b"\x01\x00"
    assert PortSegment.encode(PortSegment(2, "10.0.0.1")) == b"\x12\x08" + b"10.0.0.1"


# Array accepts an element type instance
def test_array_element_type_instance():
    assert Array(2, UINT("x")).decode(b"\x01\x00\x02\x00") == [1, 2]
    assert Array(2, n_bytes(2)).decode(b"abcd") == [b"ab", b"cd"]
    assert Array(2, UINT("x")).encode([1, 2]) == b"\x01\x00\x02\x00"


# simple data segment length is a word count, data padded to a word
def test_data_segment_bytes_word_count():
    assert DataSegment.encode(DataSegment(b"\x01\x02\x03")) == b"\x80\x02\x01\x02\x03\x00"
    assert DataSegment.encode(DataSegment(b"\x01\x02")) == b"\x80\x01\x01\x02"
    # ANSI extended symbol unchanged
    assert DataSegment.encode(DataSegment("abc")) == b"\x91\x03abc\x00"


# FixedSizeString rejects values longer than its fixed size
def test_fixed_size_string_too_long():
    t = FixedSizeString(8)
    with pytest.raises(DataError):
        t.encode("x" * 9)
    assert t.encode("x" * 8) == b"\x08\x00\x00\x00" + b"x" * 8
    assert t.encode("ab") == b"\x02\x00\x00\x00ab" + b"\x00" * 6
    # STRING: 84 byte padded size, but DATA is only SINT[82]
    s = FixedSizeString(84, max_len_=82)
    with pytest.raises(DataError):
        s.encode("x" * 83)
    assert s.encode("x" * 82) == b"\x52\x00\x00\x00" + b"x" * 82 + b"\x00\x00"


# segment types without an encoder say so
@pytest.mark.parametrize(
    "seg", [NetworkSegment, SymbolicSegment, ConstructedDataTypeSegment, ElementaryDataTypeSegment]
)
def test_unsupported_segment_encode(seg):
    with pytest.raises(DataError) as e:
        seg.encode(seg())
    assert isinstance(e.value.__cause__, NotImplementedError)


# EnumMap name lookups are case-insensitive
def _enum_maps(cls=EnumMap):
    for sub in cls.__subclasses__():
        yield sub
        yield from _enum_maps(sub)


@pytest.mark.parametrize("enum", list(_enum_maps()), ids=lambda c: c.__name__)
def test_enum_map_lookups(enum):
    for name in enum.attributes:
        expected = enum[name.lower()]
        for key in (name, name.upper(), name.title()):
            assert enum[key] == expected
            assert enum.get(key) == expected
            assert key in enum
    assert "not_a_member" not in enum
    assert enum.get("not_a_member") is None


def test_enum_map_value_lookup():
    from pycomm3.cip import DataTypes, Services, BOOL

    assert DataTypes[0xC1] == "BOOL" and 0xC1 in DataTypes
    assert DataTypes["Bool"] is BOOL
    assert Services[b"\x01"] == "get_attributes_all" and b"\x01" in Services
