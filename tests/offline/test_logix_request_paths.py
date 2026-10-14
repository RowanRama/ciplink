"""Tag requests address the base tag by its symbol instance ID, parsed requests are memoized."""
from unittest import mock

import pytest

from ciplink.cip import DINT, DWORD, Array
from ciplink.cip_driver import CIPDriver
from ciplink.exceptions import RequestError
from ciplink.logix_driver import LogixDriver
from ciplink.packets import (
    MultiServiceRequestPacket,
    ReadModifyWriteRequestPacket,
    ReadTagFragmentedRequestPacket,
    WriteTagFragmentedRequestPacket,
)
from ciplink.tag import Tag

PROGRAM = "910c50726f6772616d3a4d61696e"  # DataSegment('Program:Main')
UDT_VAL = "05206b2408910356616c00"  # udt (id 8) .Val
PTAG_VAL = "0c" + PROGRAM + "206b2409910356616c00"  # Program:Main.ptag (id 9) .Val


def _atomic(name, instance_id, dtype=DINT, length=0):
    return {
        "tag_name": name, "instance_id": instance_id, "tag_type": "atomic",
        "data_type": dtype.__name__, "data_type_name": dtype.__name__,
        "type_class": Array(length, dtype) if length else dtype,
        "dim": 1 if length else 0, "dimensions": [length, 0, 0],
    }


def _member(offset, dtype=DINT, length=0):
    return {
        "offset": offset, "tag_type": "atomic", "data_type": dtype.__name__, "data_type_name": dtype.__name__,
        "array": length, "type_class": Array(length, dtype) if length else dtype,
    }


UDT = {
    "name": "MyUDT",
    "internal_tags": {"Val": _member(0), "Data": _member(4, length=1000), "Flags": _member(4004, DWORD, 2)},
    "attributes": ["Val", "Data", "Flags"],
    "template": {"structure_size": 4012, "structure_handle": 0x1234},
}


def _struct(name, instance_id, length=0):
    return {
        "tag_name": name, "instance_id": instance_id, "tag_type": "struct", "data_type": UDT,
        "data_type_name": "MyUDT", "dim": 1 if length else 0, "dimensions": [length, 0, 0],
    }


def _plc():
    plc = LogixDriver("1.2.3.4", init_tags=False)
    plc._target_is_connected = True
    tags = [
        _atomic("d", 5), _atomic("arr", 7, length=1500), _struct("udt", 8), _struct("udts", 12, 3),
        _atomic("bools", 13, DWORD, 2), _atomic("big", 11, length=70000),
        _struct("Program:Main.ptag", 9), _atomic("Program:Main.parr", 10, length=10),
        _atomic("Program:Main.pbig", 14, length=70000),
    ]
    plc._tags = {info["tag_name"]: info for info in tags}
    return plc


def _capture(plc):
    """patch _send_requests, collecting every request and replying with an empty result per request"""
    sent = []

    def fake(requests):
        sent.extend(requests)
        return {r.request_id: Tag(r.tag, None, None, None) for r in _flat(requests)}

    return sent, mock.patch.object(plc, "_send_requests", side_effect=fake)


def _flat(requests):
    return [sub for r in requests for sub in (r.requests if isinstance(r, MultiServiceRequestPacket) else [r])]


def _read(plc, *tags):
    sent, patch = _capture(plc)
    with patch:
        plc.read(*tags)
    return [r.tag_only_message().hex() for r in _flat(sent)]


def _write(plc, *tags_values):
    sent, patch = _capture(plc)
    with patch:
        results = plc.write(*tags_values)
    assert all(r.error is None for r in (results if isinstance(results, list) else [results]))
    return sent


def test_controller_reads_address_the_base_tag_by_id():
    # members, base indexes and members of an indexed base all start at the base tag's ID
    assert _read(_plc(), "d", "arr[5]", "udt.Val", "udts[2].Val") == [
        "4c" + "02206b2405" + "0100",
        "4c" + "03206b24072805" + "0100",
        "4c" + UDT_VAL + "0100",
        "4c" + "06206b240c2802910356616c00" + "0100",
    ]


def test_program_reads_address_the_tag_by_its_program_id():
    # the program by name, then the tag by its program-relative ID
    assert _read(_plc(), "Program:Main.parr", "program:Main.parr[3]", "Program:Main.ptag.Val") == [
        "4c" + "09" + PROGRAM + "206b240a" + "0100",
        "4c" + "0a" + PROGRAM + "206b240a2803" + "0100",
        "4c" + PTAG_VAL + "0100",
    ]


def test_bit_and_bool_array_reads_use_ids():
    # a bit reads its integer, a BOOL array element reads its DWORD
    assert _read(_plc(), "d.3", "udt.Val.3", "Program:Main.ptag.Val.3", "bools[40]", "udt.Flags[40]") == [
        "4c" + "02206b2405" + "0100",
        "4c" + UDT_VAL + "0100",
        "4c" + PTAG_VAL + "0100",
        "4c" + "03206b240d2801" + "0100",
        "4c" + "07206b24089105466c616773002801" + "0100",
    ]


def test_fragmented_read_uses_ids():
    plc = _plc()
    sent, patch = _capture(plc)
    with patch:
        plc.read("Program:Main.pbig{1500}")
    assert [type(r) for r in sent] == [ReadTagFragmentedRequestPacket]
    assert sent[0].tag_only_message().hex() == "52" + "09" + PROGRAM + "206b240e" + "dc05"


def test_writes_use_ids():
    # full writes, member writes and read-modify-write masks
    sent = _write(_plc(), ("udt.Val", 1), ("Program:Main.parr[3]", 2), ("d.3", True))
    assert [r.tag_only_message().hex() for r in _flat(sent)] == [
        "4d" + UDT_VAL + "c400" + "0100" + "01000000",
        "4d" + "0a" + PROGRAM + "206b240a2803" + "c400" + "0100" + "02000000",
        "4e" + "02206b2405" + "0400" + "08000000" + "ffffffff",
    ]

    sent = _write(_plc(), ("Program:Main.ptag.Val.0", True), ("udt.Flags[40]", True))
    assert [r.tag_only_message().hex() for r in _flat(sent)] == [
        "4e" + PTAG_VAL + "0400" + "01000000" + "ffffffff",
        "4e" + "07206b24089105466c616773002801" + "0400" + "00010000" + "ffffffff",
    ]


def test_bool_array_masks_on_other_words_use_ids():
    # a BOOL slice crossing a DWORD gets a mask per word, the second word is not the parsed tag
    sent = _write(_plc(), ("bools[30]{4}", [True, False, True, True]))
    requests = _flat(sent)
    assert all(isinstance(r, ReadModifyWriteRequestPacket) for r in requests)
    assert [r.tag_only_message().hex() for r in requests] == [
        "4e" + "03206b240d2800" + "0400" + "00000040" + "ffffff7f",
        "4e" + "03206b240d2801" + "0400" + "03000000" + "ffffffff",
    ]


def test_fragmented_write_segments_use_ids():
    plc = _plc()
    sent = _write(plc, ("udt.Data{1000}", list(range(1000))))
    assert [type(r) for r in sent] == [WriteTagFragmentedRequestPacket]

    segments = []

    def record(request):
        segments.append(request)
        return request.response_class(request, b"\x70\x00" + bytes(42) + b"\x01\x00" + b"\xd3\x00\x00\x00")

    with mock.patch.object(CIPDriver, "send", side_effect=record):
        assert plc._send_write_fragmented(sent[0])
    assert len(segments) > 1
    header = bytes.fromhex("53" + "05206b2408910444617461" + "c400" + "e803")
    assert all(r.tag_only_message().startswith(header) for r in segments)
    assert b"".join(r.value for r in segments) == DINT[1000].encode(list(range(1000)))


def test_large_array_chunks_encode_their_own_index():
    # each chunk starts at its own element, not at the unchunked tag's path
    plc = _plc()
    sent, patch = _capture(plc)
    with patch:
        plc.read("big{70000}")
    assert [r.tag_only_message().hex() for r in sent] == [
        "52" + "03206b240b2800" + "ffff",
        "52" + "04206b240b2900ffff" + "7111",
    ]

    sent = _write(plc, ("Program:Main.pbig{70000}", list(range(70000))))
    assert [r.request_path.hex() for r in sent] == [
        "0a" + PROGRAM + "206b240e2800",
        "0b" + PROGRAM + "206b240e2900ffff",
    ]


def test_names_without_instance_ids():
    # use_instance_ids off, or no ID known for the base tag, addresses it by name
    plc = _plc()
    plc._cfg["use_instance_ids"] = False
    assert _read(plc, "arr[5]", "udt.Val", "Program:Main.ptag.Val") == [
        "4c" + "049103617272002805" + "0100",
        "4c" + "06910375647400910356616c00" + "0100",
        "4c" + "0d" + PROGRAM + "910470746167910356616c00" + "0100",
    ]
    sent = _write(plc, ("d.3", True))
    assert sent[0].tag_only_message().hex() == "4e" + "0291016400" + "0400" + "08000000" + "ffffffff"

    plc = _plc()
    plc._tags = dict(plc._tags, udt=_struct("udt", None), d=_atomic("d", 0))  # 0 is not a symbol instance
    assert _read(plc, "udt.Val", "d") == [
        "4c" + "06910375647400910356616c00" + "0100",
        "4c" + "0291016400" + "0100",
    ]


def test_parse_is_memoized_and_packets_reuse_its_path():
    plc = _plc()
    with mock.patch.object(plc, "_parse_new_tag_request", wraps=plc._parse_new_tag_request) as parse:
        first = plc._parse_tag_request("udt.Val")
        first["plc_tag"] = "changed"  # callers get copies
        second = plc._parse_tag_request("udt.Val")
    assert parse.call_count == 1
    assert second["plc_tag"] == "udt.Val" and second["request_path"].hex() == UDT_VAL

    # repeated reads and writes encode nothing, the packets use the memoized path
    _write(plc, ("udt.Val", 1), ("udt.Val.0", True))
    with mock.patch("ciplink.logix_driver.tag_request_path") as parse_encode, \
            mock.patch("ciplink.packets.logix.tag_request_path") as packet_encode:
        assert _read(plc, "udt.Val") == ["4c" + UDT_VAL + "0100"]
        _write(plc, ("udt.Val", 1), ("udt.Val.0", True))
    assert not parse_encode.called and not packet_encode.called


def test_failed_parse_is_not_memoized():
    # a tag that shows up later in the same tag list (as a lazy load adds it) parses
    plc = _plc()
    with pytest.raises(RequestError):
        plc._parse_tag_request("late")
    plc._tags["late"] = _atomic("late", 30)
    assert plc._parse_tag_request("late")["request_path"].hex() == "02206b241e"


def test_memo_follows_tag_list_and_use_instance_ids():
    plc = _plc()
    assert plc._parse_tag_request("d")["request_path"].hex() == "02206b2405"

    plc._tags = dict(plc._tags, d=_atomic("d", 42))  # e.g. plc2._tags = plc1.tags
    assert plc._parse_tag_request("d")["request_path"].hex() == "02206b242a"

    with mock.patch.object(plc, "_upload_tag_list", return_value=[_atomic("d", 43)]):
        plc.get_tag_list()
    assert plc._parse_tag_request("d")["request_path"].hex() == "02206b242b"

    plc._cfg["use_instance_ids"] = False
    assert plc._parse_tag_request("d")["request_path"].hex() == "0291016400"
    plc._cfg["use_instance_ids"] = True
    assert plc._parse_tag_request("d")["request_path"].hex() == "02206b242b"


def test_lazy_reopen_starts_a_new_memo():
    plc = LogixDriver("1.2.3.4", lazy_tags=True)
    plc._tags = {"d": _atomic("d", 5)}
    assert plc._parse_tag_request("d")["request_path"].hex() == "02206b2405"
    with mock.patch.object(CIPDriver, "open", return_value=True), mock.patch.object(plc, "_initialize_driver"):
        assert plc.open()
    plc._tags["d"] = _atomic("d", 44)  # loaded again for the new connection
    assert plc._parse_tag_request("d")["request_path"].hex() == "02206b242c"


def test_memo_is_bounded():
    # names that never repeat (a moving index) start the memo over instead of growing it
    plc = _plc()
    with mock.patch("ciplink.logix_driver._PARSE_MEMO_SIZE", 3):
        for i in range(10):
            assert plc._parse_tag_request(f"arr[{i}]")["plc_tag"] == f"arr[{i}]"
        assert len(plc._parse_memo[1]) <= 3
        with mock.patch.object(plc, "_parse_new_tag_request") as parse:
            plc._parse_tag_request("arr[9]")  # the newest is still memoized
    assert not parse.called


def test_non_string_tag_fails_per_tag():
    plc = _plc()
    sent, patch = _capture(plc)
    with patch:
        results = plc.read(["d"], "d")
    assert results[0].error and results[1].error is None
