from unittest import mock

import pytest

from pycomm3.cip import DINT, Array, STATUS
from pycomm3.cip_driver import CIPDriver
from pycomm3.exceptions import RequestError, ResponseError
from pycomm3.logix_driver import LogixDriver, encode_value
from pycomm3.packets import (
    MultiServiceRequestPacket,
    ReadModifyWriteRequestPacket,
    ReadTagFragmentedRequestPacket,
    WriteTagRequestPacket,
    WriteTagFragmentedRequestPacket,
)
from pycomm3.packets.util import get_service_status
from pycomm3.tag import Tag


def _info(name, instance_id, elements=0):
    return {
        "tag_name": name,
        "instance_id": instance_id,
        "tag_type": "atomic",
        "data_type": "DINT",
        "data_type_name": "DINT",
        "type_class": Array(elements, DINT) if elements else DINT,
        "dim": 1 if elements else 0,
        "dimensions": [elements, 0, 0],
    }


def _plc():
    plc = LogixDriver("1.2.3.4", init_tags=False)
    plc._target_is_connected = True
    plc._tags = {
        "d": _info("d", 5),
        "i": _info("i", 6),
        "arr": _info("arr", 7, 1500),
    }
    return plc


def _capture(plc):
    """patch _send_requests, collecting every request and replying with an empty result per request"""
    sent = []

    def fake(requests):
        sent.extend(requests)
        return {r.request_id: Tag(r.tag, None, None, None) for r in requests if r.type_ != "multi"}

    return sent, mock.patch.object(plc, "_send_requests", side_effect=fake)


def test_bit_write_rejects_string_value():
    # write('d.3', 'False') must not set the bit
    plc = _plc()
    sent, patch = _capture(plc)
    with patch:
        result = plc.write("d.3", "False")
    assert result.error and not result
    assert not any(isinstance(r, ReadModifyWriteRequestPacket) for r in sent)

    sent.clear()
    with patch:
        plc.write(("d.3", "1"), ("i.2", None))
    assert not sent

    sent.clear()
    with patch:
        result = plc.write("d.3", False)
    assert result.error is None
    assert len(sent) == 1 and isinstance(sent[0], ReadModifyWriteRequestPacket)


def test_single_write_message_is_stable_and_sized_once():
    # CIPDriver.send builds the message again, it must not grow
    plc = _plc()
    parsed = plc._parse_requested_tags(["d"], "w")
    parsed[0]["value"] = 7
    request = plc._write_build_single_request(parsed[0])
    first = request.message
    request.build_message()
    assert request.message == first

    # the value is already part of the message, a 3960 byte write fits a 4000 byte connection
    parsed = plc._parse_requested_tags(["arr{990}"], "w")
    parsed[0]["value"] = list(range(990))
    request = plc._write_build_single_request(parsed[0])
    assert type(request) is WriteTagRequestPacket
    assert len(request.build_message()) <= plc.connection_size


def test_multi_write_keeps_call_order_and_fits_connection():
    # bit and fragmented writes stay in call order, nothing exceeds the connection size
    plc = _plc()
    sent, patch = _capture(plc)
    with patch:
        plc.write(("d.0", True), ("d", 0))
    assert [type(r) for r in sent] == [ReadModifyWriteRequestPacket, MultiServiceRequestPacket]

    sent.clear()
    with patch:
        plc.write(("arr{1500}", list(range(1500))), ("arr[0]", 5))
    assert [type(r) for r in sent] == [WriteTagFragmentedRequestPacket, MultiServiceRequestPacket]

    # 3996 bytes fits alone but not inside a multi-service packet
    sent.clear()
    with patch:
        plc.write(("d", 1), ("arr{996}", list(range(996))), ("i", 2))
    assert [type(r) for r in sent] == [MultiServiceRequestPacket, WriteTagRequestPacket, MultiServiceRequestPacket]
    assert all(len(r.build_message()) <= plc.connection_size for r in sent)

    # each bit write reports its own result
    sent.clear()
    with patch:
        results = plc.write(("d.0", True), ("d.1", False))
    assert [r.request_id for r in sent] == [0, 1]
    assert all(r.error is None for r in results)


def test_read_size_checks_count_reply_overhead():
    # a 4000 byte read needs a fragmented read, the reply header does not fit otherwise
    plc = _plc()
    sent, patch = _capture(plc)
    with patch:
        plc.read("arr{1000}")
    assert [type(r) for r in sent] == [ReadTagFragmentedRequestPacket]

    # a read too big for a multi-service packet must not drop the other reads
    sent.clear()
    with patch:
        plc.read("arr{996}", "d")
    assert [type(r) for r in sent] == [MultiServiceRequestPacket, ReadTagFragmentedRequestPacket]
    assert [r.tag for r in sent[0].requests] == ["d"]


SUD_HEADER = b"\x70\x00" + bytes(42)  # encapsulation header + CPF of a send_unit_data reply, status 0
MULTI_GENERAL_ERROR = SUD_HEADER + b"\x01\x00" + b"\x8a\x00\x08\x00"  # sequence, multi-service reply, status 0x08
ENCAP_ERROR = b"\x70\x00" + bytes(6) + b"\x64\x00\x00\x00" + bytes(12)  # header only, encapsulation status 0x64


def _reply_with(raw):
    return mock.patch.object(CIPDriver, "send", side_effect=lambda request: request.response_class(request, raw))


def test_error_replies_become_tag_errors():
    # error replies to multi-service or fragmented requests must not escape read()/write()
    plc = _plc()
    with _reply_with(MULTI_GENERAL_ERROR):
        results = plc.read("d", "i")
    assert [r.error for r in results] == [get_service_status(0x08)] * 2

    with _reply_with(ENCAP_ERROR):
        assert [r.error for r in plc.read("d", "i")] == [STATUS[0x64]] * 2
        assert [r.error for r in plc.write(("d", 1), ("i", 2))] == [STATUS[0x64]] * 2
        assert plc.read("arr{1000}").error == STATUS[0x64]

    with mock.patch.object(CIPDriver, "send", side_effect=ResponseError("boom")):
        results = plc.read("d", "i")
    assert [r.error for r in results] == ["boom", "boom"]


def test_bad_tag_requests_fail_per_tag():
    # a bad index, a bit on a struct or too many elements only fail that tag
    plc = _plc()
    plc._tags["udt"] = {
        "tag_name": "udt",
        "instance_id": 8,
        "tag_type": "struct",
        "data_type_name": "MyUDT",
        "data_type": {"name": "MyUDT", "template": {"structure_size": 8, "structure_handle": 0x1234}},
        "dim": 0,
        "dimensions": [0, 0, 0],
    }
    sent, patch = _capture(plc)
    with patch:
        results = plc.read("d", "arr[x]")
    assert len(results) == 2 and "arr[x]" in results[1].error
    assert [r.tag for r in sent[0].requests] == ["d"]

    sent.clear()
    with patch:
        results = plc.write(("d", 1), ("udt.3", True))
    assert len(results) == 2 and "MyUDT" in results[1].error
    assert [r.tag for r in sent[0].requests] == ["d"]

    sent.clear()
    with patch:
        result = plc.read("arr{70000}")
    assert result.error and not sent


def test_fragmented_requests_stop_and_keep_plc_error():
    # a failed segment stops the fragmented write, both keep the PLC's error
    plc = _plc()
    plc._cfg["connection_size"] = 100
    request = WriteTagFragmentedRequestPacket(1, "arr", 200, plc._tags["arr"], 0, True, 0, bytes(800))
    with _reply_with(SUD_HEADER + b"\x01\x00" + b"\xd3\x00\x0f\x00") as send:
        response = plc._send_write_fragmented(request)
    assert send.call_count == 1
    assert response.error == get_service_status(0x0F)

    request = ReadTagFragmentedRequestPacket(1, "arr", 1500, plc._tags["arr"], 0, True)
    with _reply_with(SUD_HEADER + b"\x01\x00" + b"\xd2\x00\x05\x00"):
        response = plc._send_read_fragmented(request)
    assert response.error == get_service_status(0x05)

    # fragments are still joined on success
    request = ReadTagFragmentedRequestPacket(1, "arr", 2, plc._tags["arr"], 0, True)
    replies = iter([b"\xd2\x00\x06\x00\xc4\x00\x01\x00\x00\x00", b"\xd2\x00\x00\x00\xc4\x00\x02\x00\x00\x00"])
    with mock.patch.object(
        CIPDriver, "send", side_effect=lambda r: r.response_class(r, SUD_HEADER + b"\x01\x00" + next(replies))
    ):
        response = plc._send_read_fragmented(request)
    assert response.value == [1, 2]


def test_encode_value_error_says_why():
    # the encoding error reaches Tag.error
    parsed = {"value": [1, 2, 3], "elements": 10, "bool_elements": None, "bit": None, "tag_info": _info("arr", 7, 10)}
    with pytest.raises(RequestError, match="Insufficient data"):
        encode_value(parsed)


def test_tag_names_are_case_insensitive():
    # Logix names are case-insensitive, plc.tags keys keep the controller's spelling
    plc = _plc()
    member = _info("Member", 0)
    plc._tags = {
        "MyTag": _info("MyTag", 5),
        "MyStruct": {**_info("MyStruct", 6), "tag_type": "struct", "data_type": {"internal_tags": {"Member": member}}},
        "Program:Main.t": _info("t", 7),
    }
    assert plc.get_tag_info("mytag") is plc._tags["MyTag"]
    assert plc.get_tag_info("mystruct.member") is member
    assert plc.get_tag_info("program:Main.t") is plc._tags["Program:Main.t"]
    parsed = plc._parse_tag_request("program:Main.t")
    assert parsed["plc_tag"] == "Program:Main.t" and parsed["user_tag"] == "program:Main.t"
    with pytest.raises(RequestError, match="missing"):
        plc.get_tag_info("MyStruct.missing.x")
