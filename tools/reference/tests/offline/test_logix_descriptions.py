import struct
from unittest.mock import Mock

import pytest

from ciplink import ErrorKind, LogixDriver, Tag
from ciplink.exceptions import DataError
from ciplink.logix_descriptions import _member_ids, _program_id
from ciplink.logix_metadata import (
    build_description_index_request,
    build_description_request,
    decode_description_records,
    decode_description_response,
)
from ciplink.packets import MultiServiceRequestPacket, SendUnitDataResponsePacket
from .test_logix_extended_properties import enip


def page(data=b"", first=True, last=True, offset=0):
    return struct.pack("<BBHI", 1, int(first) | (int(last) << 1), 0, offset) + data


def record(instance, value, *, path="", class_id=0x6B, owner=(0, 0),
           language=0x7F, kind=1):
    raw_path = path.encode("utf-8")
    header = (struct.pack("<HIIHH", class_id, instance, *owner, len(raw_path))
              + raw_path + struct.pack("<HHIIIIH", language, 1, 123, 0, 0, 0, kind))
    if kind == 4:
        return header
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return header + struct.pack("<H", len(raw)) + raw


@pytest.fixture
def plc():
    driver = LogixDriver("192.168.1.100", init_tags=False)
    driver._target_is_connected = True
    driver._session = 7
    driver._target_cid = b"1234"
    driver._tags = {
        "Array": {"instance_id": 425, "data_type_name": "DINT", "dim": 1,
                  "dimensions": [30, 0, 0]},
        "Scalar": {"instance_id": 1063, "data_type_name": "DINT", "dim": 0,
                   "dimensions": [0, 0, 0]},
    }
    return driver


def responses(plc, payloads, status=0):
    payloads = iter(payloads)
    requests = []

    def send(request):
        wire = request.build_message()[2:]
        requests.append(wire)
        assert wire[0] == 0x53
        reply = bytes([0xD3, 0, status, 0]) + next(payloads)
        return SendUnitDataResponsePacket(request, enip(reply))

    plc.send = Mock(side_effect=send)
    return requests


def program_tag(plc):
    plc._tags["Program:Test.Input"] = {
        "instance_id": 8, "data_type_name": "BOOL", "dim": 0,
        "dimensions": [0, 0, 0],
    }
    plc._info["programs"] = {"Test": {"instance_id": 155}}
    plc.generic_message = Mock(return_value=Tag(
        "reference", bytes.fromhex("01000d0000000320682500da5a"), None, None))


def struct_tag(plc):
    definition = {
        "name": "Sample",
        "template": {"member_count": 1, "object_definition_size": 20},
        "internal_tags": {"Acked": {"data_type_name": "BOOL"}},
    }
    plc._tags["Structs"] = {
        "instance_id": 657, "template_instance_id": 1426,
        "data_type": definition, "data_type_name": "Sample", "tag_type": "struct",
        "dim": 1, "dimensions": [200, 0, 0],
    }
    plc._cache["id:udt"][1426] = definition
    raw = bytes(8) + b"Sample;n\x00Acked\x00"
    raw += bytes((-len(raw)) % 4) + struct.pack("<H", 0xEF20)
    plc._read_template = Mock(return_value=raw)
    return definition


def test_array_element_has_its_own_description(plc):
    requests = responses(plc, [page(record(425, "Element text", path="[0]"))])
    result = plc.get_tag_description("Array[0]")
    assert result.value == "Element text"
    assert result.tag == "Array[0].@Description"
    assert requests == [build_description_request(425, path="[0]")]


def test_array_element_inherits_base_description(plc):
    responses(plc, [page(), page(record(425, "Array text"))])
    assert plc.get_tag_description("Array[1]").value == "Array text"
    assert plc.send.call_count == 2


def test_empty_element_description_is_preserved(plc):
    responses(plc, [page(record(425, "", path="[1]"))])
    result = plc.get_tag_description("Array[1]")
    assert result and result.value == ""
    assert plc.send.call_count == 1


def test_element_bit_description(plc):
    requests = responses(plc, [page(record(425, "Bit text", path="[0].1"))])
    assert plc.get_tag_description("Array[0].1").value == "Bit text"
    assert requests == [build_description_request(425, path="[0].1")]


def test_program_tag_does_not_read_controller_symbol_with_same_id(plc):
    program_tag(plc)
    requests = responses(plc, [page(record(
        0x006B5ADA, "Program text", class_id=0x68, owner=(8, 0)))])
    assert plc.get_tag_description("Program:Test.Input").value == "Program text"
    assert requests == [build_description_request(
        0x006B5ADA, class_id=0x68, owner_context=(8, 0))]
    assert plc.generic_message.call_count == 1


def test_program_tag_description_cache_is_connection_specific(plc):
    program_tag(plc)
    payload = page(record(0x006B5ADA, "Text", class_id=0x68, owner=(8, 0)))
    responses(plc, [payload, payload, payload])
    assert plc.get_tag_description("Program:Test.Input")
    assert plc.get_tag_description("program:test.input")
    plc._target_cid = b"5678"
    assert plc.get_tag_description("Program:Test.Input")
    assert plc.generic_message.call_count == 2


def test_program_reference_cache_reuses_identical_scope(plc):
    program_tag(plc)
    assert _program_id(plc, "Test") == _program_id(plc, "Test") == 23258
    plc.generic_message.assert_called_once()


@pytest.mark.parametrize("path,expected", [
    (bytes.fromhex("022068241a"), 26),
    (bytes.fromhex("0320682500da5a"), 23258),
    (bytes.fromhex("0420682600da5a0000"), 23258),
])
def test_program_reference_formats(plc, path, expected):
    program_tag(plc)
    plc.generic_message.return_value = Tag("reference", bytes.fromhex("01000d000000") + path, None, None)
    assert _program_id(plc, "Test") == expected


@pytest.mark.parametrize("raw", [b"", bytes.fromhex("01000c0000000320682500da5a"),
                                 bytes.fromhex("01000d00000003206a2500da5a"),
                                 bytes.fromhex("01000d00000003206825000000"),
                                 bytes.fromhex("01000d000000042068260000000100")])
def test_invalid_program_reference_returns_an_error(plc, raw):
    program_tag(plc)
    plc.generic_message.return_value = Tag("reference", raw, None, None)
    plc.send = Mock(side_effect=AssertionError("Unexpected request"))
    assert not plc.get_tag_description("Program:Test.Input")
    plc.send.assert_not_called()


def test_udt_member_override(plc):
    struct_tag(plc)
    path = "[0].!0592EF20"
    requests = responses(plc, [page(record(657, "Member text", path=path))])
    assert plc.get_tag_description("Structs[0].Acked").value == "Member text"
    assert requests == [build_description_request(657, path=path)]


def test_udt_member_default_and_index_cache(plc):
    struct_tag(plc)
    default = record(0x84FE0592, "Acked", class_id=0x6C, owner=(0xEF20, 0))
    requests = responses(plc, [page(), page(default), page()])
    assert plc.get_tag_description("Structs[0].Acked").value == "Acked"
    assert plc.get_tag_description("Structs[1].Acked").value == "Acked"
    assert requests[1] == build_description_index_request()
    plc._read_template.assert_called_once()


def test_index_handles_other_binary_text_and_removed_records(plc):
    struct_tag(plc)
    values = (record(12, b"\x80\x82\xff\x00", class_id=0x68)
              + record(13, None, class_id=0x68, kind=4)
              + record(0x84FE0592, "Acked", class_id=0x6C, owner=(0xEF20, 0)))
    responses(plc, [page(), page(values)])
    assert plc.get_tag_description("Structs[0].Acked").value == "Acked"


def test_udt_member_falls_back_to_element_description(plc):
    struct_tag(plc)
    responses(plc, [page(), page(), page(record(657, "Element text", path="[0]"))])
    assert plc.get_tag_description("Structs[0].Acked").value == "Element text"


def test_duplicate_member_defaults_return_an_error(plc):
    struct_tag(plc)
    default = record(0x84FE0592, "Acked", class_id=0x6C, owner=(0xEF20, 0))
    responses(plc, [page(), page(default + default)])
    result = plc.get_tag_description("Structs[0].Acked")
    assert not result and "Ambiguous" in result.error


def test_template_identifier_continuation(plc):
    definition = struct_tag(plc)
    raw = plc._read_template.return_value
    plc._read_template.return_value = raw[:-1]
    plc.generic_message = Mock(return_value=Tag("members", raw[-1:], None, None))
    assert _member_ids(plc, 1426, definition) == {"Acked": 0xEF20}
    assert plc.generic_message.call_args.kwargs["request_data"] == struct.pack("<IH", len(raw) - 1, 1)


@pytest.mark.parametrize("name", ["A", "AA", "AAA", "AAAA"])
def test_template_member_identifier_padding(plc, name):
    definition = struct_tag(plc)
    raw = bytes(8) + name.encode() + b";n\x00Acked\x00"
    raw += bytes((-len(raw)) % 4) + struct.pack("<H", 0xEF20)
    plc._read_template.return_value = raw
    assert _member_ids(plc, 1426, definition) == {"Acked": 0xEF20}


def test_nested_udt_member(plc):
    struct_tag(plc)
    child = plc._tags["Structs"]["data_type"]
    parent = {"name": "Outer", "template": {"member_count": 1},
              "internal_tags": {"Inner": {"data_type": child, "data_type_name": "Sample",
                                           "tag_type": "struct"}}}
    plc._tags["Outer"] = {"instance_id": 100, "template_instance_id": 4000,
                          "data_type": parent, "tag_type": "struct"}
    path = ".!0FA00001.!0592EF20"
    responses(plc, [page(record(100, "Nested text", path=path))])
    assert plc.get_tag_description("Outer.Inner.Acked").value == "Nested text"


def test_program_member_array(plc):
    struct_tag(plc)
    program_tag(plc)
    plc._tags["Program:Test.Structs"] = dict(plc._tags["Structs"], instance_id=9)
    path = "[2].!0592EF20"
    responses(plc, [page(record(0x006B5ADA, "Scoped member", class_id=0x68,
                                owner=(9, 0), path=path))])
    assert plc.get_tag_description("Program:Test.Structs[2].Acked").value == "Scoped member"


@pytest.mark.parametrize("field,value", [
    ("instance", 426), ("path", "[1]"), ("class_id", 0x68),
    ("owner", (1, 0)), ("owner", (0, 1)), ("language", 0x0409),
])
def test_wrong_element_target_is_rejected(plc, field, value):
    params = {"instance": 425, "path": "[0]"}
    params[field] = value
    responses(plc, [page(record(value="Wrong text", **params))])
    result = plc.get_tag_description("Array[0]")
    assert not result and "different tag/language" in result.error
    assert plc.send.call_count == 1


def test_path_fragmentation(plc):
    raw = record(425, "Element text", path="[12]")
    requests = responses(plc, [page(raw[:15], last=False),
                              page(raw[15:], first=False, offset=15)])
    assert plc.get_tag_description("Array[12]").value == "Element text"
    assert requests[1] == build_description_request(425, path="[12]", offset=15)


@pytest.mark.parametrize("address", [None, "", "Array[-1]", "Array[30]", "Array[x]",
                                      "Array[0,1]", "Array[1][2]", "Scalar[0]",
                                      "Scalar.32", "Scalar.0.Member", "Array.0", "Array{2}",
                                      "Program:", "Program:Test", "Scalar..Member"])
def test_invalid_addresses_do_not_send_requests(plc, address):
    plc.send = Mock(side_effect=AssertionError("Unexpected request"))
    assert not plc.get_tag_description(address)
    plc.send.assert_not_called()


def test_multidimensional_bounds(plc):
    plc._tags["Matrix"] = {"instance_id": 1, "dim": 2, "dimensions": [3, 4, 0]}
    responses(plc, [page(record(1, "Cell text", path="[2,3]"))])
    assert plc.get_tag_description("Matrix[2,3]").value == "Cell text"
    assert not plc.get_tag_description("Matrix[3,0]")
    assert plc.send.call_count == 1


def test_array_member_requires_an_element(plc):
    struct_tag(plc)
    plc.send = Mock(side_effect=AssertionError("Unexpected request"))
    assert not plc.get_tag_description("Structs.Acked")
    plc.send.assert_not_called()
    plc._read_template.assert_not_called()


def test_permission_denied_does_not_fall_back(plc):
    responses(plc, [b""], status=0x0F)
    result = plc.get_tag_description("Array[0]")
    assert not result and result.error == "Permission denied"
    assert plc.send.call_count == 1


def test_connection_change_discards_reply(plc):
    responses(plc, [page(record(425, "Text", path="[0]"))])
    send = plc.send.side_effect

    def changed(request):
        response = send(request)
        plc._target_cid = b"9876"
        return response

    plc.send.side_effect = changed
    result = plc.get_tag_description("Array[0]")
    assert not result and "Connection changed" in result.error


def test_records_with_variable_paths_and_utf8():
    raw = record(425, "caf\u00e9", path="[10]")
    result = decode_description_response([page(raw)])
    assert result["path"] == "[10]" and result["value"] == "caf\u00e9"
    values = decode_description_records([page(raw + record(1, None, kind=4))])
    assert len(values) == 2 and values[1]["value"] is None
    for end in range(len(raw)):
        if end:
            with pytest.raises(DataError):
                decode_description_response([page(raw[:end])])


@pytest.mark.parametrize("kwargs", [
    {"class_id": -1}, {"owner_context": (0,)}, {"owner_context": (-1, 0)},
    {"owner_context": (0, 65536)}, {"path": None}, {"path": "a" * 65536},
])
def test_invalid_description_parameters(kwargs):
    with pytest.raises(ValueError):
        build_description_request(1, **kwargs)


def controller(plc, answers=(), status=(), unanswered=False):
    """answers each description request (by its bytes) with answers' page, or an empty page, or once with status;
    multi-service packets get a sub-reply per request, or with unanswered a status 0x08 reply"""
    answers, status, sent = dict(answers), dict(status), []

    def answer(wire):
        code = status.pop(wire, 0)
        return bytes([0xD3, 0, code, 0]) + (b"" if code else answers.get(wire, page()))

    def send(request):
        sent.append(request)
        if not isinstance(request, MultiServiceRequestPacket):
            return request.response_class(request, enip(answer(request.build_message()[2:])))
        if unanswered:
            return request.response_class(request, enip(bytes([0x8A, 0, 0x08, 0])))
        replies = [answer(sub.tag_only_message()) for sub in request.requests]
        offsets, offset = b"", 2 + 2 * len(replies)
        for reply in replies:
            offsets += struct.pack("<H", offset)
            offset += len(reply)
        status_code = 0x1E if any(reply[2] for reply in replies) else 0
        return request.response_class(request, enip(bytes([0x8A, 0, status_code, 0]) + struct.pack(
            "<H", len(replies)) + offsets + b"".join(replies)))

    plc.send = Mock(side_effect=send)
    return sent


def wires(packet):
    requests = packet.requests if isinstance(packet, MultiServiceRequestPacket) else [packet]
    return [request.tag_only_message() for request in requests]


def test_batch_equals_sequential_reads(plc):
    struct_tag(plc)
    program_tag(plc)
    req = build_description_request
    answers = {
        req(425, path="[0]"): page(record(425, "Element text", path="[0]")),
        req(425): page(record(425, "Array text")),
        req(425, path="[0].1"): page(record(425, "Bit text", path="[0].1")),
        req(0x006B5ADA, class_id=0x68, owner_context=(8, 0)): page(
            record(0x006B5ADA, "Program text", class_id=0x68, owner=(8, 0))),
        req(657, path="[0].!0592EF20"): page(record(657, "Member text", path="[0].!0592EF20")),
        build_description_index_request(): page(record(0x84FE0592, "Acked", class_id=0x6C, owner=(0xEF20, 0))),
    }
    denied = {req(425, path="[2]"): 0x0F}
    names = ["Array[0]", "Array[1]", "Array[0].1", "Program:Test.Input", "Structs[0].Acked",
             "Structs[1].Acked", "Scalar", "Array[30]", "Array[2]", "Missing"]
    sent = controller(plc, answers, denied)
    batch = plc.get_tag_descriptions(*names)
    batch_packets = len(sent)
    plc._cache["descriptions"].clear()
    controller(plc, answers, denied)
    sequential = [plc.get_tag_description(name) for name in names]
    assert [(tag, tag.error_kind) for tag in batch] == [(tag, tag.error_kind) for tag in sequential]
    assert [tag.value for tag in batch[:6]] == ["Element text", "Array text", "Bit text", "Program text",
                                                 "Member text", "Acked"]
    assert batch[6].error == "No description returned for language 0x007f"
    assert batch[8].error == "Permission denied" and batch[8].error.status == 0x0F
    assert batch_packets < plc.send.call_count


def test_identical_requests_are_sent_once(plc):
    sent = controller(plc, {build_description_request(425): page(record(425, "Array text"))})
    results = plc.get_tag_descriptions("Array[1]", "Array[1]", "Array[2]")
    assert [tag.value for tag in results] == ["Array text"] * 3
    assert [tag.tag for tag in results] == ["Array[1].@Description"] * 2 + ["Array[2].@Description"]
    assert wires(sent[0]) == [build_description_request(425, path="[1]"),
                              build_description_request(425, path="[2]")]
    assert wires(sent[1]) == [build_description_request(425)]
    assert len(sent) == 2


@pytest.mark.parametrize("own_text,rounds", [(True, 1), (False, 2)])
def test_one_packet_per_round(plc, own_text, rounds):
    answers = {build_description_request(425, path=f"[{i}]"): page(record(425, f"Text {i}", path=f"[{i}]"))
               for i in range(10)} if own_text else {}
    answers[build_description_request(425)] = page(record(425, "Array text"))
    sent = controller(plc, answers)
    results = plc.get_tag_descriptions(*(f"Array[{i}]" for i in range(10)))
    assert all(results) and len(sent) == rounds
    assert isinstance(sent[0], MultiServiceRequestPacket) and len(sent[0].requests) == 10


def test_batch_continues_a_paged_reply_on_its_own(plc):
    raw = record(425, "Element text", path="[12]")
    sent = controller(plc, {
        build_description_request(425, path="[0]"): page(record(425, "Text", path="[0]")),
        build_description_request(425, path="[12]"): page(raw[:15], last=False),
        build_description_request(425, path="[12]", offset=15): page(raw[15:], first=False, offset=15),
    })
    results = plc.get_tag_descriptions("Array[12]", "Array[0]")
    assert [tag.value for tag in results] == ["Element text", "Text"]
    assert wires(sent[1]) == [build_description_request(425, path="[12]", offset=15)]
    assert len(sent) == 2


@pytest.mark.parametrize("unanswered,code", [(False, 0x06), (False, 0x11), (True, None)])
def test_requests_without_room_in_the_packet_are_read_alone(plc, unanswered, code):
    element = build_description_request(425, path="[0]")
    sent = controller(plc, {
        element: page(record(425, "Text", path="[0]")),
        build_description_request(425, path="[1]"): page(record(425, "Other", path="[1]")),
    }, {} if unanswered else {element: code}, unanswered)
    results = plc.get_tag_descriptions("Array[0]", "Array[1]")
    assert [tag.value for tag in results] == ["Text", "Other"]
    assert wires(sent[1]) == [element]
    assert len(sent) == (3 if unanswered else 2)


def test_connection_change_discards_batch(plc):
    controller(plc, {build_description_request(425, path="[0]"): page(record(425, "Text", path="[0]"))})
    send = plc.send.side_effect

    def changed(request):
        response = send(request)
        plc._target_cid = b"9876"
        return response

    plc.send.side_effect = changed
    results = plc.get_tag_descriptions("Array[0]", "Array[1]", "Array[30]")
    assert [tag.error for tag in results[:2]] == ["Connection changed during Description read"] * 2
    assert results[0].error_kind is ErrorKind.COMM
    assert "outside" in results[2].error


def test_connection_change_keeps_the_tags_finished_in_earlier_rounds(plc):
    controller(plc, {build_description_request(425, path="[0]"): page(record(425, "Text", path="[0]"))})
    send = plc.send.side_effect
    calls = []

    def changed_on_second_round(request):
        response = send(request)
        calls.append(request)
        if len(calls) == 2:
            plc._target_cid = b"9876"
        return response

    plc.send.side_effect = changed_on_second_round
    results = plc.get_tag_descriptions("Array[0]", "Array[1]")
    assert results[0].value == "Text"
    assert results[1].error == "Connection changed during Description read"


def test_shared_less_specific_candidate_and_its_error(plc):
    base = build_description_request(425)
    sent = controller(plc, {base: page(record(425, "Array text"))})
    results = plc.get_tag_descriptions("Array", "Array[3]", "Array[4]")
    assert [tag.value for tag in results] == ["Array text"] * 3
    assert [wires(packet) for packet in sent] == [
        [base, build_description_request(425, path="[3]"), build_description_request(425, path="[4]")], [base]]
    controller(plc, status={base: 0x0F})
    results = plc.get_tag_descriptions("Array[3]", "Array[4]", "Scalar")
    assert [(tag.error, tag.error_kind) for tag in results[:2]] == [("Permission denied", ErrorKind.ACCESS)] * 2
    assert results[2].error_kind is ErrorKind.NOT_FOUND
