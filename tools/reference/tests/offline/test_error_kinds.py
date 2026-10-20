"""Every LogixDriver read/write/description error is a TagError with an ErrorKind."""
import pickle
import struct
from unittest import mock

import pytest

import ciplink
from ciplink import DINT, REAL, ErrorKind, LogixDriver, ResponseError, Tag, TagError
from ciplink.cip_driver import CIPDriver
from ciplink.packets import (
    MultiServiceRequestPacket, SendRRDataResponsePacket, SendUnitDataResponsePacket,
    get_extended_status_code, response_error, status_kind,
)

from .test_logix_tag_table_version import EDITED, TAGS, V2, V3, FakePLC, clock, connected
from .test_logix_transfers import Controller, definition, driver, reply


class Faulty(Controller):
    """a Controller that fails the tags in ``ext`` with general status 0xFF and that extended status"""

    def __init__(self, ext, **kwargs):
        super().__init__(**kwargs)
        self.ext = ext

    def send(self, request):
        if getattr(request, "tag", None) in self.ext:
            self.sent.append(request)
            return reply(request, status=0xFF, extended=struct.pack("<H", self.ext[request.tag]))
        return super().send(request)


def read(plc, *tags, controller=None, side_effect=None):
    with mock.patch.object(CIPDriver, "send", side_effect=side_effect or (controller or Controller()).send):
        return plc.read(*tags)


# TagError and Tag.error_kind

def test_tag_error_is_a_str_with_a_kind():
    error = TagError("Object does not exist", ErrorKind.NOT_FOUND, 0x16)
    assert error == "Object does not exist" and isinstance(error, str)
    assert (error.kind, error.status, error.ext) == (ErrorKind.NOT_FOUND, 0x16, None)
    assert TagError("x", "comm").kind is ErrorKind.COMM
    copy = pickle.loads(pickle.dumps(error))
    assert copy == error and (copy.kind, copy.status, copy.ext) == (error.kind, error.status, error.ext)
    assert ciplink.ErrorKind is ErrorKind and ciplink.TagError is TagError


def test_tag_error_kind():
    assert Tag("a", 1).error_kind is None
    assert Tag("a", None, None, "plain").error_kind is ErrorKind.OTHER
    tag = Tag("a", None, None, TagError("gone", ErrorKind.NOT_FOUND))
    assert tag.error_kind is ErrorKind.NOT_FOUND
    name, value, typ, error = tag
    assert error == "gone" and len(tag) == 4
    assert tag._replace(error=TagError("x", ErrorKind.COMM)).error_kind is ErrorKind.COMM


# controller statuses

@pytest.mark.parametrize("status,ext,kind", [
    (0x04, None, ErrorKind.NOT_FOUND), (0x05, None, ErrorKind.NOT_FOUND), (0x16, None, ErrorKind.NOT_FOUND),
    (0x0F, None, ErrorKind.ACCESS),
    (0x0C, None, ErrorKind.REFUSED), (0x10, None, ErrorKind.REFUSED), (0x02, None, ErrorKind.REFUSED),
    (0x03, None, ErrorKind.BAD_VALUE), (0x09, None, ErrorKind.BAD_VALUE), (0x13, None, ErrorKind.BAD_VALUE),
    (0x15, None, ErrorKind.BAD_VALUE), (0x20, None, ErrorKind.BAD_VALUE),
    (0x08, None, ErrorKind.BAD_REQUEST), (0x26, None, ErrorKind.BAD_REQUEST),
    (0x11, None, ErrorKind.DEVICE), (0x1E, None, ErrorKind.DEVICE),
    (0xFF, 0x2104, ErrorKind.NOT_FOUND), (0xFF, 0x2105, ErrorKind.NOT_FOUND), (0xFF, 0x210B, ErrorKind.NOT_FOUND),
    (0xFF, 0x2107, ErrorKind.BAD_VALUE), (0xFF, 0x2109, ErrorKind.BAD_VALUE), (0xFF, 0x7, ErrorKind.BAD_VALUE),
    (0xFF, 0x2100, ErrorKind.ACCESS), (0xFF, 0x2101, ErrorKind.ACCESS), (0xFF, 0x2102, ErrorKind.ACCESS),
    (0xFF, 0x2103, ErrorKind.ACCESS),
    (0xFF, 0x2108, ErrorKind.REFUSED), (0xFF, 0x2106, ErrorKind.REFUSED),
    (0xFF, 0x210A, ErrorKind.BAD_REQUEST),
    (0xFF, 0x2001, ErrorKind.DEVICE), (0xFF, None, ErrorKind.DEVICE),
])
def test_status_kind(status, ext, kind):
    assert status_kind(status, ext) is kind


def test_extended_status_code():
    assert get_extended_status_code(bytes(48) + b"\xff\x01\x07\x21", 48) == 0x2107
    assert get_extended_status_code(bytes(48) + b"\x05\x00", 48) is None
    assert get_extended_status_code(bytes(10), 48) is None


def test_response_error_reads_the_status_of_either_reply():
    unit = SendUnitDataResponsePacket(None, b"\x70\x00" + bytes(44) + b"\xcc\x00\xff\x01\x05\x21")
    error = response_error(unit)
    assert (error.kind, error.status, error.ext) == (ErrorKind.NOT_FOUND, 0xFF, 0x2105) and error == unit.error
    rr = SendRRDataResponsePacket(None, b"\x6f\x00" + bytes(38) + b"\xcc\x00\xff\x01\x00\x21")
    assert response_error(rr, "denied") == "denied" and response_error(rr).kind is ErrorKind.ACCESS
    assert response_error(SendUnitDataResponsePacket(None, None)).kind is ErrorKind.COMM  # no reply
    bad_command = SendUnitDataResponsePacket(None, b"\x70\x00" + bytes(6) + b"\x65\x00\x00\x00" + bytes(40))
    assert response_error(bad_command).kind is ErrorKind.COMM


@pytest.mark.parametrize("status,kind", [(0x05, ErrorKind.NOT_FOUND), (0x0F, ErrorKind.ACCESS),
                                         (0x10, ErrorKind.REFUSED), (0x11, ErrorKind.DEVICE)])
def test_failed_reads_alone_and_in_a_multi_service_packet(status, kind):
    plc = driver(definition("a"), definition("b"))
    a = read(plc, "a", controller=Controller(fail={"a": status}))
    assert (a.error_kind, a.error.status) == (kind, status)
    a, b = read(plc, "a", "b", controller=Controller(fail={"a": status}))
    assert (a.error_kind, a.error.status, b.error) == (kind, status, None)


def test_extended_status_of_a_sub_reply():
    plc = driver(definition("a"), definition("b"))
    a, b = read(plc, "a", "b", controller=Faulty({"a": 0x2104}))
    assert (a.error_kind, a.error.status, a.error.ext, b.error) == (ErrorKind.NOT_FOUND, 0xFF, 0x2104, None)
    with mock.patch.object(CIPDriver, "send", side_effect=Faulty({"a": 0x2107}).send):
        assert plc.write("a", 1).error_kind is ErrorKind.BAD_VALUE


def test_lost_or_unparseable_replies_are_comm():
    plc = driver(definition("a"), definition("b"))
    assert read(plc, "a", side_effect=ResponseError("boom")).error_kind is ErrorKind.COMM
    for results in (read(plc, "a", "b", side_effect=lambda r: r.response_class(r, None)),
                    read(plc, "a", "b", side_effect=lambda r: reply(r, b"\x05\x00"))):  # reply count mismatch
        assert [r.error_kind for r in results] == [ErrorKind.COMM] * 2


def _drop_last_reply(controller, request):
    response = controller.send(request)
    if isinstance(request, MultiServiceRequestPacket):
        response.responses.pop()
    return response


def test_missing_sub_reply_is_comm():
    plc = driver(definition("a"), definition("b"))
    a, b = read(plc, "a", "b", side_effect=lambda r: _drop_last_reply(Controller(), r))
    assert a.error is None and b.error == "No reply" and b.error_kind is ErrorKind.COMM


def test_fragmented_read_without_progress_is_comm():
    plc = driver(definition("big", DINT, 300), connection_size=500)
    result = read(plc, "big{300}", side_effect=lambda r: reply(r, struct.pack("<H", DINT.code), status=6))
    assert result.error_kind is ErrorKind.COMM and "no progress" in result.error


# errors found before sending

def aoi_struct():
    member = definition("Count")
    data_type = {"name": "Valve", "internal_tags": {"Count": member, "EnableIn": definition("EnableIn")},
                 "attributes": ["Count", "EnableIn"], "template": {"structure_size": 8, "structure_handle": 1},
                 "aoi": {"whole_read": False, "readable": ["EnableIn"], "refused": ["Count"]}}
    return {"tag_name": "valve", "tag_type": "struct", "data_type": data_type, "data_type_name": "Valve",
            "instance_id": None, "dim": 0, "dimensions": [0, 0, 0], "type_class": DINT}


@pytest.mark.parametrize("tag,kind", [
    ("nope", ErrorKind.NOT_FOUND), ("valve.nope", ErrorKind.NOT_FOUND),
    ("valve.Count", ErrorKind.ACCESS),
    ("a.nope", ErrorKind.BAD_REQUEST), ("r.1", ErrorKind.BAD_REQUEST), ("a.32", ErrorKind.BAD_REQUEST),
    ("a{0}", ErrorKind.BAD_REQUEST), ("a{x}", ErrorKind.BAD_REQUEST),
    ("a{70000}", ErrorKind.BAD_REQUEST),
])
def test_bad_requests_send_nothing(tag, kind):
    plc = driver(definition("a"), definition("r", REAL), definition("arr", DINT, 3), aoi_struct())
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.read(tag)
    assert result.error_kind is kind, result.error
    send.assert_not_called()


def test_lazy_tag_that_does_not_exist():
    plc = LogixDriver("127.0.0.1", lazy_tags=True)
    plc._target_is_connected = True
    with mock.patch.object(plc, "_get_instance_attribute_list_service", return_value=[]), \
            mock.patch.object(CIPDriver, "send") as send:
        result = plc.read("nope")
    assert result.error_kind is ErrorKind.NOT_FOUND and "doesn't exist" in result.error
    send.assert_not_called()


@pytest.mark.parametrize("tag,value", [("a", "x"), ("arr{3}", [1]), ("big{70000}", [1]), ("big{70000}", b"\0")])
def test_values_that_do_not_fit_are_bad_values(tag, value):
    plc = driver(definition("a"), definition("arr", DINT, 3), definition("big", DINT, 70000))
    with mock.patch.object(CIPDriver, "send") as send:
        result = plc.write(tag, value)
    assert result.error_kind is ErrorKind.BAD_VALUE, result.error
    send.assert_not_called()


def test_unexpected_exception_is_a_bad_request():
    plc = driver(definition("a"))
    with mock.patch.object(plc, "_send_requests", return_value={}):
        assert plc.read("a").error_kind is ErrorKind.BAD_REQUEST
        assert plc.write("a", 1).error_kind is ErrorKind.BAD_REQUEST


def test_chunk_and_aoi_merges_keep_the_kind_of_the_first_failure():
    plc = driver(definition("big", DINT, 70000), aoi_struct())
    parsed = {0: {"user_tag": "big{70000}", "elements": 70000, "tag_info": definition("big", DINT, 70000),
                  "chunk_requests": [{"request_id": (0, 0)}, {"request_id": (0, 1)}]}}
    denied = TagError("denied", ErrorKind.ACCESS, 0x0F)
    results = {(0, 0): Tag("big", None, None, denied)}
    plc._merge_chunk_results(parsed, results, "r")
    assert results[0].error == "denied" and results[0].error_kind is ErrorKind.ACCESS
    results = {(0, 0): Tag("big", [1], "DINT")}
    plc._merge_chunk_results(parsed, results, "r")
    assert results[0].error_kind is ErrorKind.COMM

    parsed = {0: {"user_tag": "valve", "tag_info": aoi_struct(),
                  "aoi_requests": [{"request_id": (0, "EnableIn")}, {"request_id": (0, "Mode")}]}}
    results = {(0, "EnableIn"): Tag("valve.EnableIn", None, None, TagError("gone", ErrorKind.NOT_FOUND, 5))}
    plc._merge_aoi_results(parsed, results)
    error = results[0].error
    assert error == "EnableIn - gone" and (error.kind, error.status) == (ErrorKind.NOT_FOUND, 5)
    results = {(0, "EnableIn"): Tag("valve.EnableIn", True, "BOOL")}
    plc._merge_aoi_results(parsed, results)
    assert results[0].error == "Mode - No reply" and results[0].error_kind is ErrorKind.COMM


# tag table version

def test_table_changed_during_a_read_and_its_retry():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        fake.edit_at(0, EDITED, V2)
        fake.edit_at(3, dict(EDITED, b=(11, 2)), V3)
        a, b = plc.read("a", "b")
    assert a.error_kind is b.error_kind is ErrorKind.TABLE_CHANGED


def test_table_changed_during_a_write():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        fake.edit_at(1, EDITED, V2)
        a, b = plc.write(("a", 10), ("b", 20))
    assert a.error_kind is b.error_kind is ErrorKind.TABLE_CHANGED


def test_backoff_is_refused():
    fake = FakePLC(TAGS)
    with connected(fake) as plc, clock():
        fake.set(TAGS, None)
        refused = plc.read("a")
        assert refused.error_kind is ErrorKind.REFUSED and "controller busy" in refused.error
        assert plc.write("a", 1).error_kind is ErrorKind.REFUSED


# descriptions and metadata authentication

def test_description_errors():
    plc = driver(dict(definition("a"), instance_id=5))
    with mock.patch("ciplink.logix_driver.read_descriptions", return_value=[None]):
        assert plc.get_tag_description("a").error_kind is ErrorKind.NOT_FOUND
    assert plc.get_tag_description("nope").error_kind is ErrorKind.NOT_FOUND
    assert plc.get_tag_description("a{2}").error_kind is ErrorKind.BAD_REQUEST
    with mock.patch("ciplink.logix_driver.read_descriptions",
                    return_value=[ResponseError("Invalid program reference")]):
        assert plc.get_tag_description("a").error_kind is ErrorKind.DEVICE
    denied = SendUnitDataResponsePacket(None, b"\x70\x00" + bytes(44) + b"\xcc\x00\x0f\x00")
    with mock.patch.object(plc, "send", return_value=denied):
        result = plc.get_tag_description("a")
    assert result.error_kind is ErrorKind.ACCESS and result.error.status == 0x0F
    plc._micro800 = True
    assert plc.get_tag_description("a").error_kind is ErrorKind.BAD_REQUEST


def test_metadata_authentication_errors():
    plc = driver()
    assert plc.authenticate_metadata(object()).error_kind is ErrorKind.BAD_REQUEST
    denied = SendUnitDataResponsePacket(None, b"\x70\x00" + bytes(44) + b"\xcb\x00\x0f\x00")
    with mock.patch.object(plc, "generic_message", return_value=Tag("challenge", denied, None, denied.error)):
        result = plc.authenticate_metadata()
    assert result.error.startswith("Certificate challenge rejected") and result.error_kind is ErrorKind.ACCESS
