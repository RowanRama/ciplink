import types

import pytest

from ciplink.cip import DINT, REAL, STATUS, UDINT, UINT, Services
from ciplink.packets import (
    GenericConnectedRequestPacket,
    GenericConnectedResponsePacket,
    GenericUnconnectedResponsePacket,
    ListIdentityResponsePacket,
    MultiServiceRequestPacket,
    ReadModifyWriteRequestPacket,
    ReadTagFragmentedRequestPacket,
    ReadTagRequestPacket,
    SendRRDataResponsePacket,
    SendUnitDataResponsePacket,
    WriteTagFragmentedRequestPacket,
    WriteTagRequestPacket,
)
from ciplink.packets.logix import MultiServiceResponsePacket
from ciplink.packets.util import get_extended_status, get_service_status, request_path, tag_request_path


def test_request_path_bytes_value_is_one_id():
    # a multi-byte class/instance must go whole into one segment
    assert request_path(b"\x93", UINT.encode(300), b"\x09") == bytes.fromhex("04209325002c013009")


def test_request_path_lists_still_pair_ids():
    assert request_path([0x93, 0x94], [1, 2]) == bytes.fromhex("042093240120942402")


def _encap_header(cmd, status):
    return cmd + b"\x00" * 6 + UDINT.encode(status) + b"\x00" * 12


def test_encapsulation_errors_report_encapsulation_status():
    # a header-only error reply must report its status, not 'Failed to parse reply - '
    r = SendRRDataResponsePacket(None, _encap_header(b"\x6f\x00", 0x64))
    assert not r and r.error == STATUS[0x64]
    r = SendUnitDataResponsePacket(None, _encap_header(b"\x70\x00", 0x65))
    assert not r and r.error == STATUS[0x65]
    r = ListIdentityResponsePacket(None, _encap_header(b"\x63\x00", 0x01))
    assert not r and r.error == STATUS[0x01] and r.identity == {}


def test_services_from_reply_does_not_raise_on_odd_input():
    assert Services.from_reply(b"\x05") == Services.get(b"\x05")
    assert Services.from_reply(b"") is None


def test_get_extended_status():
    # first word is the code even when more words follow; no made-up text when none was sent
    msg = bytes([0x01, 2]) + UINT.encode(0x0109) + UINT.encode(500)
    assert get_extended_status(msg, 0).startswith("Invalid connection size")
    assert get_extended_status(b"\x05\x00", 0) is None
    assert get_extended_status(bytes([0xFF, 1]) + UINT.encode(0x2105), 0).endswith("(ff, 2105)")


def test_generic_reply_without_data_is_success_with_data_type():
    # a Set_Attribute_Single success reply carries no data; data_type must not turn it into an error
    req = types.SimpleNamespace(data_type=REAL)
    resp = GenericUnconnectedResponsePacket(req, b"\x6f\x00" + b"\x00" * 38 + b"\x90\x00\x00\x00")
    assert resp and resp.value == b""
    resp = GenericConnectedResponsePacket(req, b"\x70\x00" + b"\x00" * 44 + b"\x90\x00\x00\x00")
    assert resp and resp.value == b""
    resp = GenericUnconnectedResponsePacket(req, b"\x6f\x00" + b"\x00" * 38 + b"\x8e\x00\x00\x00" + REAL.encode(1.5))
    assert resp and resp.value == 1.5


def test_tag_request_path_contract():
    # pins the encoded paths and the ValueError for a non-integer index
    assert tag_request_path("a.b[2]", {}, False) == bytes.fromhex("0591016100910162002802")
    assert tag_request_path("a[1,2].b", {"instance_id": 5}, True) == bytes.fromhex("06206b24052801280291016200")
    # a program tag by its program-relative ID after the program name
    assert tag_request_path("Program:p.x[3]", {"instance_id": 5}, True) == bytes.fromhex(
        "09910950726f6772616d3a7000206b24052803"
    )
    with pytest.raises(ValueError):
        tag_request_path("a[x]", {}, False)


def test_connected_request_wire_bytes():
    # pins SendUnitData request framing (header, CPF, sequence) built through the base class
    req = GenericConnectedRequestPacket(3, 0x0E, 1, 1, 1)
    assert req.build_request(b"\x01\x02\x03\x04", 7, b"_pycomm_", 0) == bytes.fromhex(
        "70001e0007000000000000005f7079636f6d6d5f00000000000000000a000200a100040001020304b1000a0003000e03200124013001"
    )


@pytest.mark.parametrize(
    "cls, head",
    [
        (GenericConnectedResponsePacket, b"\x70\x00" + b"\x00" * 44),
        (GenericUnconnectedResponsePacket, b"\x6f\x00" + b"\x00" * 38),
    ],
)
def test_generic_reply_values_and_errors(cls, head, caplog):
    # both generic responses decode, fail and log the same way, under their own logger names
    req = types.SimpleNamespace(data_type=REAL)
    resp = cls(req, head + b"\x8e\x00\x00\x00" + REAL.encode(1.5))
    assert resp and resp.value == 1.5
    resp = cls(req, head + b"\x8e\x00\x00\x00" + b"\x00\x00")  # truncated REAL
    assert not resp and resp.value is None and resp.error.startswith("Failed to parse reply - ")
    assert caplog.records[-1].name == f"ciplink.packets.cip.{cls.__name__}"
    resp = cls(req, head + b"\x8e\x00\x0c\x00" + REAL.encode(1.5))  # error status with data
    assert not resp and resp.value is None and resp.error == get_service_status(0x0C)
    resp = cls(types.SimpleNamespace(data_type=None), head + b"\x8e\x00\x0c\x00" + b"\x01\x02")
    assert not resp and resp.value == b"\x01\x02"
    resp = cls(req, None)
    assert not resp and resp.value is None and resp.data_type is REAL


def test_logix_request_packet_bytes():
    info = {'tag_type': 'atomic', 'data_type': 'DINT', 'data_type_name': 'DINT', 'instance_id': 5}
    read = ReadTagRequestPacket(1, 'd', 2, info, 0, True)
    write = WriteTagRequestPacket(3, 'd', 1, info, 1, True, DINT.encode(7))
    read_frag = ReadTagFragmentedRequestPacket.from_request(iter([2]), read, 8)
    write_frag = WriteTagFragmentedRequestPacket.from_request(iter([4]), write, 4, DINT.encode(8))
    multi = MultiServiceRequestPacket(5, [read, write])
    rmw = ReadModifyWriteRequestPacket(6, 'd', info, 2, True)
    rmw.set_bit(3, True, 2)

    path = '0220 6b24 05'
    assert read.build_message() == bytes.fromhex(f'0100 4c {path} 0200')
    assert write.build_message() == bytes.fromhex(f'0300 4d {path} c400 0100 07000000')
    assert read_frag.build_message() == bytes.fromhex(f'0200 52 {path} 0200 08000000')
    assert write_frag.build_message() == bytes.fromhex(f'0400 53 {path} c400 0100 04000000 08000000')
    assert multi.build_message() == bytes.fromhex(
        f'0500 0a 0220 0224 01 0200 0600 0e00 4c {path} 0200 4d {path} c400 0100 07000000'
    )
    assert rmw.build_message() == bytes.fromhex(f'0600 4e {path} 0400 08000000 ffffffff')
    assert (read_frag.type_, write_frag.type_) == ('read', 'write')
    assert repr(MultiServiceResponsePacket(multi)) == (
        "MultiServiceResponsePacket(service=None, command=None, error='No response data received')"
    )
