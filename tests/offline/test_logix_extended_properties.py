"""Wire-level tests for the read-only extended-property investigation example."""

import struct

import pytest

from examples.logix_extended_properties import (
    decode_atomic_read,
    decode_cip_reply,
    extract_cip_reply,
    probe,
)
from examples.logix_metadata_transports import (
    DEFINITION_READ,
    IDENTITY_READ,
    METADATA_DIRECTORY_READ,
    compare_transports,
)
from pycomm3 import Tag
from pycomm3.logix_metadata import build_description_request
from pycomm3.packets import SendRRDataResponsePacket, SendUnitDataResponsePacket


def enip(cip, connected=True, extra_items=()):
    address = (0xA1, b"\x01\x02\x03\x04") if connected else (0, b"")
    data = (0xB1, b"\x6b\x00" + cip) if connected else (0xB2, cip)
    items = (address,) + extra_items + (data,)
    cpf = struct.pack("<IHH", 0, 0, len(items))
    cpf += b"".join(struct.pack("<HH", kind, len(value)) + value for kind, value in items)
    return struct.pack("<HHII8sI", 0x70 if connected else 0x6F, len(cpf), 1, 0, b"\0" * 8, 0) + cpf


@pytest.mark.parametrize("raw", [
    # Actual replies from the GuardLogix 5580 v37.13; no property payload.
    "70001a00603e0040000000000000000000000000000000000000000000000200a1000400ac49b62eb10006008800d3000f00",
    "6f001400613e0040000000005f7079636f6d6d5f00000000000000000000020000000000b2000400d3000f00",
])
def test_observed_permission_denied(raw):
    reply = decode_cip_reply(extract_cip_reply(bytes.fromhex(raw)))
    assert reply["service"] == 0x53
    assert reply["general_status"] == 0x0F
    assert reply["status_text"] == "Permission denied"
    assert reply["additional_status"] == []
    assert reply["data_hex"] == ""
    with pytest.raises(ValueError, match="successful standard Read Tag"):
        decode_atomic_read(reply)


@pytest.mark.parametrize("connected", [True, False])
def test_cpf_items_and_additional_status_have_variable_lengths(connected):
    cip = bytes.fromhex("d3001f0234127856616263")
    packet = enip(cip, connected, extra_items=((0x8000, b"extra"),))
    reply = decode_cip_reply(extract_cip_reply(packet))
    assert reply["additional_status"] == [0x1234, 0x5678]
    assert reply["data_hex"] == "616263"


def test_success_status_is_labelled_success():
    assert decode_cip_reply(bytes.fromhex("cb000000"))["status_text"] == "Success"


@pytest.mark.parametrize("cip,expected", [
    ("cc000000c40030750000", {"type": "DINT", "type_code": 0xC4, "value": 30000}),
    ("cc000000ca0000003442", {"type": "REAL", "type_code": 0xCA, "value": 45.0}),
    ("cc000000c10301", {"type": "BOOL", "type_code": 0x3C1, "value": True}),
    ("cc000000d0000300616263", {"type": "STRING", "type_code": 0xD0, "value": "abc"}),
])
def test_scalar_decode_uses_returned_type(cip, expected):
    assert decode_atomic_read(decode_cip_reply(bytes.fromhex(cip))) == expected


@pytest.mark.parametrize("cip", ["", "cc0000", "cc000001", "4c000000", "cc010000"])
def test_malformed_cip_headers_are_rejected(cip):
    with pytest.raises(ValueError):
        decode_cip_reply(bytes.fromhex(cip))


@pytest.mark.parametrize("cip", [
    "cc000000",                    # No type code.
    "cc000000c40001",              # Truncated DINT.
    "cc000000c4000100000002000000", # Two values for a scalar request.
    "cc000000a002123400000000",     # Logix struct, not CIP STRING.
    "d3000000040061626364",         # Unknown protected-object payload.
    "cc000006c40001000000",         # Partial response, not a complete value.
])
def test_unknown_or_incomplete_payloads_are_not_guessed(cip):
    with pytest.raises(Exception):
        decode_atomic_read(decode_cip_reply(bytes.fromhex(cip)))


def test_encapsulation_and_cpf_lengths_are_checked():
    packet = enip(bytes.fromhex("d3000f00"))
    for truncated in (packet[:20], packet[:-1], packet + b"\0"):
        with pytest.raises(ValueError):
            extract_cip_reply(truncated)
    missing_item = bytearray(packet)
    struct.pack_into("<H", missing_item, 30, 3)
    with pytest.raises(ValueError, match="CPF item header"):
        extract_cip_reply(bytes(missing_item))
    oversized_item = bytearray(packet)
    struct.pack_into("<H", oversized_item, 34, 1000)
    with pytest.raises(ValueError, match="CPF item data"):
        extract_cip_reply(bytes(oversized_item))


def test_probe_only_issues_read_services(monkeypatch):
    requests = []

    class ReadOnlyPLC:
        _micro800 = False
        info = {"product_name": "GuardLogix 5580 Controller",
                "revision": {"major": 37, "minor": 13}, "keyswitch": "REMOTE RUN"}

        def __init__(self, path, init_tags):
            assert init_tags is False
            self._sequence = (i for i in range(1, 100))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get_tag_list(self):
            return [{"tag_name": "Example", "instance_id": 12}]

        def send(self, request):
            message = request.build_message()[2:]
            requests.append(message)
            service = message[0]
            if service == 0x4C:
                cip = bytes.fromhex("cc000000c40030750000") if len(requests) == 1 else bytes.fromhex("cc000500")
            elif service == 0x03:
                cip = bytes.fromhex("8300000001000b00000000")
            else:
                assert service == 0x53
                assert message == bytes.fromhex(
                    "5304210049032500000001010000000000000f00ff006b000c00000000000000000000007f000100"
                )
                cip = bytes.fromhex("d3000f00")
            return SendUnitDataResponsePacket(request, enip(cip))

    monkeypatch.setattr("examples.logix_extended_properties.LogixDriver", ReadOnlyPLC)
    report = probe("10.137.22.8", ["Example"], description_object=True)
    assert [message[0] for message in requests] == [0x4C] * 7 + [0x03, 0x53]
    assert report["requests"][0]["decoded"]["value"] == 30000
    assert report["requests"][-1]["reply"]["general_status"] == 0x0F
    assert "decoded" not in report["requests"][-1]
    assert "decoded" not in report["requests"][1]


@pytest.mark.parametrize("tags,properties", [
    ([], ("Min",)), (["Program:Main.Example"], ("Min",)),
    (["Example[0]"], ("Min",)), (["Example"], ("Unknown",)),
])
def test_invalid_probe_inputs_are_rejected_before_connecting(monkeypatch, tags, properties):
    def must_not_connect(*args, **kwargs):
        pytest.fail("Invalid inputs must not contact a PLC")
    monkeypatch.setattr("examples.logix_extended_properties.LogixDriver", must_not_connect)
    with pytest.raises(ValueError):
        probe("10.137.22.8", tags, properties)


def test_transport_comparison_preserves_denials_and_only_sends_reads(monkeypatch):
    sessions = []

    class ReadOnlySession:
        def __init__(self, ip):
            assert ip == "10.137.22.8"
            self._cfg = {"cid": b"CID!", "vsn": b"VSN!", "cip_path": []}
            self._sequence = (i for i in range(1, 100))
            self.requests = []
            self._target_is_connected = False
            sessions.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.closed = True

        def _forward_open(self):
            self._target_is_connected = True
            return True

        def generic_message(self, **kwargs):
            # The only generic service is ordinary Forward Open. No captured
            # class 0x64 setup services or cached connection identities are sent.
            assert kwargs["service"] == b"\x54"
            assert kwargs["class_code"] == b"\x06"
            assert kwargs["instance"] == 1
            assert kwargs["connected"] is False
            assert kwargs["request_data"] == (
                b"\x06\x9b" + bytes(4) + b"CID!CSM\x00VSN!\x02\0\0\0"
                + struct.pack("<IH", 2000000, 0x43F8) * 2 + b"\xa3"
            )
            return Tag("forward_open", b"TCID", None, None)

        def send(self, request):
            connected = self._target_is_connected
            wire = request.build_message()[2 if connected else 0:]
            self.requests.append(wire)
            status = 0x0F if wire[0] == 0x53 else 0
            cip = bytes([wire[0] | 0x80, 0, status, 0])
            packet_type = SendUnitDataResponsePacket if connected else SendRRDataResponsePacket
            return packet_type(request, enip(cip, connected=connected))

    monkeypatch.setattr("examples.logix_metadata_transports.CIPDriver", ReadOnlySession)
    monkeypatch.setattr("examples.logix_metadata_transports.os.urandom", lambda length: b"CS")
    report = compare_transports("10.137.22.8", 1063)
    assert len(sessions) == 4
    for session, profile in zip(sessions, report["profiles"]):
        assert session.closed
        assert "transport_error" not in profile
        assert session.requests == [IDENTITY_READ, METADATA_DIRECTORY_READ,
                                    DEFINITION_READ, build_description_request(1063)]
        assert [read["reply"]["general_status"] for read in profile["reads"]] == [0, 0, 15, 15]
        assert [read["reply"]["data_hex"] for read in profile["reads"][-2:]] == ["", ""]
        assert all("decoded" not in read for read in profile["reads"])
    assert [session._target_is_connected for session in sessions] == [False, True, True, True]
    assert [session._cfg.get("connection_size") for session in sessions] == [None, 504, 4000, 504]
    assert [session._cfg.get("extended forward open") for session in sessions] == [None, False, True, False]


@pytest.mark.parametrize("ip,instance", [
    ("10.137.22.8/1/0", 1063), ("10.137.22.8", 0), ("10.137.22.8", 0x100000000),
])
def test_invalid_transport_inputs_never_connect(monkeypatch, ip, instance):
    def must_not_connect(*args, **kwargs):
        pytest.fail("Invalid inputs must not contact a PLC")
    monkeypatch.setattr("examples.logix_metadata_transports.CIPDriver", must_not_connect)
    with pytest.raises(ValueError):
        compare_transports(ip, instance)
