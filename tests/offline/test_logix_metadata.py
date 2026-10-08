"""Capture-based tests for the experimental Logix Description reader and codecs."""

import json
import struct
from pathlib import Path
from unittest.mock import Mock

import pytest

from pycomm3 import LogixDriver
from pycomm3.exceptions import DataError
from pycomm3.logix_metadata import (
    assemble_metadata_pages,
    build_description_request,
    decode_definition_response,
    decode_description_response,
    decode_metadata_page,
)
from pycomm3.packets import SendUnitDataResponsePacket
from .test_logix_extended_properties import enip


CAPTURE = json.loads(Path(__file__).with_name("logix_metadata_capture.json").read_text(encoding="utf-8"))
DESCRIPTION = CAPTURE["description"]
PAGE = bytes.fromhex(DESCRIPTION["page_hex"])


def page(data, first=True, last=True, offset=0):
    return struct.pack("<BBHI", 1, int(first) | (int(last) << 1), 0, offset) + data


def test_description_request_matches_the_real_capture():
    assert build_description_request(1063).hex() == DESCRIPTION["request_cip_hex"]
    continuation = build_description_request(1063, offset=490)
    assert continuation[10:18] == bytes.fromhex("01000000ea010000")


def test_confirmed_tag_description_and_missing_language():
    result = decode_description_response([PAGE])
    assert result["value"] == DESCRIPTION["expected"] == "HERE I AM WORLD"
    assert result["instance_id"] == 1063
    assert result["class_id"] == 0x6B
    assert result["language"] == 0x007F
    assert result["property_id"] == 1
    assert result["record_id"] == 4465
    assert decode_description_response([bytes.fromhex(CAPTURE["missing_description_page_hex"])]) is None


@pytest.mark.parametrize("definition", CAPTURE["definitions"], ids=lambda case: case["name"])
def test_every_captured_definition_decodes_without_dropping_bytes(definition):
    fields = decode_definition_response([bytes.fromhex(raw) for raw in definition["pages_hex"]])
    assert fields[9]["value"] == definition["name"]
    assert set(fields) == set(range(8, 25)) | {43}
    assert fields[19]["kind"] == 2
    assert fields[19]["type_code"] == 0xC3
    assert len(fields[19]["value"]) == 2


def test_real_fragmentation_splits_inside_a_string():
    definition = next(case for case in CAPTURE["definitions"] if case["id"] == 45)
    pages = [bytes.fromhex(raw) for raw in definition["pages_hex"]]
    assert decode_metadata_page(pages[1])["offset"] == 490
    fields = decode_definition_response(pages)
    assert fields[24]["value"] == "DataExchangeIdDefinition"
    with pytest.raises(DataError, match="Incomplete"):
        decode_definition_response(pages[:1])


@pytest.mark.parametrize("raw", [b"", b"\x01\x03", bytes.fromhex("0203000000000000"),
                                  bytes.fromhex("0104000000000000"),
                                  bytes.fromhex("0103010000000000")])
def test_invalid_page_header_is_not_treated_as_metadata(raw):
    with pytest.raises(DataError):
        decode_metadata_page(raw)


def test_bad_offsets_and_extra_pages_are_rejected():
    for pages in ([], [page(b"", first=False)], [page(b"abc", last=False)],
                  [page(b"a", last=False), page(b"b", first=False, offset=5)],
                  [page(b"a"), page(b"b", first=False, offset=1)],
                  [page(b"", last=False), page(b"", first=False)]):
        with pytest.raises(DataError):
            assemble_metadata_pages(pages)


def test_truncated_description_and_unexpected_records_are_rejected():
    for length in range(1, len(PAGE) - 8):
        with pytest.raises(DataError):
            decode_description_response([page(PAGE[8:8 + length])])
    with pytest.raises(DataError, match="additional"):
        decode_description_response([page(PAGE[8:] + b"unexpected")])


def test_empty_string_is_different_from_missing_description():
    assert decode_description_response([page(PAGE[8:44] + b"\x00\x00")])["value"] == ""


def test_explicit_text_encoding_with_synthetic_non_ascii_data():
    # Encoding is configurable; the real controller capture currently covers ASCII.
    raw = "caf\u00e9".encode("cp1252")
    result = page(PAGE[8:44] + struct.pack("<H", len(raw)) + raw)
    assert decode_description_response([result], encoding="cp1252")["value"] == "caf\u00e9"
    with pytest.raises(DataError, match="decode metadata text"):
        decode_description_response([result], encoding="utf-8")


@pytest.fixture
def plc():
    driver = LogixDriver("192.168.1.100", init_tags=False)
    driver._target_is_connected = True
    driver._tags = {"zzzTestTag": {"instance_id": 1063}}
    return driver


def mock_responses(plc, payloads, status=0):
    payloads = iter(payloads)
    requests = []

    def send(request):
        cip = request.build_message()[2:]
        requests.append(cip)
        assert cip[0] == 0x53  # Only the captured read service is issued.
        reply = bytes([0xD3, 0, status, 0]) + next(payloads)
        return SendUnitDataResponsePacket(request, enip(reply))

    plc.send = Mock(side_effect=send)
    return requests


def test_reader_decodes_the_capture(plc):
    requests = mock_responses(plc, [PAGE])
    result = plc.get_tag_description("zzzTestTag")
    assert result
    assert result.tag == "zzzTestTag.@Description"
    assert result.type == "STRING"
    assert result.value == "HERE I AM WORLD"
    assert requests[0].hex() == DESCRIPTION["request_cip_hex"]


def test_reader_preserves_permission_denied_and_does_not_retry(plc):
    mock_responses(plc, [b""], status=0x0F)
    result = plc.get_tag_description("zzzTestTag")
    assert not result and result.value is None
    assert result.error == "Permission denied"
    assert plc.send.call_count == 1


def test_reader_handles_continuations(plc):
    raw = PAGE[8:]
    requests = mock_responses(plc, [page(raw[:40], last=False),
                                    page(raw[40:], first=False, offset=40)])
    assert plc.get_tag_description("zzzTestTag").value == "HERE I AM WORLD"
    assert requests[1] == build_description_request(1063, offset=40)


def test_reader_rejects_mismatched_target(plc):
    wrong = bytearray(PAGE)
    struct.pack_into("<I", wrong, 10, 99)
    mock_responses(plc, [bytes(wrong)])
    result = plc.get_tag_description("zzzTestTag")
    assert not result and "different tag/language" in result.error


def test_reader_reports_missing_language(plc):
    mock_responses(plc, [bytes.fromhex(CAPTURE["missing_description_page_hex"])])
    result = plc.get_tag_description("zzzTestTag", language=0x0409)
    assert not result and "No description" in result.error


@pytest.mark.parametrize("tag", ["NoSuchTag", "Program:Main.Tag", "Tag.Member", "Tag[0]"])
def test_reader_rejects_unsupported_tag_addresses_without_a_read(plc, tag):
    plc.send = Mock(side_effect=AssertionError("Must not issue a PLC read"))
    assert not plc.get_tag_description(tag)
    plc.send.assert_not_called()
