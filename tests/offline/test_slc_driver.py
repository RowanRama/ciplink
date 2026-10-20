
import pytest

from ciplink.cip import UINT
from ciplink.cip.pccc import PCCC_ASCII, PCCC_STRING
from ciplink.exceptions import DataError, RequestError
from ciplink.packets import SendUnitDataRequestPacket, SendUnitDataResponsePacket
from ciplink.slc_driver import SLCDriver, _parse_file0, parse_tag, request_status, writeable_value

CONNECT_PATH = '192.168.1.100/1'


def test_b_file_bit_address_uses_word_and_bit():
    t = parse_tag('B3/17')
    assert t['element_number'] == 1 and t['sub_element'] == 1
    assert writeable_value(parse_tag('B3/17'), True) == b'\x02\x00\x02\x00'


def test_parse_tag_rejects_trailing_characters():
    assert parse_tag('N7:1000') is None
    assert parse_tag('N7:0/3x') is None
    assert parse_tag('N7:0{10}')['element_count'] == 10
    assert parse_tag('t4:0.acc') is not None


def test_pccc_string_encodes_full_84_byte_element():
    assert len(PCCC_STRING.encode('AB')) == 84
    assert len(PCCC_STRING.encode('')) == 84
    long = PCCC_STRING.encode('x' * 100)
    assert len(long) == 84 and long[:2] == b'\x52\x00'  # length capped at 82
    assert PCCC_STRING.decode(PCCC_STRING.encode('ABC')) == 'ABC'


def _pccc_reply(driver, sts=0x00, cip_status=0x00, extra=b''):
    raw = bytearray(61)
    raw[0:2] = b'\x70\x00'  # send_unit_data
    raw[46] = 0xCB  # PCCC execute reply
    raw[48] = cip_status
    raw[58] = sts
    return SendUnitDataResponsePacket(SendUnitDataRequestPacket(driver._sequence), bytes(raw) + extra)


def test_request_status_reports_ext_sts_and_cip_errors():
    driver = SLCDriver('1.2.3.4/0')
    assert request_status(_pccc_reply(driver, extra=b'\x01\x00')) is None
    assert 'EXT STS 0x07' in request_status(_pccc_reply(driver, sts=0xF0, extra=b'\x07'))
    assert '0x55' in request_status(_pccc_reply(driver, sts=0x55))

    cip_error = _pccc_reply(driver, cip_status=0x08)
    assert cip_error.error and request_status(cip_error) == cip_error.error


def _file0_rows(*codes):
    # SYS0 directory rows: type code + UINT size + 7 unused bytes
    return b''.join(bytes([code]) + UINT.encode(20) + bytes(7) for code in codes)


def test_parse_file0_input_file_is_always_file_1(capsys):
    # O0 row missing (#281): numbering used to start at I0
    data = _file0_rows(0x83, 0x84, 0x85, 0x89, 0x8A, 0x86)
    files = _parse_file0({'file_position': 0, 'row_size': 10}, data)
    assert list(files) == ['I1', 'S2', 'B3', 'N4', 'F5', 'T6']
    assert capsys.readouterr().out == ''


def test_parse_file0_numbering_with_output_row_and_gap():
    data = _file0_rows(0x82, 0x83, 0x84, 0x81, 0x89, 0x8A)
    files = _parse_file0({'file_position': 0, 'row_size': 10}, data)
    assert list(files) == ['O0', 'I1', 'S2', 'N4', 'F5']
    assert files['F5'] == {'elements': 5, 'length': 20}


def test_pccc_strings_reject_non_latin1():
    with pytest.raises(DataError):
        PCCC_STRING.encode('€')
    with pytest.raises(DataError):
        PCCC_ASCII.encode('€A')
    assert PCCC_STRING.decode(PCCC_STRING.encode('café')) == 'café'


def test_writeable_value_error_includes_cause():
    with pytest.raises(RequestError, match='Error packing'):
        writeable_value({'file_type': 'N', 'tag': 'N7:0', 'element_count': 1}, 'abc')


