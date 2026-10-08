from unittest import mock

import pytest

from pycomm3.cip import UINT, PortSegment
from pycomm3.cip.pccc import PCCC_ASCII, PCCC_STRING
from pycomm3.cip_driver import CIPDriver
from pycomm3.exceptions import DataError, RequestError, ResponseError
from pycomm3.packets import SendUnitDataRequestPacket, SendUnitDataResponsePacket
from pycomm3.slc_driver import SLCDriver, _parse_file0, parse_tag, request_status, writeable_value

CONNECT_PATH = '192.168.1.100/1'


def _sent_pccc(mock_send):
    # PCCC command bytes after the 13-byte _msg_start header
    return mock_send.call_args[0][0]._added[0][13:]


def test_b_file_bit_address_uses_word_and_bit():
    t = parse_tag('B3/17')
    assert t['element_number'] == 1 and t['sub_element'] == 1
    assert writeable_value(parse_tag('B3/17'), True) == b'\x02\x00\x02\x00'


def test_parse_tag_rejects_trailing_characters():
    assert parse_tag('N7:1000') is None
    assert parse_tag('N7:0/3x') is None
    assert parse_tag('N7:0{10}')['element_count'] == 10
    assert parse_tag('t4:0.acc') is not None


def test_bit_address_with_element_count_is_rejected():
    driver = SLCDriver(CONNECT_PATH)
    with mock.patch.object(SLCDriver, 'send') as mock_send:
        with pytest.raises(RequestError):
            driver._write_tag('N7:0/3{2}', [1, 1])
        with pytest.raises(RequestError):
            driver._read_tag('B3/3{2}')
        mock_send.assert_not_called()


def test_address_fields_of_255_are_escaped():
    driver = SLCDriver(CONNECT_PATH)
    with mock.patch.object(SLCDriver, 'send') as mock_send:
        for call in (lambda: driver._read_tag('N255:255'), lambda: driver._write_tag('N255:255', 1)):
            call()
            msg = _sent_pccc(mock_send)
            assert msg[6:9] == b'\xff\xff\x00'  # file number
            assert msg[9:10] == b'\x89'  # file type N
            assert msg[10:13] == b'\xff\xff\x00'  # element
            assert msg[13:14] == b'\x00'  # sub-element


def test_file_directory_offset_of_255_is_escaped():
    driver = SLCDriver(CONNECT_PATH)
    replies = [mock.Mock(raw=bytes(61) + bytes(510)), mock.Mock(raw=bytes(61) + bytes(10))]
    with mock.patch.object(SLCDriver, 'send', side_effect=replies) as mock_send:
        driver._read_whole_file_directory({'size': 520, 'file_type': b'\x01'})
        assert _sent_pccc(mock_send)[-4:] == b'\x01\xff\xff\x00'


def test_write_timer_preset_targets_pre_word():
    driver = SLCDriver('1.2.3.4/0')
    driver._target_is_connected = True
    with mock.patch.object(SLCDriver, 'send') as m:
        driver.write(('T4:0.PRE', 1000))
    msg = _sent_pccc(m)
    assert msg[5] == 2  # byte size: one word
    assert msg[9] == 1  # sub-element: PRE
    assert msg[-2:] == UINT.encode(1000)


def test_write_counter_acc_and_bit_sizes():
    driver = SLCDriver('1.2.3.4/0')
    driver._target_is_connected = True
    with mock.patch.object(SLCDriver, 'send') as m:
        driver.write(('C5:3.ACC', 7))
    msg = _sent_pccc(m)
    assert (msg[5], msg[8], msg[9]) == (2, 3, 2)

    with mock.patch.object(SLCDriver, 'send') as m:
        driver.write(('T4:0.DN', True))
    msg = _sent_pccc(m)
    assert (msg[5], msg[9]) == (2, 0)  # bit writes go to the control word
    assert msg[-4:] == UINT.encode(1 << 13) * 2

    with mock.patch.object(SLCDriver, 'send') as m:
        driver.write(('N7:0{3}', [1, 2, 3]))
    msg = _sent_pccc(m)
    assert msg[5] == 6 and msg[9] == 0


def test_pccc_string_encodes_full_84_byte_element():
    assert len(PCCC_STRING.encode('AB')) == 84
    assert len(PCCC_STRING.encode('')) == 84
    long = PCCC_STRING.encode('x' * 100)
    assert len(long) == 84 and long[:2] == b'\x52\x00'  # length capped at 82
    assert PCCC_STRING.decode(PCCC_STRING.encode('ABC')) == 'ABC'


def test_write_string_pair_declares_what_is_sent():
    driver = SLCDriver('1.2.3.4/0')
    driver._target_is_connected = True
    with mock.patch.object(SLCDriver, 'send') as m:
        driver.write(('ST9:0{2}', ['abc', 'de']))
    msg = _sent_pccc(m)
    assert msg[5] == 168 and len(msg[12:]) == 168
    assert PCCC_STRING.decode(msg[12 + 84:]) == 'de'


def _pccc_reply(driver, sts=0x00, cip_status=0x00, extra=b''):
    raw = bytearray(61)
    raw[0:2] = b'\x70\x00'  # send_unit_data
    raw[46] = 0xCB  # PCCC execute reply
    raw[48] = cip_status
    raw[58] = sts
    return SendUnitDataResponsePacket(SendUnitDataRequestPacket(driver._sequence), bytes(raw) + extra)


def test_get_processor_type_returns_none_on_pccc_error():
    driver = SLCDriver('1.2.3.4/0')
    with mock.patch.object(SLCDriver, 'send', return_value=_pccc_reply(driver, sts=0x10, extra=bytes(19))), \
         mock.patch.object(CIPDriver, '_forward_open'):
        assert driver.get_processor_type() is None


def test_get_processor_type_reads_type():
    driver = SLCDriver('1.2.3.4/0')
    reply = _pccc_reply(driver, extra=b'\x00' * 5 + b'1766-LEC   ' + b'\x00' * 3)
    with mock.patch.object(SLCDriver, 'send', return_value=reply), \
         mock.patch.object(CIPDriver, '_forward_open'):
        assert driver.get_processor_type() == '1766-LEC'


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


def test_get_file_directory_size():
    driver = SLCDriver('1.2.3.4/0')
    info = {'size_len': b'\x08', 'file_type': b'\x03', 'size_element': b'\x2b', 'size_const': 19968}
    with mock.patch.object(SLCDriver, 'send', return_value=_pccc_reply(driver, extra=UINT.encode(20000))):
        assert driver._get_file_directory_size(info) == 32
    with mock.patch.object(SLCDriver, 'send', return_value=_pccc_reply(driver)):
        assert driver._get_file_directory_size(info) is None


def test_pccc_strings_reject_non_latin1():
    with pytest.raises(DataError):
        PCCC_STRING.encode('€')
    with pytest.raises(DataError):
        PCCC_ASCII.encode('€A')
    assert PCCC_STRING.decode(PCCC_STRING.encode('café')) == 'café'


def test_writeable_value_error_includes_cause():
    with pytest.raises(RequestError, match='Error packing'):
        writeable_value({'file_type': 'N', 'tag': 'N7:0', 'element_count': 1}, 'abc')


def test_get_datalog_queue_reads_entries_then_clears_queue():
    driver = SLCDriver('1.2.3.4/0')
    driver._target_is_connected = True
    with mock.patch.object(SLCDriver, '_get_datalog', return_value='x') as m:
        assert driver.get_datalog_queue(2, 0) == ['x', 'x']
    assert m.call_count == 3


def test_get_datalog_entry():
    driver = SLCDriver('1.2.3.4/0')
    with mock.patch.object(SLCDriver, 'send', return_value=_pccc_reply(driver, extra=b'abc')):
        assert driver._get_datalog(0) == 'abc'
    with mock.patch.object(SLCDriver, 'send', return_value=_pccc_reply(driver, extra=b'\xff\xfe')):
        assert driver._get_datalog(0) == b'\xff\xfe'  # undecodable entries come back as bytes
    with mock.patch.object(SLCDriver, 'send', return_value=_pccc_reply(driver, sts=0x10)):
        assert driver._get_datalog(0) is None


def test_slc_driver_uses_standard_forward_open():
    driver = SLCDriver('192.168.1.100/1')
    assert driver._cfg['cip_path'] == [PortSegment('bp', 1)]
    assert driver._cfg['extended forward open'] is False and driver.connection_size == 500
    with mock.patch.object(CIPDriver, '_forward_open', return_value=False) as m, pytest.raises(ResponseError):
        driver.read('N7:0')
    assert m.call_count == 1  # no Extended Forward Open attempt first
    assert SLCDriver('10.0.0.1', connection_size=300).connection_size == 300
