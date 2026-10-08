"""Regression tests for LogixDriver init / tag list upload fixes."""
from types import SimpleNamespace
from unittest import mock

import pytest

from pycomm3.cip import DINT, STRING, UDINT, UINT, USINT, Services
from pycomm3.cip_driver import CIPDriver
from pycomm3.const import BASE_TAG_BIT, INSUFFICIENT_PACKETS, SUCCESS
from pycomm3.exceptions import CommError, ResponseError
from pycomm3.logix_driver import LogixDriver
from pycomm3.packets import (
    MultiServiceRequestPacket,
    ReadModifyWriteRequestPacket,
    ReadTagFragmentedRequestPacket,
    ReadTagRequestPacket,
    WriteTagFragmentedRequestPacket,
    WriteTagRequestPacket,
)
from pycomm3.packets.logix import MultiServiceResponsePacket
from pycomm3.tag import Tag


def _raw_tag(name, instance_id, symbol_type=0xC4):
    return {
        'tag_name': name,
        'instance_id': instance_id,
        'symbol_type': symbol_type,
        'symbol_address': 0,
        'symbol_object_address': 0,
        'software_control': 0,
        'external_access': 'Read/Write',
        'dimensions': [0, 0, 0],
    }


def _isolate_plc():
    plc = LogixDriver('1.2.3.4', init_tags=False)
    plc._info = {'programs': {}, 'tasks': {}, 'modules': {}}
    return plc


@pytest.mark.parametrize('close_error', [None, CommError('close failed')])
def test_open_closes_connection_when_init_fails(close_error):
    with mock.patch.object(CIPDriver, 'open', return_value=True), \
            mock.patch.object(LogixDriver, '_initialize_driver', side_effect=ResponseError('init failed')), \
            mock.patch.object(LogixDriver, 'close', side_effect=close_error) as mock_close:
        plc = LogixDriver('1.2.3.4', init_tags=False)
        with pytest.raises(ResponseError, match='init failed'):
            plc.open()
    mock_close.assert_called_once()


def test_namespace_filter_only_filters_user_tags():
    plc = _isolate_plc()
    raw = [
        _raw_tag('Program:MainProgram', 1, 0),
        _raw_tag('Task:MainTask', 2, 0),
        _raw_tag('Local:1:I', 3),
        _raw_tag('Line1_Speed', 4),
        _raw_tag('Other', 5),
    ]
    with mock.patch.object(LogixDriver, '_create_tag', side_effect=lambda n, t: n):
        out = plc._isolate_user_tags(raw, None, 'Line1_')
        prog_out = plc._isolate_user_tags([_raw_tag('Line1_X', 6), _raw_tag('Other', 7)], 'MainProgram', 'Line1_')

    assert out == ['Line1_Speed']
    assert prog_out == ['Program:MainProgram.Line1_X']
    assert 'MainProgram' in plc._info['programs']
    assert 'MainTask' in plc._info['tasks']
    assert 'Local' in plc._info['modules']


def test_get_tag_list_single_program_without_full_upload():
    plc = LogixDriver('1.2.3.4', init_tags=False)
    plc._info = {}
    plc._target_is_connected = True
    with mock.patch.object(LogixDriver, '_get_instance_attribute_list_service',
                           return_value=[_raw_tag('Routine:MainRoutine', 1, 0)]):
        assert plc.get_tag_list(program='MainProgram') == []
    assert plc._info['programs'] == {}


def test_isolate_user_tags_keeps_all_module_slot_types():
    plc = _isolate_plc()
    raw = [_raw_tag('Local:2:I', 1), _raw_tag('Local:2:C', 2), _raw_tag('Local:2:O', 3)]
    with mock.patch.object(LogixDriver, '_create_tag', side_effect=lambda n, t: n):
        plc._isolate_user_tags(raw)
    assert plc._info['modules']['Local']['slots'][2]['types'] == ['I', 'C', 'O']


def test_get_tag_list_accepts_program_prefix():
    plc = LogixDriver('1.2.3.4', init_tags=False)
    plc._info = {'programs': {'X': {'instance_id': 1, 'routines': []}}, 'tasks': {}, 'modules': {}}
    plc._target_is_connected = True
    with mock.patch.object(LogixDriver, '_get_instance_attribute_list_service',
                           return_value=[_raw_tag('Routine:Main', 1, 0), _raw_tag('tag', 2)]):
        tags = plc.get_tag_list(program='Program:X')
    assert [t['tag_name'] for t in tags] == ['Program:X.tag']
    assert plc._info['programs']['X']['routines'] == ['Main']


@pytest.mark.parametrize('call', [
    lambda plc: plc.get_plc_info(),
    lambda plc: plc.get_plc_name(),
    lambda plc: plc.get_tag_list(),
    lambda plc: plc._isolate_user_tags([_raw_tag('udt', 1, 0x8100)]),
    lambda plc: plc._get_data_type(0x100, 0x8100),
    lambda plc: plc._read_template(0x100, 10),
])
def test_comm_errors_are_not_wrapped(call):
    plc = _isolate_plc()
    plc._target_is_connected = True
    with mock.patch.object(LogixDriver, 'generic_message', side_effect=CommError('lost')), \
            mock.patch.object(LogixDriver, 'send', side_effect=CommError('lost')):
        with pytest.raises(CommError):
            call(plc)


def test_get_plc_info_updates_info():
    plc = LogixDriver('1.2.3.4', init_tags=False)
    plc._info = {'name': 'PLCA'}
    response = Tag('get_plc_info', {'vendor': 'x', 'status': b'`0', 'revision': {'major': 28, 'minor': 13}}, None, None)
    with mock.patch.object(LogixDriver, 'generic_message', return_value=response):
        info = plc.get_plc_info()
    assert plc._info['keyswitch'] == info['keyswitch'] == 'REMOTE RUN'
    assert plc._info['revision'] == {'major': 28, 'minor': 13}
    assert plc._info['name'] == 'PLCA'


def test_str_shows_name_device_and_revision():
    plc = LogixDriver('1.2.3.4', init_tags=False)
    assert str(plc) == 'Program Name: None, Device: None, Revision: -1.-1'
    plc._info = {'name': 'PLCA', 'product_name': '1756-L83E/B', 'revision': {'major': 28, 'minor': 13}}
    assert str(plc) == 'Program Name: PLCA, Device: 1756-L83E/B, Revision: 28.13'


def _symbol(instance, name, symbol_type, dim1=0):
    """one entry of a get_instance_attribute_list reply (attributes 1, 2, 3, 5, 6, 8, 10)"""
    return b''.join((
        UDINT.encode(instance), STRING.encode(name), UINT.encode(symbol_type),
        UDINT.encode(0), UDINT.encode(0), UDINT.encode(BASE_TAG_BIT),
        UDINT.encode(dim1), UDINT.encode(0), UDINT.encode(0), USINT.encode(3),
    ))


UDT_MAKEUP = {
    'object_definition_size': {'size': 30},
    'structure_size': {'size': 16},
    'member_count': {'count': 4},
    'structure_handle': {'handle': 0xABCD},
}
UDT_TEMPLATE = b''.join((  # member info (2B bit/array len, 2B type, 4B offset), then the names
    UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(0),  # A: DINT
    UINT.encode(2) + UINT.encode(0xC4) + UDINT.encode(4),  # B: DINT[2]
    UINT.encode(0) + UINT.encode(0xC2) + UDINT.encode(12),  # hidden SINT holding the BOOL
    UINT.encode(3) + UINT.encode(0xC1) + UDINT.encode(12),  # Flag: bit 3 of the hidden SINT
    b'MyUDT;n0000\x00A\x00B\x00ZZZZZZZZZZMyUDT0\x00Flag\x00',
))


@pytest.mark.parametrize('program, path', [
    (None, b'\x02'),
    ('Prog1', b'\x0a\x91\x0dProgram:Prog1\x00'),
    ('Program:Odd', b'\x09\x91\x0bProgram:Odd\x00'),
    ('Even', b'\x09\x91\x0cProgram:Even'),
])
def test_get_tag_list_requests_and_tag_definitions(program, path):
    plc = LogixDriver('1.2.3.4', init_tags=False)
    plc._info = {'revision': {'major': 20, 'minor': 0}}
    plc._target_is_connected = True
    pages = iter([
        SimpleNamespace(service_status=INSUFFICIENT_PACKETS,
                        data=_symbol(1, 'a', 0xC4) + _symbol(2, 'arr', 0x20C4, 10)),
        SimpleNamespace(service_status=SUCCESS,
                        data=_symbol(3, 'udt', 0x8123) + _symbol(4, 'udts', 0xA123, 3)),
    ])
    sent = []

    def send(request):
        sent.append(request.build_message()[2:])  # without the sequence count
        return next(pages)

    def generic_message(**kwargs):
        if kwargs['service'] == Services.get_attribute_list:
            return Tag('makeup', UDT_MAKEUP, None, None)
        return Tag('template', SimpleNamespace(service_status=SUCCESS, data=UDT_TEMPLATE), None, None)

    with mock.patch.object(LogixDriver, 'send', side_effect=send), \
            mock.patch.object(LogixDriver, 'generic_message', side_effect=generic_message) as gm:
        tags = plc.get_tag_list(program=program)

    attrs = b'\x07\x00\x01\x00\x02\x00\x03\x00\x05\x00\x06\x00\x08\x00\x0a\x00'
    assert sent == [b'\x55' + path + b'\x20\x6b\x24' + bytes([i]) + attrs for i in (0, 3)]

    prefix = f'Program:{program.replace("Program:", "")}.' if program else ''
    assert [t['tag_name'] for t in tags] == [prefix + n for n in ('a', 'arr', 'udt', 'udts')]
    a, arr, udt, udts = tags
    assert (a['tag_type'], a['data_type'], a['type_class']) == ('atomic', 'DINT', DINT)
    assert (arr['type_class'].length, arr['type_class'].element_type) == (10, DINT)
    assert (udt['tag_type'], udt['data_type_name']) == ('struct', 'MyUDT')
    assert udt['type_class'] is plc.data_types['MyUDT']['type_class']
    assert (udts['type_class'].length, udts['type_class'].element_type) == (3, udt['type_class'])
    raw = DINT.encode(1) + DINT.encode(2) + DINT.encode(3) + b'\x08' + bytes(3)
    assert udt['type_class'].decode(raw) == {'A': 1, 'B': [2, 3], 'Flag': True}
    assert plc.data_types['MyUDT']['attributes'] == ['A', 'B', 'Flag']
    assert gm.call_count == 2  # the second UDT tag uses the cached definition
    assert plc.tags == {t['tag_name']: t for t in tags}


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
