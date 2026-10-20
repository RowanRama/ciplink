"""
Offline tests for LogixDriver(tag_cache_file=...): nothing is uploaded on a restart if the tag table version is
unchanged, else the symbol lists are uploaded and the templates reused.
"""
import json
import logging
import tempfile
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

import pytest

from ciplink.cip import DINT, UDINT, UINT, Services
from ciplink.cip_driver import CIPDriver
from ciplink.const import SUCCESS
from ciplink.logix_driver import LogixDriver
from ciplink.packets import MultiServiceRequestPacket, TagTableVersionRequestPacket
from ciplink.tag import Tag
from tests.offline.test_logix_tag_list import UDT_MAKEUP, UDT_TEMPLATE, _symbol
from tests.offline.test_logix_tag_table_version import HEADER, V1, V2, cip_reply, version_reply

IDENTITY = {'product_name': '1756-SIM/A', 'revision': {'major': 32, 'minor': 0}, 'status': b'00',
            'serial': 'c0ffee01'}

OUTER_MAKEUP = {
    'object_definition_size': {'size': 20},
    'structure_size': {'size': 20},
    'member_count': {'count': 2},
    'structure_handle': {'handle': 0x1234},
}
OUTER_TEMPLATE = b''.join((
    UINT.encode(0) + UINT.encode(0x8123) + UDINT.encode(0),  # In: MyUDT (nested template 0x123)
    UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(16),  # X: DINT
    b'Outer;n0000\x00In\x00X\x00',
))
TEMPLATES = {0x123: (UDT_MAKEUP, UDT_TEMPLATE), 0x124: (OUTER_MAKEUP, OUTER_TEMPLATE)}

SYMBOL_REQUESTS = [('symbols', None), ('symbols', 'MainProgram')]
CACHED_REQUESTS = SYMBOL_REQUESTS + [('makeup', 0x123), ('makeup', 0x124)]  # the makeups are always read
# the makeups of all scopes in one multi-service packet, then the templates
TEMPLATE_REQUESTS = [('makeup', 0x123), ('makeup', 0x124), ('template', 0x123), ('template', 0x124)]


def _symbols():
    return {
        None: [(1, 'Program:MainProgram', 0x1068), (2, 'Task:MainTask', 0x1070), (3, 'a', 0xC4),
               (4, 'udt', 0x8123), (5, 'Local:1:I', 0xC4)],
        'MainProgram': [(1, 'Routine:MainRoutine', 0x106D), (2, 'outer', 0x8124), (3, 'arr', 0x20C4, 4)],
    }


def makeup_data(makeup):
    """the reply data of a structure makeup read (Get_Attribute_List 4, 5, 2, 1 of a template)"""
    return b''.join((
        UINT.encode(4),
        UINT.encode(4) + UINT.encode(0) + UDINT.encode(makeup['object_definition_size']['size']),
        UINT.encode(5) + UINT.encode(0) + UDINT.encode(makeup['structure_size']['size']),
        UINT.encode(2) + UINT.encode(0) + UINT.encode(makeup['member_count']['count']),
        UINT.encode(1) + UINT.encode(0) + UINT.encode(makeup['structure_handle']['handle']),
    ))


def multi_reply(request, replies):
    """the reply to a multi-service packet with these service replies"""
    offsets, offset = [], 2 + 2 * len(replies)
    for reply in replies:
        offsets.append(UINT.encode(offset))
        offset += len(reply)
    status = 0x1E if any(reply[2] not in (0, 6) for reply in replies) else 0
    data = UINT.encode(len(replies)) + b''.join(offsets) + b''.join(replies)
    return request.response_class(request, HEADER + cip_reply(0x0A, status, data))


class _Requests(list):
    version_reads = 0  # tag table version checks, not uploads


@contextmanager
def _fake_plc(symbols=None, version=None, identity=IDENTITY):
    """
    yields the upload requests sent to a fake PLC: ('symbols', scope), ('makeup', id) or ('template', id);
    with version None it answers the tag table version check like an emulator (status 0x05)
    """
    symbols = symbols or _symbols()
    requests = _Requests()

    def send(request):
        if isinstance(request, TagTableVersionRequestPacket):
            requests.version_reads += 1
            return version_reply(request, version)
        if isinstance(request, MultiServiceRequestPacket):  # structure makeups
            requests.extend(('makeup', r.instance) for r in request.requests)
            return multi_reply(request, [cip_reply(0x03, 0, makeup_data(TEMPLATES[r.instance][0]))
                                         for r in request.requests])
        message = request.build_message()
        scope = next((p for p in symbols if p and f'Program:{p}'.encode() in message), None)
        requests.append(('symbols', scope))
        return SimpleNamespace(service_status=SUCCESS, data=b''.join(_symbol(*s) for s in symbols[scope]))

    def generic_message(**kwargs):
        makeup, template = TEMPLATES[kwargs['instance']]
        if kwargs['service'] == Services.get_attribute_list:
            requests.append(('makeup', kwargs['instance']))
            return Tag('makeup', makeup, None, None)
        requests.append(('template', kwargs['instance']))
        return Tag('template', SimpleNamespace(service_status=SUCCESS, data=template), None, None)

    with mock.patch.object(CIPDriver, 'open', return_value=True), \
            mock.patch.object(LogixDriver, '_list_identity', return_value=identity), \
            mock.patch.object(LogixDriver, 'get_plc_info', return_value=dict(identity)), \
            mock.patch.object(LogixDriver, 'get_plc_name'), \
            mock.patch.object(LogixDriver, 'send', side_effect=send), \
            mock.patch.object(LogixDriver, 'generic_message', side_effect=generic_message):
        yield requests


def _driver(path, **kwargs):
    plc = LogixDriver('1.2.3.4', tag_cache_file=path and str(path), **kwargs)
    plc._target_is_connected = True
    return plc


def _upload(path, symbols=None, version=None, identity=IDENTITY, **kwargs):
    """connects to the fake PLC, returns the driver and the upload requests it sent"""
    plc = _driver(path, **kwargs)
    with _fake_plc(symbols, version, identity) as requests:
        assert plc.open()
    return plc, requests


def _plain(value):
    """the JSON-able part of a data type, type classes are new objects on every upload"""
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items() if k not in ('type_class', '_struct_members')}
    return value


def test_second_connect_uses_cached_templates(tmp_path, caplog):
    path = tmp_path / 'tags.json'
    first, first_requests = _upload(path)
    assert first_requests == SYMBOL_REQUESTS + TEMPLATE_REQUESTS  # symbol lists first, then the templates
    saved = json.loads(path.read_text())
    assert [scope for scope, _ in saved['symbols']] == [None, 'MainProgram']
    assert sorted(t[0] for t in saved['templates']) == [0x123, 0x124]
    assert list(tmp_path.iterdir()) == [path]  # no temp file left behind

    with caplog.at_level(logging.INFO, logger='ciplink'):
        second, second_requests = _upload(path)
    assert second_requests == CACHED_REQUESTS  # no template reads
    assert 'saved the reads of 2 templates' in caplog.text
    assert second.tags_json == first.tags_json
    assert _plain(second.data_types) == _plain(first.data_types)
    assert second.info == first.info
    assert set(second.tags) == {'a', 'udt', 'Local:1:I', 'Program:MainProgram.outer', 'Program:MainProgram.arr'}
    assert second.info['programs'] == {'MainProgram': {'instance_id': 1, 'routines': ['MainRoutine']}}
    raw = DINT.encode(1) + DINT.encode(2) + DINT.encode(3) + b'\x08' + bytes(3) + DINT.encode(9)
    expected = {'In': {'A': 1, 'B': [2, 3], 'Flag': True}, 'X': 9}
    assert second.tags['Program:MainProgram.outer']['type_class'].decode(raw) == expected


@pytest.mark.parametrize('change', [
    lambda s: s[None].__setitem__(2, (30, 'a', 0xC4)),  # instance id changed
    lambda s: s['MainProgram'].append((4, 'b', 0xC4)),  # tag added
])
def test_changed_symbol_list_refetches_templates(tmp_path, change):
    path = tmp_path / 'tags.json'
    _upload(path)
    symbols = _symbols()
    change(symbols)
    _, requests = _upload(path, symbols)
    assert requests == SYMBOL_REQUESTS + TEMPLATE_REQUESTS
    saved = dict(json.loads(path.read_text())['symbols'])
    assert [t['instance_id'] for t in saved[None]] == [s[0] for s in symbols[None]]
    assert [t['tag_name'] for t in saved['MainProgram']] == [s[1] for s in symbols['MainProgram']]
    assert _upload(path, symbols)[1] == CACHED_REQUESTS  # the rewritten file matches the new lists


def test_namespace_filter_keeps_cache_valid(tmp_path):
    path = tmp_path / 'tags.json'
    _upload(path)
    plc, requests = _upload(path, tag_namespace_filter='udt')
    assert requests == SYMBOL_REQUESTS + [('makeup', 0x123)]  # the raw symbol lists are not filtered, the file matches
    assert set(plc.tags) == {'udt'}
    assert [t[0] for t in json.loads(path.read_text())['templates']] == [0x123]


@pytest.mark.parametrize('corrupt', [
    lambda text: text[:len(text) // 2],  # truncated
    lambda text: text.replace('"structure_size"', '"other"'),  # template entry missing a key
])
def test_corrupt_cache_file_is_ignored(tmp_path, caplog, corrupt):
    path = tmp_path / 'tags.json'
    expected, _ = _upload(path)
    path.write_text(corrupt(path.read_text()))
    with caplog.at_level(logging.WARNING, logger='ciplink'):
        plc, requests = _upload(path)
    assert 'Ignoring unreadable tag cache file' in caplog.text
    assert requests == SYMBOL_REQUESTS + TEMPLATE_REQUESTS
    assert plc.tags_json == expected.tags_json
    assert _upload(path)[1] == CACHED_REQUESTS  # rewritten


def test_changed_makeup_refetches_the_template(tmp_path):
    # a UDT edited on the PLC with the symbol lists unchanged, its structure handle (a CRC) changed
    path = tmp_path / 'tags.json'
    _upload(path)
    makeup = dict(UDT_MAKEUP, structure_handle={'handle': 0xBEEF})
    renamed = UDT_TEMPLATE.replace(b'\x00A\x00B\x00', b'\x00P\x00Q\x00')
    with mock.patch.dict(TEMPLATES, {0x123: (makeup, renamed)}):
        plc, requests = _upload(path)
        assert requests == SYMBOL_REQUESTS + [('makeup', 0x123), ('makeup', 0x124), ('template', 0x123)]
        assert plc.data_types['MyUDT']['attributes'] == ['P', 'Q', 'Flag']
        assert plc.data_types['Outer']['internal_tags']['In']['data_type']['attributes'] == ['P', 'Q', 'Flag']
        assert _upload(path)[1] == CACHED_REQUESTS  # rewritten with the new template


def test_damaged_template_in_cache_file_uploads_again(tmp_path, caplog):
    # valid JSON and hex, so the file loads, but the template fails to parse
    path = tmp_path / 'tags.json'
    expected, _ = _upload(path)
    saved = json.loads(path.read_text())
    next(t for t in saved['templates'] if t[0] == 0x123)[2] = UDT_TEMPLATE.hex()[:16]
    path.write_text(json.dumps(saved))
    with caplog.at_level(logging.WARNING, logger='ciplink'):
        plc, requests = _upload(path)  # open() returned True
    assert 'its contents failed' in caplog.text
    assert requests == CACHED_REQUESTS + TEMPLATE_REQUESTS  # failed on the first template, after the makeups
    assert plc.tags_json == expected.tags_json
    assert plc.info == expected.info
    assert _upload(path)[1] == CACHED_REQUESTS  # rewritten


def test_other_scopes_neither_read_nor_write_the_file(tmp_path):
    path = tmp_path / 'tags.json'
    plc, _ = _upload(path)
    text = path.read_text()
    with _fake_plc() as requests:
        plc.get_tag_list(program='MainProgram')
        plc.get_tag_list()
    # uploaded as without a file, no tag table version so the templates are read again
    assert requests == [('symbols', 'MainProgram'), ('makeup', 0x124), ('template', 0x124), ('makeup', 0x123),
                        ('template', 0x123), ('symbols', None), ('makeup', 0x123), ('template', 0x123)]
    assert path.read_text() == text
    assert _upload(path)[1] == CACHED_REQUESTS

    # without program tags the startup scope is the controller
    path = tmp_path / 'controller.json'
    plc, _ = _upload(path, init_program_tags=False)
    assert _upload(path, init_program_tags=False)[1] == [('symbols', None), ('makeup', 0x123)]
    text = path.read_text()
    with _fake_plc():
        plc.get_tag_list(program='*')
    assert path.read_text() == text


def test_unwritable_cache_file_still_connects(tmp_path, caplog):
    path = tmp_path / 'missing_dir' / 'tags.json'
    with caplog.at_level(logging.WARNING, logger='ciplink'):
        plc, requests = _upload(path)  # open() returned True
    assert 'Could not write tag cache file' in caplog.text
    assert requests == SYMBOL_REQUESTS + TEMPLATE_REQUESTS
    assert len(plc.tags) == 5
    assert not path.parent.exists()


def test_no_cache_file_is_unchanged(tmp_path):
    with_file, _ = _upload(tmp_path / 'tags.json')
    plc = _driver(None)
    with _fake_plc() as requests:
        assert plc.open()
        tags = plc.get_tag_list(program='*')
    assert requests == (SYMBOL_REQUESTS + TEMPLATE_REQUESTS) * 2  # no tag table version, the templates are read again
    assert [_plain(t) for t in tags] == [_plain(t) for t in with_file.tags.values()]
    assert plc.tags_json == with_file.tags_json
    assert _plain(plc.data_types) == _plain(with_file.data_types)
    assert plc.info == with_file.info
    assert list(tmp_path.iterdir()) == [tmp_path / 'tags.json']


def test_lazy_tags_ignore_cache_file(tmp_path):
    path = tmp_path / 'tags.json'
    plc = _driver(path, lazy_tags=True)
    with _fake_plc() as requests:
        assert plc.open()
        assert requests == []
        plc.get_tag_list(program='*')
    assert requests == SYMBOL_REQUESTS + TEMPLATE_REQUESTS
    assert not path.exists()


def test_unchanged_tag_table_loads_the_tag_list_from_the_file(tmp_path, caplog):
    path = tmp_path / 'tags.json'
    first, first_requests = _upload(path, version=V1)
    assert first_requests == SYMBOL_REQUESTS + TEMPLATE_REQUESTS
    saved = json.loads(path.read_text())
    assert [saved[k] for k in ('version', 'scope', 'serial', 'table_version')] == [2, '*', 'c0ffee01', list(V1)]

    with caplog.at_level(logging.INFO, logger='ciplink'):
        second, second_requests = _upload(path, version=V1)
    assert second_requests == []  # no symbol list, makeup or template upload
    assert second_requests.version_reads == 2  # on connect (also the one before the load), after it
    assert 'loaded the tag list from it' in caplog.text
    assert second.tags_json == first.tags_json
    assert _plain(second.data_types) == _plain(first.data_types)
    assert second.info == first.info
    assert second._tag_table_version == V1
    raw = DINT.encode(1) + DINT.encode(2) + DINT.encode(3) + b'\x08' + bytes(3) + DINT.encode(9)
    expected = {'In': {'A': 1, 'B': [2, 3], 'Flag': True}, 'X': 9}
    assert second.tags['Program:MainProgram.outer']['type_class'].decode(raw) == expected
    assert json.loads(path.read_text()) == saved


@pytest.mark.parametrize('kwargs, expected', [
    ({'version': V2}, CACHED_REQUESTS),  # edited since, today's path
    ({'version': V1, 'identity': dict(IDENTITY, serial='c0ffee02')}, CACHED_REQUESTS),  # another controller
    ({'version': None}, CACHED_REQUESTS),  # no tag table version, e.g. an emulator
    ({'version': V1, 'init_program_tags': False},  # another scope
     [('symbols', None), ('makeup', 0x123), ('template', 0x123)]),
])
def test_tag_list_is_uploaded_unless_the_file_has_the_current_version(tmp_path, kwargs, expected):
    path = tmp_path / 'tags.json'
    _upload(path, version=V1)
    assert _upload(path, **kwargs)[1] == expected
    if kwargs['version'] is not None:
        assert _upload(path, **kwargs)[1] == []  # the rewritten file is current


def test_older_cache_file_format_is_a_miss(tmp_path):
    path = tmp_path / 'tags.json'
    _upload(path, version=V1)
    saved = json.loads(path.read_text())
    path.write_text(json.dumps({'version': 1, 'symbols': saved['symbols'], 'templates': saved['templates']}))
    assert _upload(path, version=V1)[1] == SYMBOL_REQUESTS + TEMPLATE_REQUESTS
    assert json.loads(path.read_text()) == saved
    assert _upload(path, version=V1)[1] == []


def test_damaged_file_with_current_version_uploads_everything(tmp_path, caplog):
    path = tmp_path / 'tags.json'
    expected, _ = _upload(path, version=V1)
    saved = json.loads(path.read_text())
    del saved['symbols'][0][1][2]['symbol_type']  # the controller's tag 'a'
    path.write_text(json.dumps(saved))
    with caplog.at_level(logging.WARNING, logger='ciplink'):
        plc, requests = _upload(path, version=V1)
    assert 'its contents failed' in caplog.text
    assert requests == SYMBOL_REQUESTS + TEMPLATE_REQUESTS
    assert plc.tags_json == expected.tags_json
    assert plc.info == expected.info
    assert _upload(path, version=V1)[1] == []  # rewritten


def test_unchanged_cache_file_is_not_rewritten(tmp_path):
    path = tmp_path / 'tags.json'
    _upload(path, version=V1)
    text = path.read_text()
    with mock.patch('ciplink.logix_driver.tempfile.mkstemp', wraps=tempfile.mkstemp) as mkstemp:
        assert _upload(path, version=V1)[1] == []  # loaded from the file
        assert not mkstemp.called and path.read_text() == text
        assert _upload(path, version=V2)[1] == CACHED_REQUESTS  # another version is written
        assert mkstemp.call_count == 1
