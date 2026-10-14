"""
Add-On Instructions byte for byte: each AOI type is probed once (one instance read whole and member by member),
a refused whole read becomes the reads of the readable members, and refused members are never requested.
"""
import json
from unittest import mock

import pytest

from ciplink.cip import DINT, UDINT, UINT
from ciplink.logix_driver import LogixDriver
from tests.offline import test_logix_tag_upload
from tests.offline.test_logix_tag_list import _symbol
from tests.offline.test_logix_tag_table_version import V2, cip_reply
from tests.offline.test_logix_tag_upload import Controller, uploaded

BOOL, DINT_ = 0xC1, 0xC4
# template id: (name, [(member, type, bit or array length, offset)], structure size, local tags)
TYPES = {
    0x200: ('Valve', [('__BitHost00', DINT_, 0, 0), ('EnableIn', BOOL, 0, 0), ('EnableOut', BOOL, 1, 0),
                      ('Cmd', BOOL, 2, 0), ('Mode', DINT_, 0, 4), ('Count', DINT_, 0, 8), ('Busy', BOOL, 3, 0)],
            12, {'Count', 'Busy'}),
    0x201: ('Proc', [('__BitHost00', DINT_, 0, 0), ('EnableIn', BOOL, 0, 0), ('EnableOut', BOOL, 1, 0)], 4, set()),
    0x202: ('Tmr', [('__BitHost00', DINT_, 0, 0), ('EnableIn', BOOL, 0, 0), ('EnableOut', BOOL, 1, 0),
                    ('ACC', DINT_, 0, 4)], 8, {'ACC'}),
    0x203: ('Outer', [('__BitHost00', DINT_, 0, 0), ('EnableIn', BOOL, 0, 0), ('EnableOut', BOOL, 1, 0),
                      ('Out', DINT_, 0, 4), ('Inner', 0x8202, 0, 8)], 16, {'Inner'}),  # Tmr only as a local
    0x204: ('Holder', [('V', DINT_, 0, 0), ('Valves', 0x8200, 2, 4)], 28, set()),  # not an AOI
    0x125: ('Simple', [('V', DINT_, 0, 0)], 4, set()),
}
# what a controller answers: the read of an AOI with locals (0x0F, extended 0x2100), of a local (0x04)
PERMISSION = bytes([0xCC, 0, 0x0F, 1]) + UINT.encode(0x2100)


@pytest.fixture(autouse=True)
def read_write_symbols(monkeypatch):
    """the symbols of the fake controller are Read/Write (0), the last byte of an entry, '-' entries are None (3)"""
    def symbol(instance, name, *args):
        return _symbol(instance, name.lstrip('-'), *args)[:-1] + bytes([3 if name.startswith('-') else 0])
    monkeypatch.setattr(test_logix_tag_upload, '_symbol', symbol)


def template(tid):
    name, members, _, _ = TYPES[tid]
    info = b''.join(UINT.encode(i) + UINT.encode(t) + UDINT.encode(o) for _, t, i, o in members)
    return info + f'{name};n0000\x00'.encode() + b''.join(m.encode() + b'\x00' for m, *_ in members)


def makeup(tid, handle=None):
    _, members, size, _ = TYPES[tid]
    return {'object_definition_size': {'size': len(template(tid)) // 4 + 10}, 'structure_size': {'size': size},
            'member_count': {'count': len(members)}, 'structure_handle': {'handle': handle or tid}}


def tag_path(path):
    """the segments of a tag request path: names, ('id', symbol instance) and ('index', element)"""
    segments, i = [], 0
    while i < len(path):
        if path[i] == 0x91:
            size = path[i + 1]
            segments.append(path[i + 2:i + 2 + size].decode())
            i += 2 + size + size % 2
        elif path[i] == 0x20:  # the symbol class
            i += 2
        elif path[i] in (0x24, 0x28):
            segments.append(('id' if path[i] == 0x24 else 'index', path[i + 1]))
            i += 2
        else:  # 0x25 or 0x29, 16 bits
            segments.append(('id' if path[i] == 0x25 else 'index', UINT.decode(path[i + 2:i + 4])))
            i += 4
    return segments


class AOIController(Controller):
    """
    The upload Controller with AOI types, it also answers tag reads (and writes, always successful) like a 5580:
    ``packets`` gets ('read', tag) or ('write', tag).  ``faults`` maps a tag to the status of its reads, replies
    bigger than ``max_reply`` are partial (0x06).
    """

    def __init__(self, scopes, **kwargs):
        super().__init__(**kwargs)
        self.scopes = scopes
        self.templates = {tid: (makeup(tid), template(tid)) for tid in TYPES}
        self.faults = {}
        self.max_reply = 1000

    def _service(self, message, multi):
        service, path = message[0], message[2:2 + 2 * message[1]]
        if service not in (0x4C, 0x4D) or path[:2] == b'\x20\x6c':  # 0x4C of a template
            return super()._service(message, multi)
        tag, status, typ = self._resolve(tag_path(path))
        kind = ('read' if service == 0x4C else 'write', tag)
        if service == 0x4D:
            return kind, cip_reply(service, 0)
        if status == 0x0F:
            return kind, PERMISSION
        if status:
            return kind, cip_reply(service, status)
        if typ & 0x8000:
            data = b'\xa0\x02' + UINT.encode(typ & 0xFFF) + bytes(TYPES[typ & 0xFFF][2])
        else:
            data = UINT.encode(typ) + (b'\x01' if typ == BOOL else DINT.encode(7))
        if len(data) > self.max_reply:
            return kind, cip_reply(service, 0x06, data[:self.max_reply])
        return kind, cip_reply(service, 0, data)

    def _resolve(self, segments):
        """(tag, status, data type) of a tag request"""
        scope = None
        if isinstance(segments[0], str) and segments[0].startswith('Program:'):
            scope = segments.pop(0)[len('Program:'):]
        first = segments.pop(0)
        symbol = next(e for e in self.scopes[scope] if (e[0] if isinstance(first, tuple) else e[1]) ==
                      (first[1] if isinstance(first, tuple) else first))
        tag, typ, status = (f'Program:{scope}.' if scope else '') + symbol[1], symbol[2] & 0x8FFF, 0
        for segment in segments:
            if isinstance(segment, tuple):
                tag += f'[{segment[1]}]'
                continue
            tag += f'.{segment}'
            if not status and segment in TYPES[typ & 0xFFF][3]:
                status = 0x04
            typ = next(t for m, t, *_ in TYPES[typ & 0xFFF][1] if m == segment)
        if not status and typ & 0x8000 and TYPES.get(typ & 0xFFF, (0, 0, 0, ()))[3]:
            status = 0x0F
        return tag, self.faults.get(tag, status), typ


CONTROLLER = [
    (10, 'valves', 0xA200, 3),  # Valve[3]
    (11, 'holder', 0x8204),  # Holder: a Valve[2] member
    (12, 'v1', 0x8200),  # Valve
    (13, 'procs', 0xA201, 2),  # Proc[2], the only Procs
    (14, 'outer', 0x8203),  # Outer, holds the only Tmr as a local
    (15, 'plain', 0x8125),  # not an AOI
    (16, 'd', 0xC4),
]
VALVE = {'whole_read': False, 'readable': ['EnableIn', 'EnableOut', 'Cmd', 'Mode'], 'refused': ['Count', 'Busy']}
PROC = {'whole_read': True, 'readable': ['EnableIn', 'EnableOut'], 'refused': []}
OUTER = {'whole_read': False, 'readable': ['EnableIn', 'EnableOut', 'Out'], 'refused': ['Inner']}
PROBES = {'Valve': VALVE, 'Proc': PROC, 'Outer': OUTER}


def fake(controller=CONTROLLER, programs=None):
    """a controller with these controller symbols and programs, {program: [symbols]}"""
    programs = programs or {}
    return AOIController({None: [(i, f'Program:{p}', 0x1068) for i, p in enumerate(programs, 1)] + controller,
                          **programs})


def reads(fake):
    """the tags read in each packet that read any"""
    return [[kind[1] for kind in packet if kind[0] == 'read'] for packet in fake.packets
            if any(kind[0] == 'read' for kind in packet)]


def test_probe_classifies_members():
    controller = fake()
    with uploaded(controller) as plc:
        assert {name: plc.data_types[name].get('aoi') for name in ('Valve', 'Proc', 'Outer', 'Tmr', 'Holder',
                                                                     'Simple')} == dict(PROBES, Tmr=None,
                                                                                         Holder=None, Simple=None)
        assert plc.tags['v1']['data_type']['aoi'] == VALVE  # the same dict
        assert plc.tags_json['v1']['data_type']['aoi'] == VALVE
        json.dumps(plc.tags_json)
    sent = reads(controller)
    assert len(sent) == 1  # every probe in one multi-service packet
    assert sorted(sent[0]) == sorted([
        'v1', 'v1.EnableIn', 'v1.EnableOut', 'v1.Cmd', 'v1.Mode', 'v1.Count', 'v1.Busy',  # a scalar tag
        'procs[0]', 'procs[0].EnableIn', 'procs[0].EnableOut',  # else element 0 of an array
        'outer', 'outer.EnableIn', 'outer.EnableOut', 'outer.Out', 'outer.Inner',  # not Tmr, inside a local
    ])


def test_transient_errors_leave_members_readable():
    controller = fake()
    controller.faults = {'v1.Count': 0x05, 'v1': 0x08, 'outer.Out': 0x1F}  # not a refusal
    with uploaded(controller) as plc:
        assert plc.data_types['Valve']['aoi'] == {'whole_read': True, 'readable': VALVE['readable'] + ['Count'],
                                                  'refused': ['Busy']}
        assert plc.data_types['Outer']['aoi'] == OUTER


def test_probe_packets_are_counted_against_the_budgets():
    controller = fake()
    with uploaded(controller, connection_size=120) as plc:
        assert {name: plc.data_types[name].get('aoi') for name in PROBES} == PROBES
    sent = [services for services in controller.messages if any(s[0] == 0x4C and s[2:4] != b'\x20\x6c'
                                                                for s in services)]
    assert [len(services) for services in sent] == [5, 5, 5]  # the 15 probes, at most 120 bytes a packet
    for services in sent:
        assert 6 + 2 + sum(2 + len(s) for s in services) <= 120  # the request: header, count, offsets, services
    assert reads(controller)[-1][-1] == 'outer'  # the biggest reply last


def test_whole_aoi_too_big_for_a_packet_is_read_alone():
    controller = fake()
    controller.max_reply = 10
    with uploaded(controller, connection_size=30) as plc:
        assert plc.data_types['Valve']['aoi'] == VALVE  # 'v1' got a partial reply (0x06), the member reads 0x04
        assert plc.data_types['Proc']['aoi'] == PROC


@pytest.mark.parametrize('symbols, instance', [
    ([(10, 'valves', 0xA200, 3), (12, 'v1', 0x8200)], 'v1'),  # a scalar before an array element
    ([(11, 'holder', 0x8204), (10, 'valves', 0xA200, 3)], 'valves[0]'),  # an array element before a member
    ([(11, 'holder', 0x8204)], 'holder.Valves[0]'),  # a member
    ([(12, '-hidden', 0x8200), (11, 'holder', 0x8204)], 'holder.Valves[0]'),  # not a tag without external access
])
def test_instance_selection(symbols, instance):
    controller = fake(symbols)
    with uploaded(controller) as plc:
        assert plc.data_types['Valve']['aoi'] == VALVE
    assert instance in reads(controller)[0] and f'{instance}.Busy' in reads(controller)[0]


def test_program_tag_instance():
    controller = fake([(16, 'd', 0xC4)], {'P1': [(1, 'Routine:R', 0x106D), (2, 'v', 0x8200)]})
    with uploaded(controller) as plc:
        assert plc.data_types['Valve']['aoi'] == VALVE
        assert plc.read('Program:P1.v').value == {'EnableIn': True, 'EnableOut': True, 'Cmd': True, 'Mode': 7}
    assert 'Program:P1.v.Busy' in reads(controller)[0]


def test_whole_aoi_read_returns_its_readable_members():
    controller = fake()
    with uploaded(controller) as plc:
        controller.packets.clear()
        d, v1, valve, nested, proc, plain = plc.read('d', 'v1', 'valves[2]', 'holder.Valves[1]', 'procs[1]', 'plain')
        expected = {'EnableIn': True, 'EnableOut': True, 'Cmd': True, 'Mode': 7}
        assert (d.value, d.error) == (7, None)
        assert v1 == ('v1', expected, 'Valve', None)
        assert valve == ('valves[2]', expected, 'Valve', None)
        assert nested == ('holder.Valves[1]', expected, 'Valve', None)
        assert proc.value == {'EnableIn': False, 'EnableOut': False} and proc.error is None  # read whole
        assert plain.value == {'V': 0} and plain.error is None
        sent = reads(controller)
        assert len(sent) == 1  # one packet, in the same call
        members = [f'{t}.{m}' for t in ('v1', 'valves[2]', 'holder.Valves[1]') for m in VALVE['readable']]
        assert set(sent[0]) == {'d', 'procs[1]', 'plain', *members}

        controller.faults = {'v1.Mode': 0x05}
        v1 = plc.read('v1')
        assert v1.value is None and v1.error.startswith('Mode - ')


def test_change_during_an_aoi_read_reads_it_again():
    controller = fake()
    with uploaded(controller) as plc:
        controller.packets.clear()
        controller.version = V2  # an online edit, seen by the read's check
        d, v1 = plc.read('d', 'v1')
        assert (d.value, v1.value, v1.error) == (7, {'EnableIn': True, 'EnableOut': True, 'Cmd': True, 'Mode': 7}, None)
    members = [f'v1.{m}' for m in VALVE['readable']]
    assert [sorted(packet) for packet in reads(controller)] == [sorted(['d', *members])] * 2  # no probe on the reload


def test_array_tag_without_index_reads_its_first_element():
    controller = fake()
    with uploaded(controller) as plc:
        controller.packets.clear()
        assert plc.read('valves').value['Mode'] == 7
    assert reads(controller) == [[f'valves[0].{m}' for m in VALVE['readable']]]


def test_refused_members_are_not_requested():
    controller = fake()
    with uploaded(controller) as plc:
        controller.packets.clear()
        for result in (plc.read('v1.Count'), plc.read('valves[1].Busy'), plc.read('outer.Inner.ACC'),
                       plc.read('v1.count'), plc.write('v1.Count', 5), plc.write('holder.Valves[0].Busy', True)):
            assert result.value is None and result.error == 'AOI local tag, not externally accessible'
        assert controller.packets == []
        mode, count = plc.read('v1.Mode', 'v1.Count')  # the others are read
        assert (mode.value, count.error) == (7, 'AOI local tag, not externally accessible')
        assert plc.write('v1', bytes(12)).error is None  # whole AOI writes are unchanged
    assert controller.packets[-2:] == [[('write', 'v1')], [('version',)]]


def test_cache_file_keeps_the_probes(tmp_path):
    path = tmp_path / 'tags.json'
    with uploaded(fake(), tag_cache_file=str(path)):
        pass
    text = path.read_text()
    assert {entry[2]['readable'][0] for entry in json.loads(text)['aoi']} == {'EnableIn'}
    controller = fake()
    with uploaded(controller, tag_cache_file=str(path)) as plc:
        assert {name: plc.data_types[name].get('aoi') for name in PROBES} == PROBES
        assert plc.read('v1.Busy').error == 'AOI local tag, not externally accessible'
    assert controller.packets == [[('version',)], [('version',)]]  # nothing uploaded, nothing probed
    assert path.read_text() == text  # not rewritten


def test_cache_file_without_probes_is_probed_and_rewritten(tmp_path):
    path = tmp_path / 'tags.json'
    with uploaded(fake(), tag_cache_file=str(path)):
        pass
    saved = json.loads(path.read_text())
    del saved['aoi']  # written before the probes
    path.write_text(json.dumps(saved))
    controller = fake()
    with uploaded(controller, tag_cache_file=str(path)) as plc:
        assert {name: plc.data_types[name].get('aoi') for name in PROBES} == PROBES
    assert len(reads(controller)) == 1 and 'aoi' in json.loads(path.read_text())


def test_cache_file_probe_of_a_changed_type_is_probed_again(tmp_path):
    path = tmp_path / 'tags.json'
    with uploaded(fake(), tag_cache_file=str(path)):
        pass
    controller = fake()
    controller.version = V2  # an edit since: the symbol lists and makeups are read
    controller.templates[0x201] = (makeup(0x201, handle=0x999), template(0x201))
    with uploaded(controller, tag_cache_file=str(path)) as plc:
        assert {name: plc.data_types[name].get('aoi') for name in PROBES} == PROBES
    assert [sorted(packet) for packet in reads(controller)] == [
        ['procs[0]', 'procs[0].EnableIn', 'procs[0].EnableOut']]  # only Proc


def test_reload_probes_only_new_or_changed_types():
    controller = fake()
    with uploaded(controller) as plc:
        controller.packets.clear()
        controller.templates[0x200] = (makeup(0x200, handle=0x999), template(0x200))  # Valve edited
        controller.version = V2
        assert plc.check_tag_table() is True
        assert {name: plc.data_types[name].get('aoi') for name in PROBES} == PROBES
        probes = reads(controller)
        assert len(probes) == 1 and {tag.split('.')[0] for tag in probes[0]} == {'v1'}

        controller.packets.clear()
        controller.version = (400, 1, 10, 10, 20)  # an online edit, no change to the AOI types
        assert plc.check_tag_table() is True
        assert reads(controller) == []
        assert plc.data_types['Valve']['aoi'] == VALVE


def test_non_aoi_structs_are_unchanged():
    controller = fake()
    with uploaded(controller) as plc:
        assert not any('aoi' in plc.data_types[name] for name in ('Holder', 'Simple', 'Tmr'))
        controller.packets.clear()
        plain, holder, v = plc.read('plain', 'holder', 'holder.V')
        assert (plain.value, holder.value['V'], v.value) == ({'V': 0}, 0, 7)
        assert plc.write('plain', bytes(4)).error is None
    assert reads(controller) == [['plain', 'holder', 'holder.V']]  # read whole


def test_type_without_an_instance_is_not_probed():
    controller = fake([(16, 'd', 0xC4)])
    with uploaded(controller) as plc:
        assert plc.data_types == {}
    assert reads(controller) == []

    controller = fake([(17, '-hidden', 0x8200)])  # Valve only in a tag without external access
    with uploaded(controller) as plc:
        assert 'aoi' not in plc.data_types['Valve']
        controller.packets.clear()
        busy = plc.read('hidden.Busy')  # read as today
        assert busy.value is None and 'IOI syntax error' in busy.error
    assert reads(controller) == [['-hidden.Busy']]


def test_lazy_tags_probe_at_the_first_use():
    controller = fake()
    with uploaded(controller, lazy_tags=True) as plc:
        assert reads(controller) == []
        assert plc.read('d').value == 7
        assert reads(controller) == [['d']]
        controller.packets.clear()
        assert plc.read('v1.Busy').error == 'AOI local tag, not externally accessible'
        assert sorted(reads(controller)[0]) == sorted(['v1', *(f'v1.{m}' for m in VALVE['readable'] +
                                                                     VALVE['refused'])])
        controller.packets.clear()
        assert plc.read('valves[1]').value['Mode'] == 7  # Valve is known, not probed again
        assert reads(controller) == [[f'valves[1].{m}' for m in VALVE['readable']]]


def test_without_instance_ids_tags_are_requested_by_name():
    controller = fake()
    with uploaded(controller) as plc:
        plc._cfg['use_instance_ids'] = False
        message = plc._parse_tag_request('v1')
        assert message['request_path'][1] == 0x91
        controller.packets.clear()
        assert plc.read('v1').value == {'EnableIn': True, 'EnableOut': True, 'Cmd': True, 'Mode': 7}
        assert plc.read('v1.Busy').error == 'AOI local tag, not externally accessible'
    sent = [m for m in controller.messages if len(m) > 1][-1]
    assert all(b'\x91\x02v1' in service for service in sent)  # the member reads, the base tag by name


def test_probe_without_instance_ids_names_the_tags():
    identity = {'product_name': '1756-L85E/B', 'revision': {'major': 20, 'minor': 0}, 'status': b'00',
                'serial': 'c0ffee01'}
    controller = fake()
    with mock.patch('tests.offline.test_logix_tag_upload.IDENTITY', identity):
        with uploaded(controller) as plc:
            assert plc._cfg['use_instance_ids'] is False
            assert {name: plc.data_types[name].get('aoi') for name in PROBES} == PROBES
    probes = [m for m in controller.messages if any(s[0] == 0x4C and b'v1' in s for s in m)]
    assert probes and all(b'\x20\x6b' not in s for s in probes[0])
