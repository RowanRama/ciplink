"""
Tag list uploads byte for byte: the program symbol lists and the structure makeups are batched in multi-service
packets, and a reload reads again only the templates whose makeup changed.
"""
from contextlib import contextmanager
from unittest import mock

from ciplink.cip import UDINT, UINT
from ciplink.cip_driver import CIPDriver
from ciplink.logix_driver import LogixDriver
from ciplink.packets import TagTableVersionRequestPacket
from tests.offline.test_logix_tag_cache import OUTER_MAKEUP, OUTER_TEMPLATE, makeup_data, multi_reply
from tests.offline.test_logix_tag_list import UDT_MAKEUP, UDT_TEMPLATE, _symbol
from tests.offline.test_logix_tag_table_version import HEADER, V1, V2, cip_reply, version_reply

IDENTITY = {'product_name': '1756-L85E/B', 'revision': {'major': 37, 'minor': 13}, 'status': b'00',
            'serial': 'c0ffee01'}
SIMPLE_MAKEUP = {
    'object_definition_size': {'size': 10},
    'structure_size': {'size': 4},
    'member_count': {'count': 1},
    'structure_handle': {'handle': 0x5555},
}
SIMPLE_TEMPLATE = UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(0) + b'Simple;n0000\x00V\x00'
ATTRIBUTES = '0700' + '0100' + '0200' + '0300' + '0500' + '0600' + '0800' + '0a00'  # the symbol list attributes


def symbol_list_request(program, instance):
    """a Get_Instance_Attribute_List of a program's symbol list (a name of 10 characters, no pad byte)"""
    return bytes.fromhex('5508910a') + f'Program:{program}'.encode() + bytes.fromhex(f'206b24{instance:02x}' + ATTRIBUTES)


def makeup_request(instance_id):
    """a Get_Attribute_List of a template's structure makeup (attributes 4, 5, 2, 1)"""
    return bytes.fromhex(f'0303206c2500{instance_id & 0xFF:02x}{instance_id >> 8:02x}' + '0400040005000200' + '0100')


def parse_path(path):
    """(program or None, class, instance) of a request path"""
    i, program, class_code, instance = 0, None, None, None
    while i < len(path):
        if path[i] == 0x91:
            size = path[i + 1]
            program = path[i + 2:i + 2 + size].decode()[len('Program:'):]
            i += 2 + size + size % 2
        elif path[i] in (0x20, 0x24):
            class_code, instance = (path[i + 1], instance) if path[i] == 0x20 else (class_code, path[i + 1])
            i += 2
        else:  # 0x25, a 16-bit instance
            instance = UINT.decode(path[i + 2:i + 4])
            i += 4
    return program, class_code, instance


class Controller:
    """
    Answers the services of a tag list upload.  A symbol list reply holds at most ``page`` symbols and every
    packet at most ``capacity``, shared by the services in it.  ``rejected`` holds 'multi' to reject every
    multi-service packet, or programs whose symbol list is rejected inside one.  ``packets`` has the services of
    each packet: ('version',), ('symbols', program, first instance), ('makeup', id) or ('template', id).
    """

    def __init__(self, page=100, capacity=100):
        self.version = V1
        self.scopes = {
            None: [(1, 'Program:P1', 0x1068), (2, 'Program:P2', 0x1068), (3, 'Program:P3', 0x1068),
                   (4, 'Task:T', 0x1070), (5, 'a', 0xC4), (6, 'udt', 0x8123)],
            'P1': [(1, 'Routine:R', 0x106D), (2, 'outer', 0x8124)],  # Outer nests MyUDT, 0x123
            'P2': [(1, 'Routine:R', 0x106D)] + [(i, f't{i}', 0xC4) for i in range(2, 7)],
            'P3': [(1, 'Routine:R', 0x106D), (2, 'x', 0x8125)],
        }
        self.templates = {0x123: (UDT_MAKEUP, UDT_TEMPLATE), 0x124: (OUTER_MAKEUP, OUTER_TEMPLATE),
                          0x125: (SIMPLE_MAKEUP, SIMPLE_TEMPLATE)}
        self.page, self.capacity = page, capacity
        self.rejected = set()
        self.packets = []
        self.messages = []  # the services of each packet, as sent

    def _service(self, message, multi):
        service, path, data = message[0], message[2:2 + 2 * message[1]], message[2 + 2 * message[1]:]
        program, class_code, instance = parse_path(path)
        if class_code == 0xAC:
            return ('version',), version_reply(TagTableVersionRequestPacket(1), self.version).raw[46:]
        if service == 0x55:
            if multi and program in self.rejected:
                return ('symbols', program, instance), cip_reply(service, 0x05)
            entries = [e for e in self.scopes[program] if e[0] >= instance]
            count = min(len(entries), self.page, self.left)
            self.left -= count
            data = b''.join(_symbol(*e) for e in entries[:count])
            return ('symbols', program, instance), cip_reply(service, 6 if count < len(entries) else 0, data)
        if service == 0x03:
            return ('makeup', instance), cip_reply(service, 0, makeup_data(self.templates[instance][0]))
        return ('template', instance), cip_reply(service, 0, self.templates[instance][1])

    def send(self, request):
        message = request.build_message()[2:]  # without the sequence count
        self.left = self.capacity
        if message[0] != 0x0A:
            kind, reply = self._service(message, False)
            self.packets.append([kind])
            self.messages.append([message])
            return request.response_class(request, HEADER + reply)
        body = message[2 + 2 * message[1]:]
        bounds = [UINT.decode(body[2 + 2 * i:4 + 2 * i]) for i in range(UINT.decode(body[:2]))] + [len(body)]
        services = [body[start:end] for start, end in zip(bounds, bounds[1:])]
        self.messages.append(services)
        if 'multi' in self.rejected:
            self.packets.append(['rejected'])
            return request.response_class(request, HEADER + cip_reply(0x0A, 0x08))
        kinds, replies = zip(*(self._service(service, True) for service in services))
        self.packets.append(list(kinds))
        return multi_reply(request, list(replies))


@contextmanager
def uploaded(fake, **kwargs):
    """a driver opened on the fake controller"""
    plc = LogixDriver('1.2.3.4', **kwargs)
    plc._target_is_connected = True
    with mock.patch.object(CIPDriver, 'open', return_value=True), \
            mock.patch.object(LogixDriver, '_list_identity', return_value=IDENTITY), \
            mock.patch.object(LogixDriver, 'get_plc_info', return_value=dict(IDENTITY)), \
            mock.patch.object(LogixDriver, 'get_plc_name'), \
            mock.patch.object(CIPDriver, 'send', side_effect=fake.send):
        assert plc.open()
        yield plc


ALL_TAGS = {'a', 'udt', 'Program:P1.outer', 'Program:P3.x', *(f'Program:P2.t{i}' for i in range(2, 7))}
PROGRAM_PAGES = [('symbols', 'P1', 0), ('symbols', 'P2', 0), ('symbols', 'P3', 0)]
MAKEUPS = [('makeup', 0x123), ('makeup', 0x124), ('makeup', 0x125)]


def test_connect_batches_program_pages_and_makeups():
    fake = Controller()
    with uploaded(fake) as plc:
        assert set(plc.tags) == ALL_TAGS
        assert plc.data_types['Outer']['internal_tags']['In']['data_type']['attributes'] == ['A', 'B', 'Flag']
    assert fake.packets == [
        [('version',)], [('symbols', None, 0)], PROGRAM_PAGES, MAKEUPS,
        [('template', 0x123)], [('template', 0x124)], [('template', 0x125)], [('version',)],
    ]
    assert fake.messages[2] == [symbol_list_request(p, 0) for p in ('P1', 'P2', 'P3')]
    assert fake.messages[3] == [makeup_request(i) for i in (0x123, 0x124, 0x125)]


def test_reload_reads_only_makeups_when_templates_are_unchanged():
    fake = Controller()
    with uploaded(fake) as plc:
        connect = len(fake.packets)
        fake.scopes['P2'].append((9, 'new', 0xC4))  # an online edit
        fake.version = V2
        assert plc.check_tag_table() is True
        assert 'Program:P2.new' in plc.tags and plc._tag_table_version == V2
        assert plc.tags['udt']['type_class'].decode(bytes(16)) == {'A': 0, 'B': [0, 0], 'Flag': False}
    assert fake.packets[connect:] == [
        [('version',)],  # the check
        [('version',)], [('symbols', None, 0)], PROGRAM_PAGES, MAKEUPS, [('version',)],  # no template read
    ]


def test_reload_reads_a_template_whose_makeup_changed():
    fake = Controller()
    with uploaded(fake) as plc:
        connect = len(fake.packets)
        fake.templates[0x125] = (dict(SIMPLE_MAKEUP, structure_handle={'handle': 0x6666}),
                                 SIMPLE_TEMPLATE.replace(b'\x00V\x00', b'\x00W\x00'))  # a member renamed
        fake.version = V2
        assert plc.check_tag_table() is True
        assert plc.data_types['Simple']['attributes'] == ['W']
        assert plc.tags['Program:P3.x']['data_type']['attributes'] == ['W']
    assert fake.packets[connect + 4:] == [MAKEUPS, [('template', 0x125)], [('version',)]]


def test_templates_are_not_kept_for_another_controller():
    fake = Controller()
    with uploaded(fake) as plc:
        plc._info = dict(plc.info, serial='c0ffee02')  # was connected to another controller
        fake.packets.clear()
        assert plc.open()
    assert [('template', 0x123)] in fake.packets  # read again


def test_pages_that_say_more_follows_continue_in_the_next_batch():
    fake = Controller(page=3)  # at most 3 symbols per reply
    fake.scopes['P3'] += [(3, 'y3', 0xC4), (4, 'y4', 0xC4), (5, 'y5', 0xC4)]
    with uploaded(fake) as plc:
        assert set(plc.tags) == ALL_TAGS | {'Program:P3.y3', 'Program:P3.y4', 'Program:P3.y5'}
        assert plc.info['programs']['P2']['routines'] == ['R']
    assert fake.packets[1:5] == [
        [('symbols', None, 0)], [('symbols', None, 4)],  # the controller's pages, one at a time
        PROGRAM_PAGES,  # P2 and P3 reply with 3 of their symbols, status 0x06
        [('symbols', 'P2', 4), ('symbols', 'P3', 4)],
    ]
    assert fake.messages[4] == [symbol_list_request('P2', 4), symbol_list_request('P3', 4)]


def test_page_without_symbols_continues_alone():
    # the packet is full before the last program's page, which comes back empty with status 0x06
    fake = Controller(capacity=3)
    with uploaded(fake) as plc:
        assert set(plc.tags) == ALL_TAGS
    assert fake.packets[1:7] == [
        [('symbols', None, 0)], [('symbols', None, 4)],
        PROGRAM_PAGES,  # P1's 2 symbols, P2's first, none of P3's
        [('symbols', 'P3', 0)],  # uploaded alone from its first page
        [('symbols', 'P2', 2)], [('symbols', 'P2', 5)],  # the only program left, a batch of one is sent alone
    ]


def test_rejected_batches_fall_back_to_requests_sent_alone():
    expected = Controller()
    with uploaded(expected) as plc:
        expected_tags = plc.tags_json
    fake = Controller()
    fake.rejected.add('multi')
    with uploaded(fake) as plc:
        assert plc.tags_json == expected_tags
    assert fake.packets == [
        [('version',)], [('symbols', None, 0)],
        ['rejected'], [('symbols', 'P1', 0)], [('symbols', 'P2', 0)], [('symbols', 'P3', 0)],
        ['rejected'], [('makeup', 0x123)], [('template', 0x123)], [('makeup', 0x124)], [('template', 0x124)],
        [('makeup', 0x125)], [('template', 0x125)], [('version',)],
    ]


def test_service_rejected_in_a_batch_is_sent_alone():
    fake = Controller()
    fake.rejected.add('P2')
    with uploaded(fake) as plc:
        assert set(plc.tags) == ALL_TAGS
    assert fake.packets[2:5] == [PROGRAM_PAGES, [('symbols', 'P2', 0)], MAKEUPS]


def test_batched_page_that_does_not_advance_continues_alone():
    # a controller that ignores the start instance inside a multi-service packet: no endless loop, no duplicates
    class IgnoresStartInBatches(Controller):
        def _service(self, message, multi):
            assert len(self.packets) < 20, 'the upload did not stop'
            if not (multi and message[0] == 0x55):
                return super()._service(message, multi)
            program, _, instance = parse_path(message[2:2 + 2 * message[1]])
            return ('symbols', program, instance), super()._service(symbol_list_request(program, 0), multi)[1]

    fake = IgnoresStartInBatches(page=3)
    fake.scopes['P3'] += [(3, 'y3', 0xC4), (4, 'y4', 0xC4), (5, 'y5', 0xC4)]
    with uploaded(fake) as plc:
        assert set(plc.tags) == ALL_TAGS | {'Program:P3.y3', 'Program:P3.y4', 'Program:P3.y5'}
        assert plc.info['programs']['P2']['routines'] == ['R']
    assert fake.packets[3:7] == [
        PROGRAM_PAGES,
        [('symbols', 'P2', 4), ('symbols', 'P3', 4)],  # both answered from instance 0 again
        [('symbols', 'P2', 4)], [('symbols', 'P3', 4)],  # continued alone
    ]


PAIR_MAKEUP = dict(SIMPLE_MAKEUP, structure_size={'size': 8}, member_count={'count': 2},
                   object_definition_size={'size': 12})
PAIR_INFO = UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(0) + UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(4)


def test_download_reads_every_template_again():
    # a download can swap two members of the same type and keep the makeup, only online edits keep the templates
    fake = Controller()
    fake.templates[0x125] = (PAIR_MAKEUP, PAIR_INFO + b'Pair;n0000\x00Start\x00Stops\x00')
    with uploaded(fake) as plc:
        connect = len(fake.packets)
        fake.templates[0x125] = (PAIR_MAKEUP, PAIR_INFO + b'Pair;n0000\x00Stops\x00Start\x00')
        fake.version = (2, 1, 11, 11, 21)  # downloaded: new download and project timestamps
        assert plc.check_tag_table() is True
        members = plc.tags['Program:P3.x']['data_type']['internal_tags']
        assert (members['Stops']['offset'], members['Start']['offset']) == (0, 4)
    assert fake.packets[connect + 4:] == [
        MAKEUPS, [('template', 0x123)], [('template', 0x124)], [('template', 0x125)], [('version',)],
    ]
