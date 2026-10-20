"""Requests by instance ID are checked against the controller's tag table version (1756-PM020 step 5)."""
import logging
from contextlib import contextmanager
from unittest import mock

import pytest

from ciplink.cip import DINT, UINT
from ciplink.cip_driver import CIPDriver
from ciplink.const import BASE_TAG_BIT
from ciplink.exceptions import ResponseError
from ciplink.logix_driver import LogixDriver, _RELOAD_BACKOFF
from ciplink.packets import (
    MultiServiceRequestPacket,
    ReadTagFragmentedRequestPacket,
    ReadTagRequestPacket,
    TagTableVersionRequestPacket,
    WriteTagRequestPacket,
)
from ciplink.packets.logix import TAG_TABLE_VERSION_ATTRIBUTES

IDENTITY = {'product_name': '1756-SIM/A', 'revision': {'major': 33, 'minor': 11}, 'status': b'00',
            'serial': 'c0ffee01'}
V1, V2, V3, V4 = (316, 1, 10, 10, 20), (318, 1, 10, 10, 20), (320, 1, 10, 10, 20), (322, 1, 10, 10, 20)
CHECK = '030220ac2401' + '0500' + '0100' + '0200' + '0300' + '0400' + '0a00'  # Get_Attribute_List 0xAC/1
HEADER = b'\x70\x00' + bytes(44)  # encapsulation and CPF header of a reply, its CIP reply starts at byte 46


def cip_reply(service, status, data=b''):
    return bytes([service | 0x80, 0, status, 0]) + data


def version_reply(request, version):
    """the reply to a tag table version check, version None replies like an emulator (status 0x05)"""
    if version is None:
        return request.response_class(request, HEADER + cip_reply(0x03, 0x05))
    data = UINT.encode(len(version)) + b''.join(
        UINT.encode(attribute) + UINT.encode(0) + data_type.encode(value)
        for (attribute, data_type), value in zip(TAG_TABLE_VERSION_ATTRIBUTES, version)
    )
    return request.response_class(request, HEADER + cip_reply(0x03, 0, data))


def raw_tag(name, instance_id, length=0):
    """a DINT or DINT[length] entry of a symbol list upload"""
    return {
        'tag_name': name, 'instance_id': instance_id, 'symbol_type': DINT.code | (0x2000 if length else 0),
        'symbol_address': 0, 'symbol_object_address': 0, 'software_control': BASE_TAG_BIT,
        'external_access': 'Read/Write', 'dimensions': [length, 0, 0],
    }


class FakePLC:
    """
    A controller with DINT tags read and written by symbol instance ID or by name, and a tag table version.
    ``edits`` maps the index of a packet to a function run right before that packet is answered.
    """

    def __init__(self, tags, version=V1):
        self.tags = {}  # name: (instance id, value)
        self.version = version
        self.packets = []
        self.uploads = 0
        self.edits = {}
        self.set(tags, version)

    def set(self, tags, version):
        """an online edit: the new tag table and its version"""
        self.tags, self.version = dict(tags), version

    def edit_at(self, offset, tags, version):
        """edits the tag table right before the packet ``offset`` packets from now"""
        self.edits[len(self.packets) + offset] = lambda: self.set(tags, version)

    def symbols(self, program=None):
        self.uploads += 1
        return [raw_tag(name, i, len(v) if isinstance(v, list) else 0) for name, (i, v) in self.tags.items()]

    def sent(self, *types):
        return [p for p in self.packets if isinstance(p, types)]

    def _tag_at(self, path):
        if path[1:3] == b'\x20\x6b':  # by symbol instance ID
            return next((name for name, (i, _) in self.tags.items() if i == path[4]), None)
        name = path[3:3 + path[2]].decode()  # by name
        return name if name in self.tags else None

    def _reply(self, request):
        service = request.tag_only_message()[0]
        if isinstance(request, TagTableVersionRequestPacket):
            return version_reply(request, self.version).raw[46:]
        name = self._tag_at(request.request_path)
        if name is None:
            return cip_reply(service, 0x05)
        instance_id, value = self.tags[name]
        if isinstance(request, WriteTagRequestPacket):
            self.tags[name] = instance_id, DINT.decode(request.value)
            return cip_reply(service, 0)
        data = b''.join(DINT.encode(v) for v in value[:request.elements]) if isinstance(value, list) else \
            DINT.encode(value)
        if isinstance(request, ReadTagFragmentedRequestPacket):  # 2000 bytes per fragment
            more = request.offset + 2000 < len(data)
            return cip_reply(service, 6 if more else 0, UINT.encode(DINT.code) + data[request.offset:][:2000])
        return cip_reply(service, 0, UINT.encode(DINT.code) + data)

    def send(self, request):
        edit = self.edits.pop(len(self.packets), None)
        self.packets.append(request)
        if edit:
            edit()
        if not isinstance(request, MultiServiceRequestPacket):
            return request.response_class(request, HEADER + self._reply(request))
        replies = [self._reply(r) for r in request.requests]
        offsets, offset = [], 2 + 2 * len(replies)
        for reply in replies:
            offsets.append(UINT.encode(offset))
            offset += len(reply)
        status = 0x1E if any(reply[2] for reply in replies) else 0
        data = UINT.encode(len(replies)) + b''.join(offsets) + b''.join(replies)
        return request.response_class(request, HEADER + cip_reply(0x0A, status, data))


@contextmanager
def connected(fake, identity=IDENTITY, **kwargs):
    """a driver opened on the fake controller, its tag list uploaded unless lazy"""
    plc = LogixDriver('1.2.3.4', **kwargs)
    plc._target_is_connected = True
    with mock.patch.object(CIPDriver, 'open', return_value=True), \
            mock.patch.object(LogixDriver, '_list_identity', return_value=identity), \
            mock.patch.object(LogixDriver, 'get_plc_info', return_value=dict(identity)), \
            mock.patch.object(LogixDriver, 'get_plc_name'), \
            mock.patch.object(CIPDriver, 'send', side_effect=fake.send), \
            mock.patch.object(LogixDriver, '_get_instance_attribute_list_service', side_effect=fake.symbols):
        assert plc.open()
        fake.connect_packets = list(fake.packets)
        fake.packets.clear()
        yield plc


@contextmanager
def clock():
    """the time.monotonic() the driver sees, ``now[0]`` is moved by the test"""
    now = [1000.0]
    with mock.patch('ciplink.logix_driver.time.monotonic', side_effect=lambda: now[0]):
        yield now


def services(packet):
    """the services of a packet, in order"""
    requests = packet.requests if isinstance(packet, MultiServiceRequestPacket) else [packet]
    return [r.tag_only_message().hex() for r in requests]


TAGS = {'a': (5, 1), 'b': (6, 2), 'arr': (7, list(range(1500))), 'arr2': (8, list(range(1500, 3000)))}
# 'b' deleted, its ID reused by the next tag created, 'b' created again with a new ID
EDITED = {'a': (5, 1), 'x': (6, 99), 'b': (9, 2), 'arr': (7, list(range(1500))), 'arr2': (8, list(range(1500, 3000)))}


def test_check_is_the_first_service_of_every_read_packet():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        assert [t.value for t in plc.read('a', 'b')] == [1, 2]
        assert plc.read('b').value == 2  # a single read is a packet of two
    assert [type(p) for p in fake.packets] == [MultiServiceRequestPacket] * 2
    assert services(fake.packets[0]) == [CHECK, '4c' + '02206b2405' + '0100', '4c' + '02206b2406' + '0100']
    assert services(fake.packets[1]) == [CHECK, '4c' + '02206b2406' + '0100']
    message = fake.packets[0].build_message()
    assert message[10 + 2 * 3:].startswith(bytes.fromhex(CHECK))  # after the header and 3 offsets


def test_packing_budget_includes_the_check():
    # 8 (reply header) + 44 (check) + 3 x 12 (DINT reads): 3 reads fit a packet, 6 would without the check
    tags = {f't{i}': (10 + i, i) for i in range(7)}
    fake = FakePLC(tags)
    with connected(fake) as plc:
        plc._cfg['connection_size'] = 8 + TagTableVersionRequestPacket.reply_size + 3 * 12
        assert [t.value for t in plc.read(*tags)] == list(range(7))
    # a sequence or offset plus the service, the reply plus its offset
    assert TagTableVersionRequestPacket.request_size == 2 + len(CHECK) // 2
    assert TagTableVersionRequestPacket.reply_size == 2 + len(version_reply(fake.packets[0].requests[0], V1).raw[46:])
    assert [services(p)[0] for p in fake.packets] == [CHECK] * 3
    assert [len(p.requests) for p in fake.packets] == [4, 4, 2]


def test_fragmented_reads_are_between_checks():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        a, arr, arr2 = plc.read('a', 'arr{1500}', 'arr2{1500}')
    assert (a.value, arr.value, arr2.value) == (1, list(range(1500)), list(range(1500, 3000)))
    check, frag = TagTableVersionRequestPacket, ReadTagFragmentedRequestPacket
    assert [type(p) for p in fake.packets] == [
        MultiServiceRequestPacket, check, frag, frag, frag, check, frag, frag, frag, check
    ]
    assert services(fake.packets[0])[0] == CHECK


def test_partial_reply_read_again_is_followed_by_a_check():
    # a read the packing thought would fit gets a partial reply, it is read again as a fragmented read
    fake = FakePLC(TAGS)
    reply = fake._reply

    def partial(request):
        if type(request) is ReadTagRequestPacket:
            return cip_reply(0x4C, 6, reply(request)[4:][:100])
        return reply(request)

    with connected(fake) as plc, mock.patch.object(fake, '_reply', side_effect=partial):
        assert plc.read('arr{900}').value == list(range(900))
    check, frag = TagTableVersionRequestPacket, ReadTagFragmentedRequestPacket
    assert [type(p) for p in fake.packets] == [MultiServiceRequestPacket, frag, frag, check]


def test_change_during_a_read_discards_it_and_reads_again():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        fake.edit_at(0, EDITED, V2)  # before the read's packet, its ID 6 now names 'x'
        a, b = plc.read('a', 'b')
    assert (a.value, a.error, b.value, b.error) == (1, None, 2, None)  # not x's 99
    assert fake.uploads == 2  # on connect, after the change
    assert plc._tag_table_version == V2 and plc.tags['b']['instance_id'] == 9
    reads = fake.sent(MultiServiceRequestPacket)
    assert len(reads) == 2
    assert services(reads[1]) == [CHECK, '4c' + '02206b2405' + '0100', '4c' + '02206b2409' + '0100']


def test_change_during_a_fragmented_read_is_seen_by_the_check_after_it():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        moved = dict(TAGS, arr=(10, list(range(1500))))
        fake.edit_at(2, moved, V2)  # at the second fragment
        assert plc.read('arr{1500}').value == list(range(1500))
    assert fake.uploads == 2
    assert fake.sent(ReadTagFragmentedRequestPacket)[-1].request_path.hex() == '02206b240a'


def test_second_change_gives_errors_instead_of_a_third_read():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        fake.edit_at(0, EDITED, V2)
        fake.edit_at(3, dict(EDITED, b=(11, 2)), V3)  # the retry's packet, after the reload's 2 checks
        a, b = plc.read('a', 'b')
        assert a.value is None and b.value is None
        assert 'Tag table changed' in a.error and 'Tag table changed' in b.error
        assert len(fake.sent(MultiServiceRequestPacket)) == 2
        assert fake.uploads == 2

        assert plc.read('b').value == 2  # the next call loads the definitions again
        assert fake.uploads == 3


def test_packet_that_failed_as_a_whole_is_not_a_change():
    # its reads have the packet's error, its check read nothing
    fake = FakePLC(TAGS)
    sent = []

    def too_large(request):
        sent.append(request)
        return request.response_class(request, HEADER + cip_reply(0x0A, 0x11))

    with connected(fake) as plc:
        CIPDriver.send.side_effect = too_large
        result = plc.read('a')
    assert result.value is None and 'too large' in result.error
    assert fake.uploads == 1 and len(sent) == 1


def test_connect_reads_the_version_twice():
    # the read on connect is also the one before the upload, then the one after it
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        assert plc._tag_table_version == V1
    assert [type(p) for p in fake.connect_packets] == [TagTableVersionRequestPacket] * 2
    assert fake.uploads == 1


def test_failed_check_backs_off_reloads():
    # 0x05 while a download is in progress: no reload, every read and write fails for 2 s without sending anything
    fake = FakePLC(TAGS)
    with connected(fake) as plc, clock() as now:
        fake.edit_at(0, TAGS, None)
        a = plc.read('a')
        assert a.value is None and 'controller busy' in a.error
        assert len(fake.packets) == 1 and fake.uploads == 1

        fake.set(EDITED, V2)  # the download ended
        now[0] += _RELOAD_BACKOFF - 0.1
        assert plc.read('a').error == a.error
        assert [r.error for r in plc.read('a', 'b')] == [a.error] * 2
        assert plc.write('b', 20).error == a.error
        assert plc.check_tag_table() is False
        assert len(fake.packets) == 1 and fake.tags['b'] == (9, 2)

        now[0] += 0.1
        assert plc.read('b').value == 2  # the next reload
    assert fake.uploads == 2 and plc._tag_table_version == V2


def test_failed_reload_backs_off():
    fake = FakePLC(TAGS)
    with connected(fake) as plc, clock() as now:
        fake.set(EDITED, V2)
        with mock.patch.object(LogixDriver, '_get_instance_attribute_list_service',
                               side_effect=ResponseError('upload refused')):
            b = plc.read('b')
        assert b.value is None and 'controller busy' in b.error and 'upload refused' in b.error
        sent = len(fake.packets)  # the read, the check before the upload
        assert plc.read('b').error == b.error
        assert plc.write('b', 20).error == b.error
        assert len(fake.packets) == sent and not fake.sent(WriteTagRequestPacket)

        now[0] += _RELOAD_BACKOFF
        assert plc.read('b').value == 2
        assert plc.write('b', 20).error is None
    assert fake.uploads == 2 and fake.tags['b'] == (9, 20)


def test_reload_failed_in_another_thread_is_not_tried_again_at_once():
    # a thread that waited on the lock while another thread's reload failed keeps to the backoff
    fake = FakePLC(TAGS)
    with connected(fake) as plc, clock():
        plc._back_off('reload failed - upload refused')  # by the other thread, once this one passed its check
        assert plc._refresh_tag_table() is False
    assert fake.packets == [] and fake.uploads == 1


def test_download_started_during_the_connect_upload_keeps_the_tag_list():
    # the version is not read after the upload: open() succeeds, the first read after the backoff loads it again
    fake = FakePLC(TAGS)
    upload = fake.symbols

    def download_starts(program=None):
        if fake.uploads == 0:
            fake.version = None
        return upload(program)

    fake.symbols = download_starts
    with clock() as now, connected(fake) as plc:
        assert set(plc.tags) == set(TAGS) and plc._tag_table_version is None
        assert 'controller busy' in plc.read('a').error and fake.packets == []
        fake.set(EDITED, V2)  # the download ended
        now[0] += _RELOAD_BACKOFF
        assert plc.read('b').value == 2  # its ID now names 'x', the check loads the tag list again
    assert fake.uploads == 2 and plc._tag_table_version == V2


def test_failed_check_before_a_write_refuses_it():
    fake = FakePLC(TAGS)
    with connected(fake) as plc, clock() as now:
        fake.set(TAGS, None)
        assert 'controller busy' in plc.write('a', 10).error
        assert [type(p) for p in fake.packets] == [TagTableVersionRequestPacket]
        fake.set(TAGS, V1)
        now[0] += _RELOAD_BACKOFF
        assert plc.write('a', 10).error is None
    assert fake.tags['a'] == (5, 10) and fake.uploads == 1


def test_tag_list_is_not_uploaded_without_its_version():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        fake.set(EDITED, None)
        with pytest.raises(ResponseError, match='Tag table version not read'):
            plc.get_tag_list()
        assert fake.uploads == 1 and plc.tags['b']['instance_id'] == 6


def test_writes_are_checked_before_and_after_never_in_their_packet():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        assert plc.write('a', 10).error is None
        assert [r.error for r in plc.write(('a', 11), ('b', 12))] == [None, None]
    check = TagTableVersionRequestPacket
    assert [type(p) for p in fake.packets] == [check, WriteTagRequestPacket, check,
                                               check, MultiServiceRequestPacket, check]
    assert not any(isinstance(r, check) for r in fake.packets[4].requests)
    assert fake.tags['a'] == (5, 11) and fake.tags['b'] == (6, 12)
    assert fake.uploads == 1


def test_change_before_a_write_reloads_first():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        fake.set(EDITED, V2)
        assert plc.write('b', 20).error is None
    assert fake.tags['b'] == (9, 20) and fake.tags['x'] == (6, 99)
    assert fake.uploads == 2
    assert fake.sent(WriteTagRequestPacket)[0].request_path.hex() == '02206b2409'


def test_change_during_a_write_is_an_error_and_not_retried():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        fake.edit_at(1, EDITED, V2)  # the write's packet, ID 6 now names 'x'
        a, b = plc.write(('a', 10), ('b', 20))
        assert 'Tag table changed' in a.error and 'Tag table changed' in b.error
        assert fake.tags['x'] == (6, 20)  # what the check guards against
        assert len(fake.sent(MultiServiceRequestPacket)) == 1
        assert fake.uploads == 2 and plc.tags['b']['instance_id'] == 9


def test_controller_without_tag_table_version_uses_names(caplog):
    fake = FakePLC(TAGS, version=None)  # like an emulator, status 0x05
    with caplog.at_level(logging.WARNING, logger='ciplink'), connected(fake) as plc:
        assert plc._cfg['use_instance_ids'] is False
        assert plc.read('a').value == 1
        assert plc.write('b', 20).error is None
        assert plc.check_tag_table() is False
    assert 'tag table change detection is unavailable' in caplog.text
    assert [services(p) for p in fake.packets] == [
        ['4c' + '0291016100' + '0100'],
        ['4d' + '0291016200' + 'c400' + '0100' + '14000000'],
    ]


@pytest.mark.parametrize('identity', [
    dict(IDENTITY, revision={'major': 20, 'minor': 0}),
    dict(IDENTITY, product_name='2080-LC50-48QWBS'),
])
def test_without_instance_ids_nothing_is_checked(identity):
    fake = FakePLC(TAGS)
    with connected(fake, identity=identity) as plc:
        assert plc.read('a', 'b')[1].value == 2
        assert plc.write('a', 3).error is None
        assert plc.check_tag_table() is False
        plc.get_tag_list()
    assert not fake.sent(TagTableVersionRequestPacket)
    assert all('206b' not in s for p in fake.packets for s in services(p))


def test_instance_ids_turned_off_send_no_check():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        plc._cfg['use_instance_ids'] = False
        assert plc.read('a').value == 1
        assert plc.write('b', 20).error is None
        assert plc.check_tag_table() is False
    assert [type(p) for p in fake.packets] == [ReadTagRequestPacket, WriteTagRequestPacket]


def test_tag_list_upload_is_repeated_if_the_table_changed_during_it():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        fake.edit_at(1, EDITED, V2)  # the check after the upload
        plc.get_tag_list()
        assert fake.uploads == 3  # on connect, and twice here
        assert plc._tag_table_version == V2 and plc.tags['b']['instance_id'] == 9
        assert [type(p) for p in fake.packets] == [TagTableVersionRequestPacket] * 4


def test_tag_list_that_keeps_changing_is_kept_and_loaded_again_later(caplog):
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        for packet, version in ((1, V2), (3, V3), (5, V4)):  # each check after an upload
            fake.edit_at(packet, EDITED, version)
        with caplog.at_level(logging.WARNING, logger='ciplink'):
            plc.get_tag_list()
        assert 'kept changing' in caplog.text
        assert fake.uploads == 4
        assert plc._tag_table_version == V3  # read before the last upload, so the next check loads it again
        assert plc.check_tag_table() is True
        assert fake.uploads == 5 and plc._tag_table_version == V4


def test_check_tag_table():
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        assert plc.check_tag_table() is False
        assert [type(p) for p in fake.packets] == [TagTableVersionRequestPacket]
        assert fake.uploads == 1

        fake.set(EDITED, V2)
        assert plc.check_tag_table() is True
        assert fake.uploads == 2 and plc._tag_table_version == V2
        assert plc.read('b').value == 2
        assert plc.check_tag_table() is False


@contextmanager
def reloaded_by_another_thread(plc, fake, method):
    """
    right before the first call of ``method``: an online edit gives 'b''s ID 6 to 'x', and another thread sharing the
    driver sees it and loads the tag definitions again, e.g. a poller calling check_tag_table()
    """
    original, calls = getattr(plc, method), []

    def run(*args):
        if not calls:
            calls.append(method)
            fake.set(EDITED, V2)
            assert plc.check_tag_table() is True
        return original(*args)

    with mock.patch.object(plc, method, side_effect=run):
        yield


def test_reload_by_another_thread_after_a_read_was_parsed():
    # the read's check matches the version the other thread loaded, not the one its IDs were parsed with
    fake = FakePLC(TAGS)
    with connected(fake) as plc, reloaded_by_another_thread(plc, fake, '_send_requests'):
        b = plc.read('b')
    assert (b.value, b.error) == (2, None)  # not x's 99
    assert fake.uploads == 3  # on connect, by the other thread, by the read
    assert services(fake.sent(MultiServiceRequestPacket)[-1])[1:] == ['4c' + '02206b2409' + '0100']


@pytest.mark.parametrize('method, b, x, error', [
    ('_read_tag_table_version', 1234, 99, None),  # before its check before: built again with b's new ID
    ('_send_requests', 2, 1234, 'Tag table changed'),  # after it: an error, as for an edit during the write
])
def test_reload_by_another_thread_after_a_write_was_built(method, b, x, error):
    fake = FakePLC(TAGS)
    with connected(fake) as plc, reloaded_by_another_thread(plc, fake, method):
        result = plc.write('b', 1234)
    assert fake.tags['b'] == (9, b) and fake.tags['x'] == (6, x)
    assert (result.error is None) if error is None else (error in result.error)
    assert fake.uploads == 3


def test_reconnect_keeps_the_version_a_kept_tag_list_was_loaded_at():
    # init_tags=False keeps the tag list over a reconnect, an edit made while disconnected loads it again
    fake = FakePLC(TAGS)
    with connected(fake, init_tags=False) as plc:
        plc.get_tag_list()
        fake.set(EDITED, V2)
        assert plc.open()  # reconnect
        assert plc._tag_table_version == V1
        b = plc.read('b')
    assert (b.value, b.error) == (2, None)  # not x's 99
    assert fake.uploads == 2 and plc.tags['b']['instance_id'] == 9


def test_tag_list_shared_before_connecting_is_loaded_again():
    # its version is unknown, the version read on connect may be newer than the list
    fake = FakePLC(TAGS)
    with connected(fake) as plc:
        plc2 = LogixDriver('1.2.3.4', init_tags=False)
        plc2._target_is_connected = True
        plc2._tags = plc.tags
        fake.set(EDITED, V2)
        assert plc2.open()
        assert plc2._tag_table_version is None
        assert plc2.read('b').value == 2
    assert fake.uploads == 2 and plc2.tags['b']['instance_id'] == 9
    assert plc.tags['b']['instance_id'] == 6  # plc's list is not changed


def test_lazy_tags_reset_on_a_change():
    fake = FakePLC(TAGS)
    with connected(fake, lazy_tags=True) as plc:
        assert fake.uploads == 0 and plc._tag_table_version == V1
        assert plc.read('b').value == 2
        assert fake.uploads == 1

        fake.edit_at(0, EDITED, V2)
        assert plc.read('b').value == 2
        assert fake.uploads == 2  # the controller's symbol list once more, for 'b' only
        assert set(plc.tags) == {'b'} and plc.tags['b']['instance_id'] == 9
        assert plc._tag_table_version == V2
