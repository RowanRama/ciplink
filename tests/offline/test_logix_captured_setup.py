"""Offline validation of bounded setup replay; no PLC traffic or real auth bytes."""

from types import SimpleNamespace

import pytest

from examples.logix_captured_setup import capture_requests
from pycomm3.packets import SendUnitDataRequestPacket


def enip(wire, cid=b'cid!', session=123):
    request = SendUnitDataRequestPacket(1)
    request.add(wire)
    return request.build_request(cid, session, b'testctx!', 0)


@pytest.fixture
def setup_capture(tmp_path, monkeypatch):
    path = tmp_path / 'synthetic.pcapng'
    path.write_bytes(b'No real authentication data')
    first = bytes.fromhex('4b0220642401') + b'\x99\x00' + bytes(279)
    second = bytes.fromhex('4c02206424011400') + bytes(20)
    rows = [[275, enip(first), '1'], [279, enip(second), '1']]
    def run(command, **kwargs):
        return SimpleNamespace(stdout='\n'.join('{}\t{}\t{}'.format(n, b.hex(), s) for n, b, s in rows))
    monkeypatch.setattr('examples.logix_captured_setup.subprocess.run', run)
    return path, rows, first, second


def test_loads_two_requests_without_replaying_enip_identities(setup_capture):
    path, _, first, second = setup_capture
    requests, digest = capture_requests(path, (275, 279), 'tshark')
    assert requests == [first, second]
    assert len(digest) == 64


@pytest.mark.parametrize('change, message', [
    ('stream', 'same ENIP session'),
    ('session', 'same ENIP session'),
    ('cid', 'same connected CIP connection'),
    ('write_service', 'observed class 0x64 setup'),
    ('bad_length', 'unobserved payload layout'),
    ('reply_service', 'completion request'),
    ('missing', 'Both selected frames'),
])
def test_rejects_other_connections_and_unobserved_requests(setup_capture, change, message):
    path, rows, first, second = setup_capture
    if change == 'stream':
        rows[1][2] = '2'
    elif change == 'session':
        rows[1][1] = enip(second, session=456)
    elif change == 'cid':
        rows[1][1] = enip(second, cid=b'else')
    elif change == 'write_service':
        rows[0][1] = enip(b'\x4d' + first[1:])
    elif change == 'bad_length':
        rows[0][1] = enip(first[:6] + b'\x98' + first[7:])
    elif change == 'reply_service':
        rows[1][1] = enip(b'\xcc' + second[1:])
    elif change == 'missing':
        rows.pop()
    with pytest.raises(ValueError, match=message):
        capture_requests(path, (275, 279), 'tshark')


def test_requires_capture_order(setup_capture):
    path, *_ = setup_capture
    with pytest.raises(ValueError, match='capture order'):
        capture_requests(path, (279, 275), 'tshark')
