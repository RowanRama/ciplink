"""Transport framing and connection lifecycle regressions; no PLC required."""
import struct
from unittest import mock

import pytest

from ciplink import CIPDriver, CommError
from ciplink.socket_ import Socket


def frame(payload):
    return struct.pack("<HH", 0x70, len(payload)).ljust(24, b"\x00") + payload


def test_tcp_frame_header_and_payload_can_be_split_at_every_byte():
    data = frame(b"payload")
    with mock.patch("socket.socket") as factory:
        factory.return_value.recv.side_effect = [bytes([value]) for value in data]
        transport = Socket()
        assert transport.receive() == data
    assert factory.return_value.recv.call_count == len(data)


def test_coalesced_frames_are_preserved_for_next_receive():
    first, second = frame(b"first"), frame(b"second")
    with mock.patch("socket.socket") as factory:
        factory.return_value.recv.return_value = first + second
        transport = Socket()
        assert transport.receive() == first
        assert transport.receive() == second
    factory.return_value.recv.assert_called_once_with(4096)


@pytest.mark.parametrize("prefix", [b"", b"\x70", frame(b"payload")[:-1]])
def test_eof_during_header_or_payload_raises_commerror(prefix):
    with mock.patch("socket.socket") as factory:
        factory.return_value.recv.side_effect = [prefix, b""] if prefix else [b""]
        transport = Socket()
        with pytest.raises(CommError, match="complete frame"):
            transport.receive()


def test_large_frame_uses_packet_sized_receive_buffer():
    data = frame(bytes(4000))
    with mock.patch("socket.socket") as factory:
        factory.return_value.recv.return_value = data
        transport = Socket()
        assert transport.receive() == data
    factory.return_value.recv.assert_called_once_with(4096)


@pytest.mark.parametrize("size,extended", [(100, False), (500, False), (511, False), (512, True), (4000, True)])
def test_connection_size_selects_forward_open_format(size, extended):
    driver = CIPDriver("127.0.0.1", connection_size=size)
    assert driver.connection_size == size
    assert driver._cfg["extended forward open"] == extended


@pytest.mark.parametrize("size", [0, -1, 65536, True, 4000.5, "500"])
def test_invalid_connection_size_is_rejected(size):
    with pytest.raises(ValueError):
        CIPDriver("127.0.0.1", connection_size=size)


@pytest.mark.parametrize("timeout", [0, -1, True, "5", float("inf"), float("nan")])
def test_invalid_socket_timeout_is_rejected(timeout):
    with pytest.raises(ValueError):
        CIPDriver("127.0.0.1", socket_timeout=timeout)


def test_context_body_is_not_entered_after_failed_registration():
    driver = CIPDriver("127.0.0.1")
    entered = False
    with mock.patch.object(driver, "open", return_value=False):
        with pytest.raises(CommError):
            with driver:
                entered = True
    assert not entered


