"""Transport framing and connection lifecycle regressions; no PLC required."""
import socket
import struct
import threading
from unittest import mock

import pytest

from pycomm3 import CIPDriver, CommError, RequestError
from pycomm3.packets import ListIdentityRequestPacket
from pycomm3.socket_ import Socket


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


def test_live_connection_size_change_is_rejected():
    driver = CIPDriver("127.0.0.1")
    driver._target_is_connected = True
    with pytest.raises(RequestError):
        driver.connection_size = 500
    assert driver.connection_size == 4000


def test_timeout_configuration_applies_to_an_open_socket():
    driver = CIPDriver("127.0.0.1", socket_timeout=2.5)
    driver._sock = mock.Mock()
    driver.socket_timeout = 1.25
    driver._sock.settimeout.assert_called_once_with(1.25)
    assert driver.socket_timeout == 1.25


@pytest.mark.parametrize("timeout", [0, -1, True, "5", float("inf"), float("nan")])
def test_invalid_socket_timeout_is_rejected(timeout):
    with pytest.raises(ValueError):
        CIPDriver("127.0.0.1", socket_timeout=timeout)


def test_failed_registration_releases_socket_and_allows_retry():
    driver = CIPDriver("127.0.0.1")
    with mock.patch("pycomm3.cip_driver.Socket") as factory, \
            mock.patch.object(driver, "_register_session", side_effect=[None, 10]):
        assert not driver.open()
        factory.return_value.close.assert_called_once()
        assert not driver.connected and driver._sock is None
        assert driver.open()
    assert factory.call_count == 2


def test_context_body_is_not_entered_after_failed_registration():
    driver = CIPDriver("127.0.0.1")
    entered = False
    with mock.patch.object(driver, "open", return_value=False):
        with pytest.raises(CommError):
            with driver:
                entered = True
    assert not entered


def test_unregister_is_attempted_even_if_forward_close_fails():
    driver = CIPDriver("127.0.0.1")
    driver._target_is_connected = driver._connection_opened = True
    driver._session = 10
    driver._target_cid = b"abcd"
    driver._sock = mock.Mock()
    with mock.patch.object(driver, "_forward_close", side_effect=CommError("failed close")), \
            mock.patch.object(driver, "_un_register_session") as unregister:
        with pytest.raises(CommError):
            driver.close()
    unregister.assert_called_once()
    assert driver._target_cid is None and driver._session == 0 and not driver.connected


def test_close_skips_unregister_after_forward_close_drops_the_connection():
    driver = CIPDriver("127.0.0.1")
    driver._target_is_connected = driver._connection_opened = True
    driver._session = 10
    transport = driver._sock = mock.Mock()
    transport.send.side_effect = socket.timeout()
    with pytest.raises(CommError, match="^failed to send message$"):
        driver.close()
    assert transport.send.call_count == 1  # no unregister on the dropped socket
    assert driver._sock is None and not driver.connected


class SlowSocket:
    """connect takes a moment, a second connect on the same socket fails"""

    def __init__(self, timeout=None):
        self.state = "new"

    def connect(self, host, port):
        if self.state != "new":
            raise OSError("connect already in progress")
        self.state = "connecting"
        threading.Event().wait(0.2)
        self.state = "connected"

    def send(self, msg):
        if self.state != "connected":
            raise OSError("not connected")

    def receive(self):  # RegisterSession reply, session 7
        return b"\x65\x00\x04\x00" + (7).to_bytes(4, "little") + bytes(16) + b"\x01\x00\x00\x00"

    def close(self):
        self.state = "closed"


def test_two_threads_can_reopen_a_shared_driver():
    driver = CIPDriver("127.0.0.1")  # dropped after a CommError, both threads call open() again
    results = []
    with mock.patch("pycomm3.cip_driver.Socket", SlowSocket):
        threads = [threading.Thread(target=lambda: results.append(driver.open())) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
    assert results == [True, True] and driver.connected and driver._session == 7


@pytest.mark.parametrize("operation", ["_send", "_receive"])
def test_transport_failure_invalidates_connection_without_retry(operation):
    driver = CIPDriver("127.0.0.1")
    transport = mock.Mock()
    driver._sock = transport
    driver._target_is_connected = driver._connection_opened = True
    driver._session = 10
    getattr(transport, operation[1:]).side_effect = socket.timeout()
    with pytest.raises(CommError):
        driver.send(ListIdentityRequestPacket())
    transport.close.assert_called_once()
    assert driver._sock is None and driver._session == 0 and not driver.connected
    assert transport.send.call_count == 1
    assert transport.receive.call_count == (operation == "_receive")


def test_zero_session_handle_is_treated_as_failed_registration():
    driver = CIPDriver("127.0.0.1")
    with mock.patch("pycomm3.cip_driver.Socket") as factory, \
            mock.patch.object(driver, "_register_session", return_value=0):
        assert not driver.open()
    factory.return_value.close.assert_called_once()
    assert not driver.connected
