"""Tests for the transport fixes (connection drop, open, receive, timeouts, list_identity)."""
import socket
import struct
import sys
import threading
from unittest import mock

import pytest

from pycomm3 import CIPDriver, CommError, LogixDriver, Tag
from pycomm3.cip import ConnectionManagerServices
from pycomm3.cip_driver import with_forward_open
from pycomm3.exceptions import ResponseError
from pycomm3.const import HEADER_SIZE, PRIORITY, TIMEOUT_TICKS
from pycomm3.packets import ListIdentityRequestPacket, SendUnitDataRequestPacket
from pycomm3.socket_ import Socket


def _connected_driver(sock):
    driver = CIPDriver("1.2.3.4")
    driver._sock = sock
    driver._session = 1
    driver._connection_opened = True
    driver._target_is_connected = True
    return driver


@pytest.mark.parametrize("error, raised", [(socket.timeout, CommError), (KeyboardInterrupt, KeyboardInterrupt)])
def test_send_drops_connection_when_reply_does_not_finish(error, raised):
    sock = mock.Mock()
    sock.receive.side_effect = error
    driver = _connected_driver(sock)

    with pytest.raises(raised):
        driver.send(ListIdentityRequestPacket())

    assert driver._sock is None
    assert driver.connected is False
    assert driver._target_is_connected is False
    assert driver._session == 0
    sock.close.assert_called_once()


def test_send_keeps_connection_when_request_fails_to_build():
    sock = mock.Mock()
    driver = _connected_driver(sock)
    request = ListIdentityRequestPacket()

    with mock.patch.object(request, "build_request", side_effect=ValueError):
        with pytest.raises(ValueError):
            driver.send(request)

    assert driver._sock is sock
    assert driver.connected is True
    sock.send.assert_not_called()


def test_open_without_session_leaves_driver_closed():
    with mock.patch("pycomm3.cip_driver.Socket") as mock_socket, \
            mock.patch.object(CIPDriver, "_register_session", return_value=None):
        driver = CIPDriver("1.2.3.4")
        assert driver.open() is False
        assert driver.connected is False
        assert driver._sock is None
        mock_socket.return_value.close.assert_called_once()

        driver.open()
        assert mock_socket.call_count == 2


def test_open_connect_error_leaves_driver_closed():
    with mock.patch("pycomm3.cip_driver.Socket") as mock_socket:
        mock_socket.return_value.connect.side_effect = OSError
        driver = CIPDriver("1.2.3.4")
        with pytest.raises(CommError):
            driver.open()
        assert driver.connected is False
        assert driver._sock is None

        with pytest.raises(CommError):
            driver.open()
        assert mock_socket.call_count == 2


def test_context_manager_raises_when_open_fails():
    with mock.patch("pycomm3.cip_driver.Socket"), \
            mock.patch.object(CIPDriver, "_register_session", return_value=None):
        body_ran = False
        with pytest.raises(CommError):
            with CIPDriver("1.2.3.4"):
                body_ran = True
        assert not body_ran


def test_socket_receive_raises_when_peer_closes_mid_reply():
    header = struct.pack("<HH", 0, 100).ljust(HEADER_SIZE, b"\x00")
    with mock.patch("socket.socket") as mock_socket:
        mock_socket.return_value.recv.side_effect = [header + bytes(10), b""]
        with pytest.raises(CommError):
            Socket().receive()


def test_unconnected_send_timeout_is_below_socket_timeout():
    # router timeout = 2^(priority/time_tick low nibble) ms * ticks
    router_timeout_ms = (2 ** (PRIORITY[0] & 0x0F)) * TIMEOUT_TICKS[0]
    assert router_timeout_ms < CIPDriver("1.2.3.4").socket_timeout * 1000


@pytest.mark.parametrize("identity", [{"product_name": "x"}, CommError])
def test_list_identity_skips_subclass_open_and_always_closes(identity):
    with mock.patch.object(CIPDriver, "open") as mock_open, \
            mock.patch.object(CIPDriver, "_list_identity", side_effect=[identity]), \
            mock.patch.object(CIPDriver, "close") as mock_close, \
            mock.patch.object(LogixDriver, "_initialize_driver") as mock_init:
        if identity is CommError:
            with pytest.raises(CommError):
                LogixDriver.list_identity("1.2.3.4/1")
        else:
            assert LogixDriver.list_identity("1.2.3.4/1") == identity
        mock_open.assert_called_once()
        mock_init.assert_not_called()
        mock_close.assert_called_once()


def test_list_identity_returns_empty_when_session_rejected():
    with mock.patch("pycomm3.cip_driver.Socket") as mock_socket, \
            mock.patch.object(CIPDriver, "_register_session", return_value=None):
        assert CIPDriver.list_identity("1.2.3.4") == {}
    mock_socket.return_value.send.assert_not_called()


def _held_by_other_thread(lock):
    free = []

    def probe():
        if lock.acquire(blocking=False):
            lock.release()
            free.append(True)

    t = threading.Thread(target=probe)
    t.start()
    t.join()
    return not free


def test_send_holds_lock_for_request_and_reply():
    driver = CIPDriver("1.2.3.4")
    held = []
    record = lambda *_: held.append(_held_by_other_thread(driver._lock))
    with mock.patch.object(CIPDriver, "_send", side_effect=record), \
            mock.patch.object(CIPDriver, "_receive", side_effect=record):
        driver.send(ListIdentityRequestPacket())
    assert held == [True, True]


def test_two_threads_send_one_forward_open():
    driver = CIPDriver("1.2.3.4")
    driver._session = 1
    entered, release = threading.Event(), threading.Event()
    calls = []

    def forward_open_reply(**kwargs):
        calls.append(kwargs["name"])
        entered.set()
        release.wait(5)
        return Tag("forward_open", b"\x01\x02\x03\x04", None, None)

    with mock.patch.object(CIPDriver, "generic_message", side_effect=forward_open_reply):
        threads = [threading.Thread(target=with_forward_open(lambda self: None), args=(driver,)) for _ in range(2)]
        threads[0].start()
        entered.wait(5)
        threads[1].start()
        threads[1].join(0.2)  # without the lock the second thread sends its own Forward Open meanwhile
        release.set()
        for t in threads:
            t.join(5)

    assert calls == ["forward_open"]
    assert driver._target_is_connected


def test_threads_share_the_sequence_counter():
    # a generator raises 'generator already executing' when two threads call next() at once
    driver = CIPDriver("1.2.3.4")
    errors = []

    def build():
        try:
            for _ in range(20000):
                SendUnitDataRequestPacket(driver._sequence)
        except ValueError as err:
            errors.append(err)

    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=build) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(interval)

    assert not errors
    # 80000 numbers taken, counting 1..65535 and wrapping back to 1
    assert SendUnitDataRequestPacket(driver._sequence)._sequence == 80000 - 65535 + 1


def test_discover_broadcasts_once_per_address():
    # getaddrinfo returns one entry per socket type (stream/dgram/raw) for the same address
    addr = (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 0))
    with mock.patch("socket.gethostname", return_value="host"), \
            mock.patch("socket.getaddrinfo", return_value=[addr] * 3) as gai, \
            mock.patch.object(CIPDriver, "_broadcast_discover", return_value=[]) as mock_broadcast:
        assert CIPDriver.discover() == []
    gai.assert_called_once_with("host", None, socket.AF_INET)
    assert [c[0][0] for c in mock_broadcast.call_args_list] == ["10.0.0.5", None]


def test_broadcast_discover_lets_ctrl_c_through_and_closes_socket():
    with mock.patch("pycomm3.cip_driver.socket.socket") as mock_socket:
        inst = mock_socket.return_value
        inst.__enter__.return_value = inst
        inst.recv.side_effect = KeyboardInterrupt
        with pytest.raises(KeyboardInterrupt):
            CIPDriver._broadcast_discover("10.0.0.5", b"", ListIdentityRequestPacket())
        assert inst.__exit__.called or inst.close.called


def test_forward_open_fallback_uses_new_triad_and_keeps_large_forward_open():
    driver = CIPDriver("1.2.3.4")
    driver._session = 1
    payloads = []

    def reject(**kwargs):
        payloads.append(kwargs["request_data"])
        return Tag("forward_open", None, None, "err")

    with mock.patch.object(CIPDriver, "generic_message", side_effect=reject):
        with pytest.raises(ResponseError):
            with_forward_open(lambda self: None)(driver)

    large, standard = payloads
    assert large[10:18] != standard[10:18]  # connection triad: csn, vendor id, vsn
    assert driver._cfg["extended forward open"] is True
    assert driver.connection_size == 4000


@pytest.mark.parametrize("method, service", [
    ("_forward_open", ConnectionManagerServices.large_forward_open),
    ("_forward_close", ConnectionManagerServices.forward_close),
])
def test_forward_open_close_address_connection_manager_instance_1(method, service):
    driver = CIPDriver("1.2.3.4")
    driver._session = 1
    with mock.patch.object(CIPDriver, "send") as mock_send:
        getattr(driver, method)()
    message = mock_send.call_args[0][0].build_message()
    assert message[:6] == service + b"\x02\x20\x06\x24\x01"  # class 0x06, instance 1


@pytest.mark.parametrize("error, raised", [(CommError, CommError), (ValueError, ResponseError)])
def test_get_module_info_lets_comm_errors_through(error, raised):
    # a connection failure stays a CommError, like the LogixDriver methods
    driver = CIPDriver("1.2.3.4")
    with mock.patch.object(driver, "generic_message", side_effect=error):
        with pytest.raises(raised):
            driver.get_module_info(1)


def test_un_register_session_resets_session_to_zero():
    # no session is 0 everywhere else (__init__, _drop_connection, close, _forward_open)
    driver = CIPDriver("1.2.3.4")
    driver._session = 1
    with mock.patch.object(driver, "send"):
        driver._un_register_session()
    assert driver._session == 0
