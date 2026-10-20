"""Tests for the transport fixes (connection drop, open, receive, timeouts, list_identity)."""
import struct
import sys
import threading
from unittest import mock

import pytest

from ciplink import CIPDriver, CommError
from ciplink.const import HEADER_SIZE, PRIORITY, TIMEOUT_TICKS
from ciplink.packets import SendUnitDataRequestPacket
from ciplink.socket_ import Socket


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


