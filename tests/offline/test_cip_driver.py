"""Tests for the logix_driver.py file.

There are quite a few methods in the CIPDriver which are difficult to
read or test due to both code clarity and complexity issues. As well as
there being no way to control the execution of many of the private
methods through the public API. This has lead to testing of quite a few
private API methods to achieve an acceptable test coverage.
"""
from unittest import mock

import pytest

from ciplink import (
    PADDED_EPATH,
    CIPDriver,
    CommError,
    DataError,
    PortSegment,
    RequestError,
    parse_connection_path,
)
from ciplink.socket_ import Socket

from . import Mocket

CONNECT_PATH = "192.168.1.100"


_simple_path = ("192.168.1.100", None, [PortSegment("bp", 0)])
_simple_paths = [
    "192.168.1.100/bp/0",
    "192.168.1.100/backplane/0",
    r"192.168.1.100\bp\0",
    r"192.168.1.100\backplane\0",
    "192.168.1.100,bp,0",
    "192.168.1.100,1,0",
]

_route_path = (
    "192.168.1.100",
    None,
    [
        PortSegment(port="backplane", link_address=1),
        PortSegment(port="enet", link_address="10.11.12.13"),
        PortSegment(port="bp", link_address=0),
    ],
)
_route_paths = [
    "192.168.1.100/backplane/1/enet/10.11.12.13/bp/0",
    r"192.168.1.100\backplane\1\enet\10.11.12.13\bp\0",
    "192.168.1.100,backplane,1,enet,10.11.12.13,bp,0",
]

path_tests = [
    *[(p, _simple_path) for p in _simple_paths],
    *[(p, _route_path) for p in _route_paths],
    ("192.168.1.100", ("192.168.1.100", None, [])),
    ('192.168.1.100:123', ('192.168.1.100', 123, [])),
    ('192.168.1.100:123/bp,0', ('192.168.1.100', 123, _simple_path[-1]))
]


@pytest.mark.parametrize("path, expected_output", path_tests)
def test_plc_path(path, expected_output):
    assert parse_connection_path(path) == expected_output


auto_slot_path_tests = [
    ("192.168.1.100", _simple_path),
    ("192.168.1.100/0", _simple_path),
    (r"192.168.1.100\0", _simple_path),
]


@pytest.mark.parametrize("path, expected_output", auto_slot_path_tests)
def test_plc_path_auto_slot(path, expected_output):
    assert parse_connection_path(path, auto_slot=True) == expected_output


_bad_paths = [
    "192.168.1.100/Z",
    "bp/0",
    "192.168.1.100/-1",
    "192.168.1.100/backplan/1",
    "192.168.1.100/backplane/1/10.11.12.13/bp/0",
    "192.168.1.100//bp/1",
    "192.168.1.100/",
    "192.168.1.100,bp,1,0",
    "192.168.1.100,",
    "192.168.1.100:abc",
    "192.168.1.100:/bp/0",
    "192.168.1.100:-123",
]


@pytest.mark.parametrize("path", _bad_paths)
def test_bad_plc_paths(path):
    with pytest.raises(
        (DataError, RequestError),
    ):
        ip, port, segments = parse_connection_path(path)
        PADDED_EPATH.encode(segments, length=True)


def test_context_manager_calls_open_close():
    with mock.patch.object(CIPDriver, "open") as mock_close, mock.patch.object(
        CIPDriver, "close"
    ) as mock_open:
        with CIPDriver(CONNECT_PATH) as driver:
            ...
        assert mock_open.called
        assert mock_close.called


def test_context_manager_calls_open_close_with_exception():
    with mock.patch.object(CIPDriver, "open") as mock_close, mock.patch.object(
        CIPDriver, "close"
    ) as mock_open:
        try:
            with CIPDriver(CONNECT_PATH) as driver:
                x = 1 / 0
        except Exception:
            ...
        assert mock_open.called
        assert mock_close.called


def test_close_raises_no_error_on_close_with_registered_session():
    driver = CIPDriver(CONNECT_PATH)
    driver._session = 1
    driver._sock = Mocket()
    driver.close()


def test_open_raises_commerror_on_connect_fail():
    with mock.patch.object(Socket, "connect") as mock_connect:
        mock_connect.side_effect = Exception
        driver = CIPDriver(CONNECT_PATH)
        with pytest.raises(CommError):
            driver.open()


