# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Ian Ottoway <ian@ottoway.dev>
# Copyright (c) 2014 Agostino Ruscito <ruscito@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

"""
The CIP driver, a thin layer over the Rust core (``ciplink._core``): the connection, Forward Open/Close, generic
messages and the raw passthrough :meth:`CIPDriver.send` run in Rust with the GIL released.
"""

__all__ = [
    "CIPDriver",
    "with_forward_open",
    "parse_connection_path",
]

import logging
import threading
from functools import wraps
from typing import Union, Optional, Tuple, List, Sequence, Type, Any, Dict

from . import _core
from .cip import CIPSegment, PortSegment, PADDED_EPATH, DataType
from .exceptions import ResponseError, CommError, RequestError
from .packets import (
    RequestPacket,
    ResponsePacket,
    SendUnitDataRequestPacket,
    SendRRDataRequestPacket,
    GenericConnectedResponsePacket,
    GenericUnconnectedResponsePacket,
)
from .tag import Tag
from .util import cycle


def with_forward_open(func):
    """Kept for compatibility: the Rust core opens the CIP connection (Forward Open) itself when a call needs it."""

    @wraps(func)
    def wrapped(self, *args, **kwargs):
        return func(self, *args, **kwargs)

    return wrapped


def _check_connection_size(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("connection_size must be an integer between 1 and 65535")


def _check_socket_timeout(value):
    if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                              or not 0 < value < float("inf")):
        raise ValueError("socket_timeout must be a positive finite number or None")


class _Cfg(dict):
    """A snapshot of the reference driver's ``_cfg`` settings; ``use_instance_ids`` can be set (tests, tools)."""

    def __init__(self, driver, items):
        super().__init__(items)
        self._driver = driver

    def __setitem__(self, key, value):
        if key == "use_instance_ids" and hasattr(self._driver._core, "set_use_instance_ids"):
            self._driver._core.set_use_instance_ids(bool(value))
        elif key == "connection_size":
            self._driver.connection_size = value
        elif key == "socket_timeout":
            self._driver.socket_timeout = value
        super().__setitem__(key, value)


class _ReplyOf:
    """What a generic response packet reads from its request: the data type to decode the reply with."""

    def __init__(self, data_type):
        self.data_type = data_type


class CIPDriver:
    """
    A base CIP driver for the SLCDriver and LogixDriver classes.  Implements common CIP services like
    (un)registering sessions, forward open/close, generic messaging, etc.
    """

    __log = logging.getLogger(f"{__module__}.{__qualname__}")
    _auto_slot_cip_path = False

    def __init__(
        self, path: str, *args, socket_timeout: float = 5.0,
        connection_size: int = 4000, **kwargs
    ):
        _check_socket_timeout(socket_timeout)
        _check_connection_size(connection_size)
        self._cip_path = path
        self._ip, self._port, self._route = parse_connection_path(path, self._auto_slot_cip_path)
        self._lock = threading.RLock()  # kept for callers that lock the driver; the core has its own lock
        self._sequence = cycle(65535, start=1)  # packets built by callers take a count, send() renumbers them
        self._core = self._make_core(path, socket_timeout, connection_size)

    def _make_core(self, path, socket_timeout, connection_size):
        return _core.CIPDriver(path, socket_timeout, connection_size)

    def __enter__(self):
        if not self.open():
            raise CommError("failed to register a session")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.close()
        except CommError:
            self.__log.exception("Error closing connection.")
            return False
        else:
            if not exc_type:
                return True
            self.__log.exception("Unhandled Client Error", exc_info=(exc_type, exc_val, exc_tb))
            return False

    def __repr__(self):
        return f"{self.__class__.__name__}(path={self._cip_path})"

    def __str__(self):
        _rev = self._info.get("revision", {"major": -1, "minor": -1})
        return f"Device: {self._info.get('product_type', 'None')}, Revision: {_rev['major']}.{_rev['minor']}"

    @property
    def _info(self) -> Dict[str, Any]:
        return {}

    @property
    def _cfg(self) -> dict:
        size = self.connection_size
        return _Cfg(self, {
            "context": b"_pycomm_",
            "protocol version": b"\x01\x00",
            "port": self._port or 44818,
            "ip address": self._ip,
            "cip_path": list(self._route),
            "option": 0,
            "extended forward open": size > 511,
            "connection_size": size,
            "socket_timeout": self.socket_timeout,
        })

    @property
    def connected(self) -> bool:
        """
        Read-Only Property to check whether or not a connection is open.

        :return: True if a connection is open, False otherwise
        """
        return self._core.connected

    @property
    def _connection_opened(self) -> bool:
        return self._core.connected

    @property
    def _target_is_connected(self) -> bool:
        return self._core.target_connected

    @property
    def connection_size(self):
        """Maximum connected message size; configure before a Forward Open."""
        return self._core.connection_size

    @connection_size.setter
    def connection_size(self, value):
        _check_connection_size(value)
        self._core.set_connection_size(value)

    @property
    def socket_timeout(self):
        """Socket open connection timeout, in seconds"""
        return self._core.socket_timeout

    @socket_timeout.setter
    def socket_timeout(self, value):
        _check_socket_timeout(value)
        self._core.set_socket_timeout(None if value is None else float(value))

    @classmethod
    def _core_class(cls):
        return _core.CIPDriver

    @classmethod
    def list_identity(cls, path) -> Optional[Dict[str, Any]]:
        """
        Uses the ListIdentity service to identify the target

        :return: device identity if reply contains valid response else {}
        """
        return cls._core_class().list_identity(path)

    @classmethod
    def discover(cls, broadcast_address="255.255.255.255") -> List[Dict[str, Any]]:
        """
        Discovers available devices on the current network(s).
        Returns a list of the discovered devices Identity Object (as ``dict``).
        """
        return cls._core_class().discover(broadcast_address)

    def get_module_info(self, slot: int) -> dict:
        """
        Get the Identity object for a given slot in the rack of the current connection
        """
        return self._core.get_module_info(slot)

    def open(self):
        """
        Creates a new Ethernet/IP socket connection to target device and registers a CIP session.

        :return: True if successful, False otherwise
        """
        return self._core.open()

    def close(self):
        """
        Closes the current connection and un-registers the session.
        """
        self._core.close()

    def generic_message(
        self,
        service: Union[int, bytes],
        class_code: Union[int, bytes],
        instance: Union[int, bytes],
        attribute: Union[int, bytes] = b"",
        request_data: Any = b"",
        data_type: Optional[Union[Type[DataType], DataType]] = None,
        name: str = "generic",
        connected: bool = True,
        unconnected_send: bool = False,
        route_path: Union[bool, Sequence[CIPSegment], bytes, str] = True,
        **kwargs,
    ) -> Tag:
        """
        Perform a generic CIP message.  Similar to how MSG instructions work in Logix.

        :param service: service code for the request (single byte)
        :param class_code: request object class ID
        :param instance: ID for an instance of the class
                         If set with 0, request class attributes.
        :param attribute: (optional) attribute ID for the service/class/instance
        :param request_data: (optional) any additional data required for the request.
        :param data_type: ``DataType`` used to decode the reply data, None for raw bytes. Only the bytes the type needs
                          are decoded, so use an array (``INT[n]``, ``INT[None]``) or a ``Struct`` for replies with
                          several values (e.g. an assembly); leave None for services that return no data
                          (``Set_Attribute_*``)
        :param name:  return ``Tag.tag`` value, arbitrary but can be used for tracking returned Tags
        :param connected: ``True`` if service required a CIP connection (forward open), ``False`` to use UCMM
        :param unconnected_send: (Unconnected only) wrap the service in an UnconnectedSend
        :param route_path: (UnconnectedSend only) route for the UnconnectedSend wrapper: ``True`` = current connection
                           path, ``False``/``None`` = none, or a path string, list of segments or encoded bytes.
                           Ignored unless ``unconnected_send=True``.
        :return: a Tag whose value is the (decoded) reply data, ``b''`` when the reply carries none
        """
        if not isinstance(route_path, (bool, str, bytes)) and route_path is not None:
            route_path = PADDED_EPATH.encode(route_path, length=True, pad_length=True) if route_path else None
        raw = self._core.generic_message(
            service, class_code, instance, attribute, bytes(request_data or b""), name, bool(connected),
            bool(unconnected_send), route_path,
        )
        response_class = GenericConnectedResponsePacket if connected else GenericUnconnectedResponsePacket
        response = response_class(_ReplyOf(data_type), raw)
        if kwargs.get("return_response_packet"):
            return Tag(name, response, data_type, error=response.error)
        return Tag(name, response.value, data_type, error=response.error)

    def send(self, request: RequestPacket) -> ResponsePacket:
        """
        Sends a request packet built by the caller through the core and returns its response packet.  Connected
        packets (SendUnitData) go over the current CIP connection with the driver's next sequence count (the
        count the packet took is replaced), unconnected ones (SendRRData) over the session.
        """
        if request.error:
            reply = None
        elif isinstance(request, SendUnitDataRequestPacket):
            reply = self._core.send_connected(request.build_message()[2:])
        elif isinstance(request, SendRRDataRequestPacket):
            reply = self._core.send_unconnected(request.build_message())
        else:
            raise RequestError(f"{type(request).__name__} cannot be sent through the driver, "
                               "only SendUnitData and SendRRData packets")
        response = request.response_class(request, reply)
        self.__log.debug("Received: %r", response)
        return response


def parse_connection_path(path: str, auto_slot: bool = False) -> Tuple[str, Optional[int], List[PortSegment]]:
    """
    Parses and validates the CIP path into the destination IP and
    sequence of port/link segments.
    Returns the IP and a list of PortSegments
    """
    try:
        path = path.replace("\\", "/").replace(",", "/")
        ip, *route = path.split("/")
        if ':' in ip:
            ip, port = ip.split(':')
            try:
                port = int(port)
            except Exception as err:
                raise RequestError(f'Invalid port: {port}')
            else:
                if port <= 0 or port >= 65535:
                    raise RequestError(f'Invalid port: {port}')

        else:
            port = None

        _path = parse_cip_route(route, auto_slot)

    except RequestError:
        raise
    except Exception as err:
        raise RequestError(f"Failed to parse connection path: {path}") from err
    else:
        return ip, port, _path


def parse_cip_route(path: Union[str, List[str]], auto_slot: bool = False) -> List[PortSegment]:
    try:
        if isinstance(path, str):
            path = path.replace("\\", "/")
            segments = path.split("/")
        else:
            segments = path

        if not segments:
            _path = [PortSegment("bp", 0)] if auto_slot else []
        elif len(segments) == 1 and auto_slot:
            _path = [PortSegment("bp", segments[0])]
        else:
            if len(segments) % 2:
                raise RequestError(
                    "Invalid connection path, must contain segment pairs(port/link), "
                    f"{len(segments)} segments provided."
                )
            pairs = (segments[i : i + 2] for i in range(0, len(segments), 2))
            _path = [
                PortSegment(int(port) if port.isdigit() else port, link) for port, link in pairs
            ]
    except RequestError:
        raise
    except Exception as err:
        raise RequestError(f"Failed to parse cip route: {path}") from err
    else:
        return _path
