"""
Modbus TCP, RTU on a serial port and RTU framed over TCP, on the same session core as
:class:`~ciplink.LogixDriver`: reads queued together are merged into the fewest Modbus requests, the driver
reconnects in the background, and :meth:`~ModbusDriver.subscribe`, :meth:`~ModbusDriver.on_connection` and the
``*_async`` calls work as they do for Logix.

Tag names come from a map file (CSV, one row per tag); anything not in it is a plain address such as
``hr100:float32`` (0-based protocol addresses: Modicon holding register 40001 is ``hr0``).  See the Modbus guide.
"""

__all__ = [
    "ModbusDriver",
]

from typing import Dict, List, Optional, Tuple, Union

from . import _core
from .subscription import _Session
from .tag import Tag

AtomicValueType = Union[int, float, bool, str]
TagValueType = Union[AtomicValueType, List[AtomicValueType]]
ReadWriteReturnType = Union[Tag, List[Tag]]


class ModbusDriver(_Session):
    """
    A Modbus driver.

    :param path: ``tcp://host[:port][?unit=N]`` (Modbus TCP, port 502, unit 1 by default),
        ``rtu://PORT[?baud=19200&parity=E&data=8&stop=1&unit=N]`` (RTU on a serial port, e.g. ``rtu://COM3``) or
        ``rtu+tcp://host[:port][?unit=N]`` (RTU frames over TCP, for serial device servers)
    :param map_file: the map file (CSV) giving tag names, types and descriptions; None for plain addresses only
    :param socket_timeout: reply timeout in seconds
    :param max_registers: most registers in one read (1..125); lower it for devices that refuse long reads
    :param max_bits: most coils or discrete inputs in one read (1..2000)
    :param max_gap: most unrequested registers (or bits) between two tags read in one request; 0 for devices
        whose register map has holes
    :param word_order: ``'ABCD'`` (Modbus standard), ``'CDAB'``, ``'BADC'`` or ``'DCBA'``, for tags without one
    :param write_multiple: always write with FC15/FC16, never FC05/FC06
    :param keep_alive_address: the keep-alive reads this plain address instead of sending FC08
    :param reconnect: reconnect in the background after the link is lost
    :param keep_alive: seconds of idle before a keep-alive request, None for none, ``'auto'``: 30 s over TCP,
        none for ``rtu://``
    """

    def __init__(self, path: str, map_file: Optional[str] = None, *, socket_timeout: float = 1.0,
                 max_registers: int = 125, max_bits: int = 2000, max_gap: int = 8, word_order: str = "ABCD",
                 write_multiple: bool = False, keep_alive_address: Optional[str] = None,
                 reconnect: bool = True, keep_alive: Union[float, None, str] = "auto"):
        self._init_session()
        self._core = _core.ModbusDriver(path, map_file, socket_timeout, max_registers, max_bits, max_gap,
                                        word_order, write_multiple, keep_alive_address, reconnect, keep_alive)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def __str__(self):
        return str(self._core)

    def __repr__(self):
        return str(self._core)

    def open(self) -> bool:
        """connects the socket or opens the serial port (sends nothing); raises CommError on failure"""
        return self._core.open()

    def close(self):
        """drops the link: queued requests fail with a CommError, subscriptions end, reconnecting stops"""
        self._close_subscriptions()
        self._core.close()

    @property
    def connected(self) -> bool:
        """True while a socket or port is held"""
        return self._core.connected

    @property
    def socket_timeout(self) -> float:
        """the reply timeout in seconds"""
        return self._core.get_socket_timeout

    @socket_timeout.setter
    def socket_timeout(self, seconds: float):
        self._core.set_socket_timeout(seconds)

    @property
    def tags(self) -> Dict[str, dict]:
        """the map file's rows by name: ``name``, ``area``, ``address``, ``bit``, ``type`` (the map type, e.g.
        ``'float32'``), ``cip_type`` (what reads report, e.g. ``'REAL'``), ``count``, ``order``, ``unit``,
        ``scale``, ``offset``, ``units``, ``description``, ``writable``; empty without a map"""
        return self._core.tags

    def read(self, *tags: str) -> ReadWriteReturnType:
        """
        Reads map tags (``Pump1_Speed``), elements (``Totals[2]``), bits (``Drive_Status.5``) or plain addresses
        (``hr100:float32``).  A Modbus exception is that tag's ``error``; a lost link raises CommError.

        :return: a ``Tag``, or a list of them for several tags
        """
        results = self._core.read(list(tags))
        return results[0] if len(results) == 1 else results

    def write(self, *tags_values: Tuple[str, TagValueType]) -> ReadWriteReturnType:
        """
        Writes ``(tag, value)`` pairs, one request each, in order: FC05/FC15 for coils, FC06/FC16 for registers,
        FC22 (mask write) for a bit of a holding register.

        :return: a ``Tag``, or a list of them for several pairs
        """
        results = self._core.write(tags_values)
        return results[0] if len(results) == 1 else results

    async def read_async(self, *tags: str) -> ReadWriteReturnType:
        """:meth:`read` for asyncio: same arguments and results, without blocking the event loop"""
        results = await self._await_core(self._core.read_async, list(tags))
        return results[0] if len(results) == 1 else results

    async def write_async(self, *tags_values: Tuple[str, TagValueType]) -> ReadWriteReturnType:
        """:meth:`write` for asyncio: same arguments and results; writes run in the order they were made"""
        results = await self._await_core(self._core.write_async, tags_values)
        return results[0] if len(results) == 1 else results

    def device_info(self, unit: Optional[int] = None) -> dict:
        """
        Read Device Identification (FC43 / MEI 14) of ``unit`` (None: the path's unit): ``vendor_name``,
        ``product_code``, ``revision``, and ``vendor_url``, ``product_name``, ``model_name``,
        ``user_application_name`` (None where the device has none).  A device without it raises ResponseError.
        """
        return self._core.device_info(unit)

    def send_pdu(self, pdu: bytes, unit: Optional[int] = None) -> bytes:
        """sends a raw PDU (function code and data) to ``unit`` and returns the reply PDU; an exception reply
        raises ResponseError"""
        return self._core.send_pdu(bytes(pdu), unit)
