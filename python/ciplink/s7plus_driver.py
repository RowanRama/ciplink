"""
The S7comm-plus driver for Siemens S7-1500 / S7-1200 CPUs with secure PG/HMI communication (TLS 1.3, firmware 2.9
and later).
"""

__all__ = [
    "S7PlusDriver",
]

from typing import Any, Dict, List, Optional, Tuple, Union

from . import _core
from .exceptions import CommError
from .subscription import _Session
from .tag import Tag

AtomicValueType = Union[int, float, bool, str]
TagValueType = Union[AtomicValueType, List[AtomicValueType], Dict[str, "TagValueType"]]
ReadWriteReturnType = Union[Tag, List[Tag]]


class S7PlusDriver(_Session):
    """
    A driver for Siemens S7-1500 / S7-1200 CPUs over S7comm-plus with TLS.

    Tag names are TIA style: ``Line1.Conveyor.Speed``, ``Line1.Items[3]``, PLC tags of the I, Q and M areas by their
    bare name (``StartButton``); quotes around a segment are accepted (``"Line1".Speed``).  Values are those of
    :class:`~ciplink.LogixDriver` (structures as dicts, arrays as lists); a result's ``type`` is the S7 type name
    (``"WORD"``, ``"DTL"``, ``"REAL[50]"``).  Tag comments are not read.

    The TLS certificate of the PLC is not verified by default: :attr:`certificate_fingerprint` shows the SHA-256
    fingerprint seen at the latest handshake, and ``tls_fingerprint`` pins it (the connection is refused when the
    PLC presents another certificate).

    ``reconnect``, ``keep_alive``, :meth:`read_async`, :meth:`write_async`, :meth:`subscribe` and
    :meth:`on_connection` are those of :class:`~ciplink.LogixDriver`.

    :param path: ``host`` or ``host:port`` (port 102 by default)
    :param socket_timeout: seconds to wait for the PLC (None: forever)
    :param init_tags: browse the symbol table on :meth:`open` (else on the first call that needs it)
    :param tls_fingerprint: the SHA-256 fingerprint of the PLC certificate to require, hex with or without ``:``
    :param reconnect: reconnect in the background when the link is lost
    :param keep_alive: seconds of idle time before a keep-alive request, None for none
    """

    def __init__(self, path: str, *, socket_timeout: Optional[float] = 10.0, init_tags: bool = True,
                 tls_fingerprint: Optional[str] = None, reconnect: bool = True,
                 keep_alive: Optional[float] = 15.0):
        self._init_session()
        self._path = path
        self._core = _core.S7PlusDriver(path, socket_timeout, bool(init_tags), tls_fingerprint, bool(reconnect),
                                        keep_alive)

    def open(self) -> bool:
        """connects, creates a session and browses (``init_tags``); False if the PLC refused the connection"""
        return self._core.open()

    def close(self) -> None:
        """closes the connection: queued requests fail with a CommError, subscriptions end, reconnecting stops"""
        self._close_subscriptions()
        self._core.close()

    def __enter__(self):
        if not self.open():
            raise CommError("the PLC refused the connection")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __repr__(self):
        return f"{self.__class__.__name__}(path={self._path!r})"

    def __str__(self):
        return str(self._core)

    @property
    def connected(self) -> bool:
        """True while a session is open"""
        return self._core.connected

    @property
    def name(self) -> Optional[str]:
        """the PLC (station) name read at open, None before"""
        return self._core.name

    @property
    def certificate_fingerprint(self) -> Optional[str]:
        """``"AB:CD:..."``, the SHA-256 fingerprint of the certificate seen at the latest handshake, None before one"""
        return self._core.certificate_fingerprint

    @property
    def socket_timeout(self) -> Optional[float]:
        """seconds to wait for the PLC, None for forever"""
        return self._core.get_socket_timeout()

    @socket_timeout.setter
    def socket_timeout(self, seconds: Optional[float]):
        self._core.set_socket_timeout(seconds)

    # ---- reads and writes

    def read(self, *tags: str) -> ReadWriteReturnType:
        """
        Reads tags, in as few requests as the PLC's item limit allows.  A tag that fails has its ``error`` set.

        :param tags: one or many tag names
        :return: a single or list of ``Tag`` objects
        """
        if not tags:
            return []
        results = self._core.read(list(tags))
        return results if len(tags) > 1 else results[0]

    def write(self, *tags_values: Union[str, TagValueType, Tuple[str, TagValueType]]) -> ReadWriteReturnType:
        """
        Writes tags.  Whole structures (except DTL) and whole BOOL arrays are refused; write their members.

        :param tags_values: a tag name and value as two arguments, ``write('tag', value)``, or one or more (tag, value)
                            tuples, ``write(('tag1', 1), ('tag2', 2))``
        :return: a single or list of ``Tag`` objects
        """
        if not tags_values:
            return []
        if len(tags_values) == 2 and isinstance(tags_values[0], str):
            tags_values = ((*tags_values,),)
        results = self._core.write(tags_values)
        return results if len(results) > 1 else results[0]

    async def read_async(self, *tags: str) -> ReadWriteReturnType:
        """:meth:`read` for asyncio: same arguments and results; reads queued together go out as one request list"""
        if not tags:
            return []
        results = await self._await_core(self._core.read_async, list(tags))
        return results if len(tags) > 1 else results[0]

    async def write_async(self, *tags_values: Union[str, TagValueType, Tuple[str, TagValueType]]
                          ) -> ReadWriteReturnType:
        """:meth:`write` for asyncio: same arguments and results; writes run in the order they were made"""
        if not tags_values:
            return []
        if len(tags_values) == 2 and isinstance(tags_values[0], str):
            tags_values = ((*tags_values,),)
        results = await self._await_core(self._core.write_async, tags_values)
        return results if len(results) > 1 else results[0]

    # ---- tags and the PLC

    @property
    def tags(self) -> Dict[str, Dict[str, Any]]:
        """
        Top-level tags by name: every data block (``kind`` ``'data_block'``, ``type`` its structure type) and every
        PLC tag of the I, Q and M areas.  Empty before the first browse.
        """
        return self._core.tags

    @property
    def data_types(self) -> Dict[str, Dict[str, Any]]:
        """the structure types the tags use, by name: ``{"name", "rid", "interface_timestamp", "members"}``"""
        return self._core.data_types

    def tag_list(self) -> List[Dict[str, Any]]:
        """
        Every symbol as the flat list an HMI tag browser shows: members of structures expanded, elementary arrays
        and system types (DTL, IEC timers) as one entry.  Each is a dict of ``name``, ``type``, ``dims``,
        ``access``, ``crc``, ``hmi_visible``, ``hmi_accessible`` and ``hmi_read_only``.
        """
        return self._core.tag_list()

    def get_tag_info(self, name: str) -> Dict[str, Any]:
        """one name resolved, as an entry of :meth:`tag_list`; a RequestError if it doesn't resolve"""
        return self._core.get_tag_info(name)

    def refresh_tags(self) -> bool:
        """browses the symbol table again now; True if it changed"""
        return self._core.refresh_tags()

    def get_plc_info(self) -> Dict[str, Any]:
        """
        ``name``, ``order_number``, ``serial_number``, ``hardware_version``, ``firmware``, ``engineering_version``,
        ``project``, ``protection_level`` (None where the PLC gives none), ``max_read`` and ``max_write``
        """
        return self._core.get_plc_info()
