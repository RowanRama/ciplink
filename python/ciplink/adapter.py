"""
The adapter: ciplink as an EtherNet/IP I/O device that a Logix controller owns in its I/O tree, like a camera or an
I/O module.  It answers Forward Open, produces input assemblies to the controller every RPI and consumes its output
assemblies.  The I/O runs on threads in the Rust core, so a slow Python application never makes a packet late.

Nothing listens until an ``Adapter`` is created.  It needs TCP/UDP 44818 and UDP 2222 of its address to itself, so it
cannot run beside FactoryTalk Linx or RSLinx on the same IP address; see ``docs/adapter.md``.

::

    from ciplink.adapter import Adapter

    with Adapter(inputs={100: 148}, outputs={150: 32}, configs={199: 0},
                 identity={"product_name": "Station"}, app_name="Station") as adapter:
        adapter.set_input(100, b"\\x01")
        while True:
            event = adapter.next_event(1.0)
            if event and event["event"] == "output":
                data, run = adapter.output(event["instance"])
"""

from typing import Any, Dict, List, Optional, Tuple

from ._core import Adapter as _Adapter

__all__ = ["Adapter"]


class Adapter:
    """
    A running adapter, until :meth:`stop` (or the end of a ``with`` block).

    ``inputs``, ``outputs`` and ``configs`` map assembly instance -> size in bytes.  ``identity`` sets the Identity
    object: ``vendor_id`` (0 is a placeholder; a device shipped with an EDS needs its vendor's own ID),
    ``device_type``, ``product_code``, ``revision`` (major, minor), ``serial`` and ``product_name``.  ``bind`` picks
    the network card (and the one multicast leaves from); ``port`` and ``io_port`` are 0 for a free port in tests.
    RPIs are in seconds.  The other keywords are those of the Rust ``AdapterConfig``.
    """

    def __init__(
        self,
        inputs: Optional[Dict[int, int]] = None,
        outputs: Optional[Dict[int, int]] = None,
        configs: Optional[Dict[int, int]] = None,
        identity: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ):
        self._adapter = _Adapter(inputs, outputs, configs, **(identity or {}), **kwargs)

    @property
    def address(self) -> Tuple[str, int]:
        """(host, port) explicit messages and ListIdentity are served on"""
        return self._adapter.address

    @property
    def io_address(self) -> Tuple[str, int]:
        """(host, port) class 1 I/O is received on"""
        return self._adapter.io_address

    def set_input(self, instance: int, data: bytes) -> None:
        """Sets an input assembly's data, sent in the next T->O packets; shorter data leaves the rest zero."""
        self._adapter.set_input(instance, data)

    def input(self, instance: int) -> bytes:
        """An input assembly's current data"""
        return self._adapter.input(instance)

    def output(self, instance: int) -> Tuple[bytes, bool]:
        """(data, run) of an output assembly: its latest data and the controller's run bit (False before the first
        packet and after the owner closed or timed out)"""
        return self._adapter.output(instance)

    def config(self, instance: int) -> bytes:
        """A configuration assembly's data, as the last Forward Open with data sent it"""
        return self._adapter.config(instance)

    def next_event(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        The next event, waiting up to ``timeout`` seconds (None: until one comes or the adapter stops); None if
        none came.  An event is a dict with ``event``:

        - ``opened``, ``closed``, ``timed_out``, with ``connection`` (a dict as :meth:`connections` returns)
        - ``output`` with ``instance``: an output assembly's data or run bit changed; sent once until
          :meth:`output` reads it
        - ``config`` with ``instance`` and ``data``: a Forward Open carried configuration data
        """
        return self._adapter.next_event(timeout)

    def connections(self) -> List[Dict[str, Any]]:
        """
        The open class 1 connections, each a dict: ``kind`` (``exclusive_owner``, ``input_only`` or
        ``listen_only``), ``originator`` (the controller's IP), ``o_t_rpi`` and ``t_o_rpi`` (seconds), ``input`` and
        ``input_size``, ``output`` (None unless an owner) and ``output_size``, ``multicast``, ``o_t_id`` and
        ``t_o_id``.
        """
        return self._adapter.connections()

    def set_detail(self, detail: str) -> None:
        """Sets the application's status text that device browsers show, e.g. ``"station 2"``"""
        self._adapter.set_detail(detail)

    def stats(self) -> Dict[str, Any]:
        """I/O timing counters: ``produced`` packets, ``late`` ones (1 ms or more) and ``max_late`` (seconds)"""
        return self._adapter.stats()

    def stop(self) -> None:
        """Stops the adapter: closes its sockets and joins its threads.  Controllers then time out."""
        self._adapter.stop()

    def __enter__(self) -> "Adapter":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
