"""
The tag server: one process per site owns the PLC connections and serves tag values to web apps over a WebSocket
(the protocol of ``@ciplink/react``).  It runs in the Rust core; this module is its command line and a way to run
it inside a Python process.

From a terminal::

    ciplink-server run --config tagserver.toml          # real PLCs
    ciplink-server run --config tagserver.toml --mock   # simulated values, no PLC needed

or from Python::

    from ciplink.server import TagServer

    with TagServer("tagserver.toml") as server:
        print(server.address)
"""

import logging
import logging.handlers
import os
import sys
from typing import List, Optional, Tuple

from ._core import TagServer as _TagServer
from ._core import server_main as _server_main

__all__ = ["TagServer", "main"]


class TagServer:
    """
    A tag server running in this process, on threads of its own, until :meth:`stop` (or the end of a ``with``
    block).  ``host`` and ``port`` override the config file's; port 0 picks a free port.
    """

    def __init__(self, config: str, mock: bool = False, host: Optional[str] = None, port: Optional[int] = None):
        self._server = _TagServer(os.fspath(config), mock, host, port)

    @property
    def address(self) -> Tuple[str, int]:
        """(host, port) the server listens on"""
        return self._server.address

    def stop(self) -> None:
        """Stops the server: pressed buttons are released, the PLC connections closed, the audit log flushed."""
        self._server.stop()

    def __enter__(self) -> "TagServer":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def _option(args: List[str], name: str) -> Optional[str]:
    for i, arg in enumerate(args):
        if arg == name and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith(name + "="):
            return arg[len(name) + 1:]
    return None


def _setup_logging(args: List[str]) -> None:
    """The core's log records go to Python logging: to the console, or to the run's log file (rotated at 10 MB,
    5 kept), as the ``ciplink-server`` executable does."""
    log_file = _option(args, "--log-file")
    if log_file is None and args[:2] == ["service", "run"]:
        config = os.path.abspath(_option(args, "--config") or "tagserver.toml")
        log_file = os.path.join(os.path.dirname(config), "tagserver.log")
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    if log_file and args[:1] in (["run"], ["service"]):
        handlers = [logging.handlers.RotatingFileHandler(log_file, maxBytes=10_000_000, backupCount=5,
                                                         encoding="utf-8")]
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        handlers=handlers)


def main(argv: Optional[List[str]] = None) -> int:
    """The ``ciplink-server`` command (``python -m ciplink.server``)."""
    args = list(sys.argv[1:] if argv is None else argv)
    _setup_logging(args)
    return _server_main(["ciplink-server", *args], [sys.executable, "-m", "ciplink.server"])


if __name__ == "__main__":
    raise SystemExit(main())
