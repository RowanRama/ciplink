"""
Async reads and writes, subscriptions and connection events of :class:`~ciplink.LogixDriver` and
:class:`~ciplink.SLCDriver`.

Each driver has one session thread that does all of its I/O: reads queued together, from any thread or task, go
out as one read; writes run in the order they were made.  Completions, subscription changes and connection events
come from the driver's callback thread, never from the session thread, so a callback may call the driver.  Every
blocking call releases the GIL.

While the link is lost the driver reconnects in the background (``reconnect=True``, the default), with a delay
from 0.1 s doubling up to 10 s.  Meanwhile reads, writes and subscription polls fail at once with a
:class:`~ciplink.exceptions.CommError` (``not connected, reconnecting: ...``); a write that failed is never sent
again.
"""

__all__ = [
    "Subscription",
    "ConnectionEvent",
]

import asyncio
import functools
import weakref
from collections import namedtuple
from typing import Callable, List, Optional

from .tag import Tag

ConnectionEvent = namedtuple("ConnectionEvent", "event error attempt delay")
ConnectionEvent.__doc__ = """\
A change of a driver's connection, passed to the callback of :meth:`~ciplink.LogixDriver.on_connection`.

``event`` is ``'connected'`` (opened, or reconnected), ``'disconnected'`` (``error``: why, as text) or
``'reconnecting'`` (``attempt`` from 1, due after ``delay`` seconds).
"""


def _settle(fut, results, error):
    if fut.done():  # the awaiting task was cancelled
        return
    if error is not None:
        fut.set_exception(error)
    else:
        fut.set_result(results)


def _settle_threadsafe(loop, fut, results, error):
    """the core's completion, on the driver's callback thread: hand the result to the future's loop"""
    try:
        loop.call_soon_threadsafe(_settle, fut, results, error)
    except RuntimeError:  # the loop is closed: nobody is waiting any more
        pass


class Subscription:
    """
    Tags read every ``interval`` seconds (packed with the driver's other reads), delivering the tags that changed
    as a list of :class:`~ciplink.Tag`; a tag that failed has its ``error`` set (bad quality), and is delivered
    again once it reads fine.  The first delivery has every tag.

    Use one way of receiving: iterate it (``for tags in sub``, blocking, the GIL released), iterate it from asyncio
    (``async for tags in sub``), or give ``callback=`` to ``subscribe``, called on the driver's callback thread.
    Changes waiting to be received are merged per tag, so a slow consumer gets the latest value of each.

    Close it (or use it as a context manager) to unsubscribe; closing the driver closes it too.
    """

    def __init__(self, core, callback: Optional[Callable[[List[Tag]], None]] = None):
        self._core = core
        self._queue = None  # (loop, asyncio.Queue) of an async iterator
        if callback is not None:
            core.on_changes(callback)

    @property
    def tags(self) -> List[str]:
        """the subscribed tags, in order"""
        return self._core.tags

    @property
    def closed(self) -> bool:
        """True once unsubscribed, or the driver was closed"""
        return self._core.closed

    def recv(self, timeout: Optional[float] = None) -> Optional[List[Tag]]:
        """the changed tags, waiting up to ``timeout`` seconds (None: until there are some); None on timeout or once
        closed"""
        return self._core.recv(timeout)

    def close(self):
        """unsubscribes; an ``async for`` over it ends"""
        self._core.close()
        if self._queue is not None:
            loop, queue = self._queue
            try:
                loop.call_soon_threadsafe(queue.put_nowait, None)
            except RuntimeError:  # the loop is closed
                pass

    def __iter__(self):
        return self

    def __next__(self) -> List[Tag]:
        tags = self._core.recv(None)
        if tags is None:
            raise StopIteration
        return tags

    def __aiter__(self):
        if self._queue is None:
            loop = asyncio.get_running_loop()
            queue = asyncio.Queue()
            self._queue = (loop, queue)

            def deliver(tags):
                try:
                    loop.call_soon_threadsafe(queue.put_nowait, tags)
                except RuntimeError:  # the loop is closed
                    pass

            self._core.on_changes(deliver)
            if self._core.closed:  # closed before this iterator started
                queue.put_nowait(None)
        return self

    async def __anext__(self) -> List[Tag]:
        tags = await self._queue[1].get()
        if tags is None:
            self._queue[1].put_nowait(None)  # a later __anext__ ends too
            raise StopAsyncIteration
        return tags

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class _Session:
    """what LogixDriver and SLCDriver share: async calls, subscriptions and connection events on their core"""

    def _init_session(self):
        self._subscriptions = weakref.WeakSet()
        self._on_connection = None

    async def _await_core(self, method, arg):
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        method(arg, functools.partial(_settle_threadsafe, loop, fut))
        return await fut

    def _close_subscriptions(self):
        for sub in list(self._subscriptions):
            sub.close()

    def subscribe(self, *tags: str, interval: float = 1.0, deadband: Optional[float] = None,
                  callback: Optional[Callable[[List[Tag]], None]] = None) -> Subscription:
        """
        Reads ``tags`` every ``interval`` seconds and delivers the ones that changed, see :class:`Subscription`.
        The polls of several subscriptions are spread over the interval, and share reads with other callers.

        :param tags: the tags (or data file addresses) to read
        :param interval: the poll period in seconds
        :param deadband: numeric tags: a change smaller than this since the last delivered value is not delivered
        :param callback: ``callback(tags)``, called on the driver's callback thread with each change
        :return: the running :class:`Subscription`
        """
        sub = Subscription(self._core.subscribe(list(tags), interval, deadband), callback)
        self._subscriptions.add(sub)
        return sub

    def on_connection(self, callback: Optional[Callable[[ConnectionEvent], None]]) -> None:
        """
        Calls ``callback(event)`` with a :class:`ConnectionEvent` when the connection is made, lost, or a reconnect
        attempt is due; None removes it.  It runs on the driver's callback thread.  Once this returns the old
        callback is not running and will not be called again.
        """
        self._on_connection = callback
        self._core.set_connection_callback(
            None if callback is None else lambda *args: callback(ConnectionEvent(*args)))

    @property
    def connection_state(self) -> str:
        """``'closed'``, ``'connected'`` or ``'reconnecting'`` (lost, reconnecting in the background)"""
        return self._core.connection_state
