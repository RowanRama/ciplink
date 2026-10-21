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
The Logix driver over the Rust core: the tag list upload, the tag table version checks, reads, writes and
descriptions run in Rust (``ciplink._core.LogixDriver``) with the GIL released.  The core also builds the tag
definitions as the reference driver's dicts (``type_class`` entries included) and keeps them until they change.
This module keeps the public API of the reference driver and adds the ``datetime`` of
:meth:`LogixDriver.get_plc_time`.
"""

__all__ = [
    "LogixDriver",
]

import datetime
import logging
import os
import time
from functools import wraps
from typing import List, Tuple, Optional, Union, Dict

from . import _core, util
from .cip_driver import CIPDriver, with_forward_open
from .const import SEC_TO_US
from .exceptions import RequestError
from .tag import Tag, ErrorKind, TagError
from .logix_auth import LogixMetadataCredentials
from .trend import Trend

AtomicValueType = Union[int, float, bool, str]
TagValueType = Union[AtomicValueType, List[AtomicValueType], Dict[str, "TagValueType"]]
ReadWriteReturnType = Union[Tag, List[Tag]]


class _TagDict(dict):
    """``LogixDriver.tags``: remembers its driver's core (a weak reference), so ``plc2._tags = plc1.tags`` shares the
    definitions"""

    __slots__ = ("_owner",)


def _refresh_definitions(driver):
    """
    ``tags`` and ``data_types`` are plain attributes of the driver, so reading them costs a dict lookup: they are
    fetched from the core when the driver is made and again after each call that changed its definitions (the core
    keeps what it built, and builds again only what changed).  ``LogixDriver.__setattr__`` keeps them read-only.
    """
    kept = driver.__dict__
    core = kept["_core"]
    version = core.definitions_version  # read first: a change meanwhile fetches them again next time
    if kept.get("_defs_version") != version:
        kept["tags"], kept["data_types"] = core.tags, core.data_types
        kept["_defs_version"] = version


def _definitions_may_change(func):
    """for a call that may change the tag definitions (an upload, a lazy load, a reload after an online edit)"""

    @wraps(func)
    def wrapped(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        finally:
            _refresh_definitions(self)

    return wrapped


class LogixDriver(CIPDriver):
    """
    An Ethernet/IP Client driver for reading and writing tags in ControlLogix and CompactLogix PLCs.

    The options and behaviour are those of the reference ciplink driver (see its documentation): ``init_tags``,
    ``init_program_tags``, ``tag_namespace_filter``, ``lazy_tags``, ``tag_cache_file``, ``socket_timeout`` and
    ``connection_size``.  To share the tag definitions between connections to the same controller, open the second
    one with ``init_tags=False`` and set ``plc2._tags = plc1.tags``.

    ``tags`` (all the tag definitions uploaded from the controller) and ``data_types`` (all the data type definitions;
    the entry of an AOI type has an ``'aoi'`` entry once probed: ``{'whole_read': bool, 'readable': [...],
    'refused': [...]}``) are read-only attributes.
    """

    __log = logging.getLogger(f"{__module__}.{__qualname__}")
    _auto_slot_cip_path = True

    def __init__(
        self,
        path: str,
        *args,
        init_tags: bool = True,
        init_program_tags: bool = True,
        tag_namespace_filter: str = '',
        lazy_tags: bool = False,
        tag_cache_file: Optional[str] = None,
        **kwargs,
    ):
        self._init_args = {
            "init_tags": init_tags and not lazy_tags,
            "init_program_tags": init_program_tags,
            "tag_namespace_filter": tag_namespace_filter
        }
        self._lazy_tags = lazy_tags
        self._options = (bool(init_tags), bool(init_program_tags), tag_namespace_filter, bool(lazy_tags),
                         None if tag_cache_file is None else os.fspath(tag_cache_file))
        super().__init__(path, *args, **kwargs)
        _refresh_definitions(self)

    def _make_core(self, path, socket_timeout, connection_size):
        init_tags, init_program_tags, namespace, lazy, cache_file = self._options
        return _core.LogixDriver(path, init_tags, init_program_tags, namespace, lazy, cache_file, socket_timeout,
                                 connection_size)

    @classmethod
    def _core_class(cls):
        return _core.LogixDriver

    def __str__(self):
        return str(self._core)

    def __repr__(self):
        init_args = ", ".join(f"{k}={v}" for k, v in self._init_args.items())
        return f"{self.__class__.__name__}(path={self._cip_path}, {init_args})"

    @_definitions_may_change
    def open(self):
        return self._core.open()

    def close(self):
        self._core.close()

    # ---- tag definitions

    def __setattr__(self, name, value):
        if name in ("tags", "data_types"):
            raise AttributeError(f"property {name!r} of {type(self).__name__!r} object has no setter")
        super().__setattr__(name, value)

    @property
    def _tags(self) -> dict:
        return self.tags

    @_tags.setter
    @_definitions_may_change
    def _tags(self, tags):
        owner = getattr(tags, "_owner", None)
        owner = owner() if owner is not None else None
        if isinstance(owner, _core.LogixDriver):
            self._core.share_tags_from(owner)
        elif not tags:
            self._core.clear_tags()
        else:
            raise TypeError("only the tags of another LogixDriver (plc2._tags = plc1.tags) or {} can be set")

    @property
    def tags_json(self):
        """
        Read-only property to access all the tag definitions uploaded from the controller.
        Filters out any non-JSON serializable objects.  A new copy on each call; within it each data type is copied
        once and shared by the tags and members of that type, as in :attr:`tags`.
        """
        return self._core.tags_json()

    @property
    def info(self) -> dict:
        """
        Property containing a dict of all the information collected about the connected PLC: vendor,
        product_type, product_code, revision, serial, product_name, status, keyswitch, name and, after a tag list
        upload, programs, tasks and modules.
        """
        return self._core.info()

    @property
    def _info(self) -> dict:
        return self.info

    @property
    def _micro800(self) -> bool:
        return self._core.micro800

    @property
    def _cfg(self) -> dict:
        cfg = super()._cfg
        dict.__setitem__(cfg, "use_instance_ids", self._core.use_instance_ids)
        return cfg

    @property
    def _tag_table_version(self):
        return self._core.tag_table_version

    def _send_frame(self, message: bytes):
        """the reference driver's ``_send``: called from a replacement installed as ``plc._send = f``, sends
        ``message`` (once ``f`` returns)"""
        self._core.forward_frame(bytes(message))

    @property
    def _send(self):
        return getattr(self, "_send_hook", None) or self._send_frame

    @_send.setter
    def _send(self, func):
        self._send_hook = None if func == self._send_frame else func
        self._core.set_send_hook(self._send_hook)

    @property
    def revision_major(self) -> int:
        """
        Returns the major revision for the PLC or 0 if not available
        """
        return self._core.revision_major

    @property
    def name(self) -> Optional[str]:
        """
        :return: name of PLC program
        """
        return self._core.name

    def get_plc_name(self) -> str:
        """
        Requests the name of the program running in the PLC.

        :return:  the controller program name
        """
        return self._core.get_plc_name()

    def get_plc_info(self) -> dict:
        """
        Reads basic information from the controller, returns it and stores it in the ``info`` property.
        """
        return self._core.get_plc_info()

    def get_plc_time(self, fmt: str = "%A, %B %d, %Y %I:%M:%S%p", tz: datetime.timezone = None) -> Tag:
        """
        Gets the current time of the PLC system clock. The ``value`` attribute will
        be a dict containing the time in 3 different forms, *datetime* is a Python datetime.datetime object, *microseconds*
        is the integer value epoch time, and *string* is the *datetime* formatted using ``strftime`` and the ``fmt`` parameter.
        The time is in the client PC's local timezone unless ``tz`` is given (pass ``datetime.timezone.utc`` for UTC);
        *microseconds* is always UTC epoch time and *string* uses the same timezone as *datetime*.

        :param fmt: format string for converting the time to a string
        :param tz: timezone for *datetime*/*string*, the client PC's local timezone if omitted or None
        :return: a Tag object with the current time
        """
        tag = self._core.get_plc_time()
        if tag:
            _time = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=tag.value)
            _time = _time.replace(tzinfo=datetime.timezone.utc).astimezone(tz=tz)
            value = {
                "datetime": _time,
                "microseconds": tag.value,
                "string": _time.strftime(fmt),
            }
        else:
            value = None
        return Tag("get_plc_time", value, None, error=tag.error)

    def set_plc_time(self, microseconds: Optional[int] = None) -> Tag:
        """
        Set the time of the PLC system clock.

        :param microseconds: None to use client PC clock, else timestamp in microseconds to set the PLC clock to.
                             Timestamp is uS since epoch 1970-1-1, 00:00 UTC
        :return: Tag with status of request
        """
        if microseconds is None:
            microseconds = int(time.time() * SEC_TO_US)
        return self._core.set_plc_time(microseconds)

    @_definitions_may_change
    def get_tag_list(self, program: str = None, cache: bool = True, tag_namespace_filter: str = '') -> List[dict]:
        """
        Reads the tag list from the controller and the definition for each tag.

        :param program: scope to retrieve tag list, None for controller-only tags, ``'*'`` for all tags, else name of program
        :param cache: store the retrieved list in the :attr:`.tags` property
        :param tag_namespace_filter: prefix match on the tag name (without the ``Program:X.`` part)
        :return: a list containing dicts for each tag definition collected
        """
        return self._core.get_tag_list(program, cache, tag_namespace_filter)

    @_definitions_may_change
    def check_tag_table(self) -> bool:
        """
        Loads the tag definitions again if the controller's tag table changed since they were loaded, e.g. an
        online edit added, renamed or deleted a tag.  :meth:`.read` and :meth:`.write` check this on their own.

        :return: True if the tag definitions were loaded again
        """
        return self._core.check_tag_table()

    def get_tag_info(self, tag_name: str) -> Optional[dict]:
        """
        Returns the tag information for a tag collected during the tag list upload.  Can be a base tag or an attribute.

        With lazy_tags enabled, an uncached definition is resolved from the controller.

        :param tag_name: name of tag to get info for
        :return: a dict of the tag's definition
        """
        info = self.tags.get(tag_name)  # a whole tag by its name, as split_tag_name would find it
        if info is None:
            info = self._core.cached_tag_info(tag_name)  # members, any case, array elements
        if info is not None:
            return info
        _, base, attrs = _split_tag_name(tag_name)
        tags = self._core.tags
        if _tag_key(tags, base) not in tags:
            try:
                self._core.get_tag_info(tag_name)  # a lazy load, or the reference driver's error
            finally:
                _refresh_definitions(self)
            tags = self._core.tags
        try:
            data = tags[_tag_key(tags, base)]
            for attr in attrs:
                members = data["data_type"]["internal_tags"]
                data = members[_tag_key(members, attr)]
            return data
        except (KeyError, TypeError):
            self._core.get_tag_info(tag_name)  # raises the core's error
            raise RequestError(TagError(f"Tag doesn't exist - {tag_name}", ErrorKind.NOT_FOUND))

    # ---- reads and writes

    @_definitions_may_change
    def read(self, *tags: str) -> ReadWriteReturnType:
        """
        Read the value of tag(s).  Automatically will split tags into multiple requests by tracking the request and
        response size.  Will use the multi-service request to group many tags into a single packet and also will
        automatically use fragmented read requests if the response size will not fit in a single packet.  Supports
        arrays (specify element count in using curly braces (array{10}).  Also supports full structure reading (when
        possible), return value will be a dict of {attribute name: value}.

        :param tags: one or many tags to read
        :return: a single or list of ``Tag`` objects
        """
        if not tags:
            return []
        results = self._core.read(list(tags))
        return results if len(tags) > 1 else results[0]

    @_definitions_may_change
    def write(
        self, *tags_values: Union[str, TagValueType, Tuple[str, TagValueType]]
    ) -> ReadWriteReturnType:
        """
        Write to tag(s).  Supports arrays (specify element count in using curly braces (array{10}) and full structure
        writing (a sequence of values or a dict of {attribute: value} matching the structure of the destination tag).

        :param tags_values: a tag name and value as two arguments, ``write('tag', value)``, or one or more (tag, value)
                            tuples, ``write(('tag1', 1), ('tag2', 2))``. To write a list of pairs, unpack it: ``write(*pairs)``.
        :return: a single or list of ``Tag`` objects.
        """
        if not tags_values:
            return []
        if len(tags_values) == 2 and isinstance(tags_values[0], str):
            tags_values = ((*tags_values,),)
        results = self._core.write(tags_values)
        return results if len(results) > 1 else results[0]

    @_definitions_may_change
    def trend(self, *tags: str, period_ms: float = 10, capacity: int = 4096,
              duration: Optional[float] = None) -> Trend:
        """
        Starts a controller-side trend: the controller samples ``tags`` every ``period_ms`` into its trend buffer
        and the trend uploads them on a connection of its own, see :mod:`ciplink.trend`.

        :param tags: atomic tags, members or array elements of up to 32 bits, or bits (``Tag.3``)
        :param period_ms: sample period, 1 ms or more (whole microseconds)
        :param capacity: samples kept until :meth:`Trend.read`, the oldest are dropped when full
        :param duration: stop after this many seconds, None to run until closed
        :return: the running :class:`Trend`, close it (or use it as a context manager) to stop it
        """
        return Trend(self._core.trend(list(tags), round(period_ms * 1000), capacity, duration))

    # ---- metadata

    def authenticate_metadata(self, credentials: Optional[LogixMetadataCredentials] = None) -> Tag:
        """Authenticate the current CIP connection for experimental metadata reads.

        Uses the bundled or caller-supplied credentials. Authentication applies to this connection only; call
        again after a reconnect. No controller values or persistent permissions are changed.
        """
        if credentials is None:
            return self._core.authenticate_metadata()
        if not isinstance(credentials, LogixMetadataCredentials):
            return Tag("metadata_authentication", None, "BOOL",
                       TagError("Supply LogixMetadataCredentials", ErrorKind.BAD_REQUEST))
        return self._core.authenticate_metadata(credentials.certificate, credentials._private_key_der)

    def get_tag_description(self, tag_name: str, language: int = 0x007F,
                            encoding: str = "utf-8") -> Tag:
        """Read a tag, member, or array element's Description."""
        return self.get_tag_descriptions(tag_name, language=language, encoding=encoding)[0]

    @_definitions_may_change
    def get_tag_descriptions(self, *tag_names: str, language: int = 0x007F,
                             encoding: str = "utf-8") -> List[Tag]:
        """
        Read the Descriptions of tags, members, or array elements, a list of Tags in the order of ``tag_names``,
        same results as ``get_tag_description`` of each but many tags share each multi-service packet.
        """
        import codecs

        return self._core.get_tag_descriptions(list(tag_names), language, codecs.lookup(encoding).name)


def _tag_key(data, name):
    # Logix names are case-insensitive: exact key first, else a case-insensitive match
    name = util.strip_array(name)
    if name in data:
        return name
    return next((k for k in data if k.lower() == name.lower()), name)


def _split_tag_name(tag):
    if tag[:8].lower() == "program:":
        tag = "Program:" + tag[8:]
    base, *attrs = tag.split(".")
    if base.startswith("Program:"):
        base = f"{base}.{attrs.pop(0)}"
    return tag, base, attrs
