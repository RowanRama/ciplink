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

__all__ = [
    "LogixDriver",
]

import datetime
import json
import logging
import operator
import os
import tempfile
import time
from contextlib import suppress
from functools import reduce
from io import BytesIO
from typing import List, Tuple, Optional, Union, Dict, Type, Sequence

from . import util
from .cip import (
    ClassCode,
    Services,
    KEYSWITCH,
    EXTERNAL_ACCESS,
    DataTypes,
    Struct,
    STRING,
    n_bytes,
    ULINT,
    DataSegment,
    USINT,
    UINT,
    LogicalSegment,
    PADDED_EPATH,
    UDINT,
    DINT,
    Array,
    DataType,
    ArrayType,
    PortSegment,
)
from .cip_driver import CIPDriver, with_forward_open, parse_connection_path
from .const import (
    MICRO800_PREFIX,
    MULTISERVICE_READ_OVERHEAD,
    SUCCESS,
    INSUFFICIENT_PACKETS,
    BASE_TAG_BIT,
    MIN_VER_INSTANCE_IDS,
    SEC_TO_US,
    TEMPLATE_MEMBER_INFO_LEN,
    MIN_VER_EXTERNAL_ACCESS,
)
from .custom_types import (
    StructTemplateAttributes,
    StructTag,
    FixedSizeString,
    ModuleIdentityObject,
)
from .exceptions import CommError, ResponseError, RequestError
from .packets import (
    RequestPacket,
    ReadTagFragmentedRequestPacket,
    WriteTagFragmentedRequestPacket,
    ReadTagFragmentedResponsePacket,
    WriteTagFragmentedResponsePacket,
    SendUnitDataRequestPacket,
    ReadTagRequestPacket,
    WriteTagRequestPacket,
    MultiServiceRequestPacket,
    ReadModifyWriteRequestPacket,
    TagTableVersionRequestPacket,
    GenericConnectedRequestPacket,
    tag_request_path,
)
from .tag import Tag
from .logix_auth import LogixMetadataCredentials
from .logix_descriptions import read_description

_TAG_CACHE_VERSION = 2  # bump when the tag cache file layout changes
_MAKEUP_KEYS = ("object_definition_size", "structure_size", "member_count", "structure_handle")
_PARSE_MEMO_SIZE = 10_000  # parsed requests kept before the memo starts over
_TAG_TABLE_UPLOAD_TRIES = 3  # uploads of a tag table that keeps changing before the last one is kept
_RELOAD_BACKOFF = 2.0  # seconds without tag table reloads after one failed or the controller was busy
_SYMBOL_PAGE_REPLY = 1000  # reply bytes budgeted for a symbol list page in a multi-service packet, about 20 tags
_MAKEUP_REPLY = 36  # reply bytes of a structure makeup in a multi-service packet: offset, header, count, 4 attributes
_AOI_REFUSED = (0x04, 0x0F)  # IOI syntax error, permission denied: a controller's reply to reads of an AOI's locals
_AOI_LOCAL = "AOI local tag, not externally accessible"
_MAKEUP_ATTRIBUTES = b"".join((
    b"\x04\x00",  # Number of attributes
    b"\x04\x00",  # Template Object Definition Size UDINT
    b"\x05\x00",  # Template Structure Size UDINT
    b"\x02\x00",  # Template Member Count UINT
    b"\x01\x00",  # Structure Handle We can use this to read and write UINT
))

AtomicValueType = Union[int, float, bool, str]
TagValueType = Union[AtomicValueType, List[AtomicValueType], Dict[str, "TagValueType"]]
ReadWriteReturnType = Union[Tag, List[Tag]]


class LogixDriver(CIPDriver):
    """
    An Ethernet/IP Client driver for reading and writing tags in ControlLogix and CompactLogix PLCs.
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
        """
        :param path: CIP path to intended target

            The path may contain 3 forms:

            - IP Address Only (``10.20.30.100``) - Use for a ControlLogix PLC is in slot 0 or if connecting to a CompactLogix or Micro800 PLC.
            - IP Address/Slot (``10.20.30.100/1``) - (ControlLogix) if PLC is not in slot 0
            - CIP Routing Path (``1.2.3.4/backplane/2/enet/6.7.8.9/backplane/0``) - Use for more complex routing.

            .. note::

                Both the IP Address and IP Address/Slot options are shortcuts, they will be replaced with the
                CIP path automatically.  The ``enet`` / ``backplane`` (or ``bp``) segments are symbols for the CIP routing
                port numbers and will be replaced with the correct value.

        :param lazy_tags: if True, skips startup tag upload and resolves tag definitions on demand.
                          Each requested scope's symbol list is cached; templates are fetched only
                          for requested tags. Overrides init_tags.
        :param init_tags: if True (default), uploads tag definitions on connect: controller-scoped, plus program-scoped
                unless ``init_program_tags=False``
        :param init_program_tags: if False, bypasses uploading program-scoped tags. set to False if there are a lot of program tags and you aren't
                using any of them to decrease tag upload times.
        :param tag_namespace_filter: only upload tags whose name starts with this prefix, prefix match on the tag name
                (without the ``Program:X.`` part); program, task and module discovery is not filtered
        :param tag_cache_file: path of a file that keeps the tag list between connections to speed up the tag upload
                on a restart. It stores the symbol lists, the data type templates, the controller's serial number and
                the tag table version (see :meth:`.check_tag_table`) read before they were uploaded. If the controller
                reports the same serial number and version on the next connect, nothing is uploaded, the whole tag
                list comes from the file. Otherwise (an edit since, another controller, or a controller that does not
                report its version) the symbol lists are uploaded and the stored templates are only used if every
                symbol list (instance ids included) is unchanged since the file was written, else they are uploaded
                again. On that path each template's structure makeup is still read, a template whose makeup changed is
                uploaded again; a change that keeps the makeup (e.g. a member renamed to a name of the same length) is
                not detected (e.g. two members of the same type swapped: whole-structure reads and writes then use
                the wrong members), delete the file after such an edit. The file is rewritten after an upload that changed
                its contents. A missing, corrupt, older-format or unwritable file never stops the connection, it is
                logged and the upload continues without it. Only the startup scope's upload (all programs with
                ``init_program_tags``, else the controller) reads and writes it. Not used with ``lazy_tags``.
                It also keeps the AOI probes below, a probe is used again while its template's makeup is unchanged.

        .. note::

            Add-On Instructions: a controller refuses the reads of an AOI's local tags (0x04, IOI syntax error) and
            the read of a whole AOI that has any (0x0F, permission denied), and the template does not say which
            members are locals.  So after the tag definitions are loaded (with ``lazy_tags`` at the first use of a
            tag holding that AOI type), one instance of each AOI type (a struct with ``EnableIn`` and ``EnableOut``)
            is read whole and member by member, Read Tag only, a few packets for all of them.  Only types probed
            again are new ones or ones whose template makeup changed.  The result is the ``'aoi'`` entry of its
            :attr:`.data_types` entry (and of ``tag['data_type']``): ``{'whole_read': bool, 'readable': [member
            names], 'refused': [member names]}``.  A member is refused only on those two errors, any other reply
            leaves it readable.  Reading a whole AOI that is refused returns a dict of its readable members instead
            (read in the same call), reading or writing a refused member returns the error ``'AOI local tag, not
            externally accessible'`` and sends nothing.  A type without an instance to probe gets no ``'aoi'``
            entry and is read as any struct.

        .. tip::

            Initialization of tags is required for the :meth:`.read` and :meth:`.write` to work.  This is because
            they require information about the data type and structure of the tags inside the controller.  If opening
            multiple connections to the same controller, you may disable tag initialization in all but the first connection
            and set ``plc2._tags = plc1.tags`` to prevent needing to upload the tag definitions multiple times.
            Tag lists are controller-specific: on v21+ tags are addressed by instance_id, which differs between
            controllers even with identical programs, so only share a tag list between connections to the same controller.

        .. note::

            An online edit can give an instance ID to another tag (a deleted tag's ID goes to the next tag created),
            so requests by instance ID are checked against the controller's tag table version (its edit counter and
            download timestamps, Rockwell 1756-PM020): every read packet starts with the check, writes are checked
            right before and after, and a change loads the tag definitions again (see :meth:`.read`, :meth:`.write`
            and :meth:`.check_tag_table`).  The version is read on connect: a controller that cannot answer it (e.g.
            the Emulate 5580 emulator) is used with tags requested by name instead, and a warning is logged.  A tag
            list kept from an earlier connection (``init_tags=False``) keeps the version it was loaded at, so an
            edit made while disconnected loads it again.  A tag list shared as above after ``plc2`` connected is
            checked against the version read when ``plc2`` connected, one shared before has no known version and
            is loaded again at the first read or write.

        """

        super().__init__(path, *args, **kwargs)
        self._cache = {"id:struct": {}, "id:template": {}, "id:udt": {}, "id:aoi": {}}
        self._tag_cache_file = tag_cache_file
        self._lazy_tags = lazy_tags
        self._lazy_tag_lists = {}
        self._data_types = {}
        self._tags = {}
        self._parse_memo = (self._tags, {})  # (tag list, {(tag, rw, use_instance_ids): parsed request})
        self._tag_table_detection = False  # the controller reports its tag table version, see _initialize_driver
        self._tag_table_version = None  # the version self._tags was loaded at, None if unknown
        self._templates_read_at = None  # download and project timestamps of the kept templates, _upload_tag_list
        self._reload_backoff = (0.0, None)  # (time.monotonic() until which no reload is attempted, error), _back_off
        self._micro800 = False
        self._cfg["use_instance_ids"] = True
        self._init_args = {
            "init_tags": init_tags and not lazy_tags,
            "init_program_tags": init_program_tags,
            "tag_namespace_filter": tag_namespace_filter
        }

    def __str__(self):
        _rev = self._info.get("revision", {"major": -1, "minor": -1})
        return f"Program Name: {self._info.get('name')}, Device: {self._info.get('product_name')}, Revision: {_rev['major']}.{_rev['minor']}"

    def __repr__(self):
        init_args = ", ".join(f"{k}={v}" for k, v in self._init_args.items())
        return f"{self.__class__.__name__}(path={self._cip_path}, {init_args})"

    def open(self):
        with self._lock:  # other threads wait until the definitions are loaded
            if self._connection_opened:
                return True
            ret = super().open()
            if ret:
                try:
                    if self._lazy_tags:
                        self._reset_lazy_tags()
                    self._initialize_driver(**self._init_args)
                except BaseException:  # also Ctrl-C, else the next open() returns True with no definitions
                    with suppress(CommError):
                        self.close()  # drop the connection so the next open() reconnects
                    raise
            return ret

    def _initialize_driver(self, init_tags, init_program_tags, tag_namespace_filter=''):
        self.__log.info("Initializing driver...")

        target_identity = self._list_identity()
        self.__log.debug("Identified target: %r", target_identity)
        self._micro800 = target_identity.get("product_name", "").startswith(MICRO800_PREFIX)
        serial = self._info.get("serial")
        self._info = self.get_plc_info()
        if self._info.get("serial") != serial:  # template instance ids are the controller's, see _template_data
            self._cache["id:template"].clear()
            self._cache["id:aoi"].clear()
        self._reload_backoff = (0.0, None)

        self._cfg["use_instance_ids"] = (
            self.revision_major >= MIN_VER_INSTANCE_IDS
        ) and not self._micro800
        if not self._micro800:
            self.get_plc_name()

        if (
            self._micro800
            and self._cfg["cip_path"]
            and isinstance(self._cfg["cip_path"][-1], PortSegment)
        ):
            self._cfg["cip_path"].pop(
                -1
            )  # strip off backplane/0 segment, not used for these processors

        # an ID can name another tag after an online edit, IDs are only used if the tag table version shows edits
        self._tag_table_detection = False
        version = None
        if self._cfg["use_instance_ids"]:
            version = self._read_tag_table_version()
            self._tag_table_detection = version is not None
            if not self._tags:  # lazy loads come after it, a kept tag list keeps the version it was loaded at
                self._tag_table_version = version
            if not self._tag_table_detection:
                self.__log.warning(
                    "The controller does not report its tag table version, tag table change detection is "
                    "unavailable: tags are requested by name instead of by instance ID"
                )
                self._cfg["use_instance_ids"] = False

        if init_tags:  # the version just read serves as the read before the upload
            self._load_tag_list("*" if init_program_tags else None, True, tag_namespace_filter, version)

        self.__log.info("Initialization complete.")

    def _reset_lazy_tags(self):
        self._tags, self._data_types = {}, {}  # rebind: the old dict may be shared
        self._lazy_tag_lists.clear()
        for cache in self._cache.values():
            cache.clear()

    @property
    def _version_checks(self) -> bool:
        """requests by instance ID are checked against the tag table version"""
        return self._cfg["use_instance_ids"] and self._tag_table_detection

    def _read_tag_table_version(self):
        """
        Reads the tag table version (Rockwell 1756-PM020 step 5: the edit counter and the download and project
        timestamps), returns None if the controller did not return it.
        """
        response = self.send(TagTableVersionRequestPacket(self._sequence))
        if not response:
            self.__log.info(f"Tag table version not read - {response.error}")
            return None
        return response.value

    def _tag_table_changed(self, versions, loaded_at) -> bool:
        """
        True if a version read differs from ``loaded_at`` or failed (None).  ``loaded_at`` is the version of the tag
        list the requests were built from, read before they were built: another thread may load it again meanwhile.
        """
        return any(version is None or version != loaded_at for version in versions)

    def _refresh_tag_table(self) -> bool:
        """
        loads the tag definitions again as open() did, after the tag table version changed; if that fails (e.g. a
        download in progress) reloads are backed off (_back_off) and False is returned
        """
        self.__log.info("Tag table changed on the controller, loading the tag definitions again")
        with self._lock:
            if self._backoff_error():  # a reload failed in another thread while this one waited
                return False
            try:
                if self._lazy_tags:
                    version = self._read_tag_table_version()
                    if version is None:
                        raise ResponseError("the tag table version was not read")
                    self._reset_lazy_tags()
                    self._tag_table_version = version
                else:
                    self._load_tag_list("*" if self._init_args["init_program_tags"] else None, True,
                                        self._init_args["tag_namespace_filter"])
            except CommError:
                raise
            except Exception as err:
                self._back_off(f"reload failed - {err}")
                return False
        return True

    def _back_off(self, reason):
        """
        no tag table reload is attempted for the next _RELOAD_BACKOFF seconds: reads and writes get an error
        instead and send nothing (_backoff_error), e.g. while a download is in progress
        """
        self.__log.warning(f"Tag table not reloaded, {reason}, next attempt in {_RELOAD_BACKOFF} s")
        error = f"Tag table is being reloaded, controller busy ({reason}), next attempt in {_RELOAD_BACKOFF} s"
        self._reload_backoff = (time.monotonic() + _RELOAD_BACKOFF, error)

    def _backoff_error(self) -> Optional[str]:
        """the error of the requests refused while reloads are backed off, None if they are not"""
        until, error = self._reload_backoff
        return error if time.monotonic() < until else None

    def _refused(self, tags):
        """the result of a read or write refused with the backoff error"""
        error = self._reload_backoff[1]
        results = [Tag(tag, None, None, error) for tag in tags]
        return results if len(results) > 1 else results[0]

    @with_forward_open
    def check_tag_table(self) -> bool:
        """
        Loads the tag definitions again if the controller's tag table changed since they were loaded, e.g. an
        online edit added, renamed or deleted a tag.  :meth:`.read` and :meth:`.write` check this on their own, so
        it is only needed to pick up an edit while idle: e.g. a program that reads rarely can call it every few
        seconds so the next read does not wait for the reload.  Reads the version only, the tag list is uploaded
        only after a change.

        Without instance IDs (before v21, Micro800, or a controller that does not report its tag table version)
        nothing is read and False is returned.  While reloads are backed off (see :meth:`.read`) nothing is read
        and False is returned too, as when the version is not read or the reload fails.

        :return: True if the tag definitions were loaded again
        """
        if not self._version_checks or self._backoff_error():
            return False
        version = self._read_tag_table_version()
        if version is None:  # e.g. a download in progress (0x05) or the controller locked (0x10)
            self._back_off("the tag table version was not read")
            return False
        return version != self._tag_table_version and self._refresh_tag_table()

    @property
    def revision_major(self) -> int:
        """
        Returns the major revision for the PLC or 0 if not available
        """
        return self.info.get("revision", {}).get("major", 0)

    @property
    def tags(self) -> dict:
        """
        Read-only property to access all the tag definitions uploaded from the controller.
        """
        return self._tags

    @property
    def tags_json(self):
        """
        Read-only property to access all the tag definitions uploaded from the controller.
        Filters out any non-JSON serializable objects.
        """

        def _copy_datatype(src: dict):
            # copy the entire tag/data type skipping keys that have type classes in the value
            new = {k: v for k, v in src.items() if k not in {"type_class", "_struct_members"}}

            # tags or a data type internal tag need to filter the data_type too
            if isinstance(src.get("data_type"), dict):
                new["data_type"] = _copy_datatype(src["data_type"])

            # if src is from 'data_type', do each internal tag as well
            if "internal_tags" in src:
                new["internal_tags"] = {
                    k: _copy_datatype(v) for k, v in src["internal_tags"].items()
                }

            return new

        json_tags = {tag: _copy_datatype(data) for tag, data in self._tags.items()}

        return json_tags

    @property
    def data_types(self) -> dict:
        """
        Read-only property for access to all data type definitions uploaded from the controller.  The entry of an
        AOI type has an ``'aoi'`` entry once probed: ``{'whole_read': bool, 'readable': [...], 'refused': [...]}``,
        see the note on Add-On Instructions in :class:`LogixDriver`.
        """
        return self._data_types

    @property
    def info(self) -> dict:
        """
        Property containing a dict of all the information collected about the connected PLC.

        **Fields**:

        - *vendor* - name of hardware vendor, e.g. ``'Rockwell Automation/Allen-Bradley'``
        - *product_type* - typically ``'Programmable Logic Controller'``
        - *product_code* - code identifying the product type
        - *revision* - dict of {'major': <major rev (int)>, 'minor': <minor rev (int)>}
        - *serial* - hex string of PLC serial number, e.g. ``'FFFFFFFF'``
        - *product_name* - string value for PLC device type, e.g. ``'1756-L83E/B'``
        - *status* - raw 2-byte CIP Identity Object status word (attribute 5), e.g. ``b'p0'``; *keyswitch* is decoded from it
        - *keyswitch* - string value representing the current keyswitch position, e.g. ``'REMOTE RUN'``
        - *name* - string value of the current PLC program name, e.g. ``'PLCA'``

        **The following fields are added from calling** :meth:`.get_tag_list`

        - *programs* - dict of all Programs in the PLC and their routines, ``{program: {'routines': [routine, ...}...}``
        - *tasks* - dict of all Tasks in the PLC, ``{task: {'instance_id': ...}...}``
        - *modules* - dict of I/O modules in the PLC, ``{module: {'slots': {1: {'types': ['O', 'I', 'C']}, ...}, 'types':[...]}...}``

        """
        return self._info

    @property
    def name(self) -> Optional[str]:
        """
        :return: name of PLC program
        """
        return self._info.get("name")

    @with_forward_open
    def get_plc_name(self) -> str:
        """
        Requests the name of the program running in the PLC. Uses KB `23341`_ for implementation.

        .. _23341: https://rockwellautomation.custhelp.com/app/answers/answer_view/a_id/23341

        :return:  the controller program name
        """

        try:
            response = self.generic_message(
                service=Services.get_attributes_all,
                class_code=ClassCode.program_name,
                instance=1,
                data_type=STRING,
                name="get_plc_name",
            )
            if not response:
                raise ResponseError(f"response did not return valid data - {response.error}")

            self._info["name"] = response.value
            return self._info["name"]
        except CommError:
            raise
        except Exception as err:
            raise ResponseError("failed to get the plc name") from err

    def get_plc_info(self) -> dict:
        """
        Reads basic information from the controller, returns it and stores it in the ``info`` property.
        """

        try:
            response = self.generic_message(
                class_code=ClassCode.identity_object,
                instance=b"\x01",
                service=Services.get_attributes_all,
                data_type=ModuleIdentityObject,
                connected=False,
                unconnected_send=not self._micro800,
                name="get_plc_info",
            )

            if not response:
                raise ResponseError(f"get_plc_info did not return valid data - {response.error}")

            info = response.value
            info["keyswitch"] = KEYSWITCH.get(info["status"][0], {}).get(
                info["status"][1], "UNKNOWN"
            )
            self._info.update(info)
            return info
        except CommError:
            raise
        except Exception as err:
            raise ResponseError("Failed to get PLC info") from err

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
        tag = self.generic_message(
            service=Services.get_attribute_list,
            class_code=ClassCode.wall_clock_time,
            instance=b"\x01",
            request_data=b"\x01\x00\x06\x00",
            data_type=Struct(n_bytes(6), ULINT("µs")),
        )
        if tag:
            _time = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=tag.value["µs"])
            _time = _time.replace(tzinfo=datetime.timezone.utc).astimezone(tz=tz)
            value = {
                "datetime": _time,
                "microseconds": tag.value["µs"],
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

        _struct = Struct(UINT, UINT, ULINT)

        return self.generic_message(
            service=Services.set_attribute_list,
            class_code=ClassCode.wall_clock_time,
            instance=b"\x01",
            request_data=_struct.encode(
                [1, 6, microseconds]
            ),  # attribute count 1, attribute #6, time
            name="set_plc_time",
        )

    @with_forward_open
    def get_tag_list(self, program: str = None, cache: bool = True, tag_namespace_filter: str = '') -> List[dict]:
        """
        Reads the tag list from the controller and the definition for each tag.  Definitions include tag name, tag type
        (atomic vs struct), data type (including nested definitions for structs), external access, dimensions defined (0-3)
        for arrays and their length, etc.

        .. note::

            For program scoped tags the tag['tag_name'] will be ``'Program:{program}.{tag_name}'``. This is so the tag
            list can be fed directly into the read function.


        :param program: scope to retrieve tag list, None for controller-only tags, ``'*'`` for all tags, else name of program
        :param cache: store the retrieved list in the :attr:`.tags` property.  Disable if you wish to get tags retrieved
                      to not overwrite the currently cached definition. For instance if you're checking tags in a single
                      program but currently reading controller-scoped tags.
        :param tag_namespace_filter: prefix match on the tag name (without the ``Program:X.`` part), only matching tags
                      are returned; program, task and module discovery is not filtered

        With instance IDs and ``cache``, the tag table version is read before and after the upload and the upload
        is repeated if it changed (at most 3 uploads, then the last one is kept and the next read or write loads
        it again).  If the version is not read before an upload (e.g. a download in progress) a ``ResponseError``
        is raised; if it is not read after one, that upload is kept and reloads are backed off as after a failed
        reload (see :meth:`.read`), then the next read or write loads it again.

        The templates (UDT layouts) read earlier on this connection are kept after online edits (the download and
        project timestamps of the tag table version unchanged): each template's structure makeup is read again,
        and only a template whose makeup changed is read again.  After a download, or without the version, every
        template is read again.

        :return: a list containing dicts for each tag definition collected
        """
        return self._load_tag_list(program, cache, tag_namespace_filter)

    def _load_tag_list(self, program, cache, tag_namespace_filter, version=None):
        """get_tag_list, ``version`` (with checks) is a tag table version just read, the read before the upload"""
        if program and program.startswith("Program:"):
            program = program[len("Program:"):]

        with self._lock:  # a lazy load in another thread must not see the template cache cleared
            checks = cache and self._version_checks
            for attempt in range(1, _TAG_TABLE_UPLOAD_TRIES + 1):
                if not checks:
                    version = None
                elif version is None or attempt > 1:
                    version = self._read_tag_table_version()
                    if version is None:  # e.g. a download in progress (0x05) or the controller locked (0x10)
                        raise ResponseError("Tag table version not read, the tag list was not uploaded")
                tags = self._upload_tag_list(program, cache, tag_namespace_filter, version)
                if not checks:
                    break
                after = self._read_tag_table_version()
                if after == version:
                    break
                if after is None:  # e.g. a download started during the upload, kept with no known version
                    self._back_off("the tag table version was not read after the upload")
                    version = None  # so the first read or write after the backoff loads it again
                    break
                self.__log.info(f"Tag table changed during upload {attempt} of {_TAG_TABLE_UPLOAD_TRIES}")
            else:  # its version is the one before the upload, so the next check loads it again
                self.__log.warning("Tag table kept changing during the upload, keeping the last one")

            if cache:
                self._tags = {tag["tag_name"]: tag for tag in tags}
                self._lazy_tag_lists.clear()
                self._tag_table_version = version

        self.__log.info(f"Completed tag list upload. Uploaded {len(self._tags)} tags.")
        return tags

    def _upload_tag_list(self, program, cache, tag_namespace_filter, version):
        self._cache["id:struct"].clear()  # the raw templates are kept, their makeups are read again
        # only across online edits: a download can reorder a template's members and keep its makeup
        read_at = version and version[2:]  # the download and project timestamps, an online edit keeps them
        if not read_at or read_at != self._templates_read_at:
            self._cache["id:template"].clear()
            self._cache["id:aoi"].clear()  # probed again with them, _probe_aois
        self._templates_read_at = read_at
        self._cache["id:udt"].clear()
        for key in ("programs", "tasks", "modules"):
            if program in {"*", None} or key not in self._info:
                self._info[key] = {}

        self.__log.info("Starting tag list upload...")
        startup_scope = "*" if self._init_args["init_program_tags"] else None  # other scopes don't touch the file
        if cache and self._tag_cache_file and not self._lazy_tags and program == startup_scope:
            return self._get_tag_list_with_cache_file(program, tag_namespace_filter, version)
        tags = self._isolate_scopes(self._get_symbol_lists(program), tag_namespace_filter)
        if not self._lazy_tags:  # lazy, a type is probed at its first use (_parse_new_tag_request)
            self._probe_aois(tags)
        return tags

    def _get_symbol_lists(self, program):
        """
        uploads the symbol list of each scope of a get_tag_list ``program`` as [scope, symbol list]: the
        controller (None) or a program, for '*' the controller then every program in it (their pages batched)
        """
        scope = None if program == "*" else program
        symbol_lists = [[scope, self._get_symbol_list(scope)]]
        if program == "*":  # same programs, in the same order, that _isolate_user_tags will find
            programs = [t["tag_name"].replace("Program:", "") for t in symbol_lists[0][1]
                        if t["tag_name"].startswith("Program:")]
            uploaded = self._get_program_symbol_lists(programs)
            symbol_lists += [[prog, uploaded[prog]] for prog in programs]
        return symbol_lists

    def _get_symbol_list(self, program=None):
        self.__log.info(f'Beginning upload of {program or "controller"} tags...')
        all_tags = self._get_instance_attribute_list_service(program)
        self.__log.info(f'Completed upload of {program or "controller"} tags')
        return all_tags

    def _get_program_symbol_lists(self, programs):
        """
        Uploads the symbol lists of these programs as {program: symbol list}.  Every round asks each unfinished
        program for its next page, several programs per multi-service packet (_SYMBOL_PAGE_REPLY bytes budgeted
        per reply); a page that says more follows (0x06) continues in the next round.  A program whose page is
        not answered in a packet (e.g. the controller rejects the batch) or made no progress, or sent alone, is
        uploaded from that page on by itself (_get_instance_attribute_list_service).
        """
        self.__log.info(f"Beginning upload of the tags of {len(programs)} programs...")
        symbol_lists = {program: [] for program in programs}
        starts = dict.fromkeys(programs, 0)
        while starts:
            requests = {self._symbol_list_request(program, start): program for program, start in starts.items()}
            next_starts = {}
            for request, response in self._send_batched([(r, _SYMBOL_PAGE_REPLY) for r in requests]):
                program = requests[request]
                page = []
                next_start = self._parse_instance_attribute_list(response, page)
                if next_start == -1 or (page and next_start > starts[program]):
                    symbol_lists[program] += page
                    next_starts[program] = next_start
            for program, start in starts.items():
                if program not in next_starts:
                    symbol_lists[program] += self._get_instance_attribute_list_service(program, start)
            starts = {program: start for program, start in next_starts.items() if start != -1}
        self.__log.info(f"Completed upload of the tags of {len(programs)} programs")
        return symbol_lists

    def _send_batched(self, sized_requests):
        """
        Sends (request, reply size) in multi-service packets (_pack_multi_requests), returns (request, reply)
        for each request answered in one.  The others, sent alone or not answered (e.g. a controller that
        rejects the packet or the service in it), are left to the caller, which sends them on their own.
        """
        answered = []
        for packet in self._pack_multi_requests(sized_requests):
            if isinstance(packet, MultiServiceRequestPacket):
                response = self.send(packet)
                if not response.responses:
                    self.__log.info(f"Multi-service request not answered, sending its requests alone - "
                                    f"{response.error}")
                answered += [(reply.request, reply) for reply in response.responses if reply]
        return answered

    def _get_tag_list_with_cache_file(self, program, tag_namespace_filter, version):
        """
        Same result as the uploads in get_tag_list.  If the tag cache file was written for this controller and scope
        at the current tag table ``version``, nothing is uploaded, the symbol lists, makeups and templates all come
        from the file.  Else every requested symbol list is uploaded first and the templates come from the file
        only if those lists equal the stored ones, so ids are never stale, and only if their makeup, still read for
        each template, is unchanged (_get_data_type).
        """
        cached = self._load_tag_cache_file()
        current = (cached is not None and version is not None and cached["scope"] == program
                   and cached["serial"] == self._info.get("serial") and cached["table_version"] == list(version))

        def isolate():
            return self._isolate_scopes(symbols, tag_namespace_filter)

        symbols = cached["symbols"] if current else self._get_symbol_lists(program)
        templates = {}
        if cached is not None and cached["symbols"] == symbols:
            templates = cached["templates"]
            self._cache["id:aoi"].update(cached["aoi"])  # used where the makeup is unchanged, _probe_aois
        elif cached is not None:
            self.__log.info(f"Tag cache file {self._tag_cache_file} not used, it is out of date")
        if current:  # the tag table is unchanged, so are the makeups
            self._cache["id:struct"].update((i, makeup) for i, (makeup, _) in templates.items())
        self._cache["id:template"].update(templates)  # the makeups decide which ones are used (_template_data)
        try:
            tags = isolate()
        except CommError:
            raise
        except Exception as err:  # e.g. a damaged template in the file, upload everything instead
            if not (templates or current):
                raise
            self.__log.warning(f"Ignoring tag cache file {self._tag_cache_file}, its contents failed: {err!r}")
            for values in self._cache.values():
                values.clear()
            for key in ("programs", "tasks", "modules"):  # only the startup scope ('*' or None) gets here
                self._info[key] = {}
            templates = {}
            if current:  # the symbol lists came from the file too
                symbols, current = self._get_symbol_lists(program), False
            tags = isolate()

        if current:
            self.__log.info(f"Tag table unchanged since tag cache file {self._tag_cache_file} was written, "
                            f"loaded the tag list from it")
        elif templates:
            saved = sum(1 for i in self._cache["id:udt"] if self._cache["id:template"][i] is templates.get(i))
            self.__log.info(f"Used tag cache file {self._tag_cache_file}, saved the reads of {saved} templates")
        self._probe_aois(tags)
        self._save_tag_cache_file(program, symbols, version, cached and cached["file"])
        return tags

    def _load_tag_cache_file(self):
        """
        returns the tag cache file's contents, with the templates as {template instance id: (structure makeup, raw
        template)} and the AOI probes as {template instance id: (structure makeup, probe)} (_probe_aois), or None
        if the file is missing, unreadable or in an older format
        """
        try:
            with open(self._tag_cache_file, encoding="utf-8") as file:
                cached = json.load(file)
            if cached["version"] != _TAG_CACHE_VERSION:
                self.__log.info(f"Tag cache file {self._tag_cache_file} not used, it is out of date")
                return None
            return {
                "scope": cached["scope"],
                "serial": cached["serial"],
                "table_version": cached["table_version"],
                "symbols": cached["symbols"],
                "templates": {
                    int(instance_id): ({k: int(makeup[k]) for k in _MAKEUP_KEYS}, bytes.fromhex(data))
                    for instance_id, makeup, data in cached["templates"]
                },
                "aoi": {  # none in a file written before the probes, they are probed then
                    int(instance_id): ({k: int(makeup[k]) for k in _MAKEUP_KEYS}, aoi)
                    for instance_id, makeup, aoi in cached.get("aoi", [])
                },
                "file": cached,  # as read, _save_tag_cache_file does not write the same again
            }
        except FileNotFoundError:
            self.__log.info(f"Tag cache file {self._tag_cache_file} not found, it will be created")
        except Exception as err:
            self.__log.warning(f"Ignoring unreadable tag cache file {self._tag_cache_file}: {err!r}")
        return None

    def _save_tag_cache_file(self, program, symbols, version, previous=None):
        """
        atomically writes the symbol lists, every template used by them with the probes of its AOIs, and the
        controller serial and tag table version they were uploaded at (read before the upload, so a version still
        current means nothing changed); not written if that is the ``previous`` contents of the file
        """
        aois = self._cache["id:aoi"]
        cached = {
            "version": _TAG_CACHE_VERSION,
            "scope": program,
            "serial": self._info.get("serial"),
            "table_version": None if version is None else list(version),
            "symbols": symbols,
            "templates": [
                [i, self._cache["id:template"][i][0], self._cache["id:template"][i][1].hex()]
                for i in self._cache["id:udt"]
            ],
            "aoi": [[i, *aois[i]] for i in self._cache["id:udt"] if self._aoi_probed(i)],
        }
        if cached == previous:
            return
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix=".tmp", dir=os.path.dirname(os.path.abspath(self._tag_cache_file)))
            with open(fd, "w", encoding="utf-8") as file:
                json.dump(cached, file)
            os.replace(tmp, self._tag_cache_file)
        except Exception as err:
            self.__log.warning(f"Could not write tag cache file {self._tag_cache_file}: {err!r}")
            if tmp is not None:
                with suppress(OSError):
                    os.remove(tmp)

    def _symbol_list_request(self, program, instance):
        """the request for a page of the symbol list of ``program`` (None for the controller) from ``instance``"""
        segments = []
        if program:
            if not program.startswith("Program:"):
                program = f"Program:{program}"
            segments = [
                DataSegment(program),
            ]

        segments += [
            LogicalSegment(ClassCode.symbol_object, "class_id"),
            LogicalSegment(instance, "instance_id"),
        ]

        new_path = PADDED_EPATH.encode(segments, length=True)
        request = SendUnitDataRequestPacket(self._sequence)

        attributes = [
            b"\x01\x00",  # Attr. 1: Symbol name
            b"\x02\x00",  # Attr. 2 : Symbol Type
            b"\x03\x00",  # Attr. 3 : Symbol Address
            b"\x05\x00",  # Attr. 5 : Symbol Object Address
            b"\x06\x00",  # Attr. 6 : ? - Not documented (Software Control?)
            b"\x08\x00",  # Attr. 8 : array dimensions [1,2,3]
        ]

        if self.revision_major >= MIN_VER_EXTERNAL_ACCESS:
            attributes.append(b"\x0a\x00")  # Attr. 10 : external access

        request.add(
            Services.get_instance_attribute_list,
            new_path,
            UINT.encode(len(attributes)),
            *attributes,
        )
        return request

    def _get_instance_attribute_list_service(self, program=None, start=0):
        """Step 1: Finding user-created controller scope tags in a Logix5000 controller

        This service returns instance IDs for each created instance of the symbol class, along with a list
        of the attribute data associated with the requested attribute.  ``start`` is the first instance requested.
        """
        try:
            last_instance = start
            tag_list = []
            while last_instance != -1:
                # Creating the Message Request Packet
                self.__log.debug(f"Getting tags starting with instance {last_instance}")
                _start_instance = last_instance
                _num_tags_start = len(tag_list)
                request = self._symbol_list_request(program, last_instance)
                response = self.send(request)
                if not response:
                    raise ResponseError(
                        f"send_unit_data returned not valid data - {response.error}"
                    )

                last_instance = self._parse_instance_attribute_list(response, tag_list)
                if last_instance != -1 and last_instance <= _start_instance:
                    raise ResponseError("Tag list upload did not advance the instance cursor")
                self.__log.debug(
                    f"Uploaded {len(tag_list) - _num_tags_start} tags, last instance: {last_instance}"
                )

            return tag_list

        except CommError:
            raise
        except Exception as err:
            raise ResponseError("failed to get attribute list") from err

    def _parse_instance_attribute_list(self, response, tag_list):
        """extract the tags list from the message received"""

        stream = BytesIO(response.data)
        tags_returned_length = stream.getbuffer().nbytes
        instance = 0
        # TODO: turn this into an array of struct with new types
        try:
            while stream.tell() < tags_returned_length:
                instance = UDINT.decode(stream)
                tag_name = STRING.decode(stream)
                symbol_type = UINT.decode(stream)
                symbol_address = UDINT.decode(stream)
                symbol_object_address = UDINT.decode(stream)
                software_control = UDINT.decode(stream)
                dim1 = UDINT.decode(stream)
                dim2 = UDINT.decode(stream)
                dim3 = UDINT.decode(stream)

                if self.revision_major >= MIN_VER_EXTERNAL_ACCESS:
                    access = USINT.decode(stream)
                else:
                    access = None

                tag_list.append(
                    {
                        "instance_id": instance,
                        "tag_name": tag_name,
                        "symbol_type": symbol_type,
                        "symbol_address": symbol_address,
                        "symbol_object_address": symbol_object_address,
                        "software_control": software_control,
                        "external_access": EXTERNAL_ACCESS.get(access, "Unknown"),
                        "dimensions": [dim1, dim2, dim3],
                    }
                )

        except Exception as err:
            raise ResponseError("failed to parse instance attribute list") from err

        if response.service_status == SUCCESS:
            return -1
        elif response.service_status == INSUFFICIENT_PACKETS:
            return instance + 1
        else:
            self.__log.warning("unknown status during _parse_instance_attribute_list")
            return -1

    def _isolate_user_tags(self, all_tags, program=None, tag_namespace_filter=''):
        return self._isolate_scopes([[program, all_tags]], tag_namespace_filter)

    def _isolate_scopes(self, symbol_lists, tag_namespace_filter=''):
        """
        the user tags of each [scope, symbol list], in order, with their definitions; the structure makeups of their
        templates are read first, batched (_prefetch_templates)
        """
        try:
            user_symbols = [user_symbol for scope, all_tags in symbol_lists
                            for user_symbol in self._user_symbols(all_tags, scope, tag_namespace_filter)]
            self._prefetch_templates(tag["symbol_type"] & 0b_0000_1111_1111_1111 for _, tag in user_symbols
                                     if tag["symbol_type"] & 0b_1000_0000_0000_0000)  # as _create_tag
            return [self._create_tag(name, tag) for name, tag in user_symbols]
        except CommError:
            raise
        except Exception as err:
            raise ResponseError("failed isolating user tags") from err

    def _user_symbols(self, all_tags, program=None, tag_namespace_filter=''):
        """the (tag name, symbol) of the user tags in a symbol list, records its programs, routines, tasks and modules"""
        user_tags = []
        self.__log.debug(f'Isolating user tags for {program or "controller"} ...')
        for tag in all_tags:
            io_tag = False
            name = tag["tag_name"]
            if name.startswith("Program:"):
                prog_name = name.replace("Program:", "")
                self._info["programs"][prog_name] = {
                    "instance_id": tag["instance_id"],
                    "routines": [],
                }
                continue

            if name.startswith("Routine:"):
                rtn_name = name.replace("Routine:", "")
                _program = self._info["programs"].get(program)
                if _program is None:
                    self.__log.error(f"Program {program} not defined in tag list")
                else:
                    _program["routines"].append(rtn_name)
                continue

            if name.startswith("Task:"):
                self._info["tasks"][name.replace("Task:", "")] = {
                    "instance_id": tag["instance_id"]
                }
                continue

            # system tags that may interfere w/ finding I/O modules
            if "Map:" in name or "Cxn:" in name:
                continue

            # I/O module tags
            # Logix 5000 Controllers I/O and Tag Data, page 17  (1756-pm004_-en-p.pdf)
            if any(x in name for x in (":I", ":O", ":C", ":S")):
                io_tag = True
                mod = name.split(":")
                mod_name = mod[0]
                if mod_name not in self._info["modules"]:
                    self._info["modules"][mod_name] = {"slots": {}}
                if len(mod) == 3 and mod[1].isdigit():
                    mod_slot = int(mod[1])
                    if mod_slot not in self._info["modules"][mod_name]["slots"]:
                        self._info["modules"][mod_name]["slots"][mod_slot] = {"types": []}
                    self._info["modules"][mod_name]["slots"][mod_slot]["types"].append(mod[2])
                elif len(mod) == 2:
                    if "types" not in self._info["modules"][mod_name]:
                        self._info["modules"][mod_name]["types"] = []
                    self._info["modules"][mod_name]["types"].append(mod[1])
                # Not sure if this branch will ever be hit, but added to see if above branches may need additional work
                else:
                    if "__UNKNOWN__" not in self._info["modules"][mod_name]:
                        self._info["modules"][mod_name]["__UNKNOWN__"] = []
                    self._info["modules"][mod_name]["__UNKNOWN__"].append(":".join(mod[1:]))

            # other system or junk tags
            if (not io_tag and ":" in name) or name.startswith("__"):
                continue
            if tag["symbol_type"] & 0b0001_0000_0000_0000:
                continue

            # only user tags are filtered, by name without the Program:X. part
            if not name.startswith(tag_namespace_filter):
                continue

            if program is not None:
                name = f"Program:{program}.{name}"

            user_tags.append((name, tag))

        self.__log.debug(f'Finished isolating tags for {program or "controller"}')
        return user_tags

    def _create_tag(self, name, raw_tag):
        copy_keys = [
            "instance_id",
            "symbol_address",
            "symbol_object_address",
            "software_control",
            "external_access",
            "dimensions",
        ]
        new_tag = {
            "tag_name": name,
            "dim": (raw_tag["symbol_type"] & 0b0110000000000000)
            >> 13,  # bit 13 & 14, number of array dims
            "alias": False if raw_tag["software_control"] & BASE_TAG_BIT else True,
            **{k: raw_tag[k] for k in copy_keys},
        }

        if raw_tag["symbol_type"] & 0b_1000_0000_0000_0000:  # bit 15, 1 = struct, 0 = atomic
            template_instance_id = raw_tag["symbol_type"] & 0b_0000_1111_1111_1111
            tag_type = "struct"
            new_tag["template_instance_id"] = template_instance_id
            new_tag["data_type"] = self._get_data_type(template_instance_id, raw_tag["symbol_type"])
            new_tag["data_type_name"] = new_tag["data_type"]["name"]
            _type_class = new_tag["data_type"]["type_class"]
        else:
            tag_type = "atomic"
            datatype = raw_tag["symbol_type"] & 0b_0000_0000_1111_1111
            new_tag["data_type"] = DataTypes.get(datatype)
            new_tag["data_type_name"] = new_tag["data_type"]
            _type_class = DataTypes.get(new_tag["data_type"])
            if datatype == DataTypes.bool.code:  # TODO: make sure this is right
                new_tag["bit_position"] = (raw_tag["symbol_type"] & 0b_0000_0111_0000_0000) >> 8

        if new_tag["dim"]:
            total_elements = reduce(operator.mul, new_tag["dimensions"][: new_tag["dim"]], 1)
            type_class = Array(length_=total_elements, element_type_=_type_class)
        else:
            type_class = _type_class

        new_tag["tag_type"] = tag_type
        new_tag["type_class"] = type_class

        return new_tag

    def _get_structure_makeup(self, instance_id):
        """
        get the structure makeup for a specific structure
        """
        if instance_id not in self._cache["id:struct"]:
            response = self.generic_message(
                service=Services.get_attribute_list,
                class_code=ClassCode.template_object,
                instance=instance_id,
                connected=True,
                request_data=_MAKEUP_ATTRIBUTES,
                data_type=StructTemplateAttributes,
                name=f"_get_structure_makeup(instance_id={instance_id!r})",
            )
            if not response:
                raise ResponseError("send_unit_data returned not valid data", response.error)
            _struct = _parse_structure_makeup_attributes(response)
            self._cache["id:struct"][instance_id] = _struct

        return self._cache["id:struct"][instance_id]

    def _read_structure_makeups(self, instance_ids):
        """
        reads the structure makeups of these templates into the cache in multi-service packets, those not answered
        there are left to _get_structure_makeup
        """
        requests = {}
        for instance_id in instance_ids:
            request = GenericConnectedRequestPacket(
                self._sequence, Services.get_attribute_list, ClassCode.template_object, instance_id,
                request_data=_MAKEUP_ATTRIBUTES, data_type=StructTemplateAttributes,
            )
            requests[request] = instance_id
        for request, response in self._send_batched([(request, _MAKEUP_REPLY) for request in requests]):
            self._cache["id:struct"][requests[request]] = _parse_structure_makeup_attributes(response)

    def _prefetch_templates(self, instance_ids):
        """
        Reads the structure makeups of these templates, then of the templates nested in them, level by level in
        multi-service packets (_read_structure_makeups), and the templates not read yet or whose makeup changed
        (_template_data), so _get_data_type finds them all in the cache.
        """
        pending = set(instance_ids)
        while pending:
            self._read_structure_makeups(sorted(pending - self._cache["id:struct"].keys()))
            nested = set()
            for instance_id in sorted(pending):
                template = self._get_structure_makeup(instance_id)  # read alone if not answered in a batch
                nested |= _nested_template_ids(self._template_data(instance_id, template), template)
            pending = nested - self._cache["id:struct"].keys()

    def _template_data(self, instance_id, template):
        """
        the raw template, read again only if its structure makeup changed since it was read on this connection or
        stored in the tag cache file: a change that keeps the makeup (e.g. a member renamed to a name of the same
        length, or two members of the same type swapped) is not detected, so the kept templates are cleared after
        a download (_upload_tag_list)
        """
        cached = self._cache["id:template"].get(instance_id)  # (makeup, raw template)
        if cached is None or cached[0] != template:  # a changed makeup means the template changed
            cached = template, self._read_template(instance_id, template["object_definition_size"])
            self._cache["id:template"][instance_id] = cached
        return cached[1]

    def _read_template(self, instance_id, object_definition_size):
        """get a list of the tags in the plc"""

        offset = 0
        template_raw = b""
        try:
            while True:
                response = self.generic_message(
                    service=Services.read_tag,
                    class_code=ClassCode.template_object,
                    instance=instance_id,
                    request_data=b"".join(
                        (
                            DINT.encode(offset),
                            UINT.encode(((object_definition_size * 4) - 21) - offset),
                        )
                    ),
                    name=f"_read_template(instance_id={instance_id}, object_definition_size={object_definition_size}, offset={offset})",
                    return_response_packet=True,
                )
                response_pkt = response.value
                if response_pkt.service_status not in (SUCCESS, INSUFFICIENT_PACKETS):
                    raise ResponseError("Error reading template", response)

                template_raw += response_pkt.data

                if response_pkt.service_status == SUCCESS:
                    break

                if not response_pkt.data:
                    raise ResponseError("Template read made no progress")
                offset += len(response_pkt.data)

        except CommError:
            raise
        except Exception as err:
            raise ResponseError("Failed to read template") from err
        else:
            return template_raw

    def _parse_template_data(self, data, template, symbol_type):
        info_len = template["member_count"] * TEMPLATE_MEMBER_INFO_LEN
        info_data = data[:info_len]
        self.__log.debug(f"Parsing template {template!r} from {data!r}")

        chunks = (
            info_data[i : i + TEMPLATE_MEMBER_INFO_LEN]
            for i in range(0, info_len, TEMPLATE_MEMBER_INFO_LEN)
        )

        member_data = [self._parse_template_data_member_info(chunk) for chunk in chunks]

        member_names = []
        template_name = None
        for name in (x.decode(errors="replace") for x in data[info_len:].split(b"\x00")):
            if template_name is None and ";" in name:
                template_name, _ = name.split(";", maxsplit=1)
            else:
                member_names.append(name)

        _type = symbol_type & 0b_0000_1111_1111_1111

        # range of non-predefined structs is 0x100 - 0xEFF according to spec
        # so if outside that range assume it is a predefined type
        predefine = _type < 0x100 or _type > 0xEFF
        if predefine and template_name is None:  # predefined types put name as first member (DWORD)
            template_name = member_names.pop(0)

        if template_name == "ASCIISTRING82":  # internal name for STRING builtin type
            template_name = "STRING"

        data_type = {
            "name": template_name,
            "internal_tags": {},
            "attributes": [],
            "template": template,
        }

        _struct_members = []
        _bit_members = {}
        _private_members = set()
        _unk_member_count = 0
        for member, info in zip(member_names, member_data):
            if not member:  # handle unnamed private members
                member = f'__unknown{_unk_member_count}'  # double-underscore makes it 'private'
                _unk_member_count += 1
            if (
                member.startswith("ZZZZZZZZZZ") or
                member.startswith("__") or
                (predefine and member in {"CTL", "Control"})
            ):
                _private_members.add(member)
            else:
                data_type["attributes"].append(member)

            data_type["internal_tags"][member] = info

            if info["data_type_name"] == "BOOL" and 'bit' in info:
                # bit members aren't really 'struct' members since they are aliased to bits of other members
                _bit_members[member] = (info['offset'], info['bit'])
            else:
                _struct_members.append((info["type_class"](member), info["offset"]))

        if (  # determine if struct is a string or not
            data_type["attributes"] == ["LEN", "DATA"]
            and data_type["internal_tags"]["DATA"]["data_type_name"] == "SINT"
            and data_type["internal_tags"]["DATA"].get("array")
        ):
            data_type["string"] = data_type["internal_tags"]["DATA"]["array"]

            data_type["type_class"] = FixedSizeString(template["structure_size"] - 4, max_len_=data_type["string"])
        else:
            data_type["_struct_members"] = (_struct_members, _bit_members)
            data_type["type_class"] = StructTag(
                *_struct_members,
                bit_members=_bit_members,
                struct_size=template["structure_size"],
                private_members=_private_members,
            )

        self.__log.debug(f"Completed parsing template as data type {data_type!r}")

        return data_type

    def _parse_template_data_member_info(self, info):
        stream = BytesIO(info)
        type_info = UINT.decode(stream)
        typ = UINT.decode(stream)
        member = {"offset": UDINT.decode(stream)}
        tag_type = "atomic"

        data_type = DataTypes.get(typ)
        if data_type:
            type_class = DataTypes.get_type(typ)
        if data_type is None:
            instance_id = typ & 0b0000_1111_1111_1111
            type_class = DataTypes.get_type(instance_id)
            if type_class:
                data_type = str(type_class)
        if data_type is None:
            tag_type = "struct"
            data_type = self._get_data_type(instance_id, typ)
            type_class = data_type["type_class"]

        member["tag_type"] = tag_type
        member["data_type"] = data_type
        member["data_type_name"] = data_type["name"] if tag_type == "struct" else data_type

        if data_type == "BOOL":
            member["bit"] = type_info
        elif data_type is not None:
            member["array"] = type_info
            if type_info:
                type_class = Array(length_=type_info, element_type_=type_class)

        member["type_class"] = type_class

        return member

    def _get_data_type(self, instance_id, symbol_type):
        if instance_id not in self._cache["id:udt"]:
            try:
                self.__log.debug(f"Getting data type for id {instance_id}")
                template = self._get_structure_makeup(instance_id)  # instance id from type
                data_type = self._parse_template_data(self._template_data(instance_id, template), template,
                                                      symbol_type)
                self._cache["id:udt"][instance_id] = data_type
                self._data_types[data_type["name"]] = data_type
                self.__log.debug(f'Got data type {data_type["name"]} for id {instance_id}')
            except CommError:
                raise
            except Exception as err:
                raise ResponseError(
                    f"Failed to get data type information for {instance_id}"
                ) from err

        return self._cache["id:udt"][instance_id]

    def _aoi_probed(self, instance_id) -> bool:
        """the AOI template was probed at its current structure makeup"""
        probe = self._cache["id:aoi"].get(instance_id)
        return probe is not None and probe[0] == self._cache["id:struct"].get(instance_id)

    def _probe_aois(self, tags):
        """
        Finds which members of each AOI data type are readable: a controller refuses the reads of an AOI's local
        tags, and the read of a whole AOI that has any.  For each AOI type not probed yet at its current makeup, one
        instance reachable from ``tags`` (_aoi_instances) is read whole and member by member, Read Tag only, in
        multi-service packets.  A read refused with 0x04 (IOI syntax error) or 0x0F (permission denied) is refused,
        any other reply or none leaves it readable.  The result goes on the data type as ``data_type['aoi']``, a type
        with no instance gets none.  The template has no documented marker of locals, nor of AOIs (_is_aoi).
        """
        with self._lock:
            wanted = {dt["name"]: i for i, dt in self._cache["id:udt"].items()
                      if _is_aoi(dt) and not self._aoi_probed(i)}
            instances = self._aoi_instances(tags, wanted) if wanted else {}
            use_ids = self._cfg["use_instance_ids"]
            requests = {}  # request: (AOI name, member or None for the whole AOI)
            for name, (path, base_tag) in instances.items():
                data_type = self._cache["id:udt"][wanted[name]]
                whole = {"tag_type": "struct", "data_type": data_type, "data_type_name": name,
                         "type_class": data_type["type_class"]}
                reads = [(None, path, whole)]
                reads += [(member, f"{path}.{member}", data_type["internal_tags"][member])
                          for member in data_type["attributes"]]
                for member, tag, info in reads:
                    request = ReadTagRequestPacket(self._sequence, tag, 1, info, len(requests), use_ids)
                    request.request_path = tag_request_path(tag, {"instance_id": base_tag["instance_id"]}, use_ids)
                    requests[request] = name, member
            # smallest replies first so they share packets, a whole AOI too big for one is sent alone (0x06, readable)
            sized_requests = sorted(((request, _read_reply_size({"tag_info": request.tag_info, "elements": 1}))
                                     for request in requests), key=lambda item: item[1])
            refused = set()
            packets = self._pack_multi_requests(sized_requests)
            for packet in packets:
                response = self.send(packet)
                replies = response.responses if isinstance(packet, MultiServiceRequestPacket) else [response]
                refused.update(reply.request for reply in replies if reply.service_status in _AOI_REFUSED)

            probes = {name: {"whole_read": True, "readable": [], "refused": []} for name in instances}
            for request, (name, member) in requests.items():
                if member is None:
                    probes[name]["whole_read"] = request not in refused
                else:
                    probes[name]["refused" if request in refused else "readable"].append(member)
            for name, probe in probes.items():
                self._cache["id:aoi"][wanted[name]] = self._cache["id:struct"][wanted[name]], probe
            if probes:
                self.__log.info(f"Probed the member access of {len(probes)} AOI types in {len(packets)} packets")
            for i, data_type in self._cache["id:udt"].items():
                if self._aoi_probed(i):
                    data_type["aoi"] = self._cache["id:aoi"][i][1]

    @staticmethod
    def _aoi_instances(tags, wanted):
        """
        {AOI name: (tag path, its base tag)} of an instance of each ``wanted`` AOI type in ``tags``: a tag of that
        type, else element 0 of an array tag of it, else a member of a struct tag (not through an AOI: its struct
        members are locals); the first one found in ``tags`` order
        """
        nested = {}  # struct name: {AOI name: member path}, the AOIs in its members

        def members(data_type):
            if data_type["name"] not in nested:
                found = nested[data_type["name"]] = {}
                for attr in data_type["attributes"]:
                    info = data_type["internal_tags"][attr]
                    if info["tag_type"] != "struct":
                        continue
                    path = f".{attr}[0]" if info.get("array") else f".{attr}"
                    if _is_aoi(info["data_type"]):
                        found.setdefault(info["data_type"]["name"], path)
                    else:
                        for name, sub_path in members(info["data_type"]).items():
                            found.setdefault(name, path + sub_path)
            return nested[data_type["name"]]

        best = {}  # AOI name: (rank, tag path, base tag)
        for tag in tags:
            if tag["tag_type"] != "struct" or tag["external_access"] == "None":
                continue
            path = tag["tag_name"] + (f"[{','.join('0' * tag['dim'])}]" if tag["dim"] else "")
            if _is_aoi(tag["data_type"]):
                found = {tag["data_type"]["name"]: (1 if tag["dim"] else 0, path)}
            else:
                found = {name: (2, path + sub_path) for name, sub_path in members(tag["data_type"]).items()}
            for name, (rank, tag_path) in found.items():
                if name in wanted and rank < best.get(name, (3,))[0]:
                    best[name] = rank, tag_path, tag
        return {name: (tag_path, tag) for name, (_, tag_path, tag) in best.items()}

    def authenticate_metadata(self, credentials: Optional[LogixMetadataCredentials] = None) -> Tag:
        """Authenticate the current CIP connection for experimental metadata reads.

        Uses Python and the bundled or caller-supplied credentials. Authentication applies
        to this connection only; call again after a reconnect. No controller
        values or persistent permissions are changed. Native Linx is not used.
        """
        name = "metadata_authentication"
        try:
            if credentials is None:
                credentials = LogixMetadataCredentials.bundled()
            if not isinstance(credentials, LogixMetadataCredentials):
                raise RequestError("Supply LogixMetadataCredentials")
            if self._micro800:
                raise RequestError("Metadata authentication requires a Logix controller")
            challenge = self.generic_message(
                service=0x4B, class_code=0x64, instance=1,
                request_data=credentials.certificate, connected=True,
                name="Metadata certificate challenge", return_response_packet=True,
            )
            if not challenge:
                raise ResponseError("Certificate challenge rejected: " + str(challenge.error))
            if challenge.value.raw[46:50] != bytes.fromhex("cb000000"):
                raise ResponseError("Unexpected certificate challenge reply header")
            connection = (self._session, self._target_cid)
            proof = credentials.answer_challenge(challenge.value.data)
            if not self._target_is_connected or connection != (self._session, self._target_cid):
                raise ResponseError("CIP connection changed during metadata authentication")
            completion = self.generic_message(
                service=0x4C, class_code=0x64, instance=1,
                request_data=b"\x14\x00" + proof, connected=True,
                name="Metadata challenge completion", return_response_packet=True,
            )
            if not completion:
                raise ResponseError("Challenge completion rejected: " + str(completion.error))
            if completion.value.raw[46:50] != bytes.fromhex("cc000000"):
                raise ResponseError("Unexpected metadata completion reply")
            credentials.validate_completion(completion.value.data)
            if not self._target_is_connected or connection != (self._session, self._target_cid):
                raise ResponseError("CIP connection changed during metadata authentication")
            return Tag(name, True, "BOOL", None)
        except Exception as error:
            return Tag(name, None, "BOOL", str(error))

    @with_forward_open
    def get_tag_description(self, tag_name: str, language: int = 0x007F,
                            encoding: str = "utf-8") -> Tag:
        """Read a tag, member, or array element's Description."""
        result_name = f"{tag_name}.@Description"
        try:
            if self._micro800:
                raise RequestError("Extended descriptions require a Logix controller")
            with self._lock:
                value = read_description(self, tag_name, language, encoding)
            if value is None:
                return Tag(result_name, None, "STRING",
                           "No description returned for language 0x{:04x}".format(language))
            return Tag(result_name, value, "STRING", None)
        except Exception as error:
            return Tag(result_name, None, "STRING", str(error))

    @with_forward_open
    def read(self, *tags: str) -> ReadWriteReturnType:
        """
        Read the value of tag(s).  Automatically will split tags into multiple requests by tracking the request and
        response size.  Will use the multi-service request to group many tags into a single packet and also will automatically
        use fragmented read requests if the response size will not fit in a single packet.  Supports arrays (specify element
        count in using curly braces (array{10}).  Also supports full structure reading (when possible), return value
        will be a dict of {attribute name: value}; for an AOI whose whole read is refused, a dict of its readable
        members (see the note on Add-On Instructions in :class:`LogixDriver`).

        With instance IDs, every packet starts with a check of the tag table version (fragmented reads are sent
        between two checks).  If the tag table changed since the tag definitions were loaded, e.g. by an online
        edit, an ID may have named another tag: every result is discarded, the definitions are loaded again (see
        :meth:`.check_tag_table`) and the tags are read once more.  If it changed again during that second read,
        every result gets an error instead.  If the version is not read (e.g. a download in progress or the
        controller locked) or the reload fails, every result gets an error and for the next 2 seconds reads and
        writes get one too without sending anything, then the next one tries the reload again.

        :param tags: one or many tags to read
        :return: a single or list of ``Tag`` objects
        """

        if not tags:
            return []
        for attempt in range(2):
            if self._backoff_error():
                return self._refused(tags)
            # before the parse: get_tag_list sets the tags before their version, so a reload in between is a retry
            loaded_at = self._tag_table_version
            parsed_requests = self._parse_requested_tags(tags, "r")
            requests = self._read_build_requests(parsed_requests)
            read_results = self._send_requests(requests)
            versions = [read_results.pop(key).value for key in list(read_results)
                        if isinstance(key, TagTableVersionRequestPacket)]
            self._merge_chunk_results(parsed_requests, read_results, "r")
            self._merge_aoi_results(parsed_requests, read_results)
            if not self._tag_table_changed(versions, loaded_at):
                break
            if None in versions:  # e.g. a download in progress (0x05) or the controller locked (0x10)
                self._back_off("the tag table version was not read")
                return self._refused(tags)
            if attempt == 0:
                if not self._refresh_tag_table():
                    return self._refused(tags)
            else:  # no third read, the next call loads the definitions again
                error = "Tag table changed on the controller during the read and again during its retry, discarded"
                read_results = {key: Tag(result.tag, None, None, error) for key, result in read_results.items()}

        results = []

        for i, tag in enumerate(tags):
            try:
                request_data = parsed_requests[i]
                if request_data.get("error"):
                    results.append(Tag(tag, None, None, request_data["error"]))
                    continue

                result = read_results[i]
                bool_elements = request_data["bool_elements"]
                if result:
                    bit = request_data.get("bit")

                    if request_data["tag_info"]["data_type_name"] != "DWORD":
                        if bit is not None:
                            result = Tag(
                                request_data["user_tag"],
                                bool(result.value & 1 << bit),
                                "BOOL",
                                result.error,
                            )
                    else:
                        bit = bit or 0
                        if bool_elements is not None:
                            bools = result.value[bit : bit + bool_elements]
                            data_type = f"BOOL[{bool_elements}]"
                            result = Tag(request_data["user_tag"], bools, data_type, result.error)
                        else:
                            val = result.value[bit]
                            result = Tag(request_data["user_tag"], val, "BOOL", result.error)
                else:
                    result = Tag(request_data["user_tag"], None, None, result.error)

                results.append(result)

            except Exception as err:
                self.__log.exception("Invalid tag request")
                results.append(Tag(tag, None, None, f"Invalid tag request - {err!r}"))

        if len(tags) > 1:
            return results
        else:
            return results[0]

    def _read_build_requests(self, parsed_tags):
        sized_requests = []
        for tag_data in self._split_large_requests(self._expand_aoi_reads(parsed_tags), "r").values():
            request = self._read_build_single_request(tag_data)
            if request is not None:
                sized_requests.append((request, _read_reply_size(tag_data)))
        # reads are matched by request_id, so batch the small reads ahead of the fragmented ones
        sized_requests.sort(key=lambda item: isinstance(item[0], ReadTagFragmentedRequestPacket))
        return self._pack_multi_requests(sized_requests, self._version_checks)

    def _expand_aoi_reads(self, parsed_tags):
        """
        The reads to send: the read of a whole AOI whose probe found it refused (_probe_aois) is replaced by the
        reads of its readable members, merged again by _merge_aoi_results.  Reads of several elements are not.
        """
        expanded = {}
        for request_id, tag_data in parsed_tags.items():
            aoi = None if tag_data.get("error") else _aoi_probe(tag_data["tag_info"])
            if aoi is None or aoi["whole_read"] or tag_data["bit"] is not None or tag_data["elements"] != 1:
                expanded[request_id] = tag_data
                continue
            info = tag_data["tag_info"]
            path = tag_data["plc_tag"]
            dim = info.get("dim") or (1 if info.get("array") else 0)
            if dim and not path.endswith("]"):  # an array without an index reads its first element
                path += f"[{','.join('0' * dim)}]"
            base = {"instance_id": info.get("base_instance_id", info.get("instance_id"))}
            members = []
            for member in aoi["readable"]:
                member_info = info["data_type"]["internal_tags"][member]
                plc_tag = f"{path}.{member}"
                members.append(dict(
                    tag_data, request_id=(request_id, member), plc_tag=plc_tag, tag_info=member_info,
                    elements=member_info.get("array") or 1,
                    request_path=tag_request_path(plc_tag, base, self._cfg["use_instance_ids"]),
                ))
            tag_data["aoi_requests"] = members
            expanded.update((member["request_id"], member) for member in members)
        return expanded

    def _merge_aoi_results(self, parsed_tags, results):
        """the member reads of an AOI read (_expand_aoi_reads) as its result, a dict of its readable members"""
        for request_id, tag_data in parsed_tags.items():
            members = tag_data.get("aoi_requests")
            if members is None:
                continue
            values, error = {}, None
            for member in members:
                name = member["request_id"][1]
                result = results.pop(member["request_id"], None)
                if result is None or result.error:
                    error = error or f'{name} - {result.error if result is not None else "No reply"}'
                else:
                    values[name] = result.value
            results[request_id] = Tag(tag_data["user_tag"], values, tag_data["tag_info"]["data_type_name"], error)

    def _pack_multi_requests(self, sized_requests, version_checks=False):
        """
        Groups consecutive requests into multi-service packets, in call order, bounding both the request and
        the reply size. Fragmented requests, requests too big for a multi-service packet, and groups of one
        are sent alone.

        With ``version_checks`` (reads only) every multi-service packet starts with a tag table version check, so
        a group of one is a packet of two, and a request sent alone gets a standalone check before and after it.
        """
        if self._micro800:  # micro800 don't support multi-request packets
            return [request for request, _ in sized_requests]

        packets = []
        group = []
        empty_request = MULTISERVICE_READ_OVERHEAD
        empty_response = 8  # sequence, reply header, and service count
        if version_checks:
            empty_request += TagTableVersionRequestPacket.request_size
            empty_response += TagTableVersionRequestPacket.reply_size
        request_size, response_size = empty_request, empty_response

        def flush():
            if version_checks and group:
                packets.append(MultiServiceRequestPacket(
                    self._sequence, [TagTableVersionRequestPacket(self._sequence), *group]))
            elif len(group) == 1:
                packets.append(group[0])
            elif group:
                packets.append(MultiServiceRequestPacket(self._sequence, list(group)))
            group.clear()

        for request, reply_size in sized_requests:
            # an embedded service omits its 2-byte sequence and adds a 2-byte offset, so its size is unchanged
            message_size = len(request.build_message())
            if (isinstance(request, (ReadTagFragmentedRequestPacket, WriteTagFragmentedRequestPacket))
                    or empty_request + message_size > self.connection_size
                    or empty_response + reply_size > self.connection_size):
                flush()
                if version_checks and not (packets and isinstance(packets[-1], TagTableVersionRequestPacket)):
                    packets.append(TagTableVersionRequestPacket(self._sequence))
                packets.append(request)
                if version_checks:
                    packets.append(TagTableVersionRequestPacket(self._sequence))
                request_size, response_size = empty_request, empty_response
                continue

            if (request_size + message_size > self.connection_size
                    or response_size + reply_size > self.connection_size):
                flush()
                request_size, response_size = empty_request, empty_response
            group.append(request)
            request_size += message_size
            response_size += reply_size
        flush()
        return packets

    def _read_build_single_request(self, parsed_tag):
        """
        creates a single read_tag request packet
        """

        if parsed_tag.get("error") is None:
            request = ReadTagRequestPacket(
                self._sequence,
                parsed_tag["plc_tag"],
                parsed_tag["elements"],
                parsed_tag["tag_info"],
                parsed_tag["request_id"],
                self._cfg["use_instance_ids"],
            )
            request.request_path = parsed_tag.get("request_path")  # None encodes it from the tag

            if _read_reply_size(parsed_tag) > self.connection_size:
                request = ReadTagFragmentedRequestPacket.from_request(self._sequence, request)

            return request

        self.__log.error(f'Skipping making request, error: {parsed_tag["error"]}')
        return None

    @with_forward_open
    def write(
        self, *tags_values: Union[str, TagValueType, Tuple[str, TagValueType]]
    ) -> ReadWriteReturnType:
        """
        Write to tag(s). Automatically will split tags into multiple requests by tracking the request and
        response size.  Will use the multi-service request to group many tags into a single packet and also will automatically
        use fragmented write requests if the request size will not fit in a single packet.  Supports arrays (specify element
        count in using curly braces (array{10}).  Also supports full structure writing (when possible), value must be a
        sequence of values or a dict of {attribute: value} matching the exact structure of the destination tag.

        With instance IDs, the tag table version is checked right before the writes are sent (if it changed, the tag
        definitions are loaded again first, see :meth:`.check_tag_table`) and right after them.  If it changed
        during the writes, an ID may have named another tag: the definitions are loaded again and every result gets
        an error.  Writes are never retried.  While reloads are backed off (see :meth:`.read`), or if the version
        before the writes is not read or the reload fails, nothing is written and every result gets an error.

        :param tags_values: a tag name and value as two arguments, ``write('tag', value)``, or one or more (tag, value)
                            tuples, ``write(('tag1', 1), ('tag2', 2))``. To write a list of pairs, unpack it: ``write(*pairs)``.
        :return: a single or list of ``Tag`` objects.
        """

        if not tags_values:
            return []
        if len(tags_values) == 2 and isinstance(tags_values[0], str):
            tags_values = ((*tags_values,),)

        def build():
            loaded_at = self._tag_table_version  # before the parse, as in read()
            tags = (tag for (tag, value) in tags_values)
            parsed = self._parse_requested_tags(tags, "w")
            for i, (tag, value) in enumerate(tags_values):
                parsed[i]["value"] = value
            return loaded_at, parsed, self._write_build_requests(parsed)

        if self._backoff_error():
            return self._refused(tag for tag, _ in tags_values)
        loaded_at, parsed_requests, requests = build()
        checks = self._version_checks and bool(requests)  # never in a packet with a write, before and after them
        if checks:
            version = self._read_tag_table_version()
            if version is None:  # e.g. a download in progress (0x05) or the controller locked (0x10)
                self._back_off("the tag table version was not read")
                return self._refused(tag for tag, _ in tags_values)
            if version != loaded_at:
                if not self._refresh_tag_table():
                    return self._refused(tag for tag, _ in tags_values)
                loaded_at, parsed_requests, requests = build()
        write_results = self._send_requests(requests)
        version = self._read_tag_table_version() if checks else loaded_at
        changed = checks and self._tag_table_changed([version], loaded_at)
        if changed and version is None:
            self._back_off("the tag table version was not read after the write")
        elif changed:
            self._refresh_tag_table()

        # a mask can carry bits of several requests and a BOOL slice can span several masks
        for packet in requests:
            subrequests = packet.requests if isinstance(packet, MultiServiceRequestPacket) else [packet]
            for request in subrequests:
                if isinstance(request, ReadModifyWriteRequestPacket):
                    result = write_results.pop(request.request_id)
                    for req_id in set(request._request_ids):
                        previous = write_results.get(req_id)
                        if previous is None or previous.error is None:
                            write_results[req_id] = result

        self._merge_chunk_results(parsed_requests, write_results, "w")
        if changed:
            error = "Tag table changed on the controller during the write, it may have written another tag"
            write_results = {key: result._replace(error=error) for key, result in write_results.items()}
        results = []
        for i, (tag, value) in enumerate(tags_values):
            try:
                request_data = parsed_requests[i]
                if request_data.get("error"):
                    results.append(Tag(tag, None, None, request_data["error"]))
                    continue

                bit = parsed_requests[i].get("bit")
                result = write_results[i]
                data_type = request_data["tag_info"]["data_type_name"]
                bool_elements = request_data["bool_elements"]

                if bit is not None and bool_elements is None:
                    data_type = "BOOL"
                elif bool_elements:
                    data_type = f"BOOL[{bool_elements}]"
                elif request_data["elements"] > 1:
                    data_type = f'{data_type}[{request_data["elements"]}]'

                user_result = Tag(request_data["user_tag"], value, data_type, result.error)

                results.append(user_result)
            except Exception as err:
                self.__log.exception("Invalid tag request")
                results.append(Tag(tag, None, None, f"Invalid tag request - {err!r}"))

        if len(tags_values) > 1:
            return results
        else:
            return results[0]

    def _write_build_requests(self, parsed_tags):
        return self._write_build_multi_requests(self._split_large_requests(parsed_tags, "w"))

    def _write_build_multi_requests(self, parsed_tags):
        sized_requests = []
        bit_writes = {}
        bit_requests = []

        def flush_bit_writes():
            pending = list(bit_writes.values())
            sized_requests.extend((request, 6) for request in pending)
            bit_requests.extend(pending)
            bit_writes.clear()

        for request_id, tag_data in parsed_tags.items():
            if tag_data.get("error"):
                continue
            bit = tag_data.get("bit")
            bool_elements = tag_data["bool_elements"]
            is_bool_array = tag_data["tag_info"]["data_type_name"] == "DWORD"
            partial_array = is_bool_array and bool_elements and (
                (bit or 0) % 32 or bool_elements % 32
            )
            try:
                if (bit is not None and bool_elements is None) or partial_array:
                    values = [tag_data["value"]]
                    if partial_array:
                        values = tag_data["value"]
                        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
                            raise RequestError("BOOL array writes require a sequence of values")
                        if len(values) < bool_elements:
                            raise RequestError("Insufficient data for requested BOOL elements")
                        values = values[:bool_elements]
                    for value in values:  # masks only check truthiness, so a string like 'False' would set the bit
                        if value is None or isinstance(value, Sequence):
                            raise RequestError(f"Invalid value for BOOL - {value!r}")
                    for index, value in enumerate(values):
                        target = tag_data["plc_tag"]
                        target_bit = bit or 0
                        if is_bool_array:
                            word_tag, word_index = util.get_array_index(target)
                            word_offset, target_bit = divmod((bit or 0) % 32 + index, 32)
                            target = f"{word_tag}[{(word_index or 0) + word_offset}]"
                        if target not in bit_writes:
                            same_path = target == tag_data["plc_tag"]  # a BOOL array mask may be another word
                            bit_writes[target] = ReadModifyWriteRequestPacket(
                                self._sequence, target, tag_data["tag_info"],
                                -1 - len(bit_requests) - len(bit_writes), self._cfg["use_instance_ids"],
                                tag_data.get("request_path") if same_path else None,
                            )
                        bit_writes[target].set_bit(target_bit, value, request_id)
                else:
                    # A full write may overlap any pending masks, including array slices.
                    # Finish those masks before queuing it to preserve caller order.
                    flush_bit_writes()
                    request = self._write_build_single_request(tag_data)
                    if request is not None:
                        sized_requests.append((request, 6))  # sequence and reply header
            except RequestError as err:
                tag_data["error"] = str(err)

        flush_bit_writes()
        return self._pack_multi_requests(sized_requests)

    def _write_build_single_request(self, parsed_tag):
        try:  # bit writes are built as masks in _write_build_multi_requests
            parsed_tag["write_value"] = encode_value(parsed_tag)

            request = WriteTagRequestPacket(
                self._sequence,
                parsed_tag["plc_tag"],
                parsed_tag["elements"],
                parsed_tag["tag_info"],
                parsed_tag["request_id"],
                self._cfg["use_instance_ids"],
                parsed_tag["write_value"],
            )
            request.request_path = parsed_tag.get("request_path")  # None encodes it from the tag
            if len(request.build_message()) > self.connection_size:
                request = WriteTagFragmentedRequestPacket.from_request(self._sequence, request)

            return request
        except RequestError as err:
            parsed_tag["error"] = f"Invalid Tag Request - {err!r}"
            self.__log.exception(f'Failed to build request for {parsed_tag["plc_tag"]} - skipping')
            return None

    def get_tag_info(self, tag_name: str) -> Optional[dict]:
        """
        Returns the tag information for a tag collected during the tag list upload.  Can be a base tag or an attribute.

        With lazy_tags enabled, an uncached definition is resolved from the controller.
        Otherwise this method uses only definitions already in the tag cache.

        :param tag_name: name of tag to get info for
        :return: a dict of the tag's definition

        """
        _, base, attrs = _split_tag_name(tag_name)
        return self._get_tag_info(base, attrs)

    def _get_tag_info(self, base, attrs) -> Optional[dict]:
        def _recurse_attrs(attrs, data):
            cur, *remain = attrs
            info = data[_tag_key(data, cur)]
            return _recurse_attrs(remain, info["data_type"]["internal_tags"]) if remain else info

        try:
            name = _tag_key(self._tags, base)
            if name not in self._tags and self._lazy_tags:
                name = self._load_tag_definition(name)
            data = self._tags[name]
            if not len(attrs):
                return data
            else:
                return _recurse_attrs(attrs, data["data_type"]["internal_tags"])

        except KeyError as err:
            raise RequestError(f"Tag doesn't exist - {err.args[0]}")

        except (CommError, RequestError):
            raise

        except Exception as err:
            _msg = f"failed to get tag data for: {base}, {attrs}"
            self.__log.exception(_msg)
            raise RequestError(_msg) from err

    @with_forward_open
    def _load_tag_definition(self, name):
        """Read each scope's symbol list once and resolve only requested templates, returns the tag's name."""
        with self._lock:  # one lazy load at a time, they share the symbol lists and template cache
            program = None
            symbol_name = name
            if name.startswith("Program:"):
                scope, symbol_name = name.split(".", 1)
                program = scope[len("Program:"):]
            if program not in self._lazy_tag_lists:
                raw_tags = self._get_instance_attribute_list_service(program)
                self._lazy_tag_lists[program] = {tag["tag_name"]: tag for tag in raw_tags}
            symbol_name = _tag_key(self._lazy_tag_lists[program], symbol_name)
            raw_tag = self._lazy_tag_lists[program].get(symbol_name)
            if (raw_tag is None or symbol_name.startswith("__")
                    or raw_tag["symbol_type"] & 0x1000
                    or not symbol_name.startswith(self._init_args["tag_namespace_filter"])):
                raise RequestError(f"Tag doesn't exist - {name}")
            name = f"Program:{program}.{symbol_name}" if program else symbol_name
            self._tags[name] = self._create_tag(name, raw_tag)
            return name

    def _parse_requested_tags(self, tags, rw="r"):

        requests = {}
        for i, tag in enumerate(tags):
            parsed = {"request_id": i, "request_tag": tag}
            try:
                parsed_request = self._parse_tag_request(tag, rw)
                if parsed_request is not None:
                    parsed.update(parsed_request)

            except RequestError as err:
                self.__log.exception(f"Failed to parse tag request: {tag}")
                parsed["error"] = str(err)

            finally:
                requests[i] = parsed
        return requests

    def _parse_tag_request(self, tag: str, rw="r") -> dict:
        """
        rw: read/write - because of how bool arrays always read from 0, but writing doesn't

        Successful parses are memoized for the current tag list, rebinding self._tags or a full memo starts a new one.
        Returns a copy, callers may change it.
        """
        if not isinstance(tag, str):  # e.g. read([...]), unhashable, the parse reports it per tag
            return self._parse_new_tag_request(tag, rw)
        if self._parse_memo[0] is not self._tags:
            self._parse_memo = (self._tags, {})
        memo = self._parse_memo[1]
        key = (tag, rw, self._cfg["use_instance_ids"])
        if key not in memo:
            if len(memo) >= _PARSE_MEMO_SIZE:  # e.g. a moving index, names that never repeat must not pile up
                memo.clear()
            memo[key] = self._parse_new_tag_request(tag, rw)  # a failure raises, it is not memoized
        return dict(memo[key])

    def _parse_new_tag_request(self, tag: str, rw="r") -> dict:
        try:
            if tag.endswith("}") and "{" in tag:
                tag, _tmp = tag.split("{")
                elements = int(_tmp[:-1])
                implicit_element = False
            else:
                elements = 1
                implicit_element = True

            if elements < 1:
                raise RequestError("Element count must be positive")
            request_tag = tag
            tag, base, attrs = _split_tag_name(tag)
            bit = None
            bool_elements = None

            if len(attrs) and attrs[-1].isdigit():
                bit = int(attrs.pop(-1))
                tag = base if not len(attrs) else f"{base}.{'.'.join(attrs)}"

            tag_info = self._get_tag_info(base, attrs)
            if self._lazy_tags:  # the first use of an AOI type probes it
                self._probe_aois([self._get_tag_info(base, [])])
            for i in range(len(attrs)):  # a local tag of an AOI, or in one, is not requested
                parent = self._get_tag_info(base, attrs[:i])
                aoi = _aoi_probe(parent)
                if aoi and _tag_key(parent["data_type"]["internal_tags"], attrs[i]) in aoi["refused"]:
                    raise RequestError(_AOI_LOCAL)
            if attrs:  # a member definition, the request addresses its base tag by the base's ID
                tag_info = {**tag_info, "base_instance_id": self._get_tag_info(base, []).get("instance_id")}

            if tag_info["data_type"] == "DWORD":
                _tag, idx = util.get_array_index(tag)
                if idx is not None:
                    tag = f"{_tag}[{idx // 32}]"
                bit = (idx or 0) % 32 if rw == "r" else (idx or 0)
                bool_elements = None if implicit_element or elements == 1 else elements
                total_size = (bit or 0) % 32 + elements
                elements = (total_size // 32) + (1 if total_size % 32 else 0)

            if bit is not None and tag_info["data_type"] != "DWORD":
                if tag_info["data_type_name"] not in {"SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "ULINT"}:
                    raise RequestError(f"Bit access is not supported on {tag_info['data_type_name']}")
                if bit >= DataTypes.get(tag_info["data_type_name"]).size * 8:
                    raise RequestError("Bit index is outside the tag's data type")
            path = tag_request_path(tag, tag_info, self._cfg["use_instance_ids"])  # a bad index fails here, per tag

            return {
                "user_tag": request_tag,  # tag name from user, without element request
                "plc_tag": tag,  # parsed tag name, the name of the tag in the plc the request will be using
                "bit": bit,
                "elements": elements,
                "tag_info": tag_info,
                "bool_elements": bool_elements,
                "request_path": path,  # encoded once, the packets use it as is
            }
        except (CommError, RequestError):
            raise
        except Exception as err:
            raise RequestError(f"Failed to parse tag request {tag!r}: {err}") from err

    def _split_large_requests(self, parsed_tags, rw):
        """Split one-dimensional array operations at the UINT service-count limit."""
        expanded = {}
        for request_id, tag_data in parsed_tags.items():
            if tag_data.get("error") or tag_data["elements"] <= 65535:
                expanded[request_id] = tag_data
                continue
            try:
                info = tag_data["tag_info"]
                if (not issubclass(info["type_class"], ArrayType)
                        or info.get("dim", 1) > 1 or info["data_type_name"] == "DWORD"):
                    raise RequestError("Large element counts require a one-dimensional non-BOOL array")
                array_tag, start = util.get_array_index(tag_data["plc_tag"])
                start = start or 0
                count = tag_data["elements"]
                values = tag_data.get("value")
                if rw == "w" and not isinstance(values, bytes):
                    if not isinstance(values, Sequence) or isinstance(values, str) or len(values) < count:
                        raise RequestError("Insufficient data for requested array elements")
                chunks = []
                element_size = _tag_return_size({"tag_info": info, "elements": 1})
                for offset in range(0, count, 65535):
                    chunk_count = min(65535, count - offset)
                    chunk_id = (request_id, len(chunks))
                    chunk = dict(tag_data, request_id=chunk_id, request_path=None,  # encoded for the chunk's index
                                 plc_tag=f"{array_tag}[{start + offset}]", elements=chunk_count)
                    if rw == "w":
                        begin, end = offset, offset + chunk_count
                        if isinstance(values, bytes):
                            begin, end = begin * element_size, end * element_size
                            if len(values) < count * element_size:
                                raise RequestError("Insufficient bytes for requested array elements")
                        chunk["value"] = values[begin:end]
                    chunks.append(chunk)
                    expanded[chunk_id] = chunk
                tag_data["chunk_requests"] = chunks
            except (RequestError, ValueError) as err:
                tag_data["error"] = str(err)
        return expanded

    def _merge_chunk_results(self, parsed_tags, results, rw):
        for request_id, tag_data in parsed_tags.items():
            chunks = tag_data.get("chunk_requests")
            if not chunks:
                continue
            values = []
            error = None
            for chunk in chunks:
                result = results.pop(chunk["request_id"], None)
                if chunk.get("error") or result is None or result.error:
                    error = error or chunk.get("error") or (
                        result.error if result is not None else "Missing array chunk response"
                    )
                elif rw == "r":
                    values.extend(result.value if isinstance(result.value, list) else [result.value])
            results[request_id] = Tag(
                tag_data["user_tag"], values if rw == "r" and error is None else tag_data.get("value"),
                f'{tag_data["tag_info"]["data_type_name"]}[{tag_data["elements"]}]', error,
            )

    def _send_requests(self, requests):
        results = {}

        for request in requests:
            multi = request.type_ == "multi"
            # a version check is only answered by its own reply, a packet that failed as a whole read nothing
            subrequests = [req for req in (request.requests if multi else [request])
                           if not isinstance(req, TagTableVersionRequestPacket)]
            try:
                response = self.send(request)
            except (RequestError, ResponseError) as err:
                self.__log.exception("Error sending request")
                for req in subrequests:
                    results[req.request_id] = Tag(req.tag, None, None, str(err))
                continue
            for resp in response.responses if multi else [response]:
                req = resp.request
                if type(req) is ReadTagRequestPacket and resp.service_status == INSUFFICIENT_PACKETS:
                    # partial reply, read it again as a fragmented read, checked after it if the packet was (a read
                    # sent alone is already followed by a check)
                    fragmented = ReadTagFragmentedRequestPacket.from_request(self._sequence, req)
                    checked = multi and isinstance(request.requests[0], TagTableVersionRequestPacket)
                    after = [TagTableVersionRequestPacket(self._sequence)] if checked else []
                    results.update(self._send_requests([fragmented, *after]))
                elif resp:
                    results[req.request_id] = Tag(req.tag, resp.value, resp.data_type, None)
                else:
                    results[req.request_id] = Tag(req.tag, None, None, resp.error)
            for req in subrequests:
                results.setdefault(req.request_id, Tag(req.tag, None, None, response.error or "No reply"))
        return results

    def send(self, request: RequestPacket):
        if isinstance(request, ReadTagFragmentedRequestPacket):
            return self._send_read_fragmented(request)
        elif isinstance(request, WriteTagFragmentedRequestPacket):
            return self._send_write_fragmented(request)
        else:
            return super().send(request)

    def _send_read_fragmented(
        self, request: ReadTagFragmentedRequestPacket
    ) -> ReadTagFragmentedResponsePacket:
        offset = request.offset
        expected_size = _tag_return_size({"tag_info": request.tag_info, "elements": request.elements})
        responses = []
        while offset is not None:
            response: ReadTagFragmentedResponsePacket = super().send(request)
            if response and responses and response._data_type != responses[0]._data_type:
                response._error = "Data type changed during fragmented read"
            if not response:
                self.__log.error(f"Fragment failed with error: {response.error}")
                return response  # keeps the PLC's error
            responses.append(response)
            if response.service_status == INSUFFICIENT_PACKETS:
                offset += len(response.value_bytes)
                if not response.value_bytes or offset >= expected_size:
                    response._error = "Fragmented read made no progress or exceeded the expected size"
                    return response
                request = ReadTagFragmentedRequestPacket.from_request(
                    self._sequence, request, offset
                )
            else:
                offset = None

        final_response = responses[-1]
        final_response.value_bytes = b"".join(resp.value_bytes for resp in responses)
        final_response.parse_value()

        self.__log.debug(f"Reassembled Response: {final_response!r}")
        return final_response

    def _send_write_fragmented(
        self, request: WriteTagFragmentedRequestPacket
    ) -> WriteTagFragmentedResponsePacket:
        request.build_message()
        segment_size = self.connection_size - (len(request.message) - len(request.value))
        if segment_size <= 0:
            failed_response = WriteTagFragmentedResponsePacket(request, None)
            failed_response._error = "Fragmented write header exceeds connection_size"
            return failed_response
        segments = (
            request.value[i : i + segment_size]
            for i in range(0, len(request.value), segment_size)
        )

        offset = 0
        for segment in segments:
            _request = WriteTagFragmentedRequestPacket.from_request(
                self._sequence, request, offset, segment
            )
            _response = super().send(_request)
            if not _response:
                return _response  # stop at the first failed segment, keeps the PLC's error
            offset += len(segment)

        self.__log.debug(f"Final Response: {_response!r}")
        return _response


def _parse_structure_makeup_attributes(response):
    """
    extract the tags list from the message received
    """
    structure = {}

    try:
        _struct = response.value
        structure["object_definition_size"] = _struct["object_definition_size"]["size"]
        structure["structure_size"] = _struct["structure_size"]["size"]
        structure["member_count"] = _struct["member_count"]["count"]
        structure["structure_handle"] = _struct["structure_handle"]["handle"]

        return structure

    except Exception as err:
        raise ResponseError("failed to parse structure attributes") from err


def _is_aoi(data_type) -> bool:
    """an Add-On Instruction's data type: the template has no marker for it, but every AOI has EnableIn and EnableOut"""
    return {"EnableIn", "EnableOut"} <= data_type["internal_tags"].keys()


def _aoi_probe(tag_info):
    """the AOI probe of a tag or member's data type (_probe_aois), None if not an AOI or not probed"""
    return tag_info["data_type"].get("aoi") if tag_info["tag_type"] == "struct" else None


def _nested_template_ids(data, template):
    """the instance ids of the templates of a raw template's struct members, as _parse_template_data_member_info"""
    ids = set()
    for i in range(template["member_count"]):
        typ = UINT.decode(data[i * TEMPLATE_MEMBER_INFO_LEN + 2:i * TEMPLATE_MEMBER_INFO_LEN + 4])
        if DataTypes.get(typ) is None and not DataTypes.get_type(typ & 0b0000_1111_1111_1111):
            ids.add(typ & 0b0000_1111_1111_1111)
    return ids


def encode_value(parsed_tag: dict) -> bytes:
    if isinstance(parsed_tag["value"], bytes):
        return parsed_tag["value"]

    try:
        value = parsed_tag["value"]
        elements = parsed_tag["elements"]
        _type: Type[DataType] = parsed_tag["tag_info"]["type_class"]

        value_elements = parsed_tag["bool_elements"] or elements
        if issubclass(_type, ArrayType):

            if value_elements > 1:
                if len(value) < value_elements:
                    raise RequestError(
                        f"Insufficient data for requested elements, expected {value_elements} and got {len(value)}"
                    )
                if len(value) > value_elements:
                    value = value[:value_elements]
            elif not isinstance(value, Sequence) or isinstance(value, str):
                value = [
                    value,
                ]

            return _type.encode(value, value_elements)

        return _type.encode(value)

    except Exception as err:
        raise RequestError(f"Unable to create a writable value - {err}") from err


def _tag_return_size(tag_data):
    tag_info = tag_data["tag_info"]
    if tag_info["tag_type"] == "atomic":
        size = DataTypes[tag_info["data_type"]].size
    else:
        size = tag_info["data_type"]["template"]["structure_size"]

    size = size * tag_data["elements"]

    return size


def _read_reply_size(tag_data):
    # sequence, reply header, type code (+2 struct handle)
    return _tag_return_size(tag_data) + (10 if tag_data["tag_info"]["tag_type"] == "struct" else 8)


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
