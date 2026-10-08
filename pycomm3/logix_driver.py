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
import logging
import operator
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
    tag_request_path,
)
from .tag import Tag
from .logix_auth import LogixMetadataCredentials
from .logix_metadata import (
    build_description_request,
    decode_metadata_page,
    decode_description_response,
)

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

        .. tip::

            Initialization of tags is required for the :meth:`.read` and :meth:`.write` to work.  This is because
            they require information about the data type and structure of the tags inside the controller.  If opening
            multiple connections to the same controller, you may disable tag initialization in all but the first connection
            and set ``plc2._tags = plc1.tags`` to prevent needing to upload the tag definitions multiple times.
            Tag lists are controller-specific: on v21+ tags are addressed by instance_id, which differs between
            controllers even with identical programs, so only share a tag list between connections to the same controller.

        """

        super().__init__(path, *args, **kwargs)
        self._cache = {"id:struct": {}, "id:udt": {}}
        self._lazy_tags = lazy_tags
        self._lazy_tag_lists = {}
        self._data_types = {}
        self._tags = {}
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
                        self._tags, self._data_types = {}, {}  # rebind: the old dict may be shared
                        self._lazy_tag_lists.clear()
                        for cache in self._cache.values():
                            cache.clear()
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
        self._info = self.get_plc_info()

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

        if init_tags:
            self.get_tag_list(tag_namespace_filter=tag_namespace_filter, program="*" if init_program_tags else None)

        self.__log.info("Initialization complete.")

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
        Read-only property for access to all data type definitions uploaded from the controller.
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

        :return: a list containing dicts for each tag definition collected
        """

        if program and program.startswith("Program:"):
            program = program[len("Program:"):]

        with self._lock:  # a lazy load in another thread must not see the template cache cleared
            for values in self._cache.values():
                values.clear()
            for key in ("programs", "tasks", "modules"):
                if program in {"*", None} or key not in self._info:
                    self._info[key] = {}

            self.__log.info("Starting tag list upload...")
            if program == "*":
                tags = self._get_tag_list(tag_namespace_filter=tag_namespace_filter)
                for prog in self._info["programs"]:
                    tags += self._get_tag_list(prog, tag_namespace_filter=tag_namespace_filter)
            else:
                tags = self._get_tag_list(program, tag_namespace_filter=tag_namespace_filter)

            if cache:
                self._tags = {tag["tag_name"]: tag for tag in tags}
                self._lazy_tag_lists.clear()

        self.__log.info(f"Completed tag list upload. Uploaded {len(self._tags)} tags.")
        return tags

    def _get_tag_list(self, program=None, tag_namespace_filter=''):
        self.__log.info(f'Beginning upload of {program or "controller"} tags...')
        all_tags = self._get_instance_attribute_list_service(program)
        self.__log.info(f'Completed upload of {program or "controller"} tags')
        return self._isolate_user_tags(all_tags, program, tag_namespace_filter)

    def _get_instance_attribute_list_service(self, program=None):
        """Step 1: Finding user-created controller scope tags in a Logix5000 controller

        This service returns instance IDs for each created instance of the symbol class, along with a list
        of the attribute data associated with the requested attribute
        """
        try:
            last_instance = 0
            tag_list = []
            while last_instance != -1:
                # Creating the Message Request Packet
                self.__log.debug(f"Getting tags starting with instance {last_instance}")
                _start_instance = last_instance
                _num_tags_start = len(tag_list)
                segments = []
                if program:
                    if not program.startswith("Program:"):
                        program = f"Program:{program}"
                    segments = [
                        DataSegment(program),
                    ]

                segments += [
                    LogicalSegment(ClassCode.symbol_object, "class_id"),
                    LogicalSegment(last_instance, "instance_id"),
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
        try:
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

                user_tags.append(self._create_tag(name, tag))

            self.__log.debug(f'Finished isolating tags for {program or "controller"}')
            return user_tags
        except CommError:
            raise
        except Exception as err:
            raise ResponseError("failed isolating user tags") from err

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
            attrs = (
                b"\x04\x00",  # Number of attributes
                b"\x04\x00",  # Template Object Definition Size UDINT
                b"\x05\x00",  # Template Structure Size UDINT
                b"\x02\x00",  # Template Member Count UINT
                b"\x01\x00",  # Structure Handle We can use this to read and write UINT
            )

            response = self.generic_message(
                service=Services.get_attribute_list,
                class_code=ClassCode.template_object,
                instance=instance_id,
                connected=True,
                request_data=b"".join(attrs),
                data_type=StructTemplateAttributes,
                name=f"_get_structure_makeup(instance_id={instance_id!r})",
            )
            if not response:
                raise ResponseError("send_unit_data returned not valid data", response.error)
            _struct = _parse_structure_makeup_attributes(response)
            self._cache["id:struct"][instance_id] = _struct

        return self._cache["id:struct"][instance_id]

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
                _data = self._read_template(instance_id, template["object_definition_size"])
                data_type = self._parse_template_data(_data, template, symbol_type)
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
        """Experimentally read a controller base tag's extended Description.

        Validated against capture and authenticated live reads on GuardLogix
        5580 v37.13. An unauthenticated session returns Permission denied. This
        method does not authenticate; call authenticate_metadata first with
        caller-provided credentials, or use the optional native Linx example.
        Tag definitions must already be uploaded. Program tags, members, array
        elements and other extended properties are not supported by this method.

        :param tag_name: controller-scoped base tag name
        :param language: captured language selector (0x007F returned the test text)
        :param encoding: text encoding; capture evidence currently covers ASCII
        :return: a STRING Tag with the description or an explicit error
        """
        result_name = tag_name + ".@Description"
        try:
            if not tag_name or any(char in tag_name for char in ".[]{}"):
                raise RequestError("Specify a controller-scoped base tag")
            if self._micro800:
                raise RequestError("Extended descriptions require a Logix controller")
            info = self.get_tag_info(tag_name)
            instance_id = info["instance_id"]
            pages = []
            offset = 0
            for _ in range(1024):
                request = SendUnitDataRequestPacket(self._sequence)
                request.add(build_description_request(instance_id, language, offset))
                response = self.send(request)
                if not response:
                    return Tag(result_name, None, "STRING", response.error)
                page = decode_metadata_page(response.data)
                if page["first"] != (offset == 0) or page["offset"] != offset:
                    raise ResponseError("Out-of-order extended description page")
                pages.append(response.data)
                if page["last"]:
                    record = decode_description_response(pages, encoding)
                    if record is None:
                        return Tag(result_name, None, "STRING",
                                   "No description returned for language 0x{:04x}".format(language))
                    if record["instance_id"] != instance_id or record["language"] != language:
                        raise ResponseError("Extended description reply targets a different tag/language")
                    return Tag(result_name, record["value"], "STRING", None)
                if not page["data"]:
                    raise ResponseError("Extended description continuation made no progress")
                offset += len(page["data"])
            raise ResponseError("Extended description exceeded 1024 pages")
        except Exception as error:
            return Tag(result_name, None, "STRING", str(error))

    @with_forward_open
    def read(self, *tags: str) -> ReadWriteReturnType:
        """
        Read the value of tag(s).  Automatically will split tags into multiple requests by tracking the request and
        response size.  Will use the multi-service request to group many tags into a single packet and also will automatically
        use fragmented read requests if the response size will not fit in a single packet.  Supports arrays (specify element
        count in using curly braces (array{10}).  Also supports full structure reading (when possible), return value
        will be a dict of {attribute name: value}.

        :param tags: one or many tags to read
        :return: a single or list of ``Tag`` objects
        """

        if not tags:
            return []
        parsed_requests = self._parse_requested_tags(tags, "r")
        requests = self._read_build_requests(parsed_requests)
        read_results = self._send_requests(requests)
        self._merge_chunk_results(parsed_requests, read_results, "r")

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
        for tag_data in self._split_large_requests(parsed_tags, "r").values():
            request = self._read_build_single_request(tag_data)
            if request is not None:
                sized_requests.append((request, _read_reply_size(tag_data)))
        # reads are matched by request_id, so batch the small reads ahead of the fragmented ones
        sized_requests.sort(key=lambda item: isinstance(item[0], ReadTagFragmentedRequestPacket))
        return self._pack_multi_requests(sized_requests)

    def _pack_multi_requests(self, sized_requests):
        """
        Groups consecutive requests into multi-service packets, in call order, bounding both the request and
        the reply size. Fragmented requests, requests too big for a multi-service packet, and groups of one
        are sent alone.
        """
        if self._micro800:  # micro800 don't support multi-request packets
            return [request for request, _ in sized_requests]

        packets = []
        group = []
        request_size = MULTISERVICE_READ_OVERHEAD
        response_size = 8  # sequence, reply header, and service count

        def flush():
            if len(group) == 1:
                packets.append(group[0])
            elif group:
                packets.append(MultiServiceRequestPacket(self._sequence, list(group)))
            group.clear()

        for request, reply_size in sized_requests:
            # an embedded service omits its 2-byte sequence and adds a 2-byte offset, so its size is unchanged
            message_size = len(request.build_message())
            if (isinstance(request, (ReadTagFragmentedRequestPacket, WriteTagFragmentedRequestPacket))
                    or MULTISERVICE_READ_OVERHEAD + message_size > self.connection_size
                    or 8 + reply_size > self.connection_size):
                flush()
                packets.append(request)
                request_size, response_size = MULTISERVICE_READ_OVERHEAD, 8
                continue

            if (request_size + message_size > self.connection_size
                    or response_size + reply_size > self.connection_size):
                flush()
                request_size, response_size = MULTISERVICE_READ_OVERHEAD, 8
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

        :param tags_values: a tag name and value as two arguments, ``write('tag', value)``, or one or more (tag, value)
                            tuples, ``write(('tag1', 1), ('tag2', 2))``. To write a list of pairs, unpack it: ``write(*pairs)``.
        :return: a single or list of ``Tag`` objects.
        """

        if not tags_values:
            return []
        if len(tags_values) == 2 and isinstance(tags_values[0], str):
            tags_values = ((*tags_values,),)

        tags = (tag for (tag, value) in tags_values)
        parsed_requests = self._parse_requested_tags(tags, "w")

        for i, (tag, value) in enumerate(tags_values):
            parsed_requests[i]["value"] = value

        requests = self._write_build_requests(parsed_requests)
        write_results = self._send_requests(requests)

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
                            bit_writes[target] = ReadModifyWriteRequestPacket(
                                self._sequence, target, tag_data["tag_info"],
                                -1 - len(bit_requests) - len(bit_writes), self._cfg["use_instance_ids"],
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
        """
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
            tag_request_path(tag, tag_info, self._cfg["use_instance_ids"])  # a bad array index fails here, per tag

            return {
                "user_tag": request_tag,  # tag name from user, without element request
                "plc_tag": tag,  # parsed tag name, the name of the tag in the plc the request will be using
                "bit": bit,
                "elements": elements,
                "tag_info": tag_info,
                "bool_elements": bool_elements,
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
                    chunk = dict(tag_data, request_id=chunk_id,
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
            subrequests = request.requests if multi else [request]
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
                    # partial reply, read it again as a fragmented read
                    fragmented = ReadTagFragmentedRequestPacket.from_request(self._sequence, req)
                    results.update(self._send_requests([fragmented]))
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
