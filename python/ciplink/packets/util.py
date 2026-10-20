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

import string

from io import BytesIO
from typing import Union, Optional

from ..cip import (
    ClassCode,
    ConnectionManagerServices,
    SERVICE_STATUS,
    EXTEND_CODES,
    StringDataType,
    ArrayType,
    UDINT,
    BitArrayType,
    LogicalSegment,
    PADDED_EPATH,
    DataSegment,
    UINT,
    USINT,
)
from ..const import PRIORITY, TIMEOUT_TICKS, STRUCTURE_READ_REPLY, SUCCESS
from ..tag import ErrorKind, TagError

__all__ = [
    "wrap_unconnected_send",
    "request_path",
    "tag_request_path",
    "get_service_status",
    "get_extended_status",
    "get_extended_status_code",
    "status_kind",
    "response_error",
    "parse_read_reply",
    "dword_to_bool_array",
    "print_bytes_msg",
    "PacketLazyFormatter",
]


def wrap_unconnected_send(message: bytes, route_path: bytes) -> bytes:
    rp = request_path(class_code=ClassCode.connection_manager, instance=b"\x01")
    msg_len = len(message)
    return b"".join(
        [
            ConnectionManagerServices.unconnected_send,
            rp,
            PRIORITY,
            TIMEOUT_TICKS,
            UINT.encode(msg_len),
            message,
            b"\x00" if msg_len % 2 else b"",
            route_path,
        ]
    )


def request_path(
    class_code: Union[int, bytes, list, tuple],
    instance: Union[int, bytes, list, tuple],
    attribute: Union[int, bytes] = b"",
) -> bytes:
    segments = []
    if isinstance(class_code, (list, tuple)):
        if isinstance(instance, (list, tuple)):
            for c, i in zip(class_code, instance):
                segments.append(LogicalSegment(c, "class_id"))
                segments.append(LogicalSegment(i, "instance_id"))
        else:
            for c in class_code:
                segments.append(LogicalSegment(c, "class_id"))
                segments.append(LogicalSegment(instance, "instance_id"))
    elif isinstance(instance, (list, tuple)):
        for i in instance:
            segments.append(LogicalSegment(class_code, "class_id"))
            segments.append(LogicalSegment(i, "instance_id"))
    else:
        segments = [
            LogicalSegment(class_code, "class_id"),
            LogicalSegment(instance, "instance_id"),
        ]

    if attribute:
        segments.append(LogicalSegment(attribute, "attribute_id"))

    return PADDED_EPATH.encode(segments, length=True)


def tag_request_path(tag, tag_info, use_instance_ids):
    """
    Returns the tag request path encoded as a padded EPATH; raises ValueError for a non-integer index.

    With use_instance_ids the base tag is addressed by its symbol instance ID: ``base_instance_id`` when tag_info
    is a member definition, else ``instance_id``.  A program tag's ID is relative to its program, so the program
    is named first.  Without an ID the base tag is addressed by name, 0 counts as none (it is never a symbol).
    """

    base, *attrs = tag.split(".")
    segments = []
    if base.startswith("Program:") and attrs:
        segments.append(DataSegment(base))
        base, *attrs = attrs
    base_tag, index = _find_tag_index(base)
    instance_id = tag_info.get("base_instance_id", tag_info.get("instance_id"))
    if use_instance_ids and instance_id:
        segments += [
            LogicalSegment(ClassCode.symbol_object, "class_id"),
            LogicalSegment(instance_id, "instance_id"),
        ]
    else:
        segments.append(DataSegment(base_tag))

    segments += [LogicalSegment(int(idx), "member_id") for idx in index]

    for attr in attrs:
        attr, index = _find_tag_index(attr)

        attr_segments = [DataSegment(attr)]
        attr_segments += [LogicalSegment(int(idx), "member_id") for idx in index]

        segments += attr_segments

    return PADDED_EPATH.encode(segments, length=True)


def _find_tag_index(tag):
    if "[" in tag:  # Check if is an array tag
        t = tag[: len(tag) - 1]  # Remove the last square bracket
        inside_value = t[t.find("[") + 1 :]  # Isolate the value inside bracket
        index = inside_value.split(
            ","
        )  # Now split the inside value in case part of multidimensional array
        tag = t[: t.find("[")]  # Get only the tag part
    else:
        index = []
    return tag, index


def get_service_status(status) -> str:
    return SERVICE_STATUS.get(status, f"Unknown Error ({status:0>2x})")


def get_extended_status(msg, start) -> Optional[str]:
    stream = BytesIO(msg[start:])
    status = USINT.decode(stream)
    # send_rr_data
    # 42 General Status
    # 43 Size of additional status
    # 44..n additional status

    # send_unit_data
    # 48 General Status
    # 49 Size of additional status
    # 50..n additional status
    if not USINT.decode(stream):  # additional status size, in 16-bit words
        return None
    ext = UINT.decode(stream)  # first word is the extended code; further words are object specific
    return f"{EXTEND_CODES.get(status, {}).get(ext, 'Extended status')}  ({status:0>2x}, {ext:0>2x})"


def get_extended_status_code(msg, start) -> Optional[int]:
    """the first word of the extended status of the general status at msg[start], None if there is none"""
    try:
        return UINT.decode(msg[start + 2:start + 4]) if msg[start + 1] else None
    except Exception:
        return None


_STATUS_KINDS = {
    **dict.fromkeys((0x04, 0x05, 0x16), ErrorKind.NOT_FOUND),
    0x0F: ErrorKind.ACCESS,
    **dict.fromkeys((0x0C, 0x10, 0x02), ErrorKind.REFUSED),
    **dict.fromkeys((0x03, 0x09, 0x13, 0x15, 0x20), ErrorKind.BAD_VALUE),
    **dict.fromkeys((0x08, 0x26), ErrorKind.BAD_REQUEST),
}
_EXTENDED_KINDS = {  # of general status 0xFF
    **dict.fromkeys((0x2104, 0x2105, 0x210B), ErrorKind.NOT_FOUND),
    **dict.fromkeys((0x2107, 0x2109, 0x7), ErrorKind.BAD_VALUE),
    **dict.fromkeys((0x2100, 0x2101, 0x2102, 0x2103), ErrorKind.ACCESS),
    **dict.fromkeys((0x2108, 0x2106), ErrorKind.REFUSED),
    0x210A: ErrorKind.BAD_REQUEST,
}


def status_kind(status: int, ext: Optional[int] = None) -> ErrorKind:
    """the ErrorKind of a CIP general status and its first extended status word"""
    if status == 0xFF:
        return _EXTENDED_KINDS.get(ext, ErrorKind.DEVICE)
    return _STATUS_KINDS.get(status, ErrorKind.DEVICE)


def response_error(response, message: Optional[str] = None) -> TagError:
    """the error of a failed reply as a TagError, COMM if the reply was lost or could not be parsed"""
    message = response.error if message is None else message
    status = response.service_status
    if response._error is not None or response.command_status != SUCCESS or status is None:
        return TagError(message, ErrorKind.COMM)
    # SendRRData (0x6F) replies have the status at 42, SendUnitData and padded multi-service replies at 48
    ext = get_extended_status_code(response.raw, 42 if response.command == b"\x6f\x00" else 48)
    return TagError(message, status_kind(status, ext), status, ext)


def parse_read_reply(data, data_type, elements):
    dt_name = data_type["data_type_name"]
    _type = data_type["type_class"]
    is_struct = data[:2] == STRUCTURE_READ_REPLY
    stream = BytesIO(data[4:] if is_struct else data[2:])
    if issubclass(_type, ArrayType):
        _value = _type.decode(stream, length=elements)

        if elements == 1 and not issubclass(_type.element_type, BitArrayType):
            _value = _value[0]
    else:
        _value = _type.decode(stream)
        if is_struct and not issubclass(_type, StringDataType):
            _value = {
                attr: _value[attr] for attr in data_type["data_type"]["attributes"]
            }

    if dt_name == "DWORD":
        dt_name = f"BOOL[{elements * 32}]"

    elif elements > 1:
        dt_name = f"{dt_name}[{elements}]"

    return _value, dt_name


def dword_to_bool_array(dword: Union[bytes, int]):
    dword = UDINT.decode(dword) if isinstance(dword, bytes) else dword
    bits = [x == "1" for x in bin(dword)[2:]]
    bools = [False for _ in range(32 - len(bits))] + bits
    bools.reverse()
    return bools


def _to_hex(bites):
    return " ".join((f"{b:0>2x}" for b in bites))


PRINTABLE = set(
    b"".join(
        bytes(x, "ascii")
        for x in (string.ascii_letters, string.digits, string.punctuation, " ")
    )
)


def _to_ascii(bites):
    return "".join(f"{chr(b)}" if b in PRINTABLE else "•" for b in bites)


def print_bytes_msg(msg):
    line_len = 16
    lines = (msg[i : i + line_len] for i in range(0, len(msg), line_len))

    formatted_lines = (
        f"({i * line_len:0>4x}) {_to_hex(line): <48}    {_to_ascii(line)}"
        for i, line in enumerate(lines)
    )

    return "\n".join(formatted_lines)


class PacketLazyFormatter:
    def __init__(self, data):
        self._data = data

    def __str__(self):
        return print_bytes_msg(self._data)

    def __len__(self):
        return len(self._data)
