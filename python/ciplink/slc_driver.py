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
    "SLCDriver",
]

import logging
import re
from typing import List, Tuple, Optional, Union

from . import _core
from .cip_driver import CIPDriver, with_forward_open
from .cip import (
    PCCC_CT,
    PCCC_DATA_TYPE,
    PCCC_DATA_SIZE,
    PCCC_ERROR_CODE,
    USINT,
    UINT,
    PCCCDataTypes,
)
from .const import (
    SUCCESS,
    SLC_CMD_CODE,
    SLC_FNC_READ,
    SLC_FNC_WRITE,
    SLC_REPLY_START,
    PCCC_PATH,
)
from .exceptions import ResponseError, RequestError
from .tag import Tag
from .packets import SendUnitDataRequestPacket

AtomicValueType = Union[int, float, bool]
TagValueType = Union[AtomicValueType, List[Union[AtomicValueType, str]]]
ReadWriteReturnType = Union[Tag, List[Tag]]

IO_RE = re.compile(
    r"(?P<file_type>[IO])(?P<file_number>\d{1,3})?"
    r"(:)(?P<element_number>\d{1,3})"
    r"((\.)(?P<position_number>\d{1,3}))?"
    r"(/(?P<sub_element>\d{1,2}))?"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

CT_RE = re.compile(
    r"(?P<file_type>[CT])(?P<file_number>\d{1,3})"
    r"(:)(?P<element_number>\d{1,3})"
    r"(.)(?P<sub_element>ACC|PRE|EN|DN|TT|CU|CD|DN|OV|UN|UA)",
    flags=re.IGNORECASE,
)

LFBN_RE = re.compile(
    r"(?P<file_type>[LFBN])(?P<file_number>\d{1,3})"
    r"(:)(?P<element_number>\d{1,3})"
    r"(/(?P<sub_element>\d{1,2}))?"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

S_RE = re.compile(
    r"(?P<file_type>S)"
    r"(:)(?P<element_number>\d{1,3})"
    r"(/(?P<sub_element>\d{1,2}))?"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

A_RE = re.compile(
    r"(?P<file_type>A)(?P<file_number>\d{1,3})"
    r"(:)(?P<element_number>\d{1,4})"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

B_RE = re.compile(
    r"(?P<file_type>B)(?P<file_number>\d{1,3})"
    r"(/)(?P<element_number>\d{1,4})"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

ST_RE = re.compile(
    r"(?P<file_type>ST)(?P<file_number>\d{1,3})"
    r"(:)(?P<element_number>\d{1,4})"
    r"(?P<_elem_cnt_token>{(?P<element_count>[12])})?",
    flags=re.IGNORECASE,
)


class SLCDriver(CIPDriver):
    """
    An Ethernet/IP Client driver for reading and writing of data files in SLC or MicroLogix PLCs.
    """

    __log = logging.getLogger(f"{__module__}.{__qualname__}")
    _auto_slot_cip_path = True

    def __init__(self, path, *args, connection_size=500, **kwargs):
        super().__init__(path, *args, connection_size=connection_size, **kwargs)  # SLC/MicroLogix: standard Forward Open

    def _make_core(self, path, socket_timeout, connection_size):
        return _core.SLCDriver(path, socket_timeout, connection_size)

    @classmethod
    def _core_class(cls):
        return _core.SLCDriver

    def read(self, *addresses: str) -> ReadWriteReturnType:
        """
        Reads data file addresses. To read multiple words add the word count to the address using curly braces,
        e.g. ``N120:10{10}``.

        Does not track request/response size like the CLXDriver.

        :param addresses: one or many data file addresses to read
        :return: a single or list of ``Tag`` objects
        """
        results = self._core.read(list(addresses))

        if len(results) == 1:
            return results[0]

        return results

    def write(self, *address_values: Tuple[str, TagValueType]) -> ReadWriteReturnType:
        """
        Write values to data file addresses.  To write to multiple words in a file use curly braces in the address
        to indicate the number of words, then set the value to a list of values to write e.g. ``('N120:10{10}', [1, 2, ...])``.

        Does not track request/response size like the CLXDriver.


        :param address_values: one or many 2-element tuples of (address, value)
        :return: a single or list of ``Tag`` objects
        """
        results = self._core.write(address_values)

        if len(results) == 1:
            return results[0]

        return results

    def get_processor_type(self):
        """the processor's catalog number, e.g. ``'1747-L552'``, None if the processor reported an error"""
        return self._core.get_processor_type()

    def get_datalog_queue(self, num_data_logs, queue_num):
        """reads ``num_data_logs`` entries of data log queue ``queue_num``, then one more to clear the queue"""
        return self._core.get_datalog_queue(num_data_logs, queue_num)

    def get_file_directory(self):
        """the data files of the processor, ``{'N7': {'elements': 100, 'length': 200}, ...}``"""
        return self._core.get_file_directory()


def _parse_file0(sys0_info, data):
    file_pos = sys0_info["file_position"]
    row_size = sys0_info["row_size"]

    data_files = {}
    file_num = 0
    while file_pos < len(data):
        file_code = data[file_pos : file_pos + 1]
        file_type = PCCC_DATA_TYPE.get(file_code, None)
        if file_type == "I" and file_num == 0:  # O0 row missed (#281): I is always data file 1
            file_num = 1

        if file_type:
            file_name = f"{file_type}{file_num}"

            element_size = PCCC_DATA_SIZE.get(file_type, 2)
            file_size = UINT.decode(data[file_pos + 1 :])
            data_files[file_name] = {
                "elements": file_size // element_size,
                "length": file_size,
            }

        if file_type or file_code == b"\x81":  # 0x81 reserved type, for skipped file numbers?
            file_num += 1

        file_pos += row_size

    return data_files


def _get_sys0_info(plc_type):
    prefix = plc_type[:4]

    if prefix in {
        "1761",
    }:  # MLX1000, SLC 5/02
        # FIXME: Not sure if these are correct, never tested
        return {
            "file_position": 93,
            "row_size": 8,
            "file_type": b"\x00",
            "size_element": b"\x23",
            "size_len": b"\x04",
        }
    elif prefix in {"1763", "1762", "1764"}:  # MLX 1100, 1200, 1500
        # FIXME: values from 1100 and 1400, not tested on 1200/1500
        return {
            "file_position": 233,
            "row_size": 10,
            "file_type": b"\x02",
            "size_element": b"\x28",
            "size_len": b"\x08",
            "size_const": 19968,  # no idea why, but this seems like a const added to the size? wtf?
        }
    elif prefix in {
        "1766",
    }:  # MLX 1400
        return {
            "file_position": 233,
            "row_size": 10,
            "file_type": b"\x03",
            "size_element": b"\x2b",
            "size_len": b"\x08",
            "size_const": 19968,  # no idea why, but this seems like a const added to the size? wtf?
        }
    else:  # SLC 5/05
        return {
            "file_position": 79,
            "row_size": 10,
            "file_type": b"\x01",
            "size_element": b"\x23",
            "size_len": b"\x04",
        }


def _parse_read_reply(tag, data) -> Tag:
    try:
        bit_read = tag.get("address_field", 0) == 3
        bit_position = int(tag.get("sub_element") or 0)
        data_size = PCCC_DATA_SIZE[tag["file_type"]]
        unpack_func = PCCCDataTypes[tag["file_type"]].decode
        if bit_read:
            new_value = 0
            if tag["file_type"] in {"T", "C"}:
                if bit_position == PCCC_CT["PRE"]:
                    return Tag(
                        tag["tag"],
                        unpack_func(data[new_value + 2 : new_value + 2 + data_size]),
                        tag["file_type"],
                        None,
                    )

                elif bit_position == PCCC_CT["ACC"]:
                    return Tag(
                        tag["tag"],
                        unpack_func(data[new_value + 4 : new_value + 4 + data_size]),
                        tag["file_type"],
                        None,
                    )

            tag_value = unpack_func(data[new_value : new_value + data_size])
            return Tag(tag["tag"], get_bit(tag_value, bit_position), tag["file_type"], None)

        else:
            values_list = [
                unpack_func(data[i : i + data_size]) for i in range(0, len(data), data_size)
            ]
            if len(values_list) > 1:
                return Tag(tag["tag"], values_list, tag["file_type"], None)
            else:
                return Tag(tag["tag"], values_list[0], tag["file_type"], None)
    except Exception as err:
        raise ResponseError("Failed parsing tag read reply") from err


def parse_tag(tag: str) -> Optional[dict]:
    t = CT_RE.fullmatch(tag)
    if (
        t
        and (1 <= int(t.group("file_number")) <= 255)
        and (0 <= int(t.group("element_number")) <= 255)
    ):
        return {
            "file_type": t.group("file_type").upper(),
            "file_number": t.group("file_number"),
            "element_number": t.group("element_number"),
            "sub_element": PCCC_CT[t.group("sub_element").upper()],
            "address_field": 3,
            "element_count": 1,
            "tag": t.group(0),
        }

    t = LFBN_RE.fullmatch(tag)
    if t:
        _cnt = t.group("_elem_cnt_token")
        tag_name = t.group(0).replace(_cnt, "") if _cnt else t.group(0)

        if t.group("sub_element") is not None:
            if (
                (1 <= int(t.group("file_number")) <= 255)
                and (0 <= int(t.group("element_number")) <= 255)
                and (0 <= int(t.group("sub_element")) <= 15)
            ):
                element_count = t.group("element_count")
                return {
                    "file_type": t.group("file_type").upper(),
                    "file_number": t.group("file_number"),
                    "element_number": t.group("element_number"),
                    "sub_element": t.group("sub_element"),
                    "address_field": 3,
                    "element_count": int(element_count) if element_count is not None else 1,
                    "tag": tag_name,
                }
        else:
            if (1 <= int(t.group("file_number")) <= 255) and (
                0 <= int(t.group("element_number")) <= 255
            ):
                element_count = t.group("element_count")
                return {
                    "file_type": t.group("file_type").upper(),
                    "file_number": t.group("file_number"),
                    "element_number": t.group("element_number"),
                    "sub_element": t.group("sub_element"),
                    "address_field": 2,
                    "element_count": int(element_count) if element_count is not None else 1,
                    "tag": tag_name,
                }

    t = IO_RE.fullmatch(tag)
    if t:
        _cnt = t.group("_elem_cnt_token")
        tag_name = t.group(0).replace(_cnt, "") if _cnt else t.group(0)
        file_number = "0" if t.group("file_type").upper() == "O" else "1"
        position_number = "0" if t.group("position_number") == None else t.group("position_number")
        if t.group("sub_element") is not None:
            if (
                (0 <= int(file_number) <= 255)
                and (0 <= int(t.group("element_number")) <= 255)
                and (0 <= int(t.group("sub_element")) <= 15)
            ):
                element_count = t.group("element_count")
                return {
                    "file_type": t.group("file_type").upper(),
                    "file_number": file_number,
                    "element_number": t.group("element_number"),
                    "pos_number": position_number,
                    "sub_element": t.group("sub_element"),
                    "address_field": 3,
                    "element_count": int(element_count) if element_count is not None else 1,
                    "tag": tag_name,
                }
        else:
            if 0 <= int(t.group("element_number")) <= 255:
                element_count = t.group("element_count")
                return {
                    "file_type": t.group("file_type").upper(),
                    "file_number": file_number,
                    "element_number": t.group("element_number"),
                    "pos_number": position_number,
                    "sub_element": 0,
                    "address_field": 2,
                    "element_count": int(element_count) if element_count is not None else 1,
                    "tag": tag_name,
                }

    t = ST_RE.fullmatch(tag)
    if (
        t
        and (1 <= int(t.group("file_number")) <= 255)
        and (0 <= int(t.group("element_number")) <= 255)
    ):
        _cnt = t.group("_elem_cnt_token")
        tag_name = t.group(0).replace(_cnt, "") if _cnt else t.group(0)
        element_number = int(t.group("element_number"))
        element_count = t.group("element_count")
        return {
            "file_type": t.group("file_type").upper(),
            "file_number": t.group("file_number"),
            "element_number": element_number,
            "address_field": 2,
            "element_count": int(element_count) if element_count is not None else 1,
            "tag": tag_name,
        }

    t = A_RE.fullmatch(tag)
    if (
        t
        and (1 <= int(t.group("file_number")) <= 255)
        and (0 <= int(t.group("element_number")) <= 255)
    ):
        _cnt = t.group("_elem_cnt_token")
        tag_name = t.group(0).replace(_cnt, "") if _cnt else t.group(0)
        element_number = int(t.group("element_number"))
        element_count = t.group("element_count")
        return {
            "file_type": t.group("file_type").upper(),
            "file_number": t.group("file_number"),
            "element_number": element_number,
            "address_field": 2,
            "element_count": int(element_count) if element_count is not None else 1,
            "tag": tag_name,
        }

    t = S_RE.fullmatch(tag)
    if t:
        _cnt = t.group("_elem_cnt_token")
        tag_name = t.group(0).replace(_cnt, "") if _cnt else t.group(0)
        element_count = t.group("element_count")
        if t.group("sub_element") is not None:
            if (0 <= int(t.group("element_number")) <= 255) and (
                0 <= int(t.group("sub_element")) <= 15
            ):
                return {
                    "file_type": t.group("file_type").upper(),
                    "file_number": "2",
                    "element_number": t.group("element_number"),
                    "sub_element": t.group("sub_element"),
                    "address_field": 3,
                    "element_count": int(element_count) if element_count is not None else 1,
                    "tag": t.group(0),
                }
        else:
            if 0 <= int(t.group("element_number")) <= 255:
                return {
                    "file_type": t.group("file_type").upper(),
                    "file_number": "2",
                    "element_number": t.group("element_number"),
                    "address_field": 2,
                    "element_count": int(element_count) if element_count is not None else 1,
                    "tag": tag_name,
                }

    t = B_RE.fullmatch(tag)
    if (
        t
        and (1 <= int(t.group("file_number")) <= 255)
        and (0 <= int(t.group("element_number")) <= 4095)
    ):
        _cnt = t.group("_elem_cnt_token")
        tag_name = t.group(0).replace(_cnt, "") if _cnt else t.group(0)
        bit_position = int(t.group("element_number"))
        element_number, sub_element = divmod(bit_position, 16)
        element_count = t.group("element_count")
        return {
            "file_type": t.group("file_type").upper(),
            "file_number": t.group("file_number"),
            "element_number": element_number,
            "sub_element": sub_element,
            "address_field": 3,
            "element_count": int(element_count) if element_count is not None else 1,
            "tag": tag_name,
        }

    return None


def _addr(v) -> bytes:
    v = int(v)
    return b"\xff" + UINT.encode(v) if v >= 255 else USINT.encode(v)  # PCCC: 0xFF escapes a 2-byte value


def get_bit(value: int, idx: int) -> bool:
    """:returns value of bit at position idx"""
    return (value & (1 << idx)) != 0


def writeable_value(tag: dict, value: Union[bytes, TagValueType]) -> bytes:
    if isinstance(value, bytes):
        return value
    bit_field = tag.get("address_field", 0) == 3
    bit_position = int(tag.get("sub_element") or 0) if bit_field else 0
    bit_mask = UINT.encode(2 ** bit_position) if bit_field else b"\xFF\xFF"

    element_count = tag.get("element_count") or 1
    if element_count > 1:
        if len(value) < element_count:
            raise RequestError(
                f"Insufficient data for requested elements, expected {element_count} and got {len(value)}"
            )
        if len(value) > element_count:
            value = value[:element_count]

    try:
        pack_func = PCCCDataTypes[tag["file_type"]].encode

        if element_count > 1:
            _value = b"".join(pack_func(val) for val in value)
        else:
            if bit_field:
                if tag["file_type"] in ["T", "C"] and bit_position in {
                    PCCC_CT["PRE"],
                    PCCC_CT["ACC"],
                }:
                    bit_mask = b"\xff\xff"
                    _value = pack_func(value)
                else:
                    _value = bit_mask if value else b"\x00\x00"
            else:
                _value = pack_func(value)

    except Exception as err:
        raise RequestError(
            f'Failed to create a writeable value for {tag["tag"]} from {value} - {err}'
        ) from err

    else:
        return bit_mask + _value


def request_status(response) -> Optional[str]:
    if not response:
        return response.error  # CIP or encapsulation error
    data = response.raw
    if len(data) <= 58:
        return "Unknown Status"
    status = data[58]
    if status == SUCCESS:
        return None
    msg = PCCC_ERROR_CODE.get(status, f"Unknown Status (0x{status:02x})")
    if status == 0xF0 and len(data) > SLC_REPLY_START:
        msg += f" (EXT STS 0x{data[SLC_REPLY_START]:02x})"
    return msg
