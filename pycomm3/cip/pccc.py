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

from io import BytesIO

from .data_types import INT, DINT, REAL, StringDataType, UINT

from ..map import EnumMap


class PCCCStringType(StringDataType):
    @classmethod
    def _slc_string_swap(cls, data):
        """
        Swaps bytes within 16-bit words.

        SLC processors store strings as arrays of 16-bit integers.
        To read/write them correctly as ASCII, the bytes in each word must be swapped.
        e.g., 'AB' (0x4142) is stored as 0x4241 on the PLC.
        """
        # Create a mutable working copy
        ba = bytearray(data)

        # Defensive check: Ensure even length to prevent swap crashes
        # (Though _encode now handles this, it protects _decode against malformed packets)
        if len(ba) % 2:
            ba.append(0)

        ba[0::2], ba[1::2] = ba[1::2], ba[0::2]

        return bytes(ba)


class PCCC_ASCII(PCCCStringType):
    """
    SLC ASCII file type (A).
    Represents exactly 2 characters packed into a single 16-bit integer.
    """
    @classmethod
    def _encode(cls, value: str, *args, **kwargs) -> bytes:
        # PCCC ASCII is fixed at 2 bytes.
        # We truncate longer strings and pad shorter ones with spaces.
        b_value = (value or "").encode(cls.encoding, "ignore")[:2]

        if len(b_value) == 0:
            b_value = b"  "
        elif len(b_value) == 1:
            b_value = b_value + b" "

        return cls._slc_string_swap(b_value)

    @classmethod
    def _decode(cls, stream: BytesIO) -> str:
        return cls._slc_string_swap(stream.read(2)).decode(cls.encoding)


class PCCC_STRING(PCCCStringType):
    """
    SLC String file type (ST).
    Structure: [Length (UINT)] + [Data (82 bytes)]
    """
    @classmethod
    def _encode(cls, value: str) -> bytes:
        # Encode first to handle characters dropped by "ignore"
        data = (value or "").encode(cls.encoding, "ignore")
        true_len = len(data)

        # Pad with null byte if length is odd so it aligns to 16-bit words.
        # This padding is NOT included in the length field.
        if true_len & 1:
            data += b'\x00'

        # Return unpadded length + swapped padded data
        return UINT.encode(true_len) + cls._slc_string_swap(data)

    @classmethod
    def _decode(cls, stream: BytesIO) -> str:
        # Read the explicit length, then the fixed 82-byte buffer
        _len = UINT.decode(stream)
        raw = stream.read(82)

        # Swap bytes to correct order, then slice to the actual length
        swapped = cls._slc_string_swap(raw)
        return swapped[:_len].decode(cls.encoding, "ignore")


class PCCCDataTypes(EnumMap):
    _return_caps_only_ = True
    n = INT
    b = INT
    t = INT
    c = INT
    s = INT
    o = INT
    i = INT
    f = REAL
    a = PCCC_ASCII
    r = DINT
    st = PCCC_STRING
    l = DINT


PCCC_CT = {
    "PRE": 1,
    "ACC": 2,
    "EN": 15,
    "TT": 14,
    "DN": 13,
    "CU": 15,
    "CD": 14,
    "OV": 12,
    "UN": 11,
    "UA": 10,
}

_PCCC_DATA_TYPE = {
    "N": b"\x89",
    "B": b"\x85",
    "T": b"\x86",
    "C": b"\x87",
    "S": b"\x84",
    "F": b"\x8a",
    "ST": b"\x8d",
    "A": b"\x8e",
    "R": b"\x88",
    "O": b"\x82",  # or b'\x8b'?
    "I": b"\x83",  # or b'\x8c'?
    "L": b"\x91",
    "MG": b"\x92",
    "PD": b"\x93",
    "PLS": b"\x94",
}


PCCC_DATA_TYPE = {
    **_PCCC_DATA_TYPE,
    **{v: k for k, v in _PCCC_DATA_TYPE.items()},
}


PCCC_DATA_SIZE = {
    "N": 2,
    "L": 4,
    "B": 2,
    "T": 6,
    "C": 6,
    "S": 2,
    "F": 4,
    "ST": 84,
    "A": 2,
    "R": 6,
    "O": 2,
    "I": 2,
    "MG": 50,
    "PD": 46,
    "PLS": 12,
}
