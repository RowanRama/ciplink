"""Experimental codecs inferred from Logix extended-property captures.

Validated against GuardLogix 5580 firmware 37.13, including live authenticated
reads. These codecs do not authenticate a connection. An unauthenticated
pycomm3 session on the test controller is denied access.
Only controller base-tag Description and definition records have capture evidence;
other tag properties, scopes, inheritance and non-ASCII text remain unverified.
"""

import struct
from typing import Any, Dict, Optional, Sequence

from .cip import DataTypes
from .exceptions import DataError


DESCRIPTION_SERVICE = 0x53
METADATA_CLASS = 0x349
# Preserve the exact 16-bit class/instance path observed in the capture.
_READ_PREFIX = bytes.fromhex("53042100490325000000")


def build_description_request(instance_id: int, language: int = 0x007F,
                              offset: int = 0) -> bytes:
    """Build the captured controller base-tag Description read, including CIP path.

    The fixed selector bytes reproduce the observed query; they are not a public
    protocol specification. 0x007F returned the confirmed description whereas
    0x0409 returned an empty result. Continuations use byte offsets and clear the
    initial-page flag, as observed for a split definition response.
    """
    if not isinstance(instance_id, int) or not 1 <= instance_id <= 0xFFFFFFFF:
        raise ValueError("Symbol instance_id must be a positive UDINT")
    if not isinstance(language, int) or not 0 <= language <= 0xFFFF:
        raise ValueError("Language must be a UINT")
    if not isinstance(offset, int) or not 0 <= offset <= 0xFFFFFFFF:
        raise ValueError("Offset must be a UDINT")
    header = struct.pack("<BBHI", 1, 1 if offset == 0 else 0, 0, offset)
    selector = struct.pack("<HHHIIIHH", 0x0F, 0xFF, 0x6B, instance_id, 0, 0,
                           language, 1)
    return _READ_PREFIX + header + selector


def decode_metadata_page(data: bytes) -> Dict[str, Any]:
    """Parse the vendor page header after the standard CIP reply/status header.

    Flags 1 and 2 mark first and last pages. The byte offset counts preceding
    payload bytes, excluding the eight-byte page header. A split capture cuts
    through a string; pages must be assembled before parsing any records.
    """
    if len(data) < 8:
        raise DataError("Truncated Logix metadata page header")
    version, flags, reserved, offset = struct.unpack_from("<BBHI", data)
    if version != 1 or flags & ~3 or reserved:
        raise DataError("Unsupported Logix metadata page header")
    return {"first": bool(flags & 1), "last": bool(flags & 2),
            "offset": offset, "data": data[8:]}


def assemble_metadata_pages(pages: Sequence[bytes]) -> bytes:
    """Validate a complete ordered response and join its payload pages."""
    if not pages:
        raise DataError("No Logix metadata pages")
    chunks = []
    offset = 0
    for index, raw in enumerate(pages):
        page = decode_metadata_page(raw)
        if page["first"] != (index == 0) or page["offset"] != offset:
            raise DataError("Out-of-order Logix metadata page")
        if page["last"] != (index == len(pages) - 1):
            raise DataError("Incomplete response or data after final metadata page")
        if not page["last"] and not page["data"]:
            raise DataError("Logix metadata continuation made no progress")
        chunks.append(page["data"])
        offset += len(page["data"])
    return b"".join(chunks)


class _Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, count: int) -> bytes:
        end = self.offset + count
        if end > len(self.data):
            raise DataError("Truncated Logix metadata record")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def unpack(self, format_: str):
        return struct.unpack(format_, self.read(struct.calcsize(format_)))

    def value(self, kind: int, encoding: str) -> Dict[str, Any]:
        start = self.offset
        if kind == 1:
            length, = self.unpack("<H")
            raw = self.read(length)
            try:
                value = raw.decode(encoding)
            except UnicodeError as error:
                raise DataError("Cannot decode metadata text using {}".format(encoding)) from error
            result = {"value": value}
        elif kind == 2:
            code, count = self.unpack("<HH")
            if code not in range(0xC1, 0xCC):
                raise DataError("Unsupported metadata atomic type 0x{:04x}".format(code))
            data_type = DataTypes.get_type(code)
            raw = self.read(count * data_type.size)
            result = {"type_code": code, "value": [
                data_type.decode(raw[i:i + data_type.size])
                for i in range(0, len(raw), data_type.size)
            ]}
        else:
            raise DataError("Unsupported metadata value kind {}".format(kind))
        result["kind"] = kind
        result["raw_value_hex"] = self.data[start:self.offset].hex()
        return result


def decode_definition_response(pages: Sequence[bytes],
                               encoding: str = "utf-8") -> Dict[int, Dict[str, Any]]:
    """Parse captured definition fields, keeping unknown context words intact.

    Text is length-prefixed bytes. ASCII was verified; callers may select another
    encoding for additional captures. Numeric records carry a CIP type and count.
    """
    cursor = _Cursor(assemble_metadata_pages(pages))
    fields = {}
    while cursor.offset < len(cursor.data):
        identifier, a, b, c, kind = cursor.unpack("<HIIIH")
        if identifier in fields:
            raise DataError("Duplicate metadata definition field {}".format(identifier))
        record = cursor.value(kind, encoding)
        record["context"] = [a, b, c]
        fields[identifier] = record
    return fields


def decode_description_response(pages: Sequence[bytes],
                                encoding: str = "utf-8") -> Optional[Dict[str, Any]]:
    """Parse the observed single-property Description response, or missing result.

    This intentionally rejects unverified multi-property layouts. A valid empty
    response means that the selected language/query returned no property, which
    is distinct from a configured description whose string length is zero.
    """
    cursor = _Cursor(assemble_metadata_pages(pages))
    if not cursor.data:
        return None
    class_id, instance_id, a, b, language = cursor.unpack("<HIIIH")
    property_id, record_id, c, d, e, kind = cursor.unpack("<HIIIIH")
    if class_id != 0x6B or property_id != 1 or kind != 1:
        raise DataError("Response is not the captured Symbol Description layout")
    record = cursor.value(kind, encoding)
    if cursor.offset != len(cursor.data):
        raise DataError("Unexpected additional Description records")
    record.update({"class_id": class_id, "instance_id": instance_id,
                   "language": language, "property_id": property_id,
                   "record_id": record_id, "owner_context": [a, b],
                   "context": [c, d, e]})
    return record
