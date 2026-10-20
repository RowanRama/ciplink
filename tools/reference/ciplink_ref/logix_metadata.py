"""Logix metadata records."""

import struct
from typing import Any, Dict, Optional, Sequence

from .cip import DataTypes
from .exceptions import DataError


DESCRIPTION_SERVICE = 0x53
METADATA_CLASS = 0x349
_READ_PREFIX = bytes.fromhex("53042100490325000000")


def build_description_request(instance_id: int, language: int = 0x007F,
                              offset: int = 0, *, path: str = "",
                              class_id: int = 0x6B,
                              owner_context: Sequence[int] = (0, 0)) -> bytes:
    """Create a Description request."""
    if not isinstance(instance_id, int) or not 1 <= instance_id <= 0xFFFFFFFF:
        raise ValueError("Symbol instance_id must be a positive UDINT")
    if not isinstance(language, int) or not 0 <= language <= 0xFFFF:
        raise ValueError("Language must be a UINT")
    if not isinstance(offset, int) or not 0 <= offset <= 0xFFFFFFFF:
        raise ValueError("Offset must be a UDINT")
    if not isinstance(class_id, int) or not 0 <= class_id <= 0xFFFF:
        raise ValueError("Class must be a UINT")
    if (len(owner_context) != 2 or not isinstance(owner_context[0], int)
            or not 0 <= owner_context[0] <= 0xFFFFFFFF
            or not isinstance(owner_context[1], int)
            or not 0 <= owner_context[1] <= 0xFFFF):
        raise ValueError("Invalid Description owner")
    if not isinstance(path, str):
        raise ValueError("Description path must be a string")
    raw_path = path.encode("utf-8")
    if len(raw_path) > 0xFFFF:
        raise ValueError("Description path is too long")
    header = struct.pack("<BBHI", 1, 1 if offset == 0 else 0, 0, offset)
    selector = (struct.pack("<HHHIIHH", 0x0F, 0xFF, class_id, instance_id,
                            owner_context[0], owner_context[1], len(raw_path))
                + raw_path + struct.pack("<HH", language, 1))
    return _READ_PREFIX + header + selector


def build_description_index_request(language: int = 0x007F, offset: int = 0) -> bytes:
    if not isinstance(language, int) or not 0 <= language <= 0xFFFF:
        raise ValueError("Language must be a UINT")
    if not isinstance(offset, int) or not 0 <= offset <= 0xFFFFFFFF:
        raise ValueError("Offset must be a UDINT")
    return (_READ_PREFIX + struct.pack("<BBHIHHHH", 1, int(offset == 0), 0,
                                      offset, 0x0C, 0xFF, language, 1))


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
                value = raw if encoding is None else raw.decode(encoding)
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
    """Return one Description record, or None."""
    records = decode_description_records(pages, encoding, max_records=1)
    if not records:
        return None
    if len(records) != 1:
        raise DataError("Unexpected additional Description records")
    if records[0]["kind"] != 1:
        raise DataError("Response is not a text Description")
    return records[0]


def decode_description_records(pages: Sequence[bytes],
                               encoding: Optional[str] = "utf-8", *,
                               max_records: Optional[int] = None) -> Sequence[Dict[str, Any]]:
    cursor = _Cursor(assemble_metadata_pages(pages))
    records = []
    while cursor.offset < len(cursor.data):
        if max_records is not None and len(records) >= max_records:
            raise DataError("Unexpected additional Description records")
        class_id, instance_id, a, b = cursor.unpack("<HIIH")
        path = cursor.value(1, "utf-8")["value"]
        language, = cursor.unpack("<H")
        property_id, record_id, c, d, e, kind = cursor.unpack("<HIIIIH")
        if property_id != 1 or kind not in (1, 4):
            raise DataError("Response is not a Description record")
        record = (cursor.value(kind, encoding) if kind == 1
                  else {"value": None, "kind": kind, "raw_value_hex": ""})
        record.update({"class_id": class_id, "instance_id": instance_id,
                       "language": language, "property_id": property_id,
                       "record_id": record_id, "owner_context": [a, b],
                       "path": path, "context": [c, d, e]})
        records.append(record)
    return records
