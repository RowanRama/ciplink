"""Codec fixtures: CIP data types, path segments, connection paths, request paths, status text and kinds."""

import struct

from fixturelib import enc, outcome, write

from ciplink.cip import (
    BOOL, SINT, INT, DINT, LINT, USINT, UINT, UDINT, ULINT, REAL, LREAL, STIME, DATE, TIME_OF_DAY,
    DATE_AND_TIME, DT, LDT, TIME32, LOGIX_STRING, STRING, SHORT_STRING, STRING2, STRINGN, STRINGI, BYTE, WORD,
    DWORD, LWORD, FTIME, LTIME, ITIME, TIME, ENGUNIT, Array, DataTypes, PortSegment, LogicalSegment,
    DataSegment, PADDED_EPATH, PACKED_EPATH, SERVICE_STATUS, EXTEND_CODES, STATUS, KEYSWITCH, EXTERNAL_ACCESS,
    PRODUCT_TYPES, VENDORS, STATES,
)
from ciplink.custom_types import FixedSizeString, ListIdentityObject, ModuleIdentityObject, Revision
from ciplink.cip_driver import parse_connection_path, parse_cip_route
from ciplink.const import MSG_ROUTER_PATH
from ciplink.packets.util import (
    request_path, tag_request_path, get_service_status, get_extended_status, get_extended_status_code,
    status_kind, wrap_unconnected_send, dword_to_bool_array,
)

ELEMENTARY = [BOOL, SINT, INT, DINT, LINT, USINT, UINT, UDINT, ULINT, REAL, LREAL, STIME, DATE, TIME_OF_DAY, DT,
              LDT, TIME32, FTIME, LTIME, ITIME, TIME]

INT_RANGES = {
    SINT: (-128, 127), INT: (-32768, 32767), DINT: (-2**31, 2**31 - 1), LINT: (-2**63, 2**63 - 1),
    USINT: (0, 255), UINT: (0, 65535), UDINT: (0, 2**32 - 1), ULINT: (0, 2**64 - 1),
}


def int_range(cls):
    for base, rng in INT_RANGES.items():
        if issubclass(cls, base):
            return rng
    return None


def elementary_cases():
    cases = []
    for cls in ELEMENTARY:
        name = cls.__name__
        values = [True, False, 0, 1, 2, -1, 0.5, "1", None, [1]]
        rng = int_range(cls)
        if rng:
            lo, hi = rng
            values += [lo, hi, lo - 1, hi + 1, 100, -100, 1.0]
        if cls in (REAL, LREAL):
            values += [0.0, 1.5, -2.25, 3.4028234663852886e38, 1e39, -1e39, 1e-45, 123456789, 2**70,
                       float("inf"), float("-inf"), 0.1]
        for value in values:
            cases.append({"type": name, "value": enc(value), "result": outcome(cls.encode, value)})
    return cases


def elementary_decode_cases():
    cases = []
    samples = [b"", b"\x00", b"\x01", b"\xff", b"\x80\x00", b"\x00\x80", b"\xff\xff\xff\xff",
               b"\x01\x02\x03\x04\x05\x06\x07\x08", b"\x00\x00\xc0\x7f", b"\x00\x00\x80\x7f", b"\xcd\xcc\x8c\x3f",
               bytes(range(1, 17)), b"\x00\x00\x00\x00\x00\x00\xf8\x7f"]
    for cls in ELEMENTARY + [DATE_AND_TIME]:
        for raw in samples:
            res = outcome(cls.decode, raw)
            if "ok" in res and isinstance(res["ok"], dict) and "float" in res["ok"]:
                f = res["ok"]["float"]
                if isinstance(f, str):  # nan/inf: compare bits instead
                    res["ok"] = {"float_bits": raw[:cls.size].hex()}
            cases.append({"type": cls.__name__, "raw": raw.hex(), "result": res})
    return cases


def string_cases():
    cases = []
    for cls in (STRING, SHORT_STRING, STRING2, LOGIX_STRING):
        for value in ("", "a", "hello", "héllo", "x" * 300, "日本"):
            cases.append({"type": cls.__name__, "op": "encode", "value": enc(value), "result": outcome(cls.encode, value)})
    for char_size in (1, 2, 4, 3):
        for value in ("", "abc", "héllo"):
            cases.append({"type": "STRINGN", "op": "encode", "char_size": char_size, "value": enc(value),
                          "result": outcome(STRINGN.encode, value, char_size)})
    raws = {
        "STRING": [b"\x00\x00", b"\x03\x00abc", b"\x03\x00ab", b"\x00", b"", b"\x02\x00\xe9\xe8"],
        "SHORT_STRING": [b"\x00", b"\x03abc", b"\x05ab", b""],
        "STRING2": [b"\x02\x00a\x00b\x00", b"\x01\x00a", b"\x00\x00"],
        "LOGIX_STRING": [b"\x03\x00\x00\x00abc", b"\x00\x00\x00\x00", b"\x05\x00\x00\x00ab"],
        "STRINGN": [b"\x01\x00\x03\x00abc", b"\x02\x00\x02\x00a\x00b\x00", b"\x04\x00\x01\x00a\x00\x00\x00",
                    b"\x03\x00\x01\x00abc", b"\x01\x00\x00\x00"],
        "STRINGI": [b"\x01engq\x04\x00\x03\x00abc", b"\x02eng\xd0\x04\x00\x02\x00hideu\xda\x04\x00\x02yo",
                    b"\x01eng\xd5\xe8\x03\x02\x00a\x00b\x00", b"\x00"],
    }
    types = {"STRING": STRING, "SHORT_STRING": SHORT_STRING, "STRING2": STRING2, "LOGIX_STRING": LOGIX_STRING,
             "STRINGN": STRINGN, "STRINGI": STRINGI}
    for name, samples in raws.items():
        for raw in samples:
            cases.append({"type": name, "op": "decode", "raw": raw.hex(), "result": outcome(types[name].decode, raw)})
    # Logix STRING as uploaded: FixedSizeString(size, max_len)
    for size, max_len in ((82, 82), (20, 20), (4, 4)):
        fs = FixedSizeString(size, max_len_=max_len)
        for value in ("", "abc", "x" * max_len, "x" * (max_len + 1), "é"):
            cases.append({"type": "FIXED", "size": size, "max_len": max_len, "op": "encode", "value": enc(value),
                          "result": outcome(fs.encode, value)})
        for raw in (struct.pack("<I", 3) + b"abc" + bytes(size - 3), struct.pack("<I", 0) + bytes(size),
                    struct.pack("<I", size + 5) + b"y" * size, struct.pack("<I", 2) + b"ab"):
            cases.append({"type": "FIXED", "size": size, "max_len": max_len, "op": "decode", "raw": raw.hex(),
                          "result": outcome(fs.decode, raw)})
    return cases


def bits_cases():
    cases = []
    for cls in (BYTE, WORD, DWORD, LWORD, ENGUNIT):
        n = cls.size * 8
        for raw in (bytes(cls.size), b"\xff" * cls.size, bytes([0b10100101] * cls.size), b"\x01" + bytes(cls.size - 1), b""):
            cases.append({"type": cls.__name__, "op": "decode", "raw": raw.hex(), "result": outcome(cls.decode, raw)})
        for value in ([True] * n, [False] * n, [i % 3 == 0 for i in range(n)], [1, 0] * (n // 2), [True] * (n - 1),
                      [2] * n, ["x"] * n):
            cases.append({"type": cls.__name__, "op": "encode", "value": enc(value), "result": outcome(cls.encode, value)})
    for dword in (0, 1, 0x80000000, 0xFFFFFFFF, 0x12345678):
        cases.append({"type": "dword_to_bool_array", "op": "int", "value": enc(dword), "result": outcome(dword_to_bool_array, dword)})
    return cases


def array_cases():
    cases = []
    specs = [("DINT", DINT, 3), ("INT", INT, 1), ("REAL", REAL, 2), ("BOOL", BOOL, 4), ("SINT", SINT, 5),
             ("DWORD", DWORD, 2), ("LINT", LINT, 2)]
    for name, cls, length in specs:
        typ = Array(length, cls)
        n = length * (32 if cls is DWORD else 1)
        values = [list(range(n)), list(range(n + 2)), list(range(n - 1)), [True] * n, [1.5] * n, []]
        if cls is DWORD:
            values = [[i % 2 == 0 for i in range(64)], [True] * 63, [True] * 96, [False] * 64]
        for value in values:
            for override in (None, 1, length):
                res = outcome(typ.encode, value, override) if override else outcome(typ.encode, value)
                cases.append({"elem": name, "length": length, "override": override, "op": "encode",
                              "value": enc(value), "result": res})
        raw = bytes(range(1, 1 + cls.size * length + 3))
        for chunk in (raw, raw[:cls.size * length], raw[:max(cls.size * length - 1, 0)], b""):
            for override in (None, 1, length):
                res = outcome(typ.decode, chunk, override) if override else outcome(typ.decode, chunk)
                cases.append({"elem": name, "length": length, "override": override, "op": "decode",
                              "raw": chunk.hex(), "result": res})
    for name, cls in (("DINT", DINT), ("UINT", UINT)):
        typ = Array(None, cls)
        for raw in (b"", bytes(range(8)), bytes(range(9))):
            cases.append({"elem": name, "length": None, "override": None, "op": "decode", "raw": raw.hex(),
                          "result": outcome(typ.decode, raw)})
    typ = Array(UINT, DINT)
    for raw in (b"\x02\x00\x01\x00\x00\x00\x02\x00\x00\x00", b"\x00\x00", b"\x03\x00\x01\x00\x00\x00"):
        cases.append({"elem": "DINT", "length": "UINT", "override": None, "op": "decode", "raw": raw.hex(),
                      "result": outcome(typ.decode, raw)})
    return cases


def segment_cases():
    cases = []
    ports = [("bp", 0), ("backplane", 1), ("enet", "10.20.30.40"), (2, "192.168.1.10"), (1, 15), (18, 1),
             (20, "10.1.1.1"), ("bp", "3"), ("enet", b"\x01\x02"), ("dhrio-a", 2), ("dhrio-b", 1), ("dnet", 5),
             ("cnet", 3), ("dh485-a", 1), ("dh485-b", 2), ("bogus", 1), ("bp", "not-an-ip"), (1, 300),
             (14, 1), (15, 1), (0x1234, "10.0.0.1"), ("enet", "::1")]
    for port, link in ports:
        seg = PortSegment(port, link)
        cases.append({"kind": "port", "port": enc(port), "link": enc(link),
                      "result": outcome(PortSegment.encode, seg)})
    for ltype in ("class_id", "instance_id", "member_id", "connection_point", "attribute_id", "special",
                  "service_id", "bogus"):
        for value in (0, 1, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000, b"\x01", b"\x01\x02",
                      b"\x01\x02\x03", b"\x01\x02\x03\x04"):
            for padded in (False, True):
                seg = LogicalSegment(value, ltype)
                cases.append({"kind": "logical", "type": ltype, "value": enc(value), "padded": padded,
                              "result": outcome(LogicalSegment.encode, seg, padded)})
    for data in ("Tag", "Tags", "", "Program:MainProgram", "日本", b"\x01", b"\x01\x02", b""):
        cases.append({"kind": "data", "data": enc(data), "result": outcome(DataSegment.encode, DataSegment(data))})
    return cases


def epath_cases():
    cases = []
    segment_sets = {
        "router": MSG_ROUTER_PATH,
        "bp0": [PortSegment("bp", 0)],
        "route": [PortSegment("bp", 2), PortSegment("enet", "10.1.2.3"), PortSegment("bp", 0)],
        "symbol": [DataSegment("Program:Main"), LogicalSegment(0x6B, "class_id"), LogicalSegment(0x1234, "instance_id")],
        "empty": [],
        "raw": [b"\x20\x06", LogicalSegment(1, "instance_id")],
    }
    for name, segments in segment_sets.items():
        for cls in (PADDED_EPATH, PACKED_EPATH):
            for length in (False, True):
                for pad_length in (False, True):
                    cases.append({"set": name, "padded": cls is PADDED_EPATH, "length": length,
                                  "pad_length": pad_length,
                                  "result": outcome(cls.encode, segments, length, pad_length)})
    return cases


def connection_path_cases():
    paths = ["10.0.0.1", "10.0.0.1/1", "10.0.0.1/3", "10.0.0.1/bp/2/enet/10.0.0.2/bp/0", "10.0.0.1:44819/1",
             "10.0.0.1:0", "10.0.0.1:65535", "10.0.0.1:65534", "10.0.0.1:abc", "10.0.0.1\\bp\\0", "10.0.0.1,bp,0",
             "10.0.0.1/bp", "10.0.0.1/bp/0/enet", "plc.local/1", "10.0.0.1/1/2", "10.0.0.1/backplane/1",
             "10.0.0.1/2/10.0.0.9", "10.0.0.1/bp/x", "", "10.0.0.1/", "10.0.0.1:44818"]
    cases = []
    for path in paths:
        for auto_slot in (False, True):
            def parse():
                ip, port, route = parse_connection_path(path, auto_slot)
                return [ip, port, PADDED_EPATH.encode(route, length=True, pad_length=True),
                        PADDED_EPATH.encode(route + MSG_ROUTER_PATH, length=True),
                        PADDED_EPATH.encode(route[:-1], length=True, pad_length=True)]
            cases.append({"path": path, "auto_slot": auto_slot, "result": outcome(parse)})
    for route in ("bp/0", "bp/1/enet/10.1.1.1", "1/2", "bp", ""):
        cases.append({"route": route, "result": outcome(lambda: PADDED_EPATH.encode(parse_cip_route(route), length=True, pad_length=True))})
    return cases


def request_path_cases():
    cases = []
    specs = [(0x6B, 1, b""), (0x6C, 0x123, b""), (0x02, 1, b""), (1, 1, 7), (0xAC, 1, 0x10A), (0x8B, b"\x01", b""),
             (b"\x01", b"\x01", b"\x01"), ([0x6B, 0x6C], [1, 2], b""), ([0x6B, 0x6C], 5, b""), (0x6B, [1, 2, 3], 4),
             (0x1234, 0x12345678, 0x300)]
    for class_code, instance, attribute in specs:
        cases.append({"class": enc(class_code), "instance": enc(instance), "attribute": enc(attribute),
                      "result": outcome(request_path, class_code, instance, attribute)})
    infos = [{}, {"instance_id": 0}, {"instance_id": 7}, {"instance_id": 0x1234}, {"instance_id": 0x12345},
             {"instance_id": 5, "base_instance_id": 9}, {"base_instance_id": 0, "instance_id": 4}]
    tags = ["Tag", "Tag[1]", "Tag[1,2,3]", "Tag.Member", "Tag[2].Member[3].Sub", "Program:Main.Tag",
            "Program:Main.Tag[1].Mem", "Tag[300]", "Tag[70000]", "Tag.Mem.Sub.Leaf", "Tag[x]", "Program:Main",
            "T_odd", "Tag[1].Arr[2,3]", "a.b[1,2,3].c"]
    for tag in tags:
        for i, info in enumerate(infos):
            for use_ids in (True, False):
                cases.append({"tag": tag, "info": enc(info), "use_ids": use_ids,
                              "result": outcome(tag_request_path, tag, info, use_ids)})
    for message, route in ((b"\x01\x02\x24\x01", b"\x01\x00\x01\x00"), (b"\x01\x02\x24\x01\x00", b""),
                           (b"", b"\x01\x00\x01\x02")):
        cases.append({"wrap": message.hex(), "route": route.hex(), "result": outcome(wrap_unconnected_send, message, route)})
    return cases


def status_cases():
    cases = []
    for status in range(256):
        cases.append({"fn": "service_status", "status": status, "result": outcome(get_service_status, status)})
    exts = sorted({ext for codes in EXTEND_CODES.values() for ext in codes} | {0x1234, 0, 1})
    for status in sorted(set(EXTEND_CODES) | {0x02, 0x06, 0x1E}):
        for ext in exts:
            for words in (0, 1, 2):
                msg = bytes(10) + bytes([status, words]) + struct.pack("<H", ext) * words
                cases.append({"fn": "extended_status", "msg": msg.hex(), "start": 10,
                              "result": outcome(get_extended_status, msg, 10)})
                cases.append({"fn": "extended_status_code", "msg": msg.hex(), "start": 10,
                              "result": outcome(get_extended_status_code, msg, 10)})
    for status in range(256):
        cases.append({"fn": "status_kind", "status": status, "ext": None, "result": {"ok": enc(status_kind(status).value)}})
    for ext in exts + [0x2108, 0x2106, 0x210A]:
        cases.append({"fn": "status_kind", "status": 0xFF, "ext": ext, "result": {"ok": enc(status_kind(0xFF, ext).value)}})
    return cases


def table_cases():
    """the lookup tables as the driver uses them"""
    return {
        "STATUS": [[k, v] for k, v in STATUS.items()],
        "KEYSWITCH": [[k, sk, v] for k, d in KEYSWITCH.items() for sk, v in d.items()],
        "EXTERNAL_ACCESS": [[k, v] for k, v in EXTERNAL_ACCESS.items()],
        "STATES": [[k, v] for k, v in STATES.items()],
        "PRODUCT_TYPES": [[k, v] for k, v in PRODUCT_TYPES.items() if isinstance(k, int)],
        "VENDORS": [[k, v] for k, v in VENDORS.items() if isinstance(k, int)],
        "DATA_TYPES": [[code, DataTypes.get(code)] for code in range(0xC0, 0xE0) if DataTypes.get(code)],
    }


def identity_cases():
    cases = []
    module = struct.pack("<HHHBB", 1, 0x0E, 166, 33, 11) + b"\x60\x30" + struct.pack("<I", 0x1234ABCD) + b"\x0a1756-SIM/A"
    for raw in (module, module[:-3], struct.pack("<HHHBB", 9999, 0x77, 1, 1, 2) + b"\x70\x20" + bytes(4) + b"\x00", b""):
        cases.append({"type": "module", "raw": raw.hex(), "result": outcome(ModuleIdentityObject.decode, raw)})
    li = (struct.pack("<HHH", 0x0C, 51, 1) + struct.pack("<h", 2) + struct.pack(">H", 44818) + bytes([192, 0, 2, 15])
          + bytes(8) + struct.pack("<HHHBB", 1, 0x0E, 166, 33, 11) + b"\x30\x30" + struct.pack("<I", 0xDEADBEEF)
          + b"\x0a1756-SIM/A" + b"\x03")
    for raw in (li, li[:-1], li[:20]):
        cases.append({"type": "list_identity", "raw": raw.hex(), "result": outcome(ListIdentityObject.decode, raw)})
    for raw in (b"\x21\x0b", b"\x01"):
        cases.append({"type": "revision", "raw": raw.hex(), "result": outcome(Revision.decode, raw)})
    return cases


if __name__ == "__main__":
    write("codec.json", {
        "elementary_encode": elementary_cases(),
        "elementary_decode": elementary_decode_cases(),
        "strings": string_cases(),
        "bits": bits_cases(),
        "arrays": array_cases(),
        "segments": segment_cases(),
        "epaths": epath_cases(),
        "connection_paths": connection_path_cases(),
        "request_paths": request_path_cases(),
        "status": status_cases(),
        "identity": identity_cases(),
    })
    write("tables.json", table_cases())
