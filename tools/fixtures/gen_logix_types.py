"""
Logix tag and type model fixtures: symbol list pages, structure makeups, templates parsed into data types, tag
definitions and the scope info of a tag list upload, read reply decoding, write value encoding and the helpers.

Templates are synthesised here (UDTs with nested UDTs, bit members, strings, arrays, an AOI, TIMER/COUNTER/CONTROL)
and fed through the reference driver's parsers; the resulting dicts are dumped without their type classes.
"""

from types import SimpleNamespace
from unittest import mock

from fixturelib import enc, outcome, write

from ciplink import util
from ciplink.cip import DINT, STRING, UDINT, UINT, USINT
from ciplink.custom_types import StructTemplateAttributes
from ciplink.exceptions import ResponseError
from ciplink.logix_driver import (
    LogixDriver, _is_aoi, _nested_template_ids, _parse_structure_makeup_attributes, _read_reply_size,
    _split_tag_name, _tag_key, _tag_return_size, encode_value,
)
from ciplink.packets.util import parse_read_reply

# ---------------------------------------------------------------------------------------------- template building


def member(name, typ, offset, info=0):
    return name, typ, offset, info


def template(name, members, predefined=False):
    """raw template bytes: member infos, then the name ('NAME;n...' or, predefined, 'NAME' as the first name)"""
    infos = b"".join(UINT.encode(info) + UINT.encode(typ) + UDINT.encode(offset) for _, typ, offset, info in members)
    head = name if predefined else f"{name};nABCD1234"
    names = [head] + [m[0] for m in members]
    return infos + b"\x00".join(n.encode() for n in names) + b"\x00"


def makeup(raw, size, count, handle=0x1234):
    return {"object_definition_size": (len(raw) + 21 + 3) // 4, "structure_size": size, "member_count": count,
            "structure_handle": handle}


def tpl(name, members, size, predefined=False, handle=0x1234, raw=None):
    raw = raw if raw is not None else template(name, members, predefined)
    return makeup(raw, size, len(members), handle), raw


MYUDT = 0x101
STR20 = 0x103
OUTER = 0x104
AOI = 0x105
DEEP = 0x106
OVERLAP = 0x107
BITOUT = 0x108
STRINGT = 0xFCE
TIMER = 0xF83
COUNTER = 0xF82
CONTROL = 0xF84

TEMPLATES = {
    MYUDT: tpl("MyUDT", [
        member("A", 0xC4, 0), member("B", 0xCA, 4), member("ZZZZZZZZZZMyUDT2", 0xC2, 8),
        member("Flag", 0xC1, 8, 0), member("Flag2", 0xC1, 8, 3), member("Arr", 0xC4, 12, 3),
        member("Bits", 0xD3, 24, 1),
    ], 28, handle=0xAAAA),
    STR20: tpl("STR20", [member("LEN", 0xC4, 0), member("DATA", 0xC2, 4, 20)], 24),
    STRINGT: tpl("ASCIISTRING82", [member("LEN", 0xC4, 0), member("DATA", 0xC2, 4, 82)], 88, predefined=True,
                 handle=0x0FCE),
    OUTER: tpl("Outer", [
        member("In", 0x8000 | MYUDT, 0), member("Name", 0x8000 | STRINGT, 28),
        member("Items", 0x8000 | MYUDT, 116, 2), member("X", 0x20C4, 172), member("", 0xC2, 176),
        member("__Hidden", 0xC4, 180), member("Short", 0x8000 | STR20, 184), member("L", 0xC5, 208),
        member("Words", 0xD3, 216, 2),
    ], 224),
    DEEP: tpl("Deep", [member("O", 0x8000 | OUTER, 0), member("Z", 0xCB, 224)], 232),
    # members at the same offset, one going backwards, a bit member with a bit number >= 8
    OVERLAP: tpl("Overlap", [member("A", 0xC4, 0), member("B", 0xC4, 0), member("C", 0xC3, 2),
                             member("Hi", 0xC1, 0, 9)], 8),
    # a member past the structure size and a bit member past it: decoding fails, encoding grows the bytes
    BITOUT: tpl("BitOut", [member("X", 0xC4, 0), member("Y", 0xC4, 8), member("Flag", 0xC1, 6, 2)], 4),
    AOI: tpl("MyAOI", [
        member("EnableIn", 0xC1, 0, 0), member("EnableOut", 0xC1, 0, 1), member("ZZZZZZZZZZMyAOI0", 0xC2, 0),
        member("In", 0xC4, 4), member("Out", 0xCA, 8), member("Local", 0xC4, 12),
    ], 16),
    TIMER: tpl("TIMER", [
        member("CTL", 0xC4, 0), member("PRE", 0xC4, 4), member("ACC", 0xC4, 8),
        member("EN", 0xC1, 3, 7), member("TT", 0xC1, 3, 6), member("DN", 0xC1, 3, 5),
    ], 12, predefined=True),
    COUNTER: tpl("COUNTER", [
        member("CTL", 0xC4, 0), member("PRE", 0xC4, 4), member("ACC", 0xC4, 8), member("CU", 0xC1, 3, 7),
        member("CD", 0xC1, 3, 6), member("DN", 0xC1, 3, 5), member("OV", 0xC1, 3, 4), member("UN", 0xC1, 3, 3),
    ], 12, predefined=True),
    CONTROL: tpl("CONTROL", [
        member("Control", 0xC4, 0), member("LEN", 0xC4, 4), member("POS", 0xC4, 8),
        member("EN", 0xC1, 3, 7), member("DN", 0xC1, 3, 5), member("ER", 0xC1, 3, 3),
    ], 12, predefined=True),
}


def driver(templates, revision=33):
    plc = LogixDriver("1.2.3.4", init_tags=False)
    plc._info = {"revision": {"major": revision, "minor": 1}, "programs": {}, "tasks": {}, "modules": {}}
    for instance_id, (mk, raw) in templates.items():
        plc._cache["id:struct"][instance_id] = mk
        plc._cache["id:template"][instance_id] = (mk, raw)
    return plc


def no_reads():
    """a template missing from the cache fails as a read the controller refused"""
    return mock.patch.object(LogixDriver, "generic_message", side_effect=ResponseError("template not available"))


def copy_datatype(src):
    """LogixDriver.tags_json's copy: without type classes"""
    new = {k: v for k, v in src.items() if k not in {"type_class", "_struct_members"}}
    if isinstance(src.get("data_type"), dict):
        new["data_type"] = copy_datatype(src["data_type"])
    if "internal_tags" in src:
        new["internal_tags"] = {k: copy_datatype(v) for k, v in src["internal_tags"].items()}
    return new


def templates_json(templates):
    return [[i, mk, raw.hex()] for i, (mk, raw) in templates.items()]


# ---------------------------------------------------------------------------------------------- symbol lists


def symbol(instance, name, symbol_type, dims=(0, 0, 0), access=3, software_control=1 << 26, address=0x1000,
           object_address=0x2000, revision=33):
    data = UDINT.encode(instance) + STRING.encode(name) + UINT.encode(symbol_type) + UDINT.encode(address)
    data += UDINT.encode(object_address) + UDINT.encode(software_control) + b"".join(UDINT.encode(d) for d in dims)
    if revision >= 18:
        data += USINT.encode(access)
    return data


CONTROLLER_SYMBOLS = [
    (1, "Program:MainProgram", 0x1068), (2, "Program:Other", 0x1068), (3, "Task:MainTask", 0x1070),
    (4, "Map:Local", 0x1069), (5, "Cxn:Standard:1", 0x107E), (6, "Local:1:I", 0xC4), (7, "Local:1:O", 0xC4),
    (8, "Local:1:C", 0xC4), (9, "Local:I", 0xC4), (10, "Remote:1:2:I", 0xC4), (11, "Mod:x:O", 0xC4),
    (12, "__sys", 0xC4), (13, "sysbit", 0x10C4), (14, "a", 0xC4), (15, "b", 0x02C1), (16, "arr", 0x20C4, (10, 0, 0)),
    (17, "arr2", 0x40C4, (2, 3, 0)), (18, "arr3", 0x60C3, (2, 2, 2)), (19, "flags", 0x20D3, (3, 0, 0)),
    (20, "udt", 0x8000 | MYUDT), (21, "udts", 0xA000 | MYUDT, (2, 0, 0)), (22, "outer", 0x8000 | OUTER),
    (23, "text", 0x8000 | STRINGT), (24, "texts", 0xA000 | STRINGT, (2, 0, 0)), (25, "t1", 0x8000 | TIMER),
    (26, "c1", 0x8000 | COUNTER), (27, "ctl", 0x8000 | CONTROL), (28, "aoi", 0x8000 | AOI),
    (29, "s20", 0x8000 | STR20), (30, "unk", 0x0001), (31, "r", 0xCA), (32, "lr", 0xCB), (33, "l", 0xC5),
    (34, "si", 0xC2), (35, "ui", 0xC7), (36, "ul", 0xC9), (37, "Line1_Speed", 0xCA), (38, "Line1_Count", 0xC4),
    (39, "deep", 0x8000 | DEEP), (40, "w", 0xD2), (41, "str", 0xD0), (42, "Local:2:I", 0xC4), (43, "Local:2:C", 0xC4),
    (44, "ov", 0x8000 | OVERLAP), (45, "bo", 0x8000 | BITOUT), (46, "outers", 0xA000 | OUTER, (2, 0, 0)),
    (47, "bools", 0x20C1, (32, 0, 0)), (48, "empty", 0x20C4), (49, "unks", 0x2001, (2, 0, 0)),
    (50, "Local:01:I", 0xC4), (51, "Caf\xe9", 0xC4),
]
PROGRAM_SYMBOLS = {
    "MainProgram": [(1, "Routine:MainRoutine", 0x106D), (2, "Routine:Sub", 0x106D), (3, "p1", 0xC4),
                    (4, "pu", 0x8000 | MYUDT), (5, "Line1_P", 0xC4), (6, "__p", 0xC4)],
    "Other": [(1, "Routine:R", 0x106D), (2, "o1", 0xCA)],
}


def symbols_data(entries, revision=33):
    out = b""
    for i, entry in enumerate(entries):
        instance, name, typ, *rest = entry
        dims = rest[0] if rest else (0, 0, 0)
        sc = 0 if name == "a" else 1 << 26  # 'a' is an alias
        out += symbol(instance, name, typ, dims, access=i % 4, software_control=sc, revision=revision)
    return out


def parse_page(plc, data, status):
    tags = []
    nxt = plc._parse_instance_attribute_list(SimpleNamespace(data=data, service_status=status), tags)
    return {"next": nxt, "tags": tags}


def symbol_list_cases():
    cases = []
    for revision in (33, 18, 17, 0):
        plc = driver({}, revision)
        data = symbols_data(CONTROLLER_SYMBOLS[:8], revision)
        for status in (0, 6, 0x1E):
            cases.append({"revision": revision, "status": status, "data": data.hex(),
                          "result": outcome(parse_page, plc, data, status)})
        cases.append({"revision": revision, "status": 6, "data": "", "result": outcome(parse_page, plc, b"", 6)})
        for cut in (1, 5, len(data) - 1):
            cases.append({"revision": revision, "status": 0, "data": data[:cut].hex(),
                          "result": outcome(parse_page, plc, data[:cut], 0)})
    latin = symbol(7, "Caf\xe9\xff", 0xC4) + symbol(8, "x" * 300, 0xC4)
    cases.append({"revision": 33, "status": 0, "data": latin.hex(), "result": outcome(parse_page, driver({}), latin, 0)})
    big = symbol(0xFFFFFFFE, "big", 0xC4)
    plc = driver({}, 33)
    cases.append({"revision": 33, "status": 6, "data": big.hex(), "result": outcome(parse_page, plc, big, 6)})
    return cases


# ---------------------------------------------------------------------------------------------- makeups


def makeup_bytes(ods, size, count, handle, statuses=(0, 0, 0, 0)):
    return b"".join((
        UINT.encode(4),
        UINT.encode(4) + UINT.encode(statuses[0]) + UDINT.encode(ods),
        UINT.encode(5) + UINT.encode(statuses[1]) + UDINT.encode(size),
        UINT.encode(2) + UINT.encode(statuses[2]) + UINT.encode(count),
        UINT.encode(1) + UINT.encode(statuses[3]) + UINT.encode(handle),
    ))


def parse_makeup(data):
    try:
        value = StructTemplateAttributes.decode(data)
    except Exception:
        value = None  # generic_message leaves the value None when the data does not decode
    return _parse_structure_makeup_attributes(SimpleNamespace(value=value))


def makeup_cases():
    cases = []
    good = makeup_bytes(20, 88, 2, 0x0FCE)
    for data in (good, good + b"\x01\x02", makeup_bytes(0xFFFFFFFF, 1, 0xFFFF, 0), makeup_bytes(1, 2, 3, 4, (1, 2, 3, 4)),
                 good[:-1], good[:10], b""):
        cases.append({"data": data.hex(), "result": outcome(parse_makeup, data)})
    return cases


def template_read(ods, offset):
    return b"".join((DINT.encode(offset), UINT.encode(((ods * 4) - 21) - offset)))


def template_read_cases():
    return [{"ods": ods, "offset": offset, "result": outcome(template_read, ods, offset)}
            for ods, offset in ((20, 0), (20, 30), (20, 59), (20, 60), (100, 200), (5, 0), (16389, 0), (16390, 0),
                                (0, 0), (2**30, 2**31 - 1))]


def nested_cases():
    cases = []
    for instance_id, (mk, raw) in TEMPLATES.items():
        cases.append({"makeup": mk, "data": raw.hex(), "result": outcome(lambda: sorted(_nested_template_ids(raw, mk)))})
    mk = {"object_definition_size": 1, "structure_size": 4, "member_count": 3, "structure_handle": 0}
    for raw in (UINT.encode(0) + UINT.encode(0x8123) + UDINT.encode(0), UINT.encode(0) + UINT.encode(0x8123),
                UINT.encode(0) + b"\x23", b""):
        cases.append({"makeup": mk, "data": raw.hex(), "result": outcome(lambda: sorted(_nested_template_ids(raw, mk)))})
    return cases


# ---------------------------------------------------------------------------------------------- templates


def parse_template(templates, instance_id, symbol_type):
    plc = driver(templates)
    mk, raw = templates[instance_id]
    with no_reads():
        data_type = plc._parse_template_data(raw, mk, symbol_type)
    return {"data_type": copy_datatype(data_type),
            "data_types": {str(k): copy_datatype(v) for k, v in plc._data_types.items()}}


def template_cases():
    cases = []
    for instance_id in TEMPLATES:
        cases.append({"name": f"t{instance_id:x}", "templates": templates_json(TEMPLATES), "instance_id": instance_id,
                      "symbol_type": 0x8000 | instance_id,
                      "result": outcome(parse_template, TEMPLATES, instance_id, 0x8000 | instance_id)})
    odd = {
        # no ';' in a user type: no name
        0x200: tpl("x", [member("A", 0xC4, 0)], 4, raw=UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(0) + b"NoName\x00A\x00"),
        # predefined type without names at all
        0xF00: tpl("x", [member("A", 0xC4, 0)], 4, raw=UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(0)),
        # duplicate member names, unnamed members, an LOGIX_STRING (code 0) member, a struct code 0x8000
        0x201: tpl("Dup", [member("A", 0xC4, 0), member("A", 0xCA, 4), member("", 0xC2, 8), member("", 0xC2, 9),
                           member("S", 0x00, 12), member("Z", 0x8000, 16)], 20),
        # 'LEN'/'DATA' but DATA is not a SINT array
        0x202: tpl("NotStr", [member("LEN", 0xC4, 0), member("DATA", 0xC4, 4, 3)], 16),
        0x203: tpl("NotStr2", [member("LEN", 0xC4, 0), member("DATA", 0xC2, 4, 0)], 5),
        # zero length string array in a predefined type: max_len falls back to the size
        0xF01: tpl("SZ", [member("LEN", 0xC4, 0), member("DATA", 0xC2, 4, 0)], 8, predefined=True),
        # CTL/Control only private in predefined types
        0x204: tpl("Ctl", [member("CTL", 0xC4, 0), member("Control", 0xC4, 4)], 8),
        # template data shorter than its member infos
        0x205: tpl("Short", [member("A", 0xC4, 0)], 4, raw=b"\x00\x00\xc4"),
        0x206: tpl("Short2", [member("A", 0xC4, 0)], 4, raw=b""),
        # a nested template that is missing
        0x207: tpl("Missing", [member("M", 0x8999, 0)], 4),
        # a nested template that fails to parse
        0x208: tpl("BadNest", [member("M", 0x8205, 0)], 4),
        # invalid utf-8 in names, extra names, a ';' in a member name after the template name
        0x209: tpl("x", [member("A", 0xC4, 0), member("B", 0xC4, 4)], 8,
                   raw=UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(0) + UINT.encode(0) + UINT.encode(0xC4)
                   + UDINT.encode(4) + b"Bad\xff;n\x00A\xe9\x00B;x\x00extra\x00"),
        # invalid utf-8 sequences of several kinds: truncated, surrogate, overlong, lone continuation bytes
        0x20A: tpl("x", [member(str(i), 0xC4, 4 * i) for i in range(6)], 24,
                   raw=b"".join(UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(4 * i) for i in range(6))
                   + b"T\xe9\x80;n\x00\xe9\x80\x00\xf0\x9f\x98A\x00\xed\xa0\x80\x00\xc0\xafz\x00\xff\xfe\x00"
                   + b"\x80\xf4\x90\x80\x80\x00"),
        # a template name only after member names, ';' twice in a name
        0xF02: tpl("x", [member("A", 0xC4, 0)], 4, raw=UINT.encode(0) + UINT.encode(0xC4) + UDINT.encode(0) + b"A\x00N;x;y\x00"),
    }
    for instance_id in odd:
        cases.append({"name": f"odd{instance_id:x}", "templates": templates_json(odd), "instance_id": instance_id,
                      "symbol_type": 0x8000 | instance_id,
                      "result": outcome(parse_template, odd, instance_id, 0x8000 | instance_id)})
    # predefined decided by the symbol type passed in
    cases.append({"name": "symtype", "templates": templates_json(TEMPLATES), "instance_id": TIMER,
                  "symbol_type": 0x8000 | 0x123, "result": outcome(parse_template, TEMPLATES, TIMER, 0x8123)})
    return cases


# ---------------------------------------------------------------------------------------------- tag lists


def scopes(revision=33):
    return [[None, symbols_data(CONTROLLER_SYMBOLS, revision)]] + [
        [p, symbols_data(s, revision)] for p, s in PROGRAM_SYMBOLS.items()]


def isolate(templates, scope_data, namespace_filter, revision=33, info=None):
    plc = driver(templates, revision)
    if info is not None:
        plc._info.update(info)
    symbol_lists = []
    for program, data in scope_data:
        symbol_lists.append([program, parse_page(plc, data, 0)["tags"]])
    with mock.patch.object(LogixDriver, "_prefetch_templates"), no_reads():
        tags = plc._isolate_scopes(symbol_lists, namespace_filter)
    plc._tags = {t["tag_name"]: t for t in tags}
    return plc, tags


def tag_list(templates, scope_data, namespace_filter, revision=33, info=None):
    plc, tags = isolate(templates, scope_data, namespace_filter, revision, info)
    return {
        "tags": [copy_datatype(t) for t in tags],
        "info": {k: plc._info[k] for k in ("programs", "tasks", "modules")},
        "data_types": {str(k): copy_datatype(v) for k, v in plc._data_types.items()},
    }


def tag_list_cases():
    cases = []
    for name, sc, flt, revision, info in (
            ("all", scopes(), "", 33, None),
            ("filtered", scopes(), "Line1_", 33, None),
            ("v17", scopes(17), "", 17, None),
            ("controller_only", scopes()[:1], "", 33, None),
            ("program_without_controller", scopes()[1:2], "", 33, None),
            ("program_known", scopes()[1:2], "", 33, {"programs": {"MainProgram": {"instance_id": 9, "routines": ["X"]}}}),
    ):
        cases.append({"name": name, "templates": templates_json(TEMPLATES), "scopes": [[p, d.hex()] for p, d in sc],
                      "filter": flt, "revision": revision, "info": info and enc(info),
                      "result": outcome(tag_list, TEMPLATES, sc, flt, revision, info)})
    # a template that fails: the whole isolation fails with ResponseError
    broken = dict(TEMPLATES)
    broken[MYUDT] = (TEMPLATES[MYUDT][0], b"\x00")
    sc = scopes()[:1]
    cases.append({"name": "broken", "templates": templates_json(broken), "scopes": [[p, d.hex()] for p, d in sc],
                  "filter": "", "revision": 33, "info": None, "result": outcome(tag_list, broken, sc, "")})
    return cases


# ---------------------------------------------------------------------------------------------- reads and writes

PLC, _ = isolate(TEMPLATES, scopes(), "")


def info_of(tag):
    return PLC.get_tag_info(tag)


def read_reply(tag, data, elements):
    return list(parse_read_reply(data, info_of(tag), elements))


def struct_reply(tag, payload):
    return b"\xa0\x02" + UINT.encode(0x1234) + payload


def atomic_reply(code, payload):
    return UINT.encode(code) + payload


def udt_bytes(a=7, b=1.5, host=0b1001, arr=(1, 2, 3), bits=0x80000001):
    import struct as st
    return st.pack("<ifb3x3iI", a, b, host, *arr, bits)


def outer_bytes():
    import struct as st
    out = udt_bytes()
    out += st.pack("<I", 5) + b"hello" + bytes(77) + bytes(3)  # Name at 28 (88 bytes)
    out += udt_bytes(1, 2.0, 1, (4, 5, 6), 2) + udt_bytes(-1, -2.0, 8, (7, 8, 9), 0)  # Items at 116
    out += st.pack("<i", 42) + b"\x09" + bytes(3) + st.pack("<i", 99)  # X at 172, pad at 176, __Hidden at 180
    out += st.pack("<I", 2) + b"hi" + bytes(18)  # Short at 184
    out += st.pack("<q", -5) + st.pack("<II", 3, 0xFFFFFFFF)  # L at 208, Words at 216
    return out


def read_cases():
    import struct as st
    udt = udt_bytes()
    cases = [
        ("a", atomic_reply(0xC4, st.pack("<i", -3)), 1),
        ("a", atomic_reply(0xC4, st.pack("<i", -3)), 2),
        ("a", atomic_reply(0xC4, b"\x01\x02"), 1),
        ("a", atomic_reply(0xC4, b""), 1),
        ("a", b"", 1),
        ("b", atomic_reply(0xC1, b"\x01"), 1),
        ("r", atomic_reply(0xCA, st.pack("<f", 2.5)), 1),
        ("lr", atomic_reply(0xCB, st.pack("<d", -0.125)), 1),
        ("l", atomic_reply(0xC5, st.pack("<q", -(2**62))), 1),
        ("ul", atomic_reply(0xC9, st.pack("<Q", 2**64 - 1)), 1),
        ("w", atomic_reply(0xD2, st.pack("<H", 0x8001)), 1),
        ("str", atomic_reply(0xD0, b"\x03\x00abc"), 1),
        ("arr", atomic_reply(0xC4, st.pack("<10i", *range(10))), 10),
        ("arr", atomic_reply(0xC4, st.pack("<10i", *range(10))), 1),
        ("arr[3]", atomic_reply(0xC4, st.pack("<3i", 3, 4, 5)), 3),
        ("arr", atomic_reply(0xC4, st.pack("<2i", 1, 2)), 5),
        ("arr2", atomic_reply(0xC4, st.pack("<6i", *range(6))), 6),
        ("flags", atomic_reply(0xD3, st.pack("<I", 0x80000005)), 1),
        ("flags", atomic_reply(0xD3, st.pack("<2I", 1, 2)), 2),
        ("flags", atomic_reply(0xD3, b"\x01"), 1),
        ("udt", struct_reply("udt", udt), 1),
        ("udt", struct_reply("udt", udt[:20]), 1),
        ("udt", struct_reply("udt", udt[:8]), 1),
        ("udt", struct_reply("udt", b""), 1),
        ("udt", udt, 1),  # not a struct reply: decoded without the attribute filter
        ("udts", struct_reply("udts", udt + udt_bytes(1, 0.5, 0, (0, 0, 0), 0)), 2),
        ("udts", struct_reply("udts", udt), 1),
        ("udts", struct_reply("udts", udt), 2),
        ("udt.A", atomic_reply(0xC4, st.pack("<i", 5)), 1),
        ("udt.Arr", atomic_reply(0xC4, st.pack("<3i", 1, 2, 3)), 3),
        ("udt.Bits", atomic_reply(0xD3, st.pack("<I", 6)), 1),
        ("udt.Flag", atomic_reply(0xC1, b"\x01"), 1),
        ("outer", struct_reply("outer", outer_bytes()), 1),
        ("outer.In", struct_reply("outer", udt), 1),
        ("outer.Name", struct_reply("outer", st.pack("<I", 3) + b"abc" + bytes(79)), 1),
        ("outer.Items", struct_reply("outer", udt + udt), 2),
        ("outer.Items", struct_reply("outer", udt + udt), 1),
        ("outer.Words", atomic_reply(0xD3, st.pack("<2I", 1, 0x80000000)), 2),
        ("deep", struct_reply("deep", outer_bytes() + st.pack("<d", 1.25)), 1),
        ("text", struct_reply("text", st.pack("<I", 5) + b"hello" + bytes(79)), 1),
        ("text", struct_reply("text", st.pack("<I", 90) + b"x" * 84), 1),
        ("text", struct_reply("text", st.pack("<I", 5) + b"hel"), 1),
        ("texts", struct_reply("texts", (st.pack("<I", 1) + b"a" + bytes(83)) * 2), 2),
        ("s20", struct_reply("s20", st.pack("<I", 2) + b"hi" + bytes(18)), 1),
        ("t1", struct_reply("t1", st.pack("<iii", -(2**31) + 2**29, 1000, 250)), 1),
        ("c1", struct_reply("c1", st.pack("<Iii", 0xF8000000, 10, 3)), 1),
        ("ctl", struct_reply("ctl", st.pack("<Iii", 0xA8000000, 10, 3)), 1),
        ("aoi", struct_reply("aoi", st.pack("<Bxxxifi", 3, 7, 0.5, 9)), 1),
        ("Program:MainProgram.pu", struct_reply("pu", udt), 1),
        ("unk", atomic_reply(0x01, b"\x00"), 1),
        ("arr", atomic_reply(0xC4, st.pack("<10i", *range(10))), 0),
        ("udts", struct_reply("udts", udt + udt), 0),
        ("udts", struct_reply("udts", udt + udt[:2]), 2),
        ("udts", struct_reply("udts", udt + udt[:10]), 2),
        ("flags", atomic_reply(0xD3, st.pack("<3I", 1, 2, 3)), 0),
        ("ov", struct_reply("ov", st.pack("<ii", -1, 0x01020304)), 1),
        ("ov", struct_reply("ov", st.pack("<i", 7)), 1),
        ("bo", struct_reply("bo", st.pack("<i", 7)), 1),
        ("bo", struct_reply("bo", st.pack("<iii", 7, 8, 9)), 1),
        ("outers", struct_reply("outers", outer_bytes() + outer_bytes()[:20]), 2),
        ("bools", atomic_reply(0xC1, bytes(range(32))), 32),
        ("bools", atomic_reply(0xC1, b"\x01"), 1),
        ("empty", atomic_reply(0xC4, st.pack("<i", 4)), 1),
        ("empty", atomic_reply(0xC4, st.pack("<i", 4)), 0),
        ("unks", atomic_reply(0x01, b"\x00\x00"), 2),
        ("a", struct_reply("a", st.pack("<i", 1)), 1),
        ("udt.A", struct_reply("udt", st.pack("<i", 1)), 1),
    ]
    return [{"tag": tag, "data": data.hex(), "elements": n, "result": outcome(read_reply, tag, data, n)}
            for tag, data, n in cases]


def encode(tag, value, elements, bool_elements):
    return encode_value({"value": value, "elements": elements, "bool_elements": bool_elements,
                         "tag_info": info_of(tag)})


def encode_cases():
    udt_value = {"A": 7, "B": 1.5, "Flag": True, "Flag2": False, "Arr": [1, 2, 3], "Bits": [True] + [False] * 31}
    cases = [
        ("a", 5, 1, None), ("a", True, 1, None), ("a", 5.0, 1, None), ("a", 2**31, 1, None), ("a", b"\x01\x02", 1, None),
        ("a", [5], 1, None), ("a", "5", 1, None), ("a", None, 1, None),
        ("b", True, 1, None), ("b", 1, 1, None), ("b", 2, 1, None),
        ("r", 2.5, 1, None), ("r", 3, 1, None), ("r", 1e39, 1, None), ("lr", -0.1, 1, None),
        ("str", "abc", 1, None),
        ("w", [True] * 16, 1, None), ("w", [True] * 15, 1, None),
        ("arr", 5, 1, None), ("arr", [5], 1, None), ("arr", [1, 2], 1, None), ("arr", [], 1, None),
        ("arr", [1, 2, 3], 3, None), ("arr", [1, 2, 3, 4], 3, None), ("arr", [1, 2], 3, None),
        ("arr", [1, True, 3], 3, None), ("arr", list(range(1, 9)), 8, None), ("arr", 5, 3, None),
        ("arr", "abc", 3, None), ("arr", {"a": 1, "b": 2}, 2, None), ("arr", 5.5, 2, None), ("arr", "x" * 40, 2, None),
        ("arr", [2**40, 1], 2, None), ("arr", list(range(20)) + ["long string " * 5], 21, None),
        ("arr", b"\x01\x02\x03", 3, None), ("arr", (1, 2), 2, None), ("arr", [1, 2], 0, None),
        ("arr2", [1, 2, 3, 4, 5, 6], 6, None),
        ("flags", [True] * 32, 1, None), ("flags", [True] * 64, 2, None), ("flags", [True] * 33, 1, None),
        ("flags", [True] * 31, 1, None), ("flags", True, 1, None), ("flags", [True] * 3, 1, 3),
        ("flags", [True] * 40, 2, 40), ("flags", [True, False] * 32, 2, 64), ("flags", [True] * 32 + [2] * 32, 2, 64),
        ("udt", udt_value, 1, None),
        ("udt", {**udt_value, "ZZZZZZZZZZMyUDT2": 99}, 1, None),
        ("udt", {**udt_value, "Bad": 1, "Alsobad": 2}, 1, None),
        ("udt", {k: v for k, v in udt_value.items() if k != "A"}, 1, None),
        ("udt", {k: v for k, v in udt_value.items() if k != "Flag"}, 1, None),
        ("udt", {**udt_value, "Flag": 2}, 1, None),
        ("udt", {**udt_value, "Arr": [1, 2]}, 1, None),
        ("udt", {**udt_value, "Arr": [1, 2, 3, 4]}, 1, None),
        ("udt", list(udt_value.values()), 1, None),
        ("udt", "text", 1, None),
        ("udt", b"\x01" * 28, 1, None),
        ("udts", [udt_value, udt_value], 2, None), ("udts", udt_value, 1, None), ("udts", [udt_value], 2, None),
        ("udts", [udt_value, {"A": 1}], 2, None),
        ("udt.A", 9, 1, None), ("udt.Arr", [4, 5, 6], 3, None), ("udt.Arr", 4, 1, None), ("udt.Flag", True, 1, None),
        ("udt.Bits", [False] * 32, 1, None),
        ("outer.Name", "hello", 1, None), ("outer.Name", "x" * 83, 1, None), ("outer.Name", 5, 1, None),
        ("outer.Name", "é", 1, None), ("outer.Name", "日", 1, None),
        ("outer.Items", [udt_value, udt_value], 2, None),
        ("text", "x" * 82, 1, None), ("text", "", 1, None), ("text", "x" * 83, 1, None),
        ("texts", ["a", "b"], 2, None), ("texts", "ab", 2, None), ("texts", "abc", 2, None),
        ("s20", "y" * 20, 1, None), ("s20", "y" * 21, 1, None),
        ("t1", {"PRE": 1000, "ACC": 5, "EN": True, "TT": False, "DN": True}, 1, None),
        ("t1", {"PRE": 1000, "ACC": 5, "EN": True, "TT": False, "DN": True, "CTL": 7}, 1, None),
        ("ctl", {"LEN": 1, "POS": 2, "EN": 0, "DN": 1, "ER": False}, 1, None),
        ("aoi", {"EnableIn": True, "EnableOut": False, "In": 1, "Out": 2.0, "Local": 3}, 1, None),
        ("unk", 5, 1, None),
        ("Program:MainProgram.pu", udt_value, 1, None),
        ("flags", "x" * 64, 2, 64), ("flags", "1" * 32, 1, 32), ("flags", "x" * 31, 1, 31), ("flags", "", 1, None),
        ("flags", [], 1, None), ("flags", {}, 1, None), ("flags", {str(i): i for i in range(32)}, 1, 32),
        ("arr", [], 0, None), ("arr", list(range(10)), 0, None), ("arr", 5, 0, None), ("arr", [1, 2], 2, 0),
        ("ov", {"A": 1, "B": 2, "C": 3, "Hi": False}, 1, None), ("ov", {"A": 1, "B": 2, "C": 3, "Hi": True}, 1, None),
        ("bo", {"X": 1, "Y": 2, "Flag": True}, 1, None), ("bo", {"X": 1, "Y": 2, "Flag": False}, 1, None),
        ("outers", [udt_value], 2, None), ("outers", [{"In": 1}, {}], 2, None), ("outers", "ab", 2, None),
        ("bools", [True] * 32, 32, None), ("bools", [True, 2], 2, None), ("bools", 1, 1, None),
        ("empty", 5, 1, None), ("empty", [1, 2], 2, None), ("unks", [1, 2], 2, None), ("unks", 1, 1, None),
        ("udt", {}, 1, None),
        ("text", "\xff" * 3, 1, None), ("text", ["a"], 1, None), ("text", None, 1, None),
        ("udt.Bits", "x" * 32, 1, None), ("udt.Bits", [True] * 32, 1, 32),
    ]
    out = []
    for tag, value, elements, bool_elements in cases:
        out.append({"tag": tag, "value": enc(value) if not isinstance(value, tuple) else enc(list(value)),
                    "tuple": isinstance(value, tuple), "elements": elements, "bool_elements": bool_elements,
                    "result": outcome(encode, tag, value, elements, bool_elements)})
    # outer whole round trip: decode a reply then encode the value back
    value, _ = read_reply("outer", struct_reply("outer", outer_bytes()), 1)
    out.append({"tag": "outer", "value": enc(value), "tuple": False, "elements": 1, "bool_elements": None,
                "result": outcome(encode, "outer", value, 1, None)})
    value, _ = read_reply("deep", struct_reply("deep", outer_bytes() + bytes(8)), 1)
    out.append({"tag": "deep", "value": enc(value), "tuple": False, "elements": 1, "bool_elements": None,
                "result": outcome(encode, "deep", value, 1, None)})
    return out


# ---------------------------------------------------------------------------------------------- helpers


def tag_info_cases():
    cases = []
    for tag in ("a", "A", "udt", "UDT.a", "udt.Arr[1]", "udt[0].A", "outer.In.Flag", "outer.items.a", "nope",
                "udt.nope", "a.b", "Program:MainProgram.pu.A", "program:MainProgram.p1", "Program:mainprogram.p1",
                "Program:Other.o1", "Program:MainProgram", "outer.Name.LEN", "deep.O.In.B", "udt.Arr[1].x", "unk.x",
                "outer.Name.DATA", "outers[1].In.Flag", "udt.flag2", "OUTER.ITEMS.ARR", "caf\xe9", "CAF\xc9", "a.",
                ".a", "udt..A"):
        def info(tag=tag):
            got = PLC.get_tag_info(tag)
            return {"tag_name": got.get("tag_name"), "data_type_name": got["data_type_name"],
                    "offset": got.get("offset")}
        cases.append({"tag": tag, "result": outcome(info)})
    return cases


def size_cases():
    cases = []
    for tag in ("a", "b", "r", "l", "str", "flags", "udt", "outer", "text", "udt.A", "udt.Arr", "outer.In", "unk",
                "outers", "bools", "unks", "outer.Name", "udt.Flag", "lr", "w"):
        for elements in (0, 1, 3):
            tag_data = {"tag_info": info_of(tag), "elements": elements}
            cases.append({"tag": tag, "elements": elements, "return_size": outcome(_tag_return_size, tag_data),
                          "reply_size": outcome(_read_reply_size, tag_data)})
    return cases


def misc_cases():
    split = [{"tag": t, "result": outcome(lambda t=t: list(_split_tag_name(t)))} for t in (
        "a", "a.b.c", "Program:Main.x", "program:Main.x.y", "PROGRAM:Main.x", "Program:Main", "prog.x", "",
        "Program:", "a..b", "arr[1].x", "Program:Main.x[1,2].y.3", "progrAm:a.b", "Program\xe9:x", "\xe9.\xe9",
        "Program:.", ".", "program")]
    keys = {"Abc": 1, "abc": 2, "Def": 3, "ÄB": 4}
    tag_keys = [{"name": n, "result": outcome(_tag_key, keys, n)} for n in (
        "Abc", "abc", "ABC", "def", "DEF[3]", "nope", "x[1]", "äb", "Abc[", "[1]")]
    array_index = [{"tag": t, "result": outcome(lambda t=t: list(util.get_array_index(t)))} for t in (
        "tag[100]", "tag", "tag[1,2]", "tag[ 5 ]", "tag[-1]", "tag[+3]", "tag[1_0]", "tag[]", "tag[x]", "a[1].b[2]",
        "tag]", "[3]", "tag[1][2]", "tag[007]", "tag[1__0]", "tag[_1]", "tag[]]", "tag[-0]", "tag[\t7\n]",
        "tag[9223372036854775807]", "tag[\xe9]", "[]", "tag[1_]")]
    strip = [{"tag": t, "result": outcome(util.strip_array, t)} for t in ("tag[1]", "tag", "a[1].b[2]", "[x", "", "\xe9[1]", "[")]
    aoi = []
    for instance_id in TEMPLATES:
        dt = PLC._cache["id:udt"][instance_id]
        aoi.append({"name": dt["name"], "result": outcome(_is_aoi, dt)})
    return {"split_tag_name": split, "tag_key": tag_keys, "get_array_index": array_index, "strip_array": strip,
            "is_aoi": aoi}


def main():
    data = {
        "symbol_lists": symbol_list_cases(),
        "makeups": makeup_cases(),
        "template_reads": template_read_cases(),
        "nested_ids": nested_cases(),
        "templates": template_cases(),
        "tag_lists": tag_list_cases(),
        "tag_info": tag_info_cases(),
        "reads": read_cases(),
        "encodes": encode_cases(),
        "sizes": size_cases(),
        "main_templates": templates_json(TEMPLATES),
        "main_scopes": [[p, d.hex()] for p, d in scopes()],
    }
    data.update(misc_cases())
    write("logix_types.json", data)


if __name__ == "__main__":
    main()
