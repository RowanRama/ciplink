"""LogixDriver description and metadata authentication fixtures: the frames the Python LogixDriver sends, in order,
the replies it got and what each call returned, for the scenarios of tools/reference/tests/offline/test_logix_descriptions.py,
the driver parts of test_logix_metadata.py and test_logix_auth.py.

Every scenario runs the real driver (session, Forward Open, tag upload and all) against a scripted socket answered
by a simulated controller with a Description database, a Description index per language, program references,
templates with member identifiers and the metadata authentication handshake.  The Rust test replays the recorded
replies in order and must send the same frames and return the same results.  The Forward Open connection triad is
random; it is fixed to zeros here and masked on both sides.

A scenario is a list of steps; steps that change the simulated controller ('edit') are not replayed, their effect
is in the recorded replies.
"""

import json
import os
import struct
from unittest import mock

from fixturelib import ROOT, enc, write

import ciplink.cip_driver as cip_driver
from ciplink import LogixDriver, LogixMetadataCredentials
from ciplink.cip import STRING, UDINT, UINT, USINT
from ciplink.const import BASE_TAG_BIT
from ciplink.packets import TagTableVersionRequestPacket
from ciplink.tag import TagError
from tests.offline.test_logix_auth import CHALLENGE, GRANTS, KEY, certificate
from tests.offline.test_logix_tag_cache import makeup_data
from tests.offline.test_logix_tag_table_version import V1, version_reply
from tests.offline.test_logix_tag_upload import parse_path

CTX = b"_pycomm_"
CID = b"\xdd\xcc\xbb\xaa"


def encap(command, data, session=1, status=0):
    return struct.pack("<HHII", command, len(data), session, status) + CTX + bytes(4) + data


def cip(service, status=0, data=b"", ext=()):
    return bytes([service | 0x80, 0, status, len(ext)]) + b"".join(struct.pack("<H", e) for e in ext) + data


def rr_frame(reply):
    cpf = bytes(4) + b"\x0a\x00\x02\x00" + bytes(4) + b"\xb2\x00" + struct.pack("<H", len(reply)) + reply
    return encap(0x6F, cpf)


def unit_frame(seq, reply):
    msg = struct.pack("<H", seq) + reply
    cpf = bytes(4) + b"\x0a\x00\x02\x00" + b"\xa1\x00\x04\x00" + CID + b"\xb1\x00" + struct.pack("<H", len(msg)) + msg
    return encap(0x70, cpf)


def identity_data(product_name, major, serial, status=b"\x60\x30"):
    name = product_name.encode()
    return (struct.pack("<HHHBB", 1, 0x0E, 0x59, major, 11) + status + struct.pack("<I", serial)
            + bytes([len(name)]) + name)


def symbol(instance, name, symbol_type, d1=0, d2=0, d3=0):
    """one entry of a symbol list reply (attributes 1, 2, 3, 5, 6, 8, 10), Read/Write"""
    return b"".join((UDINT.encode(instance), STRING.encode(name), UINT.encode(symbol_type), UDINT.encode(0),
                     UDINT.encode(0), UDINT.encode(BASE_TAG_BIT), UDINT.encode(d1), UDINT.encode(d2),
                     UDINT.encode(d3), USINT.encode(3)))


def template(members, names, identifiers=()):
    """a raw template: (info, type, offset) members, the names (template name first) and member identifiers"""
    raw = b"".join(struct.pack("<HHI", *m) for m in members) + b"".join(n.encode() + b"\x00" for n in names)
    if identifiers:
        raw += bytes((-len(raw)) % 4) + b"".join(struct.pack("<H", i) for i in identifiers)
    return raw


def makeup(ods, size, count, handle):
    return {"object_definition_size": {"size": ods}, "structure_size": {"size": size},
            "member_count": {"count": count}, "structure_handle": {"handle": handle}}


SAMPLE = template([(0, 0xC2, 0), (0, 0xC1, 0), (0, 0xC4, 4)],
                  ["Sample;n0000", "ZZZZZZZZZZSample0", "Acked", "Value"], [0xEF1F, 0xEF20, 0xEF21])
# a template whose read (object definition size * 4 - 21 bytes) ends 3 bytes before its member identifiers end
SHORT = template([(0, 0xC2, 0), (0, 0xC1, 0), (0, 0xC4, 4)],
                 ["Short;n0000", "ZZZZZZZZZZShort0", "Acked", "Value"], [0xEE01, 0xEE02, 0xEE03])
assert (len(SHORT) - 3 + 21) % 4 == 0
OUTER = template([(0, 0x8592, 0), (0, 0xC4, 8)], ["Outer;n0000", "Inner", "X"])


def templates():
    return {
        0x592: (makeup((len(SAMPLE) + 21 + 3) // 4, 8, 3, 0x1111), SAMPLE),
        0x593: (makeup((len(SHORT) - 3 + 21) // 4, 8, 3, 0x2222), SHORT),
        0xFA0: (makeup((len(OUTER) + 21 + 3) // 4, 12, 2, 0x3333), OUTER),
    }


def scopes():
    return {
        None: [(1, "Matrix", 0x40C4, 3, 4), (50, "Bits", 0x20D3, 2), (60, "Shorts", 0xA593, 5),
               (100, "Outer", 0x8FA0), (155, "Program:Test", 0x1068), (156, "Program:P24", 0x1068),
               (157, "Program:P26", 0x1068), (425, "Array", 0x20C4, 30), (657, "Structs", 0xA592, 200),
               (1063, "Scalar", 0xC4)],
        "Test": [(1, "Routine:R", 0x106D), (8, "Input", 0xC1), (9, "Structs", 0xA592, 200)],
        "P24": [(1, "Routine:R", 0x106D), (8, "Input", 0xC1)],
        "P26": [(1, "Routine:R", 0x106D), (8, "Input", 0xC1)],
    }


def record(class_id, instance, owner, path, language, value, kind=1):
    raw_path = path.encode("utf-8")
    header = (struct.pack("<HIIHH", class_id, instance, *owner, len(raw_path)) + raw_path
              + struct.pack("<HHIIIIH", language, 1, 123, 0, 0, 0, kind))
    if kind == 4:
        return header
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return header + struct.pack("<H", len(raw)) + raw


def page(data=b"", first=True, last=True, offset=0):
    return struct.pack("<BBHI", 1, int(first) | (int(last) << 1), 0, offset) + data


TAG, PROGRAM = 0x6B, 0x68
TEST = 0x006B5ADA  # program Test's description instance: class 0x6B << 16 | program instance 0x5ADA


def descriptions():
    """(class, instance, owner instance, owner word, path, language): text"""
    english = 0x7F
    return {
        (TAG, 425, 0, 0, "", english): "Array text",
        (TAG, 425, 0, 0, "[0]", english): "Element text",
        (TAG, 425, 0, 0, "[5]", english): "",
        (TAG, 425, 0, 0, "[0].1", english): "Bit text",
        (TAG, 425, 0, 0, "[12]", english): "A long element text that spans several pages",
        (PROGRAM, TEST, 8, 0, "", english): "Program text",
        (PROGRAM, 0x006B001A, 8, 0, "", english): "P24 text",
        (PROGRAM, 0x006B5ADB, 8, 0, "", english): "P26 text",
        (TAG, 657, 0, 0, "[0].!0592EF20", english): "Member text",
        (TAG, 657, 0, 0, "[7]", english): "Element seven",
        (TAG, 100, 0, 0, ".!0FA00001.!0592EF20", english): "Nested text",
        (PROGRAM, TEST, 9, 0, "[2].!0592EF20", english): "Scoped member",
        (TAG, 1, 0, 0, "[2,3]", english): "Cell text",
        (TAG, 50, 0, 0, "[40]", english): "Bit forty",
        (TAG, 60, 0, 0, "[1].!0593EE02", english): "Short member",
        (TAG, 1063, 0, 0, "", 0x0409): "café".encode("cp1252"),
        (TAG, 1063, 0, 0, "", 0x0C0A): "señal",
    }


def index():
    """language: the Description index records (member defaults are class 0x6C records)"""
    return {
        0x7F: [record(PROGRAM, 12, (0, 0), "", 0x7F, b"\x80\x82\xff\x00"),
               record(PROGRAM, 13, (0, 0), "", 0x7F, None, kind=4),
               record(0x6C, 0x84FE0592, (0xEF20, 0), "", 0x7F, "Acked default"),
               record(0x6C, 0x84FE0592, (0xEF21, 0), "", 0x7F, "Value default"),
               record(0x6C, 0x84FE0593, (0xEE02, 0), "", 0x7F, "Short default")],
    }


class Controller:
    """the connected services: tag table version, symbol lists, makeups, templates, program references and
    Descriptions; ``once`` holds a general status to answer a Description request with, once"""

    def __init__(self):
        self.scopes, self.templates = scopes(), templates()
        self.descriptions, self.index = descriptions(), index()
        self.references = {155: bytes.fromhex("01000d0000000320682500da5a"),
                           156: bytes.fromhex("01000d000000022068241a"),
                           157: bytes.fromhex("01000d0000000420682600db5a0000")}
        self.overrides = {}  # request key: the record answered instead
        self.once = {}  # request key: a general status answered once
        self.page_size = 64
        self.rejected = set()

    def service(self, message):
        service, path, data = message[0], message[2:2 + 2 * message[1]], message[2 + 2 * message[1]:]
        if path[:4] == b"\x21\x00\x49\x03":
            return self.description(service, data)
        program, class_code, instance = parse_path(path)
        if class_code == 0xAC:
            return version_reply(TagTableVersionRequestPacket(1), V1).raw[46:]
        if service == 0x55 and program not in self.scopes:
            return cip(service, 0x05)
        if service == 0x55:
            entries = [e for e in self.scopes[program] if e[0] >= instance]
            return cip(service, 0, b"".join(symbol(*e) for e in entries))
        if service == 0x03 and class_code == 0x6C:
            return cip(service, 0, makeup_data(self.templates[instance][0]))
        if service == 0x4C and class_code == 0x6C:
            offset, size = struct.unpack("<IH", data[:6])
            return cip(service, 0, self.templates[instance][1][offset:offset + size])
        if service == 0x03 and class_code == 0x6B:
            reference = self.references[instance]
            return cip(service, 0, reference) if isinstance(reference, bytes) else cip(service, reference)
        return cip(service, 0x08)

    def description(self, service, data):
        offset = struct.unpack_from("<I", data, 4)[0]
        kind = struct.unpack_from("<H", data, 8)[0]
        if kind == 0x0C:
            language = struct.unpack_from("<H", data, 12)[0]
            key = ("index", language)
            payload = b"".join(self.index.get(language, []))
        else:
            class_id, instance, a, b, size = struct.unpack_from("<HIIHH", data, 12)
            path = data[26:26 + size].decode()
            language = struct.unpack_from("<H", data, 26 + size)[0]
            key = (class_id, instance, a, b, path, language)
            text = self.descriptions.get(key)
            payload = (self.overrides[key] if key in self.overrides
                       else b"" if text is None else record(class_id, instance, (a, b), path, language, text))
        if key in self.once:
            return cip(service, self.once.pop(key))
        chunk = payload[offset:offset + self.page_size]
        return cip(service, 0, page(chunk, offset == 0, offset + len(chunk) >= len(payload), offset))


class PLC:
    """a controller at frame level (as gen_logix_driver.py's), plus the metadata authentication handshake"""

    def __init__(self, product_name="1756-SIM/A", major=33):
        self.controller = Controller()
        self.product_name, self.major, self.serial = product_name, major, 0xC0FFEE01
        self.challenge = cip(0x4B, 0, CHALLENGE)
        self.completion = cip(0x4C, 0, GRANTS)

    def reply(self, frame):
        command = frame[0]
        if command == 0x65:
            return encap(0x65, b"\x01\x00\x00\x00")
        if command == 0x63:
            identity = identity_data(self.product_name, self.major, self.serial)
            item = struct.pack("<H", 1) + struct.pack(">hH", 2, 44818) + bytes([127, 0, 0, 1]) + bytes(8) + identity + b"\x03"
            return encap(0x63, struct.pack("<HHH", 1, 0x0C, len(item)) + item, session=0)
        if command == 0x6F:
            service = frame[40]
            if service in (0x54, 0x5B):
                return rr_frame(cip(service, data=CID + bytes(22)))
            if service == 0x4E:
                return rr_frame(cip(0x4E, data=bytes(10)))
            inner = frame[50] if service == 0x52 else service
            if inner == 0x01:
                return rr_frame(cip(0x01, data=identity_data(self.product_name, self.major, self.serial)))
            return rr_frame(cip(service, 0x08))
        if command == 0x70:
            at = 36 + UINT.decode(frame[34:36]) + 4
            seq = UINT.decode(frame[at:at + 2])
            return unit_frame(seq, self.connected_reply(frame[at + 2:]))
        raise ValueError(f"unexpected frame {frame.hex()}")

    def connected_reply(self, message):
        service, path = message[0], message[2:2 + 2 * message[1]]
        if path[:2] == b"\x20\x64":
            if service == 0x4B:
                return self.challenge
            if service == 0x4C:
                return self.completion
            return cip(service, data=UINT.encode(4) + b"PLCA")  # the program name
        if path[:2] == b"\x20\x8b":
            return cip(service, 0x08)
        c = self.controller
        if service != 0x0A:
            return c.service(message)
        body = message[2 + 2 * message[1]:]
        if "multi" in c.rejected:
            return cip(0x0A, 0x08)
        bounds = [UINT.decode(body[2 + 2 * i:4 + 2 * i]) for i in range(UINT.decode(body[:2]))] + [len(body)]
        replies = [c.service(body[start:end]) for start, end in zip(bounds, bounds[1:])]
        offsets, offset = [], 2 + 2 * len(replies)
        for reply in replies:
            offsets.append(UINT.encode(offset))
            offset += len(reply)
        status = 0x1E if any(reply[2] not in (0, 6) for reply in replies) else 0
        return cip(0x0A, status, UINT.encode(len(replies)) + b"".join(offsets) + b"".join(replies))


class Script:
    """the scripted socket: answers each frame with the PLC, records frames and replies (None: receive failed)"""

    def __init__(self, plc):
        self.plc = plc
        self.sent, self.replies = [], []
        self.fail_at = set()

    def connect(self, host, port):
        pass

    def send(self, msg, timeout=0):
        self.sent.append(bytes(msg))
        return len(msg)

    def receive(self, timeout=0):
        if len(self.replies) in self.fail_at:
            self.replies.append(None)
            raise OSError("connection lost")
        try:
            reply = self.plc.reply(self.sent[-1])
        except Exception:  # a bug of the simulation, not a scenario
            import traceback
            traceback.print_exc()
            raise SystemExit(1)
        self.replies.append(reply)
        return reply

    def settimeout(self, timeout):
        pass

    def close(self):
        pass


def tag_json(tag):
    error = tag.error
    return {"tag": tag.tag, "value": tag.value, "type": tag.type,
            "error": None if error is None else str(error),
            "kind": None if error is None else error.kind.value,
            "status": getattr(error, "status", None), "ext": getattr(error, "ext", None)}


SYNTHETIC = LogixMetadataCredentials(certificate(), KEY)


def run(plc, script, driver, step):
    call, *args = step
    if call == "edit":
        args[0](plc)
        return {"call": "edit"}, None
    if call == "fail_receive":
        script.fail_at.add(len(script.replies) + (args[0] if args else 0))
        return {"call": "fail_receive"}, None
    record_ = {"call": call}
    try:
        if call == "open":
            result = enc(driver.open())
        elif call == "close":
            result = enc(driver.close())
        elif call == "desc":
            names, language, encoding = args[0], args[1] if len(args) > 1 else 0x7F, args[2] if len(args) > 2 else "utf-8"
            record_.update(names=names, language=language, encoding=encoding)
            if len(names) == 1:
                tags = [driver.get_tag_description(names[0], language=language, encoding=encoding)]
            else:
                tags = driver.get_tag_descriptions(*names, language=language, encoding=encoding)
            result = [tag_json(t) for t in tags]
        elif call == "auth":
            record_["credentials"] = args[0]
            credentials = {"synthetic": SYNTHETIC, "bundled": None}[args[0]]
            result = tag_json(driver.authenticate_metadata(credentials))
        else:
            raise ValueError(call)
        return record_, {"ok": result}
    except Exception as err:
        result = {"err": type(err).__name__, "msg": str(err)}
        if err.args and isinstance(err.args[0], TagError):
            result["kind"] = err.args[0].kind.value
        return record_, result


def scenario(name, steps, options=None, **plc_args):
    plc = PLC(**plc_args)
    script = Script(plc)
    options = options or {}
    patches = [mock.patch.object(cip_driver, "Socket", lambda *a, **k: script),
               mock.patch.object(cip_driver, "urandom", lambda n: bytes(n))]
    for p in patches:
        p.start()
    try:
        driver = LogixDriver("1.2.3.4", **options)
        recorded, results = [], []
        for step in steps:
            record_, result = run(plc, script, driver, step)
            recorded.append(record_)
            results.append(result)
    finally:
        for p in reversed(patches):
            p.stop()
    return {"name": name, "options": options, "steps": recorded, "results": results,
            "sent": [s.hex() for s in script.sent],
            "replies": [None if r is None else r.hex() for r in script.replies]}


OPEN, CLOSE = ("open",), ("close",)


def desc(*names, language=0x7F, encoding="utf-8"):
    return ("desc", list(names), language, encoding)


def edit(fn):
    return ("edit", fn)


def setc(**values):
    return edit(lambda plc: [setattr(plc.controller, k, v) for k, v in values.items()])


def once(key, status):
    return edit(lambda plc: plc.controller.once.__setitem__(key, status))


def override(key, value):
    return edit(lambda plc: plc.controller.overrides.__setitem__(key, value))


def element(path, instance=425):
    return (TAG, instance, 0, 0, path, 0x7F)


INVALID = ["", "Array[-1]", "Array[30]", "Array[x]", "Array[0,1]", "Array[1][2]", "Scalar[0]", "Scalar.32",
           "Scalar.0.Member", "Array.0", "Array{2}", "Program:", "Program:Test", "Scalar..Member", "NoSuchTag",
           "Program:Main.Tag", "Scalar.Member", "Structs.Acked", "Matrix[3,0]", "Matrix[2]", "Bits[64]",
           "Structs[0].Nope", "Program:Test.Nope", "Array[0].32", "Array[0].1.2", "Array[0].01x", "Structs[0].0",
           "Array[0].Member", "Structs[0].Acked[1]", "Array [0]", "Matrix[0,0,0]", "Array[]", "Outer[0]"]

BAD_TEXTS = [(bytes.fromhex(raw), encoding) for raw, encoding in [
    ("ff", "utf-8"),
    ("61e282", "utf-8"),
    ("e28241", "utf-8"),
    ("f09f98", "utf-8"),
    ("eda080", "utf-8"),
    ("c080", "utf-8"),
    ("6f6bf8", "utf-8"),
    ("e080", "utf-8"),
    ("f4908080", "utf-8"),
    ("e282ac", "utf-8"),
    ("6162e9e9", "ascii"),
    ("78818d", "cp1252"),
    ("809f", "cp1252"),
    ("ff00", "latin-1"),
]]

SCENARIOS = [
    # test_logix_descriptions.py, the single reads
    scenario("elements", [OPEN, desc("Array[0]"), desc("Array[1]"), desc("Array[5]"), desc("Array[0].1"),
                          desc("array[00]"), desc("Array"), desc("Scalar"), desc("Bits[40]"), desc("Bits[63]")]),
    scenario("program_tag", [OPEN, desc("Program:Test.Input"), desc("program:test.input"), CLOSE, OPEN,
                             desc("Program:Test.Input"), desc("Program:P24.Input"), desc("Program:P26.Input"),
                             desc("Program:Nope.Input")]),
    scenario("invalid_program_references", [OPEN] + [
        step for raw in ["", "01000c0000000320682500da5a", "01000d00000003206a2500da5a", "01000d00000003206825000000",
                         "01000d000000042068260000000100", "01000d0000000320682400da5a", "01000d00000002206824"]
        for step in (edit(lambda plc, raw=raw: plc.controller.references.__setitem__(155, bytes.fromhex(raw))),
                     desc("Program:Test.Input"))
    ] + [edit(lambda plc: plc.controller.references.__setitem__(155, 0x08)), desc("Program:Test.Input")]),
    scenario("udt_members", [OPEN, desc("Structs[0].Acked"), desc("Structs[3].Acked"), desc("Structs[4].Acked"),
                             desc("Structs[7].Acked"), desc("Structs[8].Value"), desc("Structs[8].ZZZZZZZZZZSample0"),
                             desc("Outer.Inner.Acked"), desc("Outer.Inner.Value"), desc("Program:Test.Structs[2].Acked"),
                             desc("Shorts[1].Acked"), desc("Shorts[2].Acked"), desc("structs[0].ACKED")]),
    scenario("duplicate_member_defaults", [
        edit(lambda plc: plc.controller.index[0x7F].append(record(0x6C, 0x84FE0592, (0xEF20, 0), "", 0x7F, "Again"))),
        OPEN, desc("Structs[3].Acked"), desc("Structs[3].Value")]),
    scenario("member_index_failures", [
        OPEN, once(("index", 0x7F), 0x0F), desc("Structs[3].Acked"),
        edit(lambda plc: plc.controller.index.__setitem__(0x7F, [b"\x01\x02\x03"])), desc("Structs[3].Acked"),
        edit(lambda plc: plc.controller.index.__setitem__(0x7F, [record(0x6C, 0x84FE0592, (0xEF20, 0), "", 0x7F, "X")])),
        desc("Structs[3].Acked"), desc("Structs[4].Acked")]),
    scenario("short_template_identifiers", [OPEN, edit(lambda plc: plc.controller.templates.__setitem__(
        0x593, (plc.controller.templates[0x593][0], SHORT[:-25]))), desc("Shorts[1].Acked")]),
    scenario("wrong_targets", [
        OPEN,
        override(element("[3]"), record(TAG, 426, (0, 0), "[3]", 0x7F, "Wrong")), desc("Array[3]"),
        override(element("[4]"), record(TAG, 425, (0, 0), "[1]", 0x7F, "Wrong")), desc("Array[4]"),
        override(element("[6]"), record(PROGRAM, 425, (0, 0), "[6]", 0x7F, "Wrong")), desc("Array[6]"),
        override(element("[8]"), record(TAG, 425, (1, 0), "[8]", 0x7F, "Wrong")), desc("Array[8]"),
        override(element("[9]"), record(TAG, 425, (0, 1), "[9]", 0x7F, "Wrong")), desc("Array[9]"),
        override(element("[10]"), record(TAG, 425, (0, 0), "[10]", 0x0409, "Wrong")), desc("Array[10]"),
        override(element("[11]"), record(TAG, 425, (0, 0), "[11]", 0x7F, "x", kind=4)), desc("Array[11]"),
        override(element("[13]"), record(TAG, 425, (0, 0), "[13]", 0x7F, "a") * 2), desc("Array[13]"),
        override(element("[14]"), b"\x6b\x00"), desc("Array[14]"),
        override(element("[15]"), record(TAG, 425, (0, 0), "[15]", 0x7F, b"\xff")), desc("Array[15]"),
    ]),
    scenario("paging", [OPEN, setc(page_size=15), desc("Array[12]"), desc("Array[12]", "Array[0]"),
                        setc(page_size=0), desc("Array[12]")]),
    scenario("invalid_addresses", [OPEN] + [desc(name) for name in INVALID] + [desc(*INVALID)]),
    scenario("matrix", [OPEN, desc("Matrix[2,3]"), desc("Matrix[3,0]"), desc("Matrix[0,4]"), desc("Matrix[1,1]")]),
    scenario("statuses", [OPEN, once(element("[2]"), 0x0F), desc("Array[2]"), once(element("[2]"), 0x05),
                          desc("Array[2]"), once(element(""), 0x0F), desc("Array[17]"),
                          once(element("[0]"), 0x11), desc("Array[0]")]),
    scenario("batch", [
        OPEN, once(element("[2]"), 0x0F),
        desc("Array[0]", "Array[1]", "Array[0].1", "Program:Test.Input", "Structs[0].Acked", "Structs[1].Acked",
             "Scalar", "Array[30]", "Array[2]", "Missing"),
        once(element("[2]"), 0x0F),
        *[desc(name) for name in ["Array[0]", "Array[1]", "Array[0].1", "Program:Test.Input", "Structs[0].Acked",
                                  "Structs[1].Acked", "Scalar", "Array[30]", "Array[2]", "Missing"]],
        desc("Array[10]", "Array[10]", "Array[11]"),
        desc(*(f"Array[{i}]" for i in range(10))),
        desc("Array", "Array[3]", "Array[4]"),
        once(element(""), 0x0F), desc("Array[3]", "Array[4]", "Scalar"),
        desc("Structs[5].Acked", "Structs[6].Value", "Shorts[1].Acked", "Outer.Inner.X", "Program:P24.Input"),
    ]),
    scenario("batch_own_texts", [
        OPEN, edit(lambda plc: plc.controller.descriptions.update(
            {element(f"[{i}]"): f"Text {i}" for i in range(20)})),
        desc(*(f"Array[{i}]" for i in range(20))), setc(page_size=8), desc("Array[0]", "Array[1]")]),
    scenario("no_room", [
        OPEN, once(element("[0]"), 0x06), desc("Array[0]", "Array[1]"),
        once(element("[0]"), 0x11), desc("Array[0]", "Array[1]"),
        once(element("[1]"), 0x11), once(element("[0]"), 0x06), desc("Array[0]", "Array[1]", "Array[3]"),
        setc(rejected={"multi"}), desc("Array[0]", "Array[1]"),
    ]),
    scenario("small_connection", [OPEN, desc(*(f"Array[{i}]" for i in range(12)), "Structs[0].Acked")],
             options={"init_program_tags": False, "connection_size": 500}),
    scenario("connection_drop_in_batch", [OPEN, ("fail_receive", 0), desc("Array[0]", "Array[1]", "Array[30]")]),
    scenario("connection_drop_second_round", [OPEN, ("fail_receive", 1), desc("Array[0]", "Array[1]", "Array[2]")]),
    scenario("connection_drop_in_fallback", [OPEN, once(element("[0]"), 0x06), once(element("[1]"), 0x06),
                                             ("fail_receive", 1), desc("Array[0]", "Array[1]", "Array[3]")]),
    scenario("connection_drop_single", [OPEN, ("fail_receive", 0), desc("Array[0]"), desc("Array[0]")]),
    scenario("languages", [
        OPEN, desc("Scalar", language=0x0409, encoding="cp1252"), desc("Scalar", language=0x0409, encoding="utf-8"),
        desc("Scalar", language=0x0409, encoding="latin-1"), desc("Scalar", language=0x0409, encoding="ascii"),
        desc("Scalar", language=0x0C0A), desc("Scalar", "Array[0]", language=0x0C0A, encoding="cp1252"),
        desc("Structs[3].Acked", language=0x0C0A), desc("Array[1]", language=0xFFFF),
    ]),
    scenario("member_default_encodings", [OPEN, edit(lambda plc: plc.controller.index.update({
        language: [record(0x6C, 0x84FE0592, (0xEF20, 0), "", language, raw)]
        for language, (raw, _) in enumerate(BAD_TEXTS, 1)}))] + [
        desc("Structs[3].Acked", language=language, encoding=encoding)
        for language, (_, encoding) in enumerate(BAD_TEXTS, 1)]),
    scenario("lazy_tags", [OPEN, desc("Program:Test.Input"), desc("Structs[0].Acked"), desc("Program:Test.Structs[2].Acked"),
                           desc("Nope"), desc("Program:Nope.Input")], options={"lazy_tags": True}),
    scenario("lazy_program_reference", [OPEN, desc("Program:P24.Input"), desc("Program:P26.Input")],
             options={"lazy_tags": True}),
    scenario("micro800", [OPEN, desc("Array[0]", "Scalar"), ("auth", "synthetic")], product_name="2080-LC50-48QWB"),
    # Python's _reset_lazy_tags (open, tag table refresh) clears the Description caches too
    scenario("lazy_reopen", [OPEN, desc("Program:Test.Input"), desc("Structs[3].Acked"), CLOSE, OPEN,
                             desc("Program:Test.Input"), desc("Structs[3].Acked")], options={"lazy_tags": True}),
    # a failure while resolving one tag (program reference, template, member identifiers) is that tag's result
    scenario("resolve_comm_failures", [OPEN, ("fail_receive", 0), desc("Program:Test.Input", "Array[0]"), OPEN,
                                       ("fail_receive", 0), desc("Structs[0].Acked", "Array[1]"), OPEN,
                                       desc("Structs[0].Acked")]),
    scenario("member_identifier_continuation_failure", [OPEN, edit(lambda plc: plc.controller.templates.__setitem__(
        0x593, (plc.controller.templates[0x593][0], SHORT[:-5]))), ("fail_receive", 1), desc("Shorts[1].Acked"),
        OPEN, desc("Shorts[1].Acked")]),
    # test_logix_auth.py, the driver parts
    scenario("auth", [
        OPEN, ("auth", "synthetic"), ("auth", "bundled"),
        edit(lambda plc: setattr(plc, "challenge", cip(0x4B, 0x09))), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "challenge", cip(0x4B, 0, CHALLENGE))),
        edit(lambda plc: setattr(plc, "completion", cip(0x4C, 0x09))), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "completion", cip(0x4C, 0, struct.pack("<HHI", 1, 3, 1)))), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "completion", cip(0x4C, 0, GRANTS)[:-1])), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "completion", bytes([0xCB, 0, 0, 0]) + GRANTS)), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "completion", cip(0x4C, 0, GRANTS))),
        edit(lambda plc: setattr(plc, "challenge", bytes.fromhex("cc000000") + CHALLENGE)), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "challenge", cip(0x4B, 0, CHALLENGE[:-1]))), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "challenge", cip(0x4B, 0, b"\x80\x00" + bytes(128)))), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "challenge", cip(0x4B, 0, CHALLENGE, ext=(0x0101,)))), ("auth", "synthetic"),
        edit(lambda plc: setattr(plc, "challenge", cip(0x4B, 0, CHALLENGE))), ("auth", "synthetic"),
    ]),
    scenario("auth_connection_drop", [OPEN, ("fail_receive", 0), ("auth", "synthetic"), ("auth", "synthetic")]),
]

write("logix_descriptions.json", {
    "credentials": {"certificate": SYNTHETIC.certificate.hex(), "key": KEY.hex()},
    "scenarios": SCENARIOS,
})
