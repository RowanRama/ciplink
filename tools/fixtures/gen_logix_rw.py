"""LogixDriver read/write fixtures: the frames the Python LogixDriver sends, in order, the replies it got and what each
read and write returned, for the scenarios of tools/reference/tests/offline/test_logix_read_write.py, test_logix_transfers.py,
test_logix_request_paths.py, test_strict_writes.py, test_error_kinds.py and the read/write parts of
test_logix_tag_table_version.py and test_logix_aoi.py.

Every scenario runs the real driver (session, identity, Forward Open, tag list upload and all) against a scripted
socket answered by a simulated controller that keeps the bytes of its tags: tag reads (whole, elements, members, bits,
fragmented), writes (whole and fragmented) and read-modify-write masks act on them, by symbol instance ID or by name.
The Python offline tests' mocks of the driver internals become faults of the simulated controller (statuses,
partial replies, damaged or missing replies, edits of the tag table).  The Rust test replays the recorded replies in
order and must send the same frames and return the same results.  The Forward Open connection triad is random; it is
fixed to zeros here and masked on both sides.

Long lists are written compactly: {"ints": [n, ...]}, {"bools": "0110..."} and {"runs": [[value, count], ...]}.
"""

import json
import os
import re
import shutil
import struct
import tempfile
from unittest import mock

from fixturelib import FIXTURES, ROOT, enc

import ciplink.cip_driver as cip_driver
import ciplink.logix_driver as logix_driver
from ciplink import LogixDriver
from ciplink.cip import UINT, UDINT
from ciplink.exceptions import CommError
from tests.offline import test_logix_tag_upload as upload_tests
from tests.offline.test_logix_aoi import AOIController, CONTROLLER as AOI_CONTROLLER
from tests.offline.test_logix_tag_table_version import V1, V2, V3
from tests.offline.test_logix_tag_upload import Controller

CTX = b"_pycomm_"
CID = b"\xdd\xcc\xbb\xaa"


# ---- frames (as tools/fixtures/gen_logix_driver.py) ----

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


def identity_data(product_name, major, serial):
    name = product_name.encode()
    return (struct.pack("<HHHBB", 1, 0x0E, 0x59, major, 11) + b"\x60\x30" + struct.pack("<I", serial)
            + bytes([len(name)]) + name)


def multi_parts(message):
    """the services of a multi-service request"""
    body = message[2 + 2 * message[1]:]
    bounds = [UINT.decode(body[2 + 2 * i:4 + 2 * i]) for i in range(UINT.decode(body[:2]))] + [len(body)]
    return [body[start:end] for start, end in zip(bounds, bounds[1:])]


def multi_join(replies, status=None):
    offsets, offset = [], 2 + 2 * len(replies)
    for reply in replies:
        offsets.append(UINT.encode(offset))
        offset += len(reply)
    if status is None:
        status = 0x1E if any(reply[2] not in (0, 6) for reply in replies) else 0
    return cip(0x0A, status, UINT.encode(len(replies)) + b"".join(offsets) + b"".join(replies))


class PLC:
    """
    A controller at frame level: the session, Forward Open/Close, identity, program name and clock here, every other
    connected service answered by ``controller._service``, multi-service packets split and joined.  ``edits`` maps
    the index of a connected packet to a function run right before it is answered.  ``overrides`` are
    [predicate(message), fn(message, reply) -> CIP reply or ("frame", bytes), times (0: always)]: the first one
    matching a connected message changes its reply (the default reply is made first, edits and all).
    """

    def __init__(self, controller, product_name="1756-SIM/A", major=33, serial=0xC0FFEE01):
        self.controller = controller
        self.product_name, self.major, self.serial = product_name, major, serial
        self.connected = 0
        self.edits = {}
        self.overrides = []

    def edit_at(self, offset, fn):
        self.edits[self.connected + offset] = fn

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
            message = frame[at + 2:]
            reply = self.connected_reply(message)
            for override in self.overrides:
                predicate, fn, times = override
                if predicate(message):
                    if times == 1:
                        self.overrides.remove(override)
                    elif times:
                        override[2] -= 1
                    reply = fn(message, reply)
                    break
            if isinstance(reply, tuple):
                return reply[1]
            return unit_frame(seq, reply)
        raise ValueError(f"unexpected frame {frame.hex()}")

    def connected_reply(self, message):
        edit = self.edits.pop(self.connected, None)
        self.connected += 1
        if edit:
            edit()
        service, path = message[0], message[2:2 + 2 * message[1]]
        if path[:2] == b"\x20\x64":  # program name
            return cip(service, data=UINT.encode(4) + b"PLCA")
        c = self.controller
        c.left = c.capacity
        if service != 0x0A:
            return c._service(message, False)[1]
        services = multi_parts(message)
        return multi_join([c._service(s, True)[1] for s in services])


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
        reply = self.plc.reply(self.sent[-1])
        self.replies.append(reply)
        return reply

    def settimeout(self, timeout):
        pass

    def close(self):
        pass


# ---- the simulated controller with tag memory ----

SIZES = {0xC1: 1, 0xC2: 1, 0xC3: 2, 0xC4: 4, 0xC5: 8, 0xC6: 1, 0xC7: 2, 0xC8: 4, 0xC9: 8, 0xCA: 4, 0xCB: 8,
         0xD1: 1, 0xD2: 2, 0xD3: 4, 0xD4: 8}
FORMATS = {0xC1: "<B", 0xC2: "<b", 0xC3: "<h", 0xC4: "<i", 0xC5: "<q", 0xC6: "<B", 0xC7: "<H", 0xC8: "<I",
           0xC9: "<Q", 0xCA: "<f", 0xCB: "<d", 0xD1: "<B", 0xD2: "<H", 0xD3: "<I", 0xD4: "<Q"}
BOOL, SINT, INT, DINT, LINT, REAL, DWORD = 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xCA, 0xD3


def symbol(instance, name, symbol_type, d1=0, d2=0, d3=0):
    """a symbol list entry: Read/Write, '-' names have no external access"""
    return b"".join((
        UDINT.encode(instance), UINT.encode(len(name.lstrip("-"))), name.lstrip("-").encode(), UINT.encode(symbol_type),
        UDINT.encode(0), UDINT.encode(0), UDINT.encode(1 << 26),
        UDINT.encode(d1), UDINT.encode(d2), UDINT.encode(d3), bytes([3 if name.startswith("-") else 0]),
    ))


def template(name, members, size, handle):
    """(makeup, template) of a structure: members are (name, type, bit or array length, offset)"""
    data = b"".join(UINT.encode(i) + UINT.encode(t) + UDINT.encode(o) for _, t, i, o in members)
    data += f"{name};n0000\x00".encode() + b"".join(m.encode() + b"\x00" for m, *_ in members)
    makeup = {"object_definition_size": {"size": len(data) // 4 + 10}, "structure_size": {"size": size},
              "member_count": {"count": len(members)}, "structure_handle": {"handle": handle}}
    return makeup, data


def tag_segments(path):
    segments, i = [], 0
    while i < len(path):
        kind = path[i]
        if kind == 0x91:
            size = path[i + 1]
            segments.append(("name", path[i + 2:i + 2 + size].decode()))
            i += 2 + size + size % 2
        elif kind == 0x20:
            i += 2
        elif kind in (0x24, 0x28):
            segments.append(("id" if kind == 0x24 else "index", path[i + 1]))
            i += 2
        elif kind in (0x25, 0x29):
            segments.append(("id" if kind == 0x25 else "index", UINT.decode(path[i + 2:i + 4])))
            i += 4
        elif kind in (0x26, 0x2A):
            segments.append(("id" if kind == 0x26 else "index", UDINT.decode(path[i + 2:i + 6])))
            i += 6
        else:
            raise ValueError(f"segment {path[i:].hex()}")
    return segments


class RWController(Controller):
    """
    The upload Controller (symbol lists, makeups, templates, the tag table version) with tags it keeps the bytes
    of.  ``table`` is {name: (instance id, symbol type, dimensions, initial value)}, a name 'Program:P.x' is a
    program tag; a value is bytes, a number for every element, or a list of numbers.  ``fail`` maps a tag (as
    'arr[1]' or 'udt.Val') to the status, or (status, extended status), of its services; regular reads whose reply
    is longer than ``max_reply`` are partial (0x06), fragmented reads reply ``fragment`` bytes at a time.
    """

    def __init__(self, table, templates=None, version=V1):
        super().__init__()
        self.templates = dict(templates or {})
        self.fail = {}
        self.max_reply = None
        self.fragment = 2000
        self.fail_symbols = False
        self.set(table, version)

    def set(self, table, version=None):
        self.version = version
        self.scopes = {None: []}
        self.memory = {}
        programs = []
        for full, (instance, typ, dims, value) in table.items():
            scope, name = None, full
            if full.startswith("Program:"):
                scope, name = full[len("Program:"):].split(".", 1)
                if scope not in programs:
                    programs.append(scope)
                    self.scopes[None].append((900 + len(programs), f"Program:{scope}", 0x1068))
                    self.scopes[scope] = [(1, "Routine:R", 0x106D)]
            dims = tuple(dims) if isinstance(dims, (tuple, list)) else ((dims,) if dims else ())
            self.scopes[scope].append((instance, name, typ, *dims))
            self.memory[(scope, name.lstrip("-"))] = self._initial(typ, dims, value)

    def _size(self, typ):
        if typ & 0x8000:
            return self.templates[typ & 0xFFF][0]["structure_size"]["size"]
        return SIZES[typ & 0xFF]

    def _initial(self, typ, dims, value):
        count = 1
        for d in dims:
            count *= d
        size = self._size(typ)
        if isinstance(value, (bytes, bytearray)):
            return bytearray(value) + bytearray(max(0, count * size - len(value)))
        if typ & 0x8000 or value is None:
            return bytearray(count * size)
        values = value if isinstance(value, list) else [value] * count
        fmt = FORMATS[typ & 0xFF]
        return bytearray(b"".join(struct.pack(fmt, v) for v in values)) + bytearray(max(0, (count - len(values)) * size))

    def members(self, tid):
        makeup, data = self.templates[tid]
        n = makeup["member_count"]["count"]
        names = [x.decode() for x in data[8 * n:].split(b"\x00")]
        names = [x for x in names if ";" not in x][:n]
        out = {}
        for i, name in enumerate(names):
            info, typ, offset = struct.unpack("<HHI", data[8 * i:8 * i + 8])
            out[name] = (info, typ, offset)
        return out

    def resolve(self, path):
        """(tag, memory, byte offset, element type, bit or None, bytes left) of a tag request, None if unknown"""
        segments = tag_segments(path)
        scope = None
        if segments[0][0] == "name" and segments[0][1].startswith("Program:"):
            scope = segments.pop(0)[1][len("Program:"):]
            scope = next((s for s in self.scopes if s and s.lower() == scope.lower()), scope)
        kind, first = segments.pop(0)
        entry = next((e for e in self.scopes.get(scope, []) if
                      (e[0] == first if kind == "id" else e[1].lstrip("-").lower() == str(first).lower())), None)
        if entry is None or entry[2] & 0x1000:
            return None
        instance, name, typ, *dims = entry
        name = name.lstrip("-")
        memory = self.memory[(scope, name)]
        tag = (f"Program:{scope}." if scope else "") + name
        typ &= 0x8FFF
        typ = typ if typ & 0x8000 else typ & 0xFF
        offset, bit, end = 0, None, len(memory)
        index = []
        while segments and segments[0][0] == "index":
            index.append(segments.pop(0)[1])
        if index:
            flat = 0
            for i, value in enumerate(index):
                flat = flat * (dims[i] if i < len(dims) else 1) + value
            offset = flat * self._size(typ)
            tag += f"[{','.join(str(i) for i in index)}]"
        while segments:
            kind, member = segments.pop(0)
            if kind != "name" or not typ & 0x8000:
                return None
            members = {k.lower(): (k, v) for k, v in self.members(typ & 0xFFF).items()}
            if member.lower() not in members:
                return None
            real, (info, mtyp, moffset) = members[member.lower()]
            tag += f".{real}"
            offset += moffset
            if mtyp == BOOL:
                bit = info
                typ = BOOL
                end = offset + 1
                continue
            typ = mtyp if mtyp & 0x8000 else mtyp & 0xFF
            size = self._size(typ)
            end = offset + size * max(info, 1)
            while segments and segments[0][0] == "index":
                i = segments.pop(0)[1]
                tag += f"[{i}]"
                offset += i * size
        return tag, memory, offset, typ, bit, end - offset

    def header(self, typ):
        if typ & 0x8000:
            return b"\xa0\x02" + UINT.encode(self.templates[typ & 0xFFF][0]["structure_handle"]["handle"])
        return UINT.encode(typ)

    def _service(self, message, multi):
        service, path, data = message[0], message[2:2 + 2 * message[1]], message[2 + 2 * message[1]:]
        if service == 0x55 and (self.fail_symbols or upload_tests.parse_path(path)[0] not in self.scopes):
            return ("symbols",), cip(0x55, 0x08 if self.fail_symbols else 0x05)
        if service not in (0x4C, 0x4D, 0x4E, 0x52, 0x53) or path[:2] in (b"\x20\x6c", b"\x20\xac"):
            return super()._service(message, multi)
        found = self.resolve(path)
        if found is None:
            return ("tag",), cip(service, 0x05)
        tag, memory, offset, typ, bit, left = found
        kind = ("tag", tag)
        fault = self.fail.get(tag, self.fail.get(re.sub(r"\[[^]]*\]", "", tag)))
        if fault is not None:
            status, ext = fault if isinstance(fault, tuple) else (fault, None)
            return kind, cip(service, status, ext=() if ext is None else (ext,))
        size = 1 if bit is not None else self._size(typ)
        if service in (0x4C, 0x52):
            elements = UINT.decode(data[:2])
            if elements * size > left:
                return kind, cip(service, 0xFF, ext=(0x2105,))
            if bit is not None:
                value = bytes([(memory[offset] >> bit) & 1])
            else:
                value = bytes(memory[offset:offset + elements * size])
            if service == 0x52:
                start = UDINT.decode(data[2:6])
                piece = value[start:start + self.fragment]
                more = start + self.fragment < len(value)
                return kind, cip(service, 6 if more else 0, self.header(typ) + piece)
            reply = self.header(typ) + value
            if self.max_reply is not None and len(reply) > self.max_reply:
                return kind, cip(service, 0x06, reply[:self.max_reply])
            return kind, cip(service, 0, reply)
        if service == 0x4E:
            n = UINT.decode(data[:2])
            or_mask = int.from_bytes(data[2:2 + n], "little")
            and_mask = int.from_bytes(data[2 + n:2 + 2 * n], "little")
            value = int.from_bytes(memory[offset:offset + n], "little")
            memory[offset:offset + n] = ((value | or_mask) & and_mask).to_bytes(n, "little")
            return kind, cip(service, 0)
        header = 4 if data[:2] == b"\xa0\x02" else 2
        body = data[header + 2:]
        start = 0
        if service == 0x53:
            start, body = UDINT.decode(body[:4]), body[4:]
        if bit is not None:
            if body[:1] != b"\x00":
                memory[offset] |= 1 << bit
            else:
                memory[offset] &= ~(1 << bit) & 0xFF
            return kind, cip(service, 0)
        at = offset + start
        body = body[:max(0, offset + left - at)]
        memory[at:at + len(body)] = body
        return kind, cip(service, 0)


# ---- scenario runner ----

def compact(value):
    """enc() with long lists of ints or bools written compactly"""
    if isinstance(value, (list, tuple)) and len(value) > 16:
        if all(isinstance(v, bool) for v in value):
            return {"bools": "".join("1" if v else "0" for v in value)}
        if all(isinstance(v, int) and not isinstance(v, bool) for v in value):
            return {"ints": list(value)}
        runs = []
        for v in value:
            if runs and type(runs[-1][0]) is type(v) and runs[-1][0] == v:
                runs[-1][1] += 1
            else:
                runs.append([v, 1])
        if len(runs) * 4 < len(value):
            return {"runs": [[compact(v), n] for v, n in runs]}
    if isinstance(value, (list, tuple)):
        return {"list": [compact(v) for v in value]}
    if isinstance(value, dict):
        return {"dict": [[str(k), compact(v)] for k, v in value.items()]}
    return enc(value)


def tag_result(tag):
    error = tag.error
    return {
        "tag": tag.tag, "value": compact(tag.value), "type": tag.type,
        "error": None if error is None else str(error),
        "kind": None if error is None else tag.error_kind.value,
        "status": getattr(error, "status", None), "ext": getattr(error, "ext", None),
    }


class Runner:
    def __init__(self, plc, script, tmp):
        self.plc, self.script, self.tmp = plc, script, tmp
        self.driver = None
        self.now = [1000.0]

    def path(self, value):
        return os.path.join(self.tmp, "tags.json") if value == "<file>" else value

    def new(self, path, kwargs):
        kwargs = dict(kwargs)
        if "tag_cache_file" in kwargs:
            kwargs["tag_cache_file"] = self.path(kwargs["tag_cache_file"])
        self.driver = LogixDriver(path, **kwargs)

    def step(self, step):
        call, *args = step
        d = self.driver
        if call == "new":
            path, kwargs = args
            self.new(path, kwargs)
            return {"call": "new", "path": path, "options": kwargs}, None
        if call == "edit":
            args[0](self.plc)
            return {"call": "edit"}, None
        if call == "fail_receive":
            self.script.fail_at.add(len(self.script.replies) + (args[0] if args else 0))
            return {"call": "fail_receive"}, None
        if call == "advance":
            self.now[0] += args[0]
            return {"call": "advance", "seconds": args[0]}, None
        if call == "use_ids":
            d._cfg["use_instance_ids"] = args[0]
            return {"call": "use_ids", "on": args[0]}, None
        record = {"call": call}
        try:
            if call == "open":
                result = enc(d.open())
            elif call == "close":
                result = enc(d.close())
            elif call == "check":
                result = enc(d.check_tag_table())
            elif call == "list":
                result = enc(len(d.get_tag_list()))
            elif call == "read":
                record["tags"] = list(args)
                results = d.read(*args)
                results = results if isinstance(results, list) else [results]
                result = [tag_result(t) for t in results]
            elif call == "write":
                record["items"] = [[tag, compact(value)] for tag, value in args]
                results = d.write(*args)
                results = results if isinstance(results, list) else [results]
                result = [tag_result(t) for t in results]
            elif call == "version":
                result = {"version": enc(d._tag_table_version),
                          "ids": [[name, tag["instance_id"]] for name, tag in d._tags.items()]}
            else:
                raise ValueError(call)
            return record, {"ok": result}
        except Exception as err:
            result = {"err": type(err).__name__, "msg": str(err)}
            if err.args and hasattr(err.args[0], "kind"):
                result["kind"] = err.args[0].kind.value
            return record, result


def scenario(name, controller, steps, path="1.2.3.4", options=None, **plc_args):
    plc = PLC(controller, **plc_args)
    tmp = tempfile.mkdtemp()
    script = Script(plc)
    runner = Runner(plc, script, tmp)
    options = dict(options or {})
    patches = [
        mock.patch.object(cip_driver, "Socket", lambda *a, **k: script),
        mock.patch.object(cip_driver, "urandom", lambda n: bytes(n)),
        mock.patch.object(logix_driver.time, "monotonic", lambda: runner.now[0]),
        mock.patch.object(upload_tests, "_symbol", symbol),
    ]
    for p in patches:
        p.start()
    try:
        runner.new(path, options)
        recorded, results = [], []
        for step in steps:
            record, result = runner.step(step)
            recorded.append(record)
            results.append(result)
    finally:
        for p in reversed(patches):
            p.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    return {"name": name, "path": path, "options": options, "steps": recorded, "results": results,
            "sent": [s.hex() for s in script.sent],
            "replies": [None if r is None else r.hex() for r in script.replies]}


OPEN, CLOSE, CHECK, VERSION = ("open",), ("close",), ("check",), ("version",)
V20 = {"major": 20}
MICRO = {"major": 21, "product_name": "2080-LC50-48QWBS"}


def read(*tags):
    return ("read", *tags)


def put(*items):
    return ("write", *items)


def edit(fn):
    return "edit", fn


def controller_set(**values):
    return edit(lambda plc: [setattr(plc.controller, k, v) for k, v in values.items()])


def override(predicate, fn, times=1):
    return edit(lambda plc: plc.overrides.append([predicate, fn, times]))


def is_multi(message):
    return message[0] == 0x0A


def is_service(*services):
    return lambda message: message[0] in services


ANY = lambda message: True  # noqa: E731


def split_multi_reply(reply):
    """the service replies of a multi-service reply"""
    data = reply[4:]
    count = UINT.decode(data[:2])
    bounds = [UINT.decode(data[2 + 2 * i:4 + 2 * i]) for i in range(count)] + [len(data)]
    return [data[start:end] for start, end in zip(bounds, bounds[1:])]


def drop_last(message, reply):
    parts = split_multi_reply(reply)
    data = reply[4:]
    count = UINT.decode(data[:2])
    offsets = data[2:2 + 2 * count]
    return reply[:4] + data[:2] + offsets + b"".join(parts[:-1])


# ---- structures ----

MYUDT = template("MyUDT", [("Val", DINT, 0, 0), ("Data", DINT, 1000, 4), ("Flags", DWORD, 2, 4004)], 4012, 0x1234)
SMALL = template("Small", [("A", DINT, 0, 0), ("B", DINT, 0, 4)], 8, 0x2222)
STRICT = template("UDT", [("x", DINT, 0, 0), ("ZZZZZZZZZZhost", SINT, 0, 4), ("flag", BOOL, 0, 4)], 8, 0x3333)
STR82 = template("STR82", [("LEN", DINT, 0, 0), ("DATA", SINT, 82, 4)], 88, 0x4444)
TEMPLATES = {0x150: MYUDT, 0x151: SMALL, 0x152: STRICT, 0x153: STR82}


def ctl(table, version=V1, **values):
    c = RWController(table, TEMPLATES, version)
    for k, v in values.items():
        setattr(c, k, v)
    return c


# ---- test_logix_read_write.py ----

RW_TABLE = {
    "d": (5, DINT, 0, 0), "i": (6, DINT, 0, 0), "arr": (7, DINT | 0x2000, 1500, list(range(1500))),
    "udt": (8, 0x8151, 0, None), "r": (9, REAL, 0, 2.5), "Program:Main.t": (3, DINT, 0, 4),
}
ENCAP_ERROR = b"\x70\x00" + bytes(6) + b"\x64\x00\x00\x00" + bytes(12)


def rw_scenarios(suffix, **plc_args):
    return [
        scenario(f"rw_bit_write_values_{suffix}", ctl(RW_TABLE), [
            OPEN, put(("d.3", "False")), put(("d.3", "1"), ("i.2", "x")), put(("d.3", False)),
            put(("d.3", True), ("d.0", 1)), read("d", "d.3", "d.0", "d.1"),
        ], **plc_args),
        scenario(f"rw_write_order_{suffix}", ctl(RW_TABLE), [
            OPEN, put(("d.0", True), ("d", 0)), put(("arr{1500}", list(range(1500, 3000))), ("arr[0]", 5)),
            put(("d", 1), ("arr{996}", list(range(996))), ("i", 2)), put(("d.0", True), ("d.1", False)),
            put(("d", 7)), put(("arr{990}", list(range(990)))), read("d", "i", "arr[0]", "arr[995]", "arr[1499]"),
        ], **plc_args),
        scenario(f"rw_read_sizes_{suffix}", ctl(RW_TABLE), [
            OPEN, read("arr{1000}"), read("arr{997}", "d"), read("d", "arr{1200}", "i"), read("arr[1]{3}"),
            read("udt", "r", "udt.B"),
        ], **plc_args),
        scenario(f"rw_error_replies_{suffix}", ctl(RW_TABLE), [
            OPEN, override(is_multi, lambda m, r: cip(0x0A, 0x08)), read("d", "i"),
            override(ANY, lambda m, r: ("frame", ENCAP_ERROR)), read("d", "i"), OPEN,
            override(ANY, lambda m, r: ("frame", ENCAP_ERROR)), put(("d", 1), ("i", 2)), OPEN,
            override(ANY, lambda m, r: ("frame", ENCAP_ERROR)), read("arr{1000}"), OPEN, read("d"),
        ], **plc_args),
        scenario(f"rw_bad_requests_{suffix}", ctl(RW_TABLE), [
            OPEN, read("d", "arr[x]"), put(("d", 1), ("udt.3", True)), read("d{70000}"),
            *[read(t) for t in ("nope", "udt.nope", "d.nope", "r.1", "d.32", "d{0}", "d{x}", "d{70000}", "arr[-1]",
                                "arr[1,2]", "d{1}{2}", "d.31", "Program:Main", "Program:Nope.x", "arr{-1}",
                                "arr[5000000000]", "udt.A.0", "udt.A.32", "d.-1", "d{ 2 }", "x" * 300)],
            put(("arr[-1]", 1)), put(("udt", {"A": 1})), put(("udt", {"A": 1, "B": 2})),
            put(("udt", bytes(8))), put(("r", 1.5), ("r.1", True)), read("udt", "r"),
        ], **plc_args),
        scenario(f"rw_fragment_errors_{suffix}", ctl(RW_TABLE, fail={"arr": 0x0F}), [
            OPEN, put(("arr{200}", list(range(200)))), controller_set(fail={"arr": 0x05}), read("arr{1500}"),
            controller_set(fail={}, fragment=4), read("arr[1]{2}", "arr[3]{5}"),
        ], options={"connection_size": 100}, **plc_args),
        scenario(f"rw_case_insensitive_{suffix}", ctl(RW_TABLE), [
            OPEN, read("program:Main.t", "D", "ARR[1]", "Udt.a", "program:main.T"),
            put(("PROGRAM:Main.t", 5), ("ARR[2]", 9)), read("Program:Main.t", "arr[2]"),
        ], **plc_args),
    ]


SCENARIOS = rw_scenarios("ids") + rw_scenarios("names", **V20)


# ---- test_logix_transfers.py ----

def xfer(name, table, steps, options=None, plc_args=None, **values):
    return scenario(f"xfer_{name}", ctl(table, **values), [OPEN, *steps], options=options, **(plc_args or V20))


LONG = ["long_symbol_" + str(i).zfill(4) + "x" * 10 for i in range(20)]
FLAGS4 = {"flags": (1, DWORD | 0x2000, 4, 0xA5A5A5A5)}
MIXED = [
    [("number.0", True), ("number", 0)],
    [("number", 1), ("number.0", False)],
    [("number.0", True), ("number", 2), ("number.1", False)],
    [("number.0", True), ("other", 9), ("number.1", True)],
]

SCENARIOS += [
    *[xfer(f"batches_{size}", {t: (i + 1, DINT, 0, 12) for i, t in enumerate(LONG)}, [read(*LONG)],
           {"connection_size": size}) for size in (50, 100, 500, 4000)],
    xfer("fits_alone", {"a": (1, DINT | 0x2000, 122, 12), "b": (2, DINT, 0, 12)}, [read("a{122}", "b")],
         {"connection_size": 500}),
    *[xfer(f"bool_slice_{start}_{count}_{'micro' if micro else 'logix'}", FLAGS4, [
        put((f"flags[{start}]{{{count}}}", [i % 3 == 0 for i in range(count)])),
        read(f"flags[{start}]{{{count}}}", "flags[0]{128}"),
    ], {"connection_size": 500}, MICRO if micro else V20)
      for start, count in ((1, 2), (30, 5), (35, 40), (63, 2)) for micro in (False, True)],
    xfer("bool_slice_failure", {"flags": (1, DWORD | 0x2000, 3, 0)}, [put(("flags[31]{2}", [True, True]))],
         fail={"flags[0]": 5}),
    xfer("bool_slice_insufficient", {"flags": (1, DWORD | 0x2000, 3, 0)}, [
        put(("flags[30]{5}", [True])), put(("flags[30]{3}", [True, "False", True])),
        put(("flags[30]{2}", [True, False, True])), put(("flags[30]{2}", 1)), put(("flags[30]{2}", "ab")),
        put(("flags[30]{2}", {"a": 1})), put(("flags[0]{32}", [True] * 31 + [2])),
    ]),
    xfer("bit_outside_width", {"n8": (1, SINT, 0, 0), "n16": (2, INT, 0, 0), "n32": (3, DINT, 0, 0),
                               "n64": (4, LINT, 0, 0)},
         [put(("n8.8", True)), put(("n16.16", True)), put(("n32.32", True)), put(("n64.63", True)),
          put(("n8.7", True), ("n16.15", True)), read("n8", "n16", "n64", "n64.63", "n8.7")]),
    xfer("last_bit", {"number": (1, DINT, 0, 0)}, [put(("number.31", True)), read("number", "number.31")]),
    xfer("multidim_bit", {"grid": (1, DINT | 0x4000, (2, 3), 0)},
         [put(("grid[1,2].5", True)), read("grid[1,2]", "grid[1,2].5", "grid{6}")]),
    xfer("aligned_bool", {"flags": (1, DWORD | 0x2000, 3, 0)},
         [put(("flags[32]{64}", [True, False] * 32)), read("flags{3}", "flags[32]{64}", "flags[33]")]),
    xfer("single_write_payload", {"numbers": (1, DINT | 0x2000, 120, 0)},
         [put(("numbers{100}", list(range(100)))), read("numbers[99]")], {"connection_size": 500}),
    *[xfer(f"malformed_multi_{i}", {"a": (1, DINT, 0, 12), "b": (2, DINT, 0, 12)}, [
        override(is_multi, (lambda p: lambda m, r: cip(0x0A, 0, p))(payload)), read("a", "b"),
    ]) for i, payload in enumerate([b"", b"\x01\x00", b"\x02\x00\xff\xff\xff\xff", b"\x05\x00"])],
    xfer("embedded_error", {"a": (1, DINT, 0, 12), "b": (2, DINT, 0, 12)}, [read("a", "b")], fail={"a": 5}),
    xfer("extended_status_skipped", {"a": (1, DINT, 0, 42)}, [
        override(ANY, lambda m, r: r[:3] + b"\x01\x00\x00" + r[4:]), read("a"),
    ]),
    xfer("partial_fallback", {"numbers": (1, DINT | 0x2000, 3, [1, 2, 3])}, [read("numbers{3}")],
         max_reply=6, fragment=8),
    xfer("fragmented_no_progress", {"numbers": (1, DINT | 0x2000, 200, 0)}, [read("numbers{200}")],
         {"connection_size": 500}, fragment=0),
    xfer("fragmented_write_rejected", {"numbers": (1, DINT | 0x2000, 300, 0)},
         [put(("numbers{300}", list(range(300))))], {"connection_size": 500}, fail={"numbers": 5}),
    xfer("fragmented_write_header_too_big", {"very_long_symbol": (1, DINT | 0x2000, 2, 0)},
         [put(("very_long_symbol{2}", [1, 2]))], {"connection_size": 10}),
    xfer("large_read", {"numbers": (1, SINT | 0x2000, 80000, [i % 100 for i in range(80000)])},
         [read("numbers[10]{70000}")], fragment=3000),
    xfer("large_write", {"numbers": (1, SINT | 0x2000, 80000, 0)},
         [put(("numbers[10]{70000}", [i % 100 for i in range(70000)])), read("numbers[65544]{3}")]),
    xfer("large_write_bytes", {"numbers": (1, SINT | 0x2000, 80000, 0)},
         [put(("numbers{70000}", bytes(i % 7 for i in range(70000)))), put(("numbers{70000}", bytes(5))),
          read("numbers[65534]{3}")], fragment=3000),
    xfer("lazy_missing", {"a": (1, DINT, 0, 12)}, [read("missing", "a"), read("A")], {"lazy_tags": True}),
    xfer("scalar_bool_write", {"flags": (1, DWORD | 0x2000, 3, 0)},
         [put(("flags", True)), put(("flags", [False] * 4)), read("flags[0]", "flags", "flags[2]{3}")]),
    xfer("bool_word_masks_one_packet", {"flags": (1, DWORD | 0x2000, 4, 0)},
         [put(("flags[1]{70}", [True] * 70)), read("flags{4}")]),
    xfer("invalid_index", {"numbers": (1, DINT | 0x2000, 100, 0)}, [read("numbers[-1]"), put(("numbers[-1]", 1))]),
    *[xfer(f"mixed_order_{size}_{'micro' if micro else 'logix'}_{i}",
           {"number": (1, DINT, 0, 0), "other": (2, DINT, 0, 0)}, [put(*writes), read("number", "other")],
           {"connection_size": size}, MICRO if micro else V20)
      for size, micro in ((50, False), (500, False), (500, True)) for i, writes in enumerate(MIXED)],
    *[xfer(f"bool_array_masks_{size}_{'micro' if micro else 'logix'}", {"flags": (1, DWORD | 0x2000, 3, 0)}, [
        put(("flags[31]{2}", [True, True]), ("flags{64}", [False] * 64), ("flags[30]{3}", [True, False, True])),
        read("flags{64}"),
    ], {"connection_size": size}, MICRO if micro else V20)
      for size, micro in ((50, False), (500, False), (500, True))],
    xfer("mask_group_errors", {"number": (1, DINT, 0, 0)}, [
        override(is_service(0x4E), lambda m, r: cip(0x4E, 5)),
        put(("number.0", True), ("number", 2), ("number.1", False)), read("number"),
    ], plc_args=MICRO),
    xfer("lazy_comm_error", {"a": (1, DINT, 0, 12)}, [("fail_receive",), read("a")], {"lazy_tags": True}),
    xfer("failed_partial_fallback", {"a": (1, DINT, 0, 12), "b": (2, DINT, 0, 12)}, [
        override(lambda m: m[0] == 0x0A, lambda m, r: multi_join(
            [cip(0x4C, 6, b"\xc4\x00")] + [p for p in split_multi_reply(r)[1:]])),
        override(is_service(0x52), lambda m, r: cip(0x52, 0x08)), read("a", "b"),
    ]),
    xfer("lazy_case_insensitive", {"MyTag": (1, DINT, 0, 3)}, [read("mytag", "MYTAG", "MyTag")], {"lazy_tags": True}),
    xfer("large_read_chunk_fails", {"numbers": (1, SINT | 0x2000, 80000, 0), "d": (2, DINT, 0, 4)},
         [read("d", "numbers{70000}", "d")], fragment=3000, fail={"numbers[65535]": 0x05}),
    # a refused chunk keeps its kind (ACCESS) in the merged result, the other chunk still goes
    xfer("large_chunk_access_denied", {"numbers": (1, SINT | 0x2000, 80000, 0), "d": (2, DINT, 0, 4)},
         [read("numbers{70000}", "d"), put(("numbers{70000}", bytes(70000)), ("d", 1)), read("d")],
         fragment=3000, fail={"numbers[0]": 0x0F}),
    xfer("large_write_chunk_bad_value", {"numbers": (1, SINT | 0x2000, 80000, 0)},
         [put(("numbers{70000}", [1] * 65535 + ["x"] + [2] * 4464)), read("numbers[65534]{3}")]),
    xfer("duplicates_and_bytes", {"d": (1, DINT, 0, 4), "arr": (2, DINT | 0x2000, 3, 0)}, [
        read("d", "d", "arr{3}", "d"), put(("arr{3}", bytes(range(12))), ("d", 5), ("d.1", True), ("d", 6)),
        read("arr{3}", "d"), put(("arr", bytes(3))), put(("arr{2}", bytes(16))), read("arr{3}"),
    ]),
]


# ---- test_logix_request_paths.py ----

PATHS_TABLE = {
    "d": (5, DINT, 0, 0), "arr": (7, DINT | 0x2000, 1500, 0), "udt": (8, 0x8150, 0, None),
    "udts": (12, 0xA150, 3, None), "bools": (13, DWORD | 0x2000, 2, 0), "big": (11, DINT | 0x2000, 70000, 0),
    "Program:Main.ptag": (9, 0x8150, 0, None), "Program:Main.parr": (10, DINT | 0x2000, 10, 0),
    "Program:Main.pbig": (14, DINT | 0x2000, 70000, 0),
}
EDITED_D = dict(PATHS_TABLE, d=(42, DINT, 0, 0))

SCENARIOS += [
    scenario("paths_reads_and_writes", ctl(PATHS_TABLE, fail={"big": 0x08, "Program:Main.pbig": 0x08}), [
        OPEN, read("d", "arr[5]", "udt.Val", "udts[2].Val"),
        read("Program:Main.parr", "program:Main.parr[3]", "Program:Main.ptag.Val"),
        read("d.3", "udt.Val.3", "Program:Main.ptag.Val.3", "bools[40]", "udt.Flags[40]"),
        read("Program:Main.pbig{1500}"),
        put(("udt.Val", 1), ("Program:Main.parr[3]", 2), ("d.3", True)),
        put(("Program:Main.ptag.Val.0", True), ("udt.Flags[40]", True)),
        put(("bools[30]{4}", [True, False, True, True])), put(("udt.Data{1000}", list(range(1000)))),
        read("udt.Val", "Program:Main.parr[3]", "d", "Program:Main.ptag.Val", "udt.Flags[40]", "bools[30]{4}",
             "udt.Data[999]", "udt.Flags{2}", "udts[2].Flags[1]"),
        read("big{70000}"), put(("Program:Main.pbig{70000}", list(range(70000)))),
        ("use_ids", False), read("arr[5]", "udt.Val", "Program:Main.ptag.Val"), put(("d.3", True)),
        ("use_ids", True), read("d"),
        edit(lambda plc: plc.controller.set(EDITED_D, V2)), CHECK, VERSION, read("d"), ("use_ids", False), read("d"),
        ("use_ids", True), read("d", "late"),
        edit(lambda plc: plc.controller.set(dict(EDITED_D, late=(30, DINT, 0, 0)), V3)), CHECK, read("late"),
    ]),
    scenario("paths_member_bool_slices", ctl(PATHS_TABLE), [
        OPEN, put(("udt.Flags[30]{4}", [True, False, True, True]), ("Program:Main.ptag.Flags[62]{2}", [True, True]),
                  ("udts[1].Flags[33]", True), ("udt.Flags[0]{64}", [False, True] * 32)),
        read("udt.Flags{2}", "Program:Main.ptag.Flags[30]{34}", "udts[1].Flags[33]", "udts[1].Flags"),
        put(("udt.Val.31", True), ("udts[2].Val.0", 1)), read("udt.Val", "udts[2].Val"),
    ], options={"connection_size": 120}),
    scenario("paths_udt_whole", ctl({"udt": (8, 0x8150, 0, None), "Program:Main.ptag": (9, 0x8150, 0, None)}), [
        OPEN, put(("udt", {"Val": 3, "Data": list(range(1000)), "Flags": [True, False] * 32})),
        read("udt.Val", "udt.Data[2]", "udt.Flags{2}"), read("udt"), read("Program:Main.ptag"),
    ]),
]


# ---- test_strict_writes.py ----

STRICT_TABLE = {
    "a": (1, DINT, 0, 0), "arr": (2, DINT | 0x2000, 3, 0), "big": (3, DINT | 0x2000, 70000, 0),
    "b": (4, BOOL, 0, 0), "r": (5, REAL, 0, 0), "flags": (6, DWORD | 0x2000, 3, 0), "s": (7, 0x8152, 0, None),
    "text": (8, 0x8153, 0, None),
}
REJECTED = [
    ("arr{3}", [1, 2, 3, 4]), ("arr", [1, 2]), ("flags[0]{32}", [True] * 33), ("flags[1]{3}", [True] * 4),
    ("big{70000}", [1] * 70001),
    ("b", 2), ("b", 1.0), ("b", "True"), ("a.3", 2), ("a.3", 0.5), ("flags[1]", 2),
    ("flags[1]{2}", [True, 2]), ("flags[0]{32}", [True] * 31 + [2]),
    ("a", True), ("r", False), ("arr{2}", [1, True]), ("a", 5.0),
    ("s", {"x": 1, "flag": True, "y": 2}), ("s", {"flag": True}), ("s", {"x": 1, "flag": 2}),
    ("text", "x" * 83), ("a", "x"), ("arr{3}", [1]), ("big{70000}", [1]), ("big{70000}", b"\0"), ("a", [1, 2]),
    ("a", 2 ** 31), ("text", 5), ("s", [1, 2]),
]
FITS = [
    ("arr{3}", [1, 2, 3]), ("arr", [5]), ("arr", 5), ("flags[0]{32}", [True] * 32), ("flags[1]{3}", [1, 0, True]),
    ("b", True), ("b", 0), ("a.3", 1), ("a.3", False), ("r", 5), ("r", 2.5),
    ("s", {"x": 1, "flag": True}), ("s", {"x": 1, "flag": 0, "ZZZZZZZZZZhost": 0}), ("text", "x" * 82),
    ("text", "héllo"), ("a", -5),
]

SCENARIOS += [
    scenario("strict_rejected", ctl(STRICT_TABLE), [OPEN, *[put(w) for w in REJECTED]], **V20),
    scenario("strict_fits", ctl(STRICT_TABLE), [
        OPEN, *[put(w) for w in FITS], read("a", "arr{3}", "b", "r", "flags{3}", "s", "text"),
    ], **V20),
    scenario("strict_other_tags_still_go", ctl(STRICT_TABLE), [OPEN, put(("arr{3}", [1, 2, 3, 4]), ("a", 5))], **V20),
]


# ---- test_error_kinds.py ----

AB = {"a": (1, DINT, 0, 12), "b": (2, DINT, 0, 12), "r": (3, REAL, 0, 0), "arr": (4, DINT | 0x2000, 3, 0),
      "big": (5, DINT | 0x2000, 300, 0)}

SCENARIOS += [
    *[scenario(f"kinds_failed_read_{status:02x}", ctl(AB, fail={"a": status}), [
        OPEN, read("a"), read("a", "b"), put(("a", 1)), put(("a", 1), ("b", 2)),
    ], **V20) for status in (0x04, 0x05, 0x0F, 0x10, 0x11, 0x08, 0x13)],
    scenario("kinds_extended_status", ctl(AB, fail={"a": (0xFF, 0x2104)}), [
        OPEN, read("a", "b"), controller_set(fail={"a": (0xFF, 0x2107)}), put(("a", 1)), read("a"),
        controller_set(fail={"a": (0xFF, 0x2001)}), read("a"),
    ], **V20),
    scenario("kinds_lost_replies", ctl(AB), [
        OPEN, override(is_multi, lambda m, r: cip(0x0A, 0, b"\x05\x00")), read("a", "b"),
        override(is_multi, drop_last), read("a", "b"), override(is_multi, drop_last), put(("a", 3), ("b", 4)),
        override(ANY, lambda m, r: r[:4] + b"\xc4"), read("a"),
        override(ANY, lambda m, r: r[:4]), read("a"),
        override(ANY, lambda m, r: r[:2]), read("a"),
        override(ANY, lambda m, r: cip(0x4C, 0, b"\xc3\x00\x01\x00")), read("a"),
        override(ANY, lambda m, r: cip(0x4C, 0, b"\xa0\x02\x01\x00" + bytes(4))), read("a"),
    ], **V20),
    scenario("kinds_fragmented_no_progress", ctl(AB, fragment=0), [OPEN, read("big{300}")],
             options={"connection_size": 500}, **V20),
    scenario("kinds_fragment_type_changed", ctl(AB, fragment=400), [
        OPEN, override(is_service(0x52), lambda m, r: r, 1),
        override(is_service(0x52), lambda m, r: r[:4] + b"\xc3\x00" + r[6:], 0), read("big{300}"),
    ], options={"connection_size": 500}, **V20),
    scenario("kinds_bad_requests", ctl(AB), [
        OPEN, *[read(t) for t in ("nope", "a.nope", "r.1", "a.32", "a{0}", "a{x}", "a{70000}")],
    ], **V20),
    scenario("kinds_lazy_nope", ctl(AB), [OPEN, read("nope"), read("a.b.c"), read("Program:X.y")],
             options={"lazy_tags": True}, **V20),
    scenario("kinds_bad_values", ctl(AB), [
        OPEN, put(("a", "x")), put(("arr{3}", [1])), put(("big{70000}", [1])), put(("big{70000}", b"\0")),
    ], **V20),
]


# ---- test_logix_tag_table_version.py (reads and writes) ----

TAGS = {"a": (5, DINT, 0, 1), "b": (6, DINT, 0, 2), "arr": (7, DINT | 0x2000, 1500, list(range(1500))),
        "arr2": (8, DINT | 0x2000, 1500, list(range(1500, 3000)))}
EDITED = {"a": (5, DINT, 0, 1), "x": (6, DINT, 0, 99), "b": (9, DINT, 0, 2),
          "arr": (7, DINT | 0x2000, 1500, list(range(1500))), "arr2": (8, DINT | 0x2000, 1500, list(range(1500, 3000)))}
MOVED = dict(TAGS, arr=(10, DINT | 0x2000, 1500, list(range(1500))))


def tset(table, version):
    """an online edit: the new tag table (values from the table) and its version"""
    return lambda plc: plc.controller.set(table, version)


def at(offset, table, version):
    """the edit right before the connected packet ``offset`` packets from now"""
    return edit(lambda plc: plc.edit_at(offset, lambda: plc.controller.set(table, version)))


def ver(name, steps, table=TAGS, version=V1, options=None, **plc_args):
    return scenario(f"ver_{name}", ctl(table, version), [OPEN, *steps], options=options, **plc_args)


SCENARIOS += [
    ver("check_first_service", [read("a", "b"), read("b")]),
    ver("packing_budget", [read(*(f"t{i}" for i in range(7)))], {f"t{i}": (10 + i, DINT, 0, i) for i in range(7)},
        options={"connection_size": 88}),
    ver("fragmented_between_checks", [read("a", "arr{1500}", "arr2{1500}")]),
    ver("partial_reply_followed_by_check", [controller_set(max_reply=100), read("arr{900}"), read("a", "arr{900}")]),
    ver("change_during_read", [at(0, EDITED, V2), read("a", "b"), VERSION]),
    ver("change_during_fragmented_read", [at(2, MOVED, V2), read("arr{1500}"), VERSION]),
    ver("second_change", [at(0, EDITED, V2), at(3, dict(EDITED, b=(11, DINT, 0, 2)), V3), read("a", "b"), read("b"),
                          VERSION]),
    ver("packet_failed_whole", [override(is_multi, lambda m, r: cip(0x0A, 0x11)), read("a"), VERSION]),
    ver("failed_check_backs_off", [
        at(0, TAGS, None), read("a"), edit(tset(EDITED, V2)), ("advance", 1.9), read("a"), read("a", "b"),
        put(("b", 20)), CHECK, ("advance", 0.1), read("b"), VERSION,
    ]),
    ver("failed_reload_backs_off", [
        edit(tset(EDITED, V2)), controller_set(fail_symbols=True), read("b"), read("b"), put(("b", 20)),
        ("advance", 2.0), controller_set(fail_symbols=False), read("b"), put(("b", 20)), read("b", "x"), VERSION,
    ]),
    ver("download_during_connect_upload", [
        CLOSE, edit(lambda plc: plc.edit_at(3, lambda: setattr(plc.controller, "version", None))), OPEN, read("a"),
        edit(tset(EDITED, V2)), ("advance", 2.0), read("b"), VERSION,
    ], options={"init_program_tags": False}),
    ver("failed_check_before_write", [
        edit(tset(TAGS, None)), put(("a", 10)), edit(tset(TAGS, V1)), ("advance", 2.0), put(("a", 10)), read("a"),
    ]),
    ver("writes_checked_before_and_after", [put(("a", 10)), put(("a", 11), ("b", 12)), read("a", "b")]),
    ver("change_before_write", [edit(tset(EDITED, V2)), put(("b", 20)), read("b", "x")]),
    ver("change_during_write", [at(1, EDITED, V2), put(("a", 10), ("b", 20)), read("x", "b"), VERSION]),
    ver("change_after_write_not_read", [at(2, TAGS, None), put(("a", 10)), read("a"), ("advance", 2.0),
                                        edit(tset(TAGS, V1)), read("a")]),
    ver("not_reported", [read("a"), put(("b", 20)), CHECK, read("b")], version=None),
    *[ver(f"without_instance_ids_{i}", [read("a", "b"), put(("a", 3)), CHECK, ("list",), read("a")], **identity)
      for i, identity in enumerate([V20, {"product_name": "2080-LC50-48QWBS"}])],
    ver("ids_turned_off", [("use_ids", False), read("a"), put(("b", 20)), CHECK, read("b")]),
    ver("check_tag_table", [CHECK, edit(tset(EDITED, V2)), CHECK, read("b"), CHECK]),
    ver("reconnect_keeps_version", [("list",), edit(tset(EDITED, V2)), CLOSE, OPEN, VERSION, read("b"), VERSION],
        options={"init_tags": False}),
    ver("lazy_reset", [read("b"), at(0, EDITED, V2), read("b"), VERSION], options={"lazy_tags": True}),
    ver("lazy_refresh_fails", [read("b"), edit(tset(EDITED, V2)),
                               edit(lambda plc: plc.edit_at(1, lambda: setattr(plc.controller, "version", None))),
                               read("b"), ("advance", 2.0), edit(tset(EDITED, V2)), read("b"), VERSION],
        options={"lazy_tags": True}),
    ver("comm_error_mid_read", [("fail_receive",), read("a", "b"), OPEN, read("a")]),
    ver("comm_error_mid_write", [("fail_receive", 1), put(("a", 1)), OPEN, read("a")]),
    ver("empty_calls", [read(), put()]),
]


# ---- test_logix_aoi.py (reads and writes) ----

def aoi_controller(controller=AOI_CONTROLLER, programs=None):
    programs = programs or {}
    return AOIController({None: [(i, f"Program:{p}", 0x1068) for i, p in enumerate(programs, 1)] + controller,
                          **programs})


def aoi(name, steps, controller=None, options=None, **plc_args):
    return scenario(f"aoi_rw_{name}", controller or aoi_controller(), [OPEN, *steps], options=options, **plc_args)


SCENARIOS += [
    aoi("program_tag", [read("Program:P1.v"), read("Program:P1.v.Busy", "Program:P1.v.Mode")],
        aoi_controller([(16, "d", 0xC4)], {"P1": [(1, "Routine:R", 0x106D), (2, "v", 0x8200)]})),
    aoi("whole_read", [
        read("d", "v1", "valves[2]", "holder.Valves[1]", "procs[1]", "plain"),
        controller_set(faults={"v1.Mode": 0x05}), read("v1"), read("v1", "valves[0]"),
        controller_set(faults={"v1.Mode": 0x0F, "v1.Cmd": 0x05}), read("v1"),
        override(is_multi, drop_last), read("v1"),
    ]),
    aoi("change_during_read", [edit(lambda plc: setattr(plc.controller, "version", V2)), read("d", "v1")]),
    aoi("array_without_index", [read("valves"), read("holder.Valves"), read("valves{2}"), read("v1.EnableIn.0")]),
    aoi("refused_members", [
        read("v1.Count"), read("valves[1].Busy"), read("outer.Inner.ACC"), read("v1.count"), put(("v1.Count", 5)),
        put(("holder.Valves[0].Busy", True)), read("v1.Mode", "v1.Count"), put(("v1", bytes(12))),
        read("holder.Valves[0].Count.1"),
    ]),
    aoi("non_aoi_structs", [read("plain", "holder", "holder.V"), put(("plain", bytes(4)))]),
    aoi("hidden_instance", [read("hidden.Busy")], aoi_controller([(17, "-hidden", 0x8200)])),
    aoi("lazy", [read("d"), read("v1.Busy"), read("valves[1]"), read("outer")], options={"lazy_tags": True}),
    aoi("without_instance_ids", [("use_ids", False), read("v1"), read("v1.Busy")]),
    aoi("probe_by_name", [read("v1", "valves[1].Mode")], **V20),
    aoi("micro800", [read("v1", "d")], **MICRO),
]

# written without indentation: the long frames and value lists of the >65535 element transfers
path = os.path.join(FIXTURES, "logix_rw.json")
with open(path, "w", encoding="utf-8", newline="\n") as file:
    file.write('{"scenarios": [\n' + ",\n".join(json.dumps(s, ensure_ascii=False) for s in SCENARIOS) + "\n]}\n")
print(f"wrote {os.path.relpath(path, ROOT)} ({len(SCENARIOS)} cases)")
