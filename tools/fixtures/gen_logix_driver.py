"""LogixDriver fixtures: the frames the Python LogixDriver sends, in order, the replies it got and what each call
returned, for the scenarios of tools/reference/tests/offline/test_logix_driver.py, test_logix_tag_list.py, test_logix_tag_upload.py,
test_logix_tag_cache.py, the probe parts of test_logix_aoi.py and the upload/check parts of
test_logix_tag_table_version.py.

Every scenario runs the real driver (connection, session, Forward Open and all) against a scripted socket answered
by a simulated controller: the fake controllers of the offline tests (their ``_service`` answers one CIP service)
behind a frame-level front that answers the session, Forward Open/Close, identity, program name and clock.  The
Rust test replays the recorded replies in order and must send the same frames and return the same results.  The
Forward Open connection triad is random; it is fixed to zeros here and masked on both sides.

A scenario is a list of steps; the Rust test maps each step to its call.  Steps that change the simulated
controller ('edit') are not replayed, their effect is in the recorded replies.  Tag cache file steps record the
file text, so the Rust test checks it writes the same bytes.
"""

import json
import os
import shutil
import struct
import tempfile
from unittest import mock

from fixturelib import enc, write

import ciplink.cip_driver as cip_driver
import ciplink.logix_driver as logix_driver
from ciplink import LogixDriver
from ciplink.tag import TagError
from ciplink.cip import DINT, UDINT, UINT
from tests.offline import test_logix_tag_upload as upload_tests
from tests.offline.test_logix_aoi import AOIController, CONTROLLER as AOI_CONTROLLER, TYPES as AOI_TYPES
from tests.offline.test_logix_aoi import makeup as aoi_makeup, template as aoi_template
from tests.offline.test_logix_tag_cache import OUTER_MAKEUP, OUTER_TEMPLATE
from tests.offline.test_logix_tag_list import UDT_MAKEUP, UDT_TEMPLATE, _symbol
from tests.offline.test_logix_tag_table_version import V1, V2, V3, V4
from tests.offline.test_logix_tag_upload import Controller, PAIR_INFO, PAIR_MAKEUP, SIMPLE_MAKEUP, SIMPLE_TEMPLATE

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


class PLC:
    """
    A controller at frame level: the session, Forward Open/Close, identity, program name and clock here, every other
    connected service answered by ``controller._service`` (a fake controller of the offline tests), multi-service
    packets split and joined as the offline tests' Controller.send does.  ``edits`` maps the index of a connected
    packet to a function run right before it is answered.
    """

    def __init__(self, controller, product_name="1756-SIM/A", major=33, serial=0xC0FFEE01):
        self.controller = controller
        self.product_name, self.major, self.serial = product_name, major, serial
        self.fo_rejects = 0  # Forward Opens to reject
        self.plc_info_fails = 0  # identity reads to fail
        self.connected = 0  # connected packets answered
        self.edits = {}
        self.session_rejects = 0  # Register Sessions to reject
        self.name_fails = False  # the program name read fails (0x08)
        self.clock_status = 0  # the general status of the clock replies
        self.clock_short = False  # the clock reply is too short for the time
        self.status = b"\x60\x30"  # the identity status word (keyswitch)
        self.program_name = b"PLCA"  # the program name, its reply data unless ``name_data`` is set
        self.name_data = None
        self.list_identity_reply = None  # a ListIdentity reply frame instead of the identity
        self.clock_data = None  # the clock read's reply data instead of the time

    def edit_at(self, offset, fn):
        self.edits[self.connected + offset] = fn

    def reply(self, frame):
        command = frame[0]
        if command == 0x65:
            if self.session_rejects:
                self.session_rejects -= 1
                return encap(0x65, b"\x01\x00\x00\x00", session=0, status=0x69)
            return encap(0x65, b"\x01\x00\x00\x00")
        if command == 0x63:
            if self.list_identity_reply is not None:
                return self.list_identity_reply
            identity = identity_data(self.product_name, self.major, self.serial)
            item = struct.pack("<H", 1) + struct.pack(">hH", 2, 44818) + bytes([127, 0, 0, 1]) + bytes(8) + identity + b"\x03"
            return encap(0x63, struct.pack("<HHH", 1, 0x0C, len(item)) + item, session=0)
        if command == 0x6F:
            service = frame[40]
            if service in (0x54, 0x5B):
                if self.fo_rejects:
                    self.fo_rejects -= 1
                    return rr_frame(cip(service, 0x01, ext=(0x0100,)))
                return rr_frame(cip(service, data=CID + bytes(22)))
            if service == 0x4E:
                return rr_frame(cip(0x4E, data=bytes(10)))
            inner = frame[50] if service == 0x52 else service
            if inner == 0x01:
                if self.plc_info_fails:
                    self.plc_info_fails -= 1
                    return rr_frame(cip(0x01, 0x08))
                return rr_frame(cip(0x01, data=identity_data(self.product_name, self.major, self.serial,
                                                             self.status)))
            return rr_frame(cip(service, 0x08))
        if command == 0x70:
            at = 36 + UINT.decode(frame[34:36]) + 4  # after the address item and the data item header
            seq = UINT.decode(frame[at:at + 2])
            return unit_frame(seq, self.connected_reply(frame[at + 2:]))
        raise ValueError(f"unexpected frame {frame.hex()}")

    def connected_reply(self, message):
        edit = self.edits.pop(self.connected, None)
        self.connected += 1
        if edit:
            edit()
        service, path = message[0], message[2:2 + 2 * message[1]]
        if path[:2] == b"\x20\x64":  # program name
            if self.name_fails:
                return cip(service, 0x08)
            if self.name_data is not None:
                return cip(service, data=self.name_data)
            return cip(service, data=UINT.encode(len(self.program_name)) + self.program_name)
        if path[:2] == b"\x20\x8b":  # wall clock time
            if self.clock_status:
                return cip(service, self.clock_status)
            if self.clock_data is not None and service == 0x03:
                return cip(service, data=self.clock_data)
            if self.clock_short and service == 0x03:
                return cip(service, data=UINT.encode(1) + UINT.encode(6) + UINT.encode(0) + b"\x01\x02")
            if service == 0x03:
                return cip(service, data=UINT.encode(1) + UINT.encode(6) + UINT.encode(0) + struct.pack("<Q", 1_700_000_000_123_456))
            return cip(service)
        c = self.controller
        c.left = c.capacity
        if service != 0x0A:
            kind, reply = c._service(message, False)
            c.packets.append([kind])
            c.messages.append([message])
            return reply
        body = message[2 + 2 * message[1]:]
        bounds = [UINT.decode(body[2 + 2 * i:4 + 2 * i]) for i in range(UINT.decode(body[:2]))] + [len(body)]
        services = [body[start:end] for start, end in zip(bounds, bounds[1:])]
        c.messages.append(services)
        if "multi" in c.rejected:
            c.packets.append(["rejected"])
            return cip(0x0A, 0x08)
        kinds, replies = zip(*(c._service(s, True) for s in services))
        c.packets.append(list(kinds))
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
        self.fail_at = set()  # indexes of the receives that fail

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
            raise
        self.replies.append(reply)
        return reply

    def settimeout(self, timeout):
        pass

    def close(self):
        pass


def kind(tag):
    """the ErrorKind value of a Tag's error, None without one"""
    return None if tag.error is None else tag.error_kind.value


def plain(value):
    """the JSON-able part of a tag or data type, as tags_json does it"""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items() if k not in ("type_class", "_struct_members")}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


def state(plc):
    return {
        "connected": plc.connected,
        "tags": plc.tags_json,
        "data_types": plain(plc.data_types),
        "info": plc.info,
        "version": plc._tag_table_version,
        "use_ids": plc._cfg["use_instance_ids"],
        "micro800": plc._micro800,
        "name": plc.name,
        "revision_major": plc.revision_major,
        "str": str(plc),
    }


class Runner:
    def __init__(self, plc, tmp):
        self.plc = plc
        self.tmp = tmp
        self.driver = None
        self.previous = None  # the driver before the last 'new', its tags are shared by 'share'
        self.now = [1000.0]

    def path(self, value):
        if value == "<file>":
            return os.path.join(self.tmp, "tags.json")
        if value == "<missing_dir_file>":
            return os.path.join(self.tmp, "missing_dir", "tags.json")
        return value

    def new(self, path, kwargs):
        kwargs = dict(kwargs)
        if "tag_cache_file" in kwargs:
            kwargs["tag_cache_file"] = self.path(kwargs["tag_cache_file"])
        self.previous, self.driver = self.driver, LogixDriver(path, **kwargs)

    def file_text(self):
        try:
            with open(self.path("<file>"), encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def step(self, step):
        """runs a step, returns (the step as recorded, its result)"""
        call, *args = step
        d = self.driver
        if call == "new":
            path, kwargs = args
            self.new(path, kwargs)
            return {"call": "new", "path": path, "options": kwargs}, None
        if call == "edit":
            args[0](self.plc)
            return {"call": "edit"}, None
        if call == "fail_receive":  # the receive ``skip`` receives from now fails
            self.script.fail_at.add(len(self.script.replies) + (args[0] if args else 0))
            return {"call": "fail_receive"}, None
        if call == "write_file":
            text = args[0](self.file_text())
            with open(self.path("<file>"), "w", encoding="utf-8") as f:
                f.write(text)
            return {"call": "write_file", "text": text}, None
        if call == "share":  # the tip of LogixDriver's docs: plc2._tags = plc1.tags
            d._tags = self.previous.tags
            return {"call": "share"}, None
        if call == "advance":
            self.now[0] += args[0]
            return {"call": "advance", "seconds": args[0]}, None
        record = {"call": call}
        try:
            if call == "open":
                result = enc(d.open())
            elif call == "close":
                result = enc(d.close())
            elif call == "check":
                result = enc(d.check_tag_table())
            elif call == "list":
                program, cache, prefix = args
                record.update(program=program, cache=cache, filter=prefix)
                result = enc(plain(d.get_tag_list(program=program, cache=cache, tag_namespace_filter=prefix)))
            elif call == "state":
                result = enc(state(d))
            elif call == "tag_info":
                record["name"] = args[0]
                result = enc(plain(d.get_tag_info(args[0])))
            elif call == "plc_time":
                tag = d.get_plc_time()
                result = enc({"value": None if tag.value is None else tag.value["microseconds"],
                              "error": None if tag.error is None else str(tag.error), "kind": kind(tag)})
            elif call == "set_plc_time":
                record["microseconds"] = args[0]
                tag = d.set_plc_time(args[0])
                result = enc({"tag": tag.tag, "value": tag.value, "error": None if tag.error is None else str(tag.error),
                              "kind": kind(tag)})
            elif call == "plc_info":
                info = d.get_plc_info()
                result = enc({"keyswitch": info["keyswitch"], "serial": info["serial"]})
            elif call == "plc_name":
                result = enc(d.get_plc_name())
            elif call == "file":
                result = enc(self.file_text())
            else:
                raise ValueError(call)
            return record, {"ok": result}
        except Exception as err:
            result = {"err": type(err).__name__, "msg": str(err)}
            if err.args and isinstance(err.args[0], TagError):
                result["kind"] = err.args[0].kind.value
            return record, result


def scenario(name, controller, steps, path="1.2.3.4", options=None, aoi=False, **plc_args):
    plc = PLC(controller, **plc_args)
    tmp = tempfile.mkdtemp()
    runner = Runner(plc, tmp)
    script = Script(plc)
    runner.script = script
    options = options or {}
    patches = [
        mock.patch.object(cip_driver, "Socket", lambda *a, **k: script),
        mock.patch.object(cip_driver, "urandom", lambda n: bytes(n)),
        mock.patch.object(logix_driver.time, "monotonic", lambda: runner.now[0]),
    ]
    if aoi:  # the AOI tests' symbols: Read/Write, '-' names have no external access
        def symbol(instance, name, *args):
            return _symbol(instance, name.lstrip("-"), *args)[:-1] + bytes([3 if name.startswith("-") else 0])
        patches.append(mock.patch.object(upload_tests, "_symbol", symbol))
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


# ---- simulated controllers ----

class FailingController(Controller):
    """
    the upload Controller whose symbol list service fails (0x08) while ``fail_symbols`` and answers the symbol
    list of an unknown program with 0x05 (path destination unknown); each of ``hooks`` (controller, message,
    multi) may answer a service instead with (kind, reply), or leave it (None)
    """

    fail_symbols = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hooks = []

    def _service(self, message, multi):
        for hook in self.hooks:
            answer = hook(self, message, multi)
            if answer is not None:
                return answer
        if message[0] == 0x55:
            program, _, instance = upload_tests.parse_path(message[2:2 + 2 * message[1]])
            if self.fail_symbols or program not in self.scopes:
                return ("symbols", program, instance), cip(0x55, 0x08 if self.fail_symbols else 0x05)
        return super()._service(message, multi)


def upload_controller(**kwargs):
    """the controller of test_logix_tag_upload.py: 3 programs, MyUDT, Outer (nests MyUDT) and Simple"""
    return FailingController(**kwargs)


def scopes_controller(scopes, templates=None, version=V1):
    c = FailingController()
    c.scopes = scopes
    if templates is not None:
        c.templates = templates
    c.version = version
    return c


DINTS = {None: [(5, "a", 0xC4), (6, "b", 0xC4)]}
EDITED_DINTS = {None: [(5, "a", 0xC4), (6, "x", 0xC4), (9, "b", 0xC4)]}
LIST_SCOPES = {
    None: [(1, "a", 0xC4), (2, "arr", 0x20C4, 10), (3, "udt", 0x8123), (4, "udts", 0xA123, 3)],
    "Prog1": [(1, "a", 0xC4), (2, "arr", 0x20C4, 10), (3, "udt", 0x8123), (4, "udts", 0xA123, 3)],
    "Odd": [(1, "a", 0xC4), (2, "arr", 0x20C4, 10), (3, "udt", 0x8123), (4, "udts", 0xA123, 3)],
    "Even": [(1, "a", 0xC4), (2, "arr", 0x20C4, 10), (3, "udt", 0x8123), (4, "udts", 0xA123, 3)],
}
CACHE_SCOPES = {  # test_logix_tag_cache.py's symbols
    None: [(1, "Program:MainProgram", 0x1068), (2, "Task:MainTask", 0x1070), (3, "a", 0xC4),
           (4, "udt", 0x8123), (5, "Local:1:I", 0xC4)],
    "MainProgram": [(1, "Routine:MainRoutine", 0x106D), (2, "outer", 0x8124), (3, "arr", 0x20C4, 4)],
}
CACHE_TEMPLATES = {0x123: (UDT_MAKEUP, UDT_TEMPLATE), 0x124: (OUTER_MAKEUP, OUTER_TEMPLATE)}


def cache_controller(version=None, scopes=None):
    return scopes_controller({k: list(v) for k, v in (scopes or CACHE_SCOPES).items()}, dict(CACHE_TEMPLATES),
                             version)


def aoi_controller(controller=AOI_CONTROLLER, programs=None):
    programs = programs or {}
    return AOIController({None: [(i, f"Program:{p}", 0x1068) for i, p in enumerate(programs, 1)] + controller,
                          **programs})


def setv(version):
    return lambda plc: setattr(plc.controller, "version", version)


def edit_scope(scope, entries):
    return lambda plc: plc.controller.scopes.__setitem__(scope, entries)


def edit_template(tid, makeup, template):
    return lambda plc: plc.controller.templates.__setitem__(tid, (makeup, template))


FILE = {"tag_cache_file": "<file>"}
OPEN, CLOSE, STATE, CHECK, FILE_TEXT = ("open",), ("close",), ("state",), ("check",), ("file",)


def connect(**options):
    """a new driver connecting with these options, then closing"""
    return [("new", "1.2.3.4", options), OPEN, CLOSE]


SCENARIOS = [
    # ---- test_logix_driver.py ----
    *[scenario(f"init_rev{major}", upload_controller(), [OPEN, STATE, ("plc_time",), ("set_plc_time", 1234567), CLOSE,
                                                         STATE], options={"init_tags": False}, major=major,
               product_name=name)
      for major, name in ((20, "1756-L55"), (21, "1756-L62"), (32, "1756-L73"))],
    scenario("init_micro800", upload_controller(), [OPEN, STATE, ("plc_time",), CLOSE, ("new", "192.168.1.100/1", {}),
                                                    OPEN, STATE], path="192.168.1.100/1", options={"init_tags": False},
             major=12, product_name="2080-LC50-48QWBS", serial=0x12345678),
    scenario("init_tags_v32", upload_controller(), [OPEN, STATE, ("plc_info",), ("plc_name",), STATE, CLOSE, STATE],
             path="192.168.1.100/1", major=32),
    scenario("open_fails_on_plc_info", upload_controller(), [
        ("edit", lambda plc: setattr(plc, "plc_info_fails", 1)), OPEN, STATE, OPEN, STATE,
    ]),
    scenario("open_fails_on_forward_open", upload_controller(), [
        ("edit", lambda plc: setattr(plc, "fo_rejects", 2)), OPEN, STATE, OPEN, ("tag_info", "a"),
    ]),
    scenario("open_fails_on_lost_reply", upload_controller(), [("fail_receive",), OPEN, STATE]),
    scenario("upload_fails_on_lost_reply", upload_controller(), [
        OPEN, ("fail_receive",), ("list", "*", True, ""), STATE, OPEN, ("list", "*", True, ""), STATE,
    ], options={"init_tags": False}),
    scenario("comm_errors_are_not_wrapped", upload_controller(), [
        OPEN, ("fail_receive",), ("plc_info",), STATE, OPEN, ("fail_receive",), ("plc_name",), OPEN,
        ("fail_receive", 4), ("list", "*", True, ""), OPEN,  # the first template read
        ("fail_receive", 3), ("list", "*", True, ""), OPEN,  # the makeups
        ("fail_receive",), CHECK, STATE,
    ], options={"init_tags": False}),
    # ---- test_logix_tag_list.py ----
    scenario("tag_list_requests", scopes_controller(LIST_SCOPES, version=V1), [
        OPEN, *[step for program in (None, "Prog1", "Program:Odd", "Even")
                for step in (("list", program, True, ""), STATE)],
        ("list", "Prog1", False, ""), ("list", None, True, ""), ("tag_info", "udt.B"), ("tag_info", "UDT.flag"), ("tag_info", "nope"),
        ("tag_info", "a.x"), ("tag_info", "udts[1].A"),
    ], options={"init_tags": False}, major=20, path="1.2.3.4/0"),
    scenario("tag_list_pages", scopes_controller(LIST_SCOPES, version=V1), [
        ("edit", lambda plc: setattr(plc.controller, "page", 2)), OPEN, ("list", None, True, ""), STATE,
    ], options={"init_tags": False}, major=17),
    scenario("namespace_filter", scopes_controller({
        None: [(1, "Program:MainProgram", 0x1068), (2, "Task:MainTask", 0x1070), (3, "Local:1:I", 0xC4),
               (4, "Line1_Speed", 0xC4), (5, "Other", 0xC4)],
        "MainProgram": [(1, "Routine:R", 0x106D), (6, "Line1_X", 0xC4), (7, "Other", 0xC4)],
    }), [OPEN, STATE, ("list", "MainProgram", True, ""), STATE, ("list", "Program:MainProgram", True, "Oth"),
         STATE], options={"tag_namespace_filter": "Line1_"}),
    scenario("module_tags", scopes_controller({
        None: [(1, "Local:2:I", 0xC4), (2, "Local:2:C", 0xC4), (3, "Local:2:O", 0xC4), (4, "Rack:I", 0xC4),
               (5, "Mod:1:2:3", 0xC4), (6, "Map:x", 0xC4), (7, "__sys", 0xC4), (8, "sys", 0x10C4),
               (9, "Routine:R", 0x106D), (10, "Weird:x", 0xC4)],
    }), [OPEN, STATE], options={"init_program_tags": False}),
    # ---- test_logix_tag_upload.py ----
    scenario("connect_batches", upload_controller(), [OPEN, STATE]),
    scenario("reload_reads_only_makeups", upload_controller(), [
        OPEN, ("edit", lambda plc: plc.controller.scopes["P2"].append((9, "new", 0xC4))), ("edit", setv(V2)),
        CHECK, STATE,
    ]),
    scenario("reload_reads_changed_makeup", upload_controller(), [
        OPEN, ("edit", edit_template(0x125, dict(SIMPLE_MAKEUP, structure_handle={"handle": 0x6666}),
                                     SIMPLE_TEMPLATE.replace(b"\x00V\x00", b"\x00W\x00"))),
        ("edit", setv(V2)), CHECK, STATE,
    ]),
    scenario("reconnect_same_controller", upload_controller(), [OPEN, CLOSE, OPEN, STATE]),
    scenario("reconnect_other_controller", upload_controller(), [
        OPEN, CLOSE, ("edit", lambda plc: setattr(plc, "serial", 0xC0FFEE02)), OPEN, STATE,
    ]),
    scenario("pages_continue_in_next_batch", upload_controller(page=3), [
        ("edit", lambda plc: plc.controller.scopes["P3"].extend([(3, "y3", 0xC4), (4, "y4", 0xC4), (5, "y5", 0xC4)])),
        OPEN, STATE,
    ]),
    scenario("page_without_symbols_continues_alone", upload_controller(capacity=3), [OPEN, STATE]),
    scenario("rejected_batches", upload_controller(), [
        ("edit", lambda plc: plc.controller.rejected.add("multi")), OPEN, STATE,
    ]),
    scenario("service_rejected_in_batch", upload_controller(), [
        ("edit", lambda plc: plc.controller.rejected.add("P2")), OPEN, STATE,
    ]),
    scenario("download_reads_every_template", upload_controller(), [
        ("edit", edit_template(0x125, PAIR_MAKEUP, PAIR_INFO + b"Pair;n0000\x00Start\x00Stops\x00")), OPEN,
        ("edit", edit_template(0x125, PAIR_MAKEUP, PAIR_INFO + b"Pair;n0000\x00Stops\x00Start\x00")),
        ("edit", setv((2, 1, 11, 11, 21))), CHECK, STATE,
    ]),
    scenario("micro800_upload", upload_controller(), [OPEN, STATE, ("plc_time",)], major=21,
             product_name="2080-LC30-48QWB"),
    scenario("small_connection_size", upload_controller(), [OPEN, STATE], options={"connection_size": 300}),
    # ---- test_logix_tag_cache.py ----
    scenario("cache_second_connect", cache_controller(), [
        *connect(**FILE), FILE_TEXT, *connect(**FILE), STATE, FILE_TEXT,
    ], major=32),
    *[scenario(f"cache_changed_symbols_{i}", cache_controller(), [
        *connect(**FILE), ("edit", edit), *connect(**FILE), FILE_TEXT, *connect(**FILE), STATE,
    ], major=32) for i, edit in enumerate([
        edit_scope(None, [CACHE_SCOPES[None][0], CACHE_SCOPES[None][1], (30, "a", 0xC4)] + CACHE_SCOPES[None][3:]),
        edit_scope("MainProgram", CACHE_SCOPES["MainProgram"] + [(4, "b", 0xC4)]),
    ])],
    scenario("cache_namespace_filter", cache_controller(), [
        *connect(**FILE), *connect(tag_namespace_filter="udt", **FILE), STATE, FILE_TEXT,
    ], major=32),
    *[scenario(f"cache_corrupt_{i}", cache_controller(), [
        *connect(**FILE), ("write_file", corrupt), *connect(**FILE), STATE, FILE_TEXT, *connect(**FILE),
    ], major=32) for i, corrupt in enumerate([
        lambda text: text[:len(text) // 2],
        lambda text: text.replace('"structure_size"', '"other"'),
        lambda text: "not json",
        lambda text: text.replace('"templates": [[', '"templates": [["x", ', 1),
    ])],
    scenario("cache_changed_makeup", cache_controller(), [
        *connect(**FILE),
        ("edit", edit_template(0x123, dict(UDT_MAKEUP, structure_handle={"handle": 0xBEEF}),
                               UDT_TEMPLATE.replace(b"\x00A\x00B\x00", b"\x00P\x00Q\x00"))),
        *connect(**FILE), STATE, *connect(**FILE), FILE_TEXT,
    ], major=32),
    scenario("cache_damaged_template", cache_controller(), [
        *connect(**FILE),
        ("write_file", lambda text: text.replace(UDT_TEMPLATE.hex(), UDT_TEMPLATE.hex()[:16])),
        *connect(**FILE), STATE, *connect(**FILE), FILE_TEXT,
    ], major=32),
    scenario("cache_other_scopes", cache_controller(), [
        ("new", "1.2.3.4", FILE), OPEN, FILE_TEXT, ("list", "MainProgram", True, ""), ("list", None, True, ""),
        FILE_TEXT, CLOSE, *connect(**FILE),
        ("new", "1.2.3.4", dict(init_program_tags=False, **FILE)), OPEN, FILE_TEXT, ("list", "*", True, ""), FILE_TEXT,
        CLOSE,
    ], major=32),
    scenario("cache_unwritable", cache_controller(), [
        ("new", "1.2.3.4", {"tag_cache_file": "<missing_dir_file>"}), OPEN, STATE, CLOSE,
    ], major=32),
    scenario("cache_lazy_ignores_file", cache_controller(), [
        ("new", "1.2.3.4", dict(lazy_tags=True, **FILE)), OPEN, ("list", "*", True, ""), STATE, FILE_TEXT, CLOSE,
    ], major=32),
    scenario("cache_unchanged_version", cache_controller(V1), [
        *connect(**FILE), FILE_TEXT, *connect(**FILE), STATE, FILE_TEXT,
    ]),
    *[scenario(f"cache_version_{name}", cache_controller(V1), [
        *connect(**FILE), *edits, *connect(**options), FILE_TEXT, *connect(**options), STATE,
    ], major=33) for name, edits, options in [
        ("edited", [("edit", setv(V2))], FILE),
        ("other_controller", [("edit", lambda plc: setattr(plc, "serial", 0xC0FFEE02))], FILE),
        ("not_reported", [("edit", setv(None))], FILE),
        ("other_scope", [], dict(init_program_tags=False, **FILE)),
    ]],
    scenario("cache_older_format", cache_controller(V1), [
        *connect(**FILE),
        ("write_file", lambda text: json.dumps({"version": 1, "symbols": json.loads(text)["symbols"],
                                                "templates": json.loads(text)["templates"]})),
        *connect(**FILE), FILE_TEXT, *connect(**FILE),
    ]),
    scenario("cache_damaged_with_current_version", cache_controller(V1), [
        *connect(**FILE), ("write_file", lambda text: text.replace('"symbol_type": 196, ', "", 1)),
        *connect(**FILE), STATE, FILE_TEXT, *connect(**FILE),
    ]),
    scenario("cache_unicode_names", cache_controller(V1, {None: [(1, "café", 0xC4), (2, "t\u00ff\u00b5", 0xC4)]}), [
        *connect(**FILE), FILE_TEXT, *connect(**FILE), STATE,
    ]),
    # ---- test_logix_aoi.py (the probes) ----
    scenario("aoi_probe_classifies_members", aoi_controller(), [OPEN, STATE], aoi=True),
    scenario("aoi_transient_errors", aoi_controller(), [
        ("edit", lambda plc: setattr(plc.controller, "faults", {"v1.Count": 0x05, "v1": 0x08, "outer.Out": 0x1F})),
        OPEN, STATE,
    ], aoi=True),
    scenario("aoi_probe_budgets", aoi_controller(), [OPEN, STATE], options={"connection_size": 120}, aoi=True),
    scenario("aoi_whole_too_big", aoi_controller(), [
        ("edit", lambda plc: setattr(plc.controller, "max_reply", 10)), OPEN, STATE,
    ], options={"connection_size": 30}, aoi=True),
    *[scenario(f"aoi_instance_selection_{i}", aoi_controller(symbols), [OPEN, STATE], aoi=True)
      for i, symbols in enumerate([
          [(10, "valves", 0xA200, 3), (12, "v1", 0x8200)],
          [(11, "holder", 0x8204), (10, "valves", 0xA200, 3)],
          [(11, "holder", 0x8204)],
          [(12, "-hidden", 0x8200), (11, "holder", 0x8204)],
      ])],
    scenario("aoi_program_tag", aoi_controller([(16, "d", 0xC4)], {"P1": [(1, "Routine:R", 0x106D),
                                                                       (2, "v", 0x8200)]}), [OPEN, STATE], aoi=True),
    scenario("aoi_cache_file_keeps_probes", aoi_controller(), [
        *connect(**FILE), FILE_TEXT, *connect(**FILE), STATE, FILE_TEXT,
    ], aoi=True),
    scenario("aoi_cache_file_without_probes", aoi_controller(), [
        *connect(**FILE),
        ("write_file", lambda text: json.dumps({k: v for k, v in json.loads(text).items() if k != "aoi"})),
        *connect(**FILE), STATE, FILE_TEXT,
    ], aoi=True),
    scenario("aoi_cache_file_changed_type", aoi_controller(), [
        *connect(**FILE), ("edit", setv(V2)),
        ("edit", edit_template(0x201, aoi_makeup(0x201, handle=0x999), aoi_template(0x201))),
        *connect(**FILE), STATE, FILE_TEXT,
    ], aoi=True),
    scenario("aoi_reload_probes_new_or_changed", aoi_controller(), [
        OPEN, ("edit", edit_template(0x200, aoi_makeup(0x200, handle=0x999), aoi_template(0x200))),
        ("edit", setv(V2)), CHECK, STATE, ("edit", setv((400, 1, 10, 10, 20))), CHECK, STATE,
    ], aoi=True),
    scenario("aoi_type_without_instance", aoi_controller([(16, "d", 0xC4)]), [OPEN, STATE], aoi=True),
    scenario("aoi_only_hidden_instance", aoi_controller([(17, "-hidden", 0x8200)]), [OPEN, STATE], aoi=True),
    scenario("aoi_lazy", aoi_controller(), [
        OPEN, STATE, ("tag_info", "v1"), STATE, ("tag_info", "valves.Mode"), ("tag_info", "nope"), STATE,
    ], options={"lazy_tags": True}, aoi=True),
    scenario("aoi_probe_by_name", aoi_controller(), [OPEN, STATE], aoi=True, major=20),
    # ---- test_logix_tag_table_version.py (uploads and checks) ----
    scenario("version_read_twice_on_connect", scopes_controller(DINTS), [OPEN, STATE]),
    scenario("version_tag_list_needs_version", scopes_controller(DINTS), [
        OPEN, ("edit", edit_scope(None, EDITED_DINTS[None])), ("edit", setv(None)), ("list", None, True, ""), STATE,
    ]),
    scenario("version_not_reported_uses_names", scopes_controller(DINTS, version=None), [OPEN, CHECK, STATE]),
    *[scenario(f"version_without_instance_ids_{i}", scopes_controller(DINTS), [
        OPEN, CHECK, ("list", None, True, ""), STATE,
    ], **identity) for i, identity in enumerate([{"major": 20}, {"product_name": "2080-LC50-48QWBS", "major": 21}])],
    scenario("version_upload_repeated", scopes_controller(DINTS), [
        OPEN, ("edit", lambda plc: plc.edit_at(1, lambda: (edit_scope(None, EDITED_DINTS[None])(plc), setv(V2)(plc)))),
        ("list", None, True, ""), STATE,
    ], options={"init_program_tags": False}),
    scenario("version_keeps_changing", scopes_controller(DINTS), [
        OPEN, ("edit", lambda plc: [plc.edit_at(n, (lambda v: lambda: setv(v)(plc))(v))
                                    for n, v in ((2, V2), (5, V3), (8, V4))]),
        ("list", None, True, ""), STATE, CHECK, STATE,
    ], options={"init_program_tags": False}),
    scenario("version_check_tag_table", scopes_controller(DINTS), [
        OPEN, CHECK, ("edit", edit_scope(None, EDITED_DINTS[None])), ("edit", setv(V2)), CHECK, STATE, CHECK,
    ], options={"init_program_tags": False}),
    scenario("version_failed_check_backs_off", scopes_controller(DINTS), [
        OPEN, ("edit", setv(None)), CHECK, ("edit", setv(V2)), ("advance", 1.9), CHECK, ("advance", 0.1), CHECK, STATE,
    ], options={"init_program_tags": False}),
    scenario("version_failed_reload_backs_off", scopes_controller(DINTS), [
        OPEN, ("edit", setv(V2)), ("edit", lambda plc: setattr(plc.controller, "fail_symbols", True)), CHECK, STATE,
        CHECK, ("advance", 2.0), ("edit", lambda plc: setattr(plc.controller, "fail_symbols", False)), CHECK, STATE,
    ], options={"init_program_tags": False}),
    scenario("version_download_during_connect_upload", scopes_controller(DINTS), [
        ("edit", lambda plc: plc.edit_at(3, lambda: setv(None)(plc))), OPEN, STATE, CHECK, ("edit", setv(V2)), ("advance", 2.0),
        CHECK, STATE,
    ], options={"init_program_tags": False}),
    scenario("version_reconnect_keeps_kept_list_version", scopes_controller(DINTS), [
        OPEN, ("list", None, True, ""), ("edit", edit_scope(None, EDITED_DINTS[None])), ("edit", setv(V2)), CLOSE,
        OPEN, STATE, CHECK, STATE,
    ], options={"init_tags": False}),
    scenario("version_lazy_reset_on_change", scopes_controller(DINTS), [
        OPEN, STATE, ("tag_info", "b"), STATE, ("edit", edit_scope(None, EDITED_DINTS[None])), ("edit", setv(V2)),
        CHECK, STATE, ("tag_info", "b"), STATE,
    ], options={"lazy_tags": True}),
]


# ---- review: branches of the Python driver the scenarios above leave out ----

def parsed(message):
    """(program, class, instance) of a service's request path"""
    return upload_tests.parse_path(message[2:2 + 2 * message[1]])


def symbols_reply(scope, status, data, multi_only=False):
    """a hook answering the symbol list of ``scope`` with this status and data"""
    def hook(c, message, multi):
        if message[0] == 0x55 and (multi or not multi_only):
            program, _, instance = parsed(message)
            if program == scope:
                return ("symbols", program, instance), cip(0x55, status, data)
    return hook


def template_reply(service, status, data=b"", multi_only=False):
    """a hook answering a template service (0x03 its makeup, 0x4C its read) with this status and data"""
    def hook(c, message, multi):
        if message[0] == service and parsed(message)[1] == 0x6C and (multi or not multi_only):
            return ("template", parsed(message)[2]), cip(service, status, data)
    return hook


def ignores_start_in_batches(c, message, multi):
    """test_batched_page_that_does_not_advance_continues_alone: a batched page always starts at instance 0"""
    if multi and message[0] == 0x55:
        program, _, instance = parsed(message)
        return ("symbols", program, instance), Controller._service(
            c, upload_tests.symbol_list_request(program, 0), multi)[1]


def hook(fn):
    return "edit", lambda plc: plc.controller.hooks.append(fn)


UNHOOK = ("edit", lambda plc: plc.controller.hooks.clear())


def plc_set(**values):
    return "edit", lambda plc: [setattr(plc, k, v) for k, v in values.items()]


LAZY_SCOPES = {
    None: [(1, "Program:Prog1", 0x1068), (2, "a", 0xC4), (3, "arr", 0x20C4, 10), (4, "udt", 0x8123),
           (5, "__sys", 0xC4), (6, "sys", 0x10C4), (7, "Local:1:I", 0xC4)],
    "Prog1": [(1, "Routine:R", 0x106D), (2, "p", 0xC4), (3, "pudt", 0x8123)],
}
SHORT_SYMBOLS = b"\x01\x00\x00"  # a symbol list page cut inside its first entry

SCENARIOS += [
    scenario("review_batched_page_without_progress", upload_controller(page=3), [
        ("edit", lambda plc: plc.controller.scopes["P3"].extend([(3, "y3", 0xC4), (4, "y4", 0xC4), (5, "y5", 0xC4)])),
        hook(ignores_start_in_batches), OPEN, STATE,
    ]),
    scenario("review_closed_and_session_rejected", upload_controller(), [
        ("tag_info", "a"), CHECK, ("list", None, True, ""), ("plc_time",), ("set_plc_time", 1), ("plc_name",),
        plc_set(session_rejects=1), OPEN, STATE, OPEN, OPEN, STATE,
    ], options={"lazy_tags": True}),
    scenario("review_forward_open_rejected", upload_controller(), [
        OPEN, plc_set(fo_rejects=8), ("plc_time",), ("list", None, True, ""), CHECK, ("plc_name",), ("plc_time",),
        ("plc_name",), STATE,
    ], options={"init_tags": False}, major=12, product_name="2080-LC50-48QWBS"),
    scenario("review_controller_info_errors", upload_controller(), [
        OPEN, plc_set(clock_status=0x08), ("plc_time",), ("set_plc_time", 5), plc_set(clock_status=0x05),
        ("plc_time",), plc_set(clock_status=0, clock_short=True), ("plc_time",), plc_set(name_fails=True),
        ("plc_name",), STATE, plc_set(plc_info_fails=1), ("plc_info",), STATE,
        *[step for status in (b"\x60\x10", b"\x70\x21", b"\x70\x31", b"\x60\x22", b"\x00\x00")
          for step in (plc_set(status=status), ("plc_info",))],
        STATE,
    ], options={"init_tags": False}),
    scenario("review_micro800_info", upload_controller(), [OPEN, ("plc_info",), ("plc_name",), STATE],
             options={"init_tags": False}, major=12, product_name="2080-LC50-48QWBS"),
    scenario("review_symbol_list_errors", upload_controller(), [
        OPEN, hook(symbols_reply(None, 0, SHORT_SYMBOLS)), ("list", None, True, ""), STATE, UNHOOK,
        hook(symbols_reply("P2", 0, SHORT_SYMBOLS, multi_only=True)), ("list", "*", True, ""), STATE, UNHOOK,
        hook(symbols_reply(None, 6, _symbol(0, "a", 0xC4))), ("list", None, True, ""), UNHOOK,
        ("list", "*", True, ""), STATE,
    ], options={"init_tags": False}),
    scenario("review_template_errors", upload_controller(), [
        OPEN,
        *[step for fault in (
            template_reply(0x4C, 0x08),  # template read refused
            template_reply(0x4C, 0x06),  # template read without progress
            template_reply(0x03, 0x08),  # makeup refused
            template_reply(0x03, 0, b"\x04\x00"),  # makeup cut short
            template_reply(0x03, 0),  # makeup without data
        ) for step in (hook(fault), ("list", None, True, ""), UNHOOK)],
        hook(template_reply(0x03, 0, b"\x04\x00", multi_only=True)), ("list", "*", True, ""), STATE, UNHOOK,
        hook(template_reply(0x03, 0, multi_only=True)), ("list", "*", True, ""), STATE, UNHOOK,
        ("list", "*", True, ""), STATE,
    ], options={"init_tags": False}),
    scenario("review_lazy_lookups", scopes_controller(LAZY_SCOPES), [
        OPEN, ("tag_info", "Program:Prog1.p"), ("tag_info", "program:prog1.PUDT.B"), ("tag_info", "Program:Nope.x"),
        ("tag_info", "__sys"), ("tag_info", "sys"), ("tag_info", "Local:1:I"), ("tag_info", "ARR[3]"),
        ("tag_info", "udt.nope"), ("tag_info", "a.b"), ("tag_info", "udt.B.x"), STATE,
    ], options={"lazy_tags": True}),
    scenario("review_lazy_failures", scopes_controller(LAZY_SCOPES), [
        OPEN, hook(template_reply(0x4C, 0x08)), ("tag_info", "udt"), STATE, UNHOOK, ("tag_info", "udt"),
        ("edit", lambda plc: setattr(plc.controller, "fail_symbols", True)), ("tag_info", "Program:Prog1.p"),
        ("edit", lambda plc: setattr(plc.controller, "fail_symbols", False)), ("fail_receive",),
        ("tag_info", "Program:Prog1.p"), STATE, OPEN, ("tag_info", "Program:Prog1.p"), STATE,
    ], options={"lazy_tags": True}),
    scenario("review_lazy_namespace_filter", scopes_controller(LAZY_SCOPES), [
        OPEN, ("tag_info", "arr"), ("tag_info", "udt"), ("tag_info", "Program:Prog1.p"), STATE,
    ], options={"lazy_tags": True, "tag_namespace_filter": "a"}),
    scenario("review_version_list_without_cache", scopes_controller(DINTS), [
        OPEN, ("list", None, False, ""), ("list", "*", False, ""), STATE,
    ], options={"init_program_tags": False}),
    scenario("review_version_lazy_refresh_fails", scopes_controller(DINTS), [
        OPEN, ("tag_info", "a"), ("edit", setv(V2)), ("edit", lambda plc: plc.edit_at(1, lambda: setv(None)(plc))),
        CHECK, STATE, CHECK, ("advance", 2.0), ("edit", setv(V2)), CHECK, STATE, ("tag_info", "b"), STATE,
    ], options={"lazy_tags": True}),
    scenario("review_version_reload_without_version", scopes_controller(DINTS), [
        OPEN, ("edit", setv(V2)), ("edit", lambda plc: plc.edit_at(1, lambda: setv(None)(plc))), CHECK, STATE,
        ("advance", 2.0), ("edit", setv(V2)), CHECK, STATE,
    ], options={"init_program_tags": False}),
]


# ---- parity review: more branches and shapes of the Python driver ----

def floats(text):
    """the tag cache file with its version, table version and template numbers written as floats (2.0 == 2)"""
    cached = json.loads(text)
    cached["version"] = float(cached["version"])
    cached["table_version"] = [float(v) for v in cached["table_version"]]
    cached["templates"] = [[float(i), {k: float(v) for k, v in makeup.items()}, data]
                           for i, makeup, data in cached["templates"]]
    return json.dumps(cached)


SCENARIOS += [
    # Micro800 strips the last port segment of its route on every connect, as Python does
    scenario("parity_micro800_route_reopen", upload_controller(), [
        OPEN, ("plc_time",), CLOSE, OPEN, ("plc_time",), CLOSE, OPEN, ("plc_time",), STATE,
    ], path="1.2.3.4/bp/2/enet/5.6.7.8/bp/0", options={"init_tags": False}, major=12,
        product_name="2080-LC50-48QWBS"),
    # an empty program name is the controller's symbol list with 'Program:.' names
    scenario("parity_empty_program", scopes_controller(LIST_SCOPES, version=V1), [
        OPEN, ("list", "", True, ""), STATE, ("list", "", False, ""), STATE,
    ], options={"init_tags": False}),
    # 8- and 16-bit instance segments in symbol list pages, alone and batched
    scenario("parity_large_instance_ids", scopes_controller({
        None: [(1, "Program:P1", 0x1068), (2, "Program:P2", 0x1068), (0x1FF, "a", 0xC4), (0x2345, "b", 0xC4)],
        "P1": [(0x100, "c", 0xC4), (0x3000, "d", 0xC4)],
        "P2": [(0x101, "e", 0xC4), (0x4000, "f", 0xC4)],
    }), [("edit", lambda plc: setattr(plc.controller, "page", 1)), OPEN, STATE]),
    scenario("parity_program_names", upload_controller(), [
        plc_set(program_name=b"Caf\xe9 \xff"), OPEN, ("plc_name",), STATE,
        plc_set(program_name=b""), ("plc_name",), plc_set(name_data=b"\x05\x00ab"), ("plc_name",), STATE,
    ], options={"init_tags": False}),
    # the tags of a connection shared by another, AOI probes included: before and after it connected
    scenario("parity_shared_tags", aoi_controller(), [
        OPEN, CLOSE, ("new", "1.2.3.4", {"init_tags": False}), ("share",), OPEN, STATE, CHECK, STATE, CLOSE,
        ("new", "1.2.3.4", {"init_tags": False}), OPEN, ("share",), STATE, CHECK,
    ], aoi=True),
    # the tag cache file compared as Python compares: 2.0 == 2, not rewritten
    scenario("parity_cache_python_numbers", cache_controller(V1), [
        *connect(**FILE), ("write_file", floats), *connect(**FILE), STATE, FILE_TEXT,
    ]),
    # an upload without cache never touches the file, init_tags=False uploads the startup scope through it
    scenario("parity_cache_list_without_cache", cache_controller(), [
        ("new", "1.2.3.4", FILE), OPEN, FILE_TEXT, ("list", "*", False, ""), FILE_TEXT, CLOSE,
        ("new", "1.2.3.4", dict(init_tags=False, **FILE)), OPEN, ("list", "*", True, ""), STATE, FILE_TEXT, CLOSE,
    ], major=32),
    # a ListIdentity the driver cannot use (an encapsulation error, no items, a cut identity): not a Micro800,
    # the connect goes on
    scenario("parity_list_identity_unusable", upload_controller(), [
        *[step for reply in (encap(0x63, b"", session=0, status=0x01), encap(0x63, b"\x00\x00", session=0),
                             encap(0x63, b"\x01\x00\x0c\x00\x30\x00\x01\x00", session=0))
          for step in (plc_set(list_identity_reply=reply), OPEN, STATE, CLOSE)],
    ], options={"init_tags": False}),
    # clock replies longer and shorter than the time
    scenario("parity_clock_reply_sizes", upload_controller(), [
        OPEN, *[step for data in (bytes(6) + struct.pack("<Q", 42) + b"\xff\xff", bytes(13), bytes(7), b"\x01")
                for step in (plc_set(clock_data=data), ("plc_time",))],
    ], options={"init_tags": False}),
    # a reconnect ends the reload backoff, an unknown program fails its upload after the version read
    scenario("parity_reconnect_ends_backoff", scopes_controller(DINTS), [
        OPEN, ("edit", setv(None)), CHECK, ("edit", setv(V1)), CHECK, CLOSE, OPEN, ("edit", setv(V2)), CHECK, STATE,
        ("list", "Nope", True, ""), ("list", "Nope", False, ""), CHECK, STATE,
    ], options={"init_program_tags": False}),
    # AOI probes on a Micro800 (each read alone) and with every multi-service packet rejected (no replies)
    scenario("parity_aoi_micro800", aoi_controller(), [OPEN, STATE], aoi=True, major=21,
             product_name="2080-LC50-48QWBS"),
    # a reload lost in its AOI probe: the kept tags keep their probes (the old data type dicts), the data types
    # parsed again have none until the next upload probes them
    scenario("parity_aoi_failed_reload_keeps_probes", aoi_controller(), [
        OPEN, ("edit", edit_template(0x200, aoi_makeup(0x200, handle=0x999), aoi_template(0x200))),
        ("edit", setv(V2)), ("fail_receive", 6), CHECK, STATE, OPEN, STATE,
    ], aoi=True),
    scenario("parity_aoi_rejected_batches", aoi_controller(), [
        ("edit", lambda plc: plc.controller.rejected.add("multi")), OPEN, STATE,
    ], aoi=True),
]

write("logix_driver.json", {"scenarios": SCENARIOS})
