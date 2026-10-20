"""SLCDriver fixtures: the frames the driver sends, in order, and what it returns for scripted replies.

Each scenario runs the Python SLCDriver against a scripted socket (replies served in order, b'' once they run out,
like the offline tests' Mocket) and records the sent frames and each call's outcome. The Forward Open connection
triad is random; it is fixed to zeros here, so the requestor serial number of the PCCC messages (the driver's vsn)
is zeros too. The Rust test masks the triad and that serial number on both sides.
"""

import struct
from unittest import mock

from fixturelib import enc, write

from ciplink import SLCDriver
from ciplink.tag import Tag
import ciplink.cip_driver as cip_driver

CTX = b"_pycomm_"


def encap(command, session, data, status=0):
    return struct.pack("<HHII", command, len(data), session, status) + CTX + bytes(4) + data


def register_reply(session):
    return encap(0x65, session, b"\x01\x00\x00\x00")


def rr_reply(service, status=0, ext=(), data=b""):
    msg = bytes([service | 0x80, 0, status, len(ext)]) + b"".join(struct.pack("<H", e) for e in ext) + data
    cpf = bytes(4) + b"\x0a\x00\x02\x00" + bytes(4) + b"\xb2\x00" + struct.pack("<H", len(msg)) + msg
    return encap(0x6F, 1, cpf)


class Script:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    def connect(self, host, port):
        pass

    def send(self, msg, timeout=0):
        self.sent.append(bytes(msg))
        return len(msg)

    def receive(self, timeout=0):
        return self.replies.pop(0) if self.replies else b""

    def settimeout(self, timeout):
        pass

    def close(self):
        pass

CID = b"\xdd\xcc\xbb\xaa"
FO_STD_OK = rr_reply(0x54, data=CID + bytes(22))
FO_LARGE_OK = rr_reply(0x5B, data=CID + bytes(22))
FO_LARGE_REJECT = rr_reply(0x5B, status=0x08)
FO_STD_REJECT = rr_reply(0x54, status=0x01, ext=(0x0100,))
FC_OK = rr_reply(0x4E, data=bytes(10))


def unit(msg, seq=1):
    msg = struct.pack("<H", seq) + msg
    cpf = (bytes(4) + b"\x0a\x00\x02\x00" + b"\xa1\x00\x04\x00" + CID + b"\xb1\x00"
           + struct.pack("<H", len(msg)) + msg)
    return encap(0x70, 1, cpf)


def pccc(payload=b"", sts=0, cip_status=0, cmd=0x4F):
    """a PCCC Execute reply: CIP header, requestor ID, CMD, STS, TNS, then the payload (from byte 61)"""
    body = b"\x07\x09\x10" + bytes(4) + bytes([cmd, sts]) + b"\x01\x00" + payload
    return unit(bytes([0xCB, 0, cip_status, 0]) + body)


def tag(t):
    return {"tag": t.tag, "value": enc(t.value), "type": t.type,
            "error": None if t.error is None else str(t.error),
            "kind": None if t.error_kind is None else t.error_kind.value}


def tags(result):
    return [tag(result)] if isinstance(result, Tag) else [tag(t) for t in result]


def run(call):
    try:
        return {"ok": call()}
    except Exception as err:
        return {"err": type(err).__name__, "msg": str(err)}


def scenario(name, path, replies, calls, **kwargs):
    script = Script(replies)
    with mock.patch.object(cip_driver, "Socket", lambda *a, **k: script), \
            mock.patch.object(cip_driver, "urandom", lambda n: bytes(n)):
        driver = SLCDriver(path, **kwargs)
        results = [run(lambda c=c: c[1](driver)) for c in calls]
    return {"name": name, "path": path, "options": kwargs, "replies": [r.hex() for r in replies],
            "calls": [c[0] for c in calls],
            "sent": [s.hex() for s in script.sent], "results": results}


def call_open():
    return {"op": "open"}, lambda d: d.open()


def call_close():
    return {"op": "close"}, lambda d: d.close()


def read(*addrs):
    return {"op": "read", "args": list(addrs)}, lambda d: tags(d.read(*addrs))


def write_(*pairs):
    return ({"op": "write", "args": [[a, enc(v)] for a, v in pairs]}, lambda d: tags(d.write(*pairs)))


def processor_type():
    return {"op": "get_processor_type"}, lambda d: d.get_processor_type()


def datalog(num, queue):
    return {"op": "get_datalog_queue", "args": [num, queue]}, lambda d: enc(d.get_datalog_queue(num, queue))


def file_directory():
    return {"op": "get_file_directory"}, lambda d: enc(d.get_file_directory())


def word(*values, fmt="<h"):
    return b"".join(struct.pack(fmt, v) for v in values)


def ptype(text):
    return pccc(bytes(5) + text.encode().ljust(11) + bytes(3), cmd=0x46)


def rows(*entries):
    return b"".join(bytes([code]) + struct.pack("<H", size) + bytes(7) for code, size in entries)


SYS0_1766 = bytes(233) + rows((0x82, 20), (0x83, 20), (0x84, 132), (0x85, 2), (0x86, 6 * 10), (0x87, 6),
                              (0x81, 0), (0x89, 2 * 100), (0x8A, 4 * 8), (0x8D, 84 * 2), (0x91, 4 * 3))
SYS0_SLC = bytes(79) + rows((0x82, 2), (0x83, 2), (0x84, 66), (0x85, 2), (0x89, 20))

SCENARIOS = [
    scenario("read_values", "127.0.0.1/1", [
        register_reply(1), FO_STD_OK,
        pccc(word(42)),
        pccc(word(1, -2, 3)),
        pccc(word(0x0002)),
        pccc(word(0x2000, 1000, 77)),
        pccc(word(0x2000, 1000, 77)),
        pccc(word(0x2000, 1000, 77)),
        pccc(struct.pack("<f", 1.5)),
        pccc(struct.pack("<i", -100000)),
        pccc(b"\x03\x00" + b"BAC\x00" + bytes(78)),
        pccc(word(0x0102)),
        pccc(word(0x0010)),
        pccc(word(0x00FF)),
        pccc(word(5, 6)),
    ], [
        call_open(),
        read("N7:0", "N7:0{3}", "B3/17", "T4:0.PRE", "T4:0.ACC", "T4:0.EN", "F8:1", "L9:2", "ST10:0",
             "A11:0", "S:1/4", "I:0/3", "O:2{2}"),
        call_close(),
    ]),
    scenario("read_errors", "127.0.0.1", [
        register_reply(1), FO_STD_OK,
        pccc(sts=0x10),
        pccc(b"\x07", sts=0xF0),
        pccc(sts=0x55),
        pccc(cip_status=0x08),
        pccc(b"\x01"),
        pccc(),
        b"",
    ], [
        call_open(),
        read("N7:0", "N7:1", "N7:2", "N7:3", "F8:0", "N7:4"),
        read("N7:5"),
    ]),
    scenario("read_request_errors", "127.0.0.1/2", [
        register_reply(1), FO_STD_OK, pccc(word(1)), pccc(word(2)),
    ], [
        call_open(),
        read("N7:0", "X7:0", "N7:1"),
        read("N7:0{200}"),
        read("B3/3{2}"),
        read("N255:255"),
    ]),
    scenario("write_values", "127.0.0.1/1", [register_reply(1), FO_STD_OK] + [pccc(cmd=0x4F)] * 11 + [
        pccc(sts=0x10)], [
        call_open(),
        write_(("N7:0", 21), ("N7:0{3}", [-30, 32767, -32767, 5]), ("B3/17", True), ("B3/18", 0),
               ("T4:0.PRE", 1000), ("C5:3.ACC", 7), ("T4:0.DN", True), ("F8:1", 2.5), ("L9:0", -70000),
               ("ST9:0{2}", ["abc", "de"]), ("N255:255", 1), ("N7:9", 3)),
        call_close(),
    ]),
    scenario("write_request_errors", "127.0.0.1", [
        register_reply(1), FO_STD_OK, pccc(), pccc(),
    ], [
        call_open(),
        write_(("N7:0", 1), ("N7:0", "abc"), ("N7:1", 2)),
        write_(("N7:0{3}", [1, 2])),
        write_(("N7:0/3{2}", [1, 1])),
        write_(("ST9:0{4}", ["a", "b", "c", "d"])),
        write_(("N7:0{200}", list(range(200)))),
        write_(("N7:1", 2)),
        write_(("N7:2", b"\xff\xff\x05\x00")),
    ]),
    scenario("processor_type", "127.0.0.1", [
        register_reply(1), FO_STD_OK, ptype("1766-LEC"), pccc(bytes(19), sts=0x10), pccc(bytes(5)),
        pccc(cip_status=0x08), b"",
    ], [
        call_open(), processor_type(), processor_type(), processor_type(), processor_type(), processor_type(),
    ]),
    scenario("datalog_queue", "127.0.0.1", [
        register_reply(1), FO_STD_OK, pccc(b"2024/01/01,1,2"), pccc(b"\xff\xfe"), pccc(sts=0x10),
        pccc(sts=0x10),
    ], [
        call_open(), datalog(3, 2),
    ]),
    scenario("file_directory_1766", "127.0.0.1", [
        register_reply(1), FO_STD_OK, ptype("1766-LEC"), pccc(struct.pack("<H", 19968 + len(SYS0_1766))),
    ] + [pccc(SYS0_1766[i:i + 0x50]) for i in range(0, len(SYS0_1766), 0x50)], [
        call_open(), file_directory(),
    ]),
    scenario("file_directory_slc", "127.0.0.1/0", [
        register_reply(1), FO_STD_OK, ptype("1747-L552"), pccc(struct.pack("<H", len(SYS0_SLC))),
    ] + [pccc(SYS0_SLC[i:i + 0x50]) for i in range(0, len(SYS0_SLC), 0x50)], [
        call_open(), file_directory(),
    ]),
    scenario("file_directory_offset_255", "127.0.0.1", [
        register_reply(1), FO_STD_OK, ptype("1747-L551"), pccc(struct.pack("<H", 520)),
        pccc(bytes(510)), pccc(bytes(10)),
    ], [
        call_open(), file_directory(),
    ]),
    scenario("file_directory_errors", "127.0.0.1", [
        register_reply(1), FO_STD_OK,
        pccc(sts=0x10),
        ptype("1763-L16"), pccc(sts=0x10),
        ptype("1763-L16"), pccc(),
        ptype("1761-L16"), pccc(struct.pack("<H", 200)), pccc(bytes(0x50)), pccc(sts=0x50),
        ptype("1764-LSP"), pccc(struct.pack("<H", 19968 - 4)),
    ], [
        call_open(), file_directory(), file_directory(), file_directory(), file_directory(), file_directory(),
    ]),
    scenario("forward_open_rejected", "127.0.0.1/1", [
        register_reply(1), FO_STD_REJECT, FO_STD_OK, pccc(word(9)),
    ], [
        call_open(), read("N7:0"), read("N7:0"),
    ]),
    scenario("forward_open_large_fallback", "127.0.0.1", [
        register_reply(1), FO_LARGE_REJECT, FO_STD_OK, pccc(word(9)), FC_OK,
    ], [
        call_open(), read("N7:0"), call_close(),
    ], connection_size=4000),
    scenario("no_session", "127.0.0.1", [], [read("N7:0"), write_(("N7:0", 1)), processor_type()]),
]

write("slc_driver.json", {"scenarios": SCENARIOS})
