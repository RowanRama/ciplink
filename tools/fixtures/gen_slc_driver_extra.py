"""More SLCDriver fixtures (parity review): transport failures, Forward Open retries, more address forms, write
value edge cases, encapsulation errors and file directory edge cases. Same format as gen_slc_driver.py; a reply
of null is a receive that raises (the Rust test queues a transport error there).
"""

import struct
from unittest import mock

from fixturelib import write

import ciplink.cip_driver as cip_driver
from ciplink import SLCDriver
from gen_slc_driver import (
    FC_OK, FO_LARGE_REJECT, FO_STD_OK, FO_STD_REJECT, Script, call_close, call_open, datalog, encap,
    file_directory, pccc, processor_type, ptype, read, register_reply, rows, run, word, write_,
)


class RaisingScript(Script):
    def receive(self, timeout=0):
        reply = self.replies.pop(0) if self.replies else b""
        if reply is None:
            raise OSError("timed out")
        return reply


def scenario(name, path, replies, calls, **kwargs):
    script = RaisingScript(replies)
    with mock.patch.object(cip_driver, "Socket", lambda *a, **k: script), \
            mock.patch.object(cip_driver, "urandom", lambda n: bytes(n)):
        driver = SLCDriver(path, **kwargs)
        results = [run(lambda c=c: c[1](driver)) for c in calls]
    return {"name": name, "path": path, "options": kwargs,
            "replies": [None if r is None else r.hex() for r in replies],
            "calls": [c[0] for c in calls],
            "sent": [s.hex() for s in script.sent], "results": results}


SYS0_I_FIRST = bytes(79) + rows((0x83, 2), (0x84, 66), (0x89, 20))

SCENARIOS = [
    scenario("comm_error_mid_read_drops_connection", "127.0.0.1", [
        register_reply(1), FO_STD_OK, pccc(word(1)), None,
        register_reply(1), FO_STD_OK, pccc(word(3)),
    ], [
        call_open(),
        read("N7:0", "N7:1"),
        read("N7:2"),
        processor_type(),
        call_open(),
        read("N7:3"),
    ]),
    scenario("large_and_standard_rejected_then_retry", "127.0.0.1", [
        register_reply(1), FO_LARGE_REJECT, FO_STD_REJECT, FO_LARGE_REJECT, FO_STD_OK, pccc(word(9)), FC_OK,
    ], [
        call_open(), read("N7:0"), read("N7:0"), call_close(),
    ], connection_size=4000),
    scenario("more_reads", "127.0.0.1", [
        register_reply(1), FO_STD_OK,
        pccc(word(0x0008)),
        pccc(word(0x1234)),
        pccc(b"\x03\x00" + b"BAC\x00" + bytes(78) + b"\x01\x00" + b"X\x00" + bytes(80)),
        pccc(word(5, 6)),
        pccc(b"BADC"),
        pccc(struct.pack("<ff", 1.5, -2.25)),
        pccc(word(-32768)),
        pccc(word(0x2000, 7, 8)),
        pccc(word(0x0020)),
        pccc(struct.pack("<ii", 1, -2)),
        pccc(word(11)),
        pccc(word(0x2000, 12, 13)),
        pccc(word(1, 2, 3)),
        pccc(word(4)),
    ], [
        call_open(),
        read("I:1.2/3", "O:0.1", "ST10:0{2}", "S:2{2}", "A11:0{2}", "F8:0{2}", "N7:0/15", "C5:0.DN",
             "B3:0/5", "L9:0{2}", "n7:0", "T4:0.pre", "N7:0{2}", "N7:0{2}"),
        call_close(),
    ]),
    scenario("more_writes", "127.0.0.1", [register_reply(1), FO_STD_OK] + [pccc()] * 12, [
        call_open(),
        write_(("ST9:1", "hello"), ("F8:0{2}", [1.5, 2.5]), ("S:1/4", True), ("O:0.1/2", 1), ("I:0/3", False),
               ("A11:0", "ab"), ("L9:0{2}", [1, 2]), ("N7:1{2}", [1, 2, 3]),
               ("B3/18", 0.0), ("N7:5", -1)),
        write_(("N7:0", True)),
        write_(("N7:2", b"\x05")),
        write_(("N7:3", 70000)),
        write_(("N7:0{3}", "abc")),
        write_(("N7:4", 4)),
    ]),
    scenario("encapsulation_and_command_errors", "127.0.0.1", [
        register_reply(1), FO_STD_OK,
        encap(0x70, 1, b"", status=0x65),
        FO_STD_OK,
        pccc(word(1), cip_status=0x01),
        pccc(b"\xf0", sts=0xF0),
        pccc(sts=0xF0),
    ], [
        call_open(), read("N7:0", "N7:1", "N7:2", "N7:3", "N7:4"),
    ]),
    scenario("datalog_zero_entries", "127.0.0.1", [
        register_reply(1), FO_STD_OK, pccc(b""), pccc(b"x"), pccc(sts=0x10),
    ], [
        call_open(), datalog(0, 255), datalog(1, 3),
    ]),
    scenario("processor_type_text", "127.0.0.1", [
        register_reply(1), FO_STD_OK,
        pccc(bytes(5) + b"\xff 1747-L5\x00\x00" + bytes(3)),
        pccc(bytes(5) + b" " * 11),
        pccc(bytes(5) + b"\t1762-L24\x1f\x0b"),
        pccc(bytes(5) + b"1764"),
    ], [
        call_open(), processor_type(), processor_type(), processor_type(), processor_type(),
    ]),
    scenario("file_directory_edges", "127.0.0.1", [
        register_reply(1), FO_STD_OK,
        ptype("1747-L552"), pccc(struct.pack("<H", len(SYS0_I_FIRST))), pccc(SYS0_I_FIRST),
        ptype("1762-L24"), pccc(struct.pack("<H", 19968)),
        ptype("1747-L552"), pccc(b"\x01"),
        ptype("1747-L552"), pccc(struct.pack("<H", 3)), pccc(b"\x01"), pccc(b"\x02\x03"),
        ptype("1747-L552"), pccc(struct.pack("<H", 81)), pccc(bytes(79) + b"\x89\x05"),
        ptype("1747-L552"), pccc(struct.pack("<H", 80)), pccc(bytes(79) + b"\x89"),
    ], [
        call_open(), file_directory(), file_directory(), file_directory(), file_directory(), file_directory(),
        file_directory(),
    ]),
]

write("slc_driver_extra.json", {"scenarios": SCENARIOS})
