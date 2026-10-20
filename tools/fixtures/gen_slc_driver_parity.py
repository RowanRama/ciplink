"""More SLCDriver fixtures (second parity review): the Forward Open error message of every call, an empty read,
calls after close(), transport failures in the file directory and datalog loops, and write values of the wrong
shape. Same format as gen_slc_driver.py; a reply of null is a receive that raises.
"""

import struct
from unittest import mock

from fixturelib import write

import ciplink.cip_driver as cip_driver
from ciplink import SLCDriver
from gen_slc_driver import (
    FC_OK, FO_LARGE_REJECT, FO_STD_OK, FO_STD_REJECT, Script, call_close, call_open, datalog, file_directory, pccc, processor_type,
    ptype, read, register_reply, run, word, write_,
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


def get_size():
    return {"op": "connection_size"}, lambda d: d.connection_size


SCENARIOS = [
    scenario("forward_open_rejected_names_the_call", "127.0.0.1", [
        register_reply(1), FO_STD_REJECT, FO_STD_REJECT, FO_STD_REJECT, FO_STD_REJECT, FO_STD_REJECT,
    ], [
        call_open(), write_(("N7:0", 1)), processor_type(), datalog(1, 0), file_directory(), read(),
    ]),
    scenario("empty_read_and_write_still_open_the_connection", "127.0.0.1", [
        register_reply(1), FO_STD_OK, FC_OK,
    ], [
        call_open(), read(), write_(), call_close(),
    ]),
    scenario("calls_after_close_need_a_new_session", "127.0.0.1", [
        register_reply(1), FO_STD_OK, pccc(word(1)), FC_OK,
    ], [
        call_open(), read("N7:0"), call_close(), read("N7:0"), write_(("N7:0", 1)), file_directory(),
    ]),
    scenario("comm_error_in_file_directory_loop", "127.0.0.1", [
        register_reply(1), FO_STD_OK, ptype("1747-L552"), pccc(struct.pack("<H", 200)), pccc(bytes(0x50)), None,
    ], [
        call_open(), file_directory(), datalog(1, 0),
    ]),
    scenario("comm_error_in_directory_size", "127.0.0.1", [
        register_reply(1), FO_STD_OK, ptype("1766-LEC"), None,
    ], [
        call_open(), file_directory(), processor_type(),
    ]),
    scenario("comm_error_in_datalog_queue", "127.0.0.1", [
        register_reply(1), FO_STD_OK, pccc(b"a"), None,
    ], [
        call_open(), datalog(3, 1), read("N7:0"),
    ]),
    scenario("no_session_with_large_connection_size", "127.0.0.1", [], [
        read("N7:0"), get_size(), datalog(1, 0),
    ], connection_size=4000),
    scenario("standard_forward_open_fails_mid_fallback", "127.0.0.1", [
        register_reply(1), FO_LARGE_REJECT, None, register_reply(1), FO_LARGE_REJECT, FO_STD_OK, pccc(word(4)),
    ], [
        call_open(), read("N7:0"), get_size(), call_open(), read("N7:0"), get_size(),
    ], connection_size=4000),
    scenario("write_value_shapes", "127.0.0.1", [register_reply(1), FO_STD_OK] + [pccc()] * 4, [
        call_open(),
        write_(("N7:0", [1, 2])),
        write_(("F8:0", "x")),
        write_(("N7:0{2}", [1, "a"])),
        write_(("ST9:0", 5)),
        write_(("B3/1", [])),
        write_(("T4:0.ACC", 1.5)),
        write_(("N7:1", b"")),
        write_(("N7:1", b"\x01\x00")),
        write_(("N7:2", 2)),
    ]),
]

write("slc_driver_parity.json", {"scenarios": SCENARIOS})
