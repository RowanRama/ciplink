"""CIPDriver fixtures: the frames the driver sends, in order, and what it returns for scripted replies.

Each scenario runs the Python CIPDriver against a scripted socket (replies served in order, b'' once they run out,
like the offline tests' Mocket) and records the sent frames and each call's outcome. The Forward Open connection
triad is random; it is fixed to zeros here and the Rust test masks it on both sides.
"""

import struct
from unittest import mock

from fixturelib import enc, write

from ciplink import CIPDriver
import ciplink.cip_driver as cip_driver

CTX = b"_pycomm_"
IDENTITY = (
    b"\x01\x00\x0e\x00Y\x00\x14\x13`0\x9b\xa0\x0f\xc0 1769-L23E-QBFC1 LOGIX5323E-QBFC1"
)


def encap(command, session, data, status=0):
    return struct.pack("<HHII", command, len(data), session, status) + CTX + bytes(4) + data


def register_reply(session):
    return encap(0x65, session, b"\x01\x00\x00\x00")


def cip_reply(service, status, ext, data):
    return bytes([service | 0x80, 0, status, len(ext)]) + b"".join(struct.pack("<H", e) for e in ext) + data


def rr_reply(service, status=0, ext=(), data=b"", session=1):
    msg = cip_reply(service, status, ext, data)
    cpf = bytes(4) + b"\x0a\x00\x02\x00" + b"\x00\x00\x00\x00" + b"\xb2\x00" + struct.pack("<H", len(msg)) + msg
    return encap(0x6F, session, cpf)


def unit_reply(service, status=0, ext=(), data=b"", seq=1, session=1, cid=b"\xdd\xcc\xbb\xaa"):
    msg = struct.pack("<H", seq) + cip_reply(service, status, ext, data)
    cpf = (bytes(4) + b"\x0a\x00\x02\x00" + b"\xa1\x00\x04\x00" + cid + b"\xb1\x00"
           + struct.pack("<H", len(msg)) + msg)
    return encap(0x70, session, cpf)


def list_identity_reply():
    item = (struct.pack("<H", 1) + struct.pack(">hH", 2, 44818) + bytes([127, 0, 0, 1]) + bytes(8)
            + IDENTITY + b"\x03")
    data = struct.pack("<HHH", 1, 0x0C, len(item)) + item
    return encap(0x63, 0, data)


FO_OK = rr_reply(0x5B, data=b"\xdd\xcc\xbb\xaa" + bytes(22))
FO_STD_OK = rr_reply(0x54, data=b"\xdd\xcc\xbb\xaa" + bytes(22))
FO_REJECT = rr_reply(0x5B, status=0x08)
FO_STD_REJECT = rr_reply(0x54, status=0x01, ext=(0x0100,))
FC_OK = rr_reply(0x4E, data=bytes(10))


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


def tag(t):
    return {"tag": t.tag, "value": enc(t.value), "error": None if t.error is None else str(t.error),
            "kind": None if t.error_kind is None else t.error_kind.value}


def run(call):
    try:
        return {"ok": call()}
    except Exception as err:
        return {"err": type(err).__name__, "msg": str(err)}


def scenario(name, path, replies, calls, **kwargs):
    script = Script(replies)
    with mock.patch.object(cip_driver, "Socket", lambda *a, **k: script), \
            mock.patch.object(cip_driver, "urandom", lambda n: bytes(n)):
        driver = CIPDriver(path, **kwargs)
        results = [run(lambda c=c: c(driver)) for c in calls]
    return {"name": name, "path": path, "options": kwargs, "replies": [r.hex() for r in replies],
            "sent": [s.hex() for s in script.sent], "results": results}


def state(d):
    return {"connected": d.connected, "target_connected": d._target_is_connected, "session": d._session,
            "connection_size": d.connection_size, "extended": d._cfg["extended forward open"]}


def generic(**kwargs):
    return lambda d: tag(d.generic_message(**kwargs))


SCENARIOS = [
    scenario("open_close", "127.0.0.1", [register_reply(0x11223344)],
             [lambda d: d.open(), lambda d: d.open(), state, lambda d: d.close(), state]),
    scenario("open_no_reply", "127.0.0.1", [], [lambda d: d.open(), state]),
    scenario("open_zero_session", "127.0.0.1", [register_reply(0)], [lambda d: d.open(), state]),
    scenario("connected_generic", "127.0.0.1/bp/0", [
        register_reply(1), FO_OK,
        unit_reply(0x0E, data=b"\x01\x02", seq=1),
        unit_reply(0x0E, status=0x05, ext=(0x0000,), seq=2),
        FC_OK,
    ], [
        lambda d: d.open(),
        generic(service=0x0E, class_code=0x01, instance=1, attribute=7, name="g1"),
        state,
        generic(service=b"\x0e", class_code=b"\x02", instance=b"\x01\x00", attribute=b"", request_data=b"\x05",
                name="g2"),
        lambda d: d.close(), state,
    ]),
    scenario("fo_fallback", "127.0.0.1/1/2", [
        register_reply(1), FO_REJECT, FO_STD_OK, unit_reply(0x01, data=b"\xaa", seq=1),
    ], [lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state]),
    scenario("fo_both_fail", "127.0.0.1", [register_reply(1), FO_REJECT, FO_STD_REJECT],
             [lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state]),
    scenario("fo_standard_only", "127.0.0.1", [register_reply(1), FO_STD_REJECT],
             [lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state],
             connection_size=500),
    scenario("fo_without_session", "127.0.0.1", [],
             [generic(service=0x01, class_code=0x01, instance=1), state]),
    scenario("unconnected_routes", "127.0.0.1/bp/0/enet/192.168.1.5", [register_reply(9)] + [
        rr_reply(0x01, data=bytes([i])) for i in range(6)
    ] + [rr_reply(0x01, status=0x05, ext=(0x0000,))], [
        lambda d: d.open(),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, name="plain"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True, name="current"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True,
                route_path=False, name="none"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True,
                route_path="bp/2", name="text"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True,
                route_path=b"\x01\x00\x01\x03", name="bytes"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True,
                request_data=b"\x01\x02\x03", name="odd"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, name="error"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, name="no reply"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True,
                route_path="bp", name="bad route"),
        state,
    ]),
    scenario("module_info", "127.0.0.1/bp/0", [register_reply(1), rr_reply(0x01, data=IDENTITY),
                                               rr_reply(0x01, status=0x05, ext=(0x0000,))], [
        lambda d: d.open(), lambda d: d.get_module_info(3), lambda d: d.get_module_info(4),
        lambda d: d.get_module_info(300), lambda d: d.get_module_info(1), state,
    ]),
    scenario("close_after_failed_forward_close", "127.0.0.1", [
        register_reply(1), FO_OK, unit_reply(0x01, data=b"\x00"), rr_reply(0x4E, status=0x01, ext=(0x0107,)),
    ], [lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), lambda d: d.close(), state]),
    scenario("close_drops_on_forward_close_without_reply", "127.0.0.1", [
        register_reply(1), FO_OK, unit_reply(0x01, data=b"\x00"),
    ], [lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), lambda d: d.close(), state]),
    scenario("list_identity_session", "127.0.0.1", [register_reply(5), list_identity_reply()], [
        lambda d: d.open(), lambda d: d._list_identity(), lambda d: d.close(), state,
    ]),
    scenario("bad_route_path", "127.0.0.1/backplan/1", [register_reply(5)], [
        lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state, lambda d: d.close(),
    ]),
]

# edge cases: reply statuses, a request that fails to build (its sequence count is still taken), empty routes,
# Forward Open sizes and the fallback state across a failed attempt and a reconnect
SCENARIOS += [
    scenario("generic_edge_replies", "127.0.0.1", [
        register_reply(1), FO_OK,
        unit_reply(0x4C, status=0x06, data=b"\xc4\x00\x01\x00\x00\x00", seq=1),
        unit_reply(0x0E, status=0x06, seq=2),
        unit_reply(0x0E, data=b"\x01", seq=4),
        encap(0x70, 1, b"", status=0x65),
        encap(0x70, 1, bytes(10)),
        rr_reply(0x4C, status=0x06),
        rr_reply(0x0E, status=0x1E, ext=(0x0101, 0x0002)),
        FC_OK,
    ], [
        lambda d: d.open(),
        generic(service=0x4C, class_code=0x6B, instance=1, name="partial"),
        generic(service=0x0E, class_code=0x01, instance=1, name="partial_not_multi"),
        generic(service=0x0E, class_code=b"\x01\x02\x03", instance=1, name="bad class"),
        generic(service=0x0E, class_code=0x01, instance=1, attribute=0, name="attr0"),
        generic(service=0x0E, class_code=0x01, instance=1, name="encap error"),
        generic(service=0x0E, class_code=0x01, instance=1, name="truncated"),
        generic(service=0x4C, class_code=0x6B, instance=1, connected=False, name="rr partial"),
        generic(service=0x0E, class_code=0x01, instance=1, connected=False, name="rr ext"),
        lambda d: d.close(), state,
    ]),
    scenario("unconnected_empty_path", "127.0.0.1", [
        register_reply(2), rr_reply(0x01, data=b"\x07"), rr_reply(0x01, data=IDENTITY), rr_reply(0x01, data=b"\x08"),
    ], [
        lambda d: d.open(),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True, name="current"),
        lambda d: d.get_module_info(2),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True,
                route_path="", name="empty text"),
        generic(service=0x01, class_code=0x01, instance=1, connected=False, unconnected_send=True,
                route_path=[], name="empty list"),
        state,
    ]),
    scenario("reopen_keeps_sequence", "127.0.0.1/bp/1", [
        register_reply(1), FO_STD_OK, unit_reply(0x01, data=b"\x01", seq=1), FC_OK,
        register_reply(2), FO_STD_OK, unit_reply(0x01, data=b"\x02", seq=2, session=2),
    ], [
        lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state, lambda d: d.close(),
        lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state,
    ], connection_size=511),
    scenario("standard_size_100", "127.0.0.1", [register_reply(1), FO_STD_OK, unit_reply(0x01, data=b"\x01")],
             [lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state], connection_size=100),
    scenario("large_size_65535", "127.0.0.1", [register_reply(1), FO_OK, unit_reply(0x01, data=b"\x01")],
             [lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state],
             connection_size=65535),
    scenario("fo_rejected_then_retried", "127.0.0.1", [
        register_reply(1), FO_REJECT, FO_STD_REJECT, FO_OK, unit_reply(0x01, data=b"\x01", seq=1),
    ], [
        lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1),
        generic(service=0x01, class_code=0x01, instance=1), state,
    ]),
    scenario("fallback_survives_reconnect", "127.0.0.1", [
        register_reply(1), FO_REJECT, FO_STD_OK, unit_reply(0x01, data=b"\x01", seq=1), FC_OK,
        register_reply(2), FO_STD_OK, unit_reply(0x01, data=b"\x02", seq=2, session=2),
    ], [
        lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), lambda d: d.close(),
        lambda d: d.open(), generic(service=0x01, class_code=0x01, instance=1), state,
    ]),
]


def list_identity_cases():
    out = []
    for name, replies in [("ok", [register_reply(5), list_identity_reply()]), ("rejected", []),
                          ("bad_reply", [register_reply(5), encap(0x63, 0, b"", status=1)])]:
        script = Script(replies)
        with mock.patch.object(cip_driver, "Socket", lambda *a, **k: script):
            result = run(lambda: CIPDriver.list_identity("127.0.0.1"))
        out.append({"name": name, "replies": [r.hex() for r in replies], "sent": [s.hex() for s in script.sent],
                    "result": enc(result.get("ok")) if "ok" in result else result})
    return out


def discover_request():
    from ciplink.packets import ListIdentityRequestPacket
    return [{"frame": ListIdentityRequestPacket().build_request(None, 0, b"\x00" * 8, 0).hex(),
             "reply": list_identity_reply().hex()}]


for s in SCENARIOS:
    for r in s["results"]:
        if "ok" in r and not isinstance(r["ok"], dict):
            r["ok"] = enc(r["ok"])
        elif "ok" in r and "tag" not in r["ok"] and "connected" not in r["ok"]:
            r["ok"] = enc(r["ok"])

write("cip_driver.json", {"scenarios": SCENARIOS, "list_identity": list_identity_cases(),
                          "discover": discover_request()})
