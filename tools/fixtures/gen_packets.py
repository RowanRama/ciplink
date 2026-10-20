"""Packet fixtures: encapsulation framing, CIP request messages, Forward Open/Close data and reply parsing."""

import types
from unittest import mock

from fixturelib import enc, outcome, write

from ciplink import CIPDriver
from ciplink.packets import (
    GenericConnectedRequestPacket,
    GenericUnconnectedRequestPacket,
    ListIdentityRequestPacket,
    ListIdentityResponsePacket,
    MultiServiceRequestPacket,
    MultiServiceResponsePacket,
    ReadModifyWriteRequestPacket,
    ReadTagFragmentedRequestPacket,
    ReadTagRequestPacket,
    RegisterSessionRequestPacket,
    RegisterSessionResponsePacket,
    SendRRDataResponsePacket,
    SendUnitDataResponsePacket,
    TagTableVersionRequestPacket,
    TagTableVersionResponsePacket,
    UnRegisterSessionRequestPacket,
    UnRegisterSessionResponsePacket,
    WriteTagFragmentedRequestPacket,
    WriteTagRequestPacket,
)
from ciplink.packets.util import response_error, tag_request_path

CTX = b"_pycomm_"
ENCAPS = [(0, CTX, 0), (0x12345678, b"\x01\x02\x03\x04\x05\x06\x07\x08", 0), (0xFFFFFFFF, CTX, 0xDEADBEEF)]
TARGET_CIDS = [b"\x01\x02\x03\x04", b"\xff\xff\xff\xff"]


def encap_args(session, context, option):
    return {"session": session, "context": context.hex(), "option": option}


def session_cases():
    cases = []
    for session, context, option in ENCAPS:
        for version, flags in [(b"\x01\x00", b"\x00\x00"), (b"\x02\x00", b"\x01\x00")]:
            req = RegisterSessionRequestPacket(version, flags)
            cases.append({"op": "register", "version": version.hex(), "flags": flags.hex(),
                          **encap_args(session, context, option),
                          "bytes": req.build_request(None, session, context, option).hex()})
        cases.append({"op": "unregister", **encap_args(session, context, option),
                      "bytes": UnRegisterSessionRequestPacket().build_request(None, session, context, option).hex()})
        cases.append({"op": "list_identity", **encap_args(session, context, option),
                      "bytes": ListIdentityRequestPacket().build_request(None, session, context, option).hex()})
    return cases


GENERIC = [
    # service, class, instance, attribute, data
    (0x0E, 1, 1, 1, b""),
    (0x01, 1, 1, b"", b""),
    (0x10, 4, 150, 3, b"\x00" * 36),
    (0x4B, 0x6B, 0, b"", b"\x01\x02\x03"),
    (0x03, 0xAC, 1, 0, b"\x02\x00\x01\x00\x02\x00"),
    (0x55, 0x6B, 0x1234, b"", bytes(range(10))),
    (0x0E, 0x300, 0x12345, 0x101, b"\x07"),
    (0x4C, 0x02, 1, b"", b""),
]


def generic_connected_cases():
    cases = []
    for service, cls, inst, attr, data in GENERIC:
        for seq in (0, 1, 3, 0xFFFF):
            req = GenericConnectedRequestPacket(seq, service, cls, inst, attr, data)
            full = []
            for (session, context, option), cid in zip(ENCAPS, TARGET_CIDS * 2):
                full.append({**encap_args(session, context, option), "cid": cid.hex(),
                             "bytes": req.build_request(cid, session, context, option).hex()})
            cases.append({"service": service, "class": cls, "instance": inst,
                          "attribute": attr if isinstance(attr, int) else None, "data": data.hex(),
                          "sequence": seq, "message": req.build_message().hex(),
                          "tag_only": req.tag_only_message().hex(), "full": full})
    return cases


ROUTES = [b"", b"\x01\x00\x01\x00", b"\x02\x00\x01\x00\x01\x05", b"\x01\x00\x01\x03"]


def generic_unconnected_cases():
    cases = []
    for service, cls, inst, attr, data in GENERIC + [(0x0E, 1, 1, 7, b"\x01")]:
        for route in ROUTES:
            for ucs in (False, True):
                req = GenericUnconnectedRequestPacket(service, cls, inst, attr, data, route, ucs)
                full = []
                for (session, context, option), cid in zip(ENCAPS, TARGET_CIDS * 2):
                    full.append({**encap_args(session, context, option), "cid": cid.hex(),
                                 "bytes": req.build_request(cid, session, context, option).hex()})
                cases.append({"service": service, "class": cls, "instance": inst,
                              "attribute": attr if isinstance(attr, int) else None, "data": data.hex(),
                              "route": route.hex(), "unconnected_send": ucs,
                              "message": req.build_message().hex(), "full": full})
    return cases


TAGS = [("a", {}, False), ("Tag1", {"instance_id": 5}, True), ("a[1,2].b", {"instance_id": 0x1234}, True),
        ("Program:Main.x[3]", {"instance_id": 7}, True), ("abc.def", {}, False), ("Arr[10]", {"instance_id": 9}, False)]


def tag_cases():
    reads, frags, writes, wfrags = [], [], [], []
    for tag, info, use_ids in TAGS:
        path = tag_request_path(tag, info, use_ids).hex()
        for elements in (1, 2, 500, 0xFFFF):
            req = ReadTagRequestPacket(5, tag, elements, info, 0, use_ids)
            reads.append({"path": path, "elements": elements, "sequence": 5, "message": req.build_message().hex(),
                          "tag_only": req.tag_only_message().hex()})
            for offset in (0, 1, 480, 0xFFFFFFFF):
                req = ReadTagFragmentedRequestPacket(9, tag, elements, info, 0, use_ids, offset)
                frags.append({"path": path, "elements": elements, "offset": offset, "sequence": 9,
                              "message": req.build_message().hex(), "tag_only": req.tag_only_message().hex()})
        write_types = [("DINT", "atomic", None), ("dint", "atomic", None), ("REAL", "atomic", None),
                       ("BOOL", "atomic", None), ("STRING", "atomic", None), ("DWORD", "atomic", None),
                       ("LINT", "atomic", None), ("MyUDT", "struct", 0x0FCE), ("MyUDT", "struct", 0),
                       ("BOGUS", "atomic", None), ("MyUDT", "struct", 0xFFFF)]
        for name, tag_type, handle in write_types:
            ti = {**info, "data_type_name": name, "tag_type": tag_type}
            if handle is not None:
                ti["data_type"] = {"template": {"structure_handle": handle}}
            for elements, value in ((1, b"\x01\x00\x00\x00"), (3, bytes(range(12))), (1, b"")):
                base = {"path": path, "type_name": name, "struct_handle": handle, "elements": elements,
                        "value": value.hex()}
                try:
                    req = WriteTagRequestPacket(4, tag, elements, ti, 0, use_ids, value)
                    writes.append({**base, "message": req.build_message().hex(),
                                   "tag_only": req.tag_only_message().hex()})
                except Exception as err:
                    writes.append({**base, "err": type(err).__name__, "msg": str(err)})
                    continue
                for offset in (0, 8, 0x10000):
                    req = WriteTagFragmentedRequestPacket(6, tag, elements, ti, 0, use_ids, offset, value)
                    req.request_path = bytes.fromhex(path)
                    wfrags.append({**base, "offset": offset, "sequence": 6, "message": req.build_message().hex(),
                                   "tag_only": req.tag_only_message().hex()})
    return reads, frags, writes, wfrags


def rmw_cases():
    cases = []
    bit_sets = [[], [(0, True)], [(0, False)], [(3, True), (5, False)], [(7, True), (7, False)],
                [(15, True)], [(31, True), (0, False)], [(32, True)], [(40, True), (63, False)], [(63, True)],
                [(70, False)], [(64, True)], [(33, False), (2, True)]]
    for name in ("SINT", "INT", "DINT", "LINT", "DWORD", "USINT", "BOOL"):
        for bits in bit_sets:
            info = {"data_type_name": name, "instance_id": 3}
            req = ReadModifyWriteRequestPacket(2, "x", info, 0, True)
            for bit, value in bits:
                req.set_bit(bit, value, 0)
            case = {"type_name": name, "path": req.request_path.hex(), "bits": [[b, v] for b, v in bits]}
            res = outcome(req.tag_only_message)
            case["tag_only"] = res
            if "ok" in res:
                case["message"] = req.build_message().hex()
            cases.append(case)
    return cases


def ttv_cases():
    req = TagTableVersionRequestPacket(11)
    return [{"sequence": 11, "message": req.build_message().hex(), "tag_only": req.tag_only_message().hex(),
             "request_size": TagTableVersionRequestPacket.request_size,
             "reply_size": TagTableVersionRequestPacket.reply_size}]


def multi_cases():
    cases = []
    subs = [
        ReadTagRequestPacket(1, "a", 1, {}, 0, False),
        ReadTagRequestPacket(1, "Tag1", 10, {"instance_id": 5}, 0, True),
        WriteTagRequestPacket(1, "b", 1, {"data_type_name": "DINT", "tag_type": "atomic"}, 0, False, b"\x05\x00\x00\x00"),
        TagTableVersionRequestPacket(1),
        ReadTagRequestPacket(1, "c.d[3]", 2, {}, 0, False),
    ]
    for group in ([], subs[:1], subs[:2], subs, subs[3:], subs[1:4]):
        req = MultiServiceRequestPacket(8, group)
        for sub in group:  # tag_only_message of a read needs its path set up
            sub.build_message()
        cases.append({"sequence": 8, "messages": [s.tag_only_message().hex() for s in group],
                      "message": req.build_message().hex()})
    return cases


FO_PATHS = ["10.0.0.5", "10.0.0.5/bp/0", "10.0.0.5/1/3", "10.0.0.5/bp/1/enet/10.1.1.1/bp/2", "10.0.0.5:44818/bp/5"]


def forward_cases():
    cases = []
    triads = [(b"\x01\x02\x03\x04", b"\x05\x06", b"\x07\x08\x09\x0a"), (b"\xff" * 4, b"\x00\x00", b"\xaa" * 4)]
    for path in FO_PATHS:
        for large in (False, True):
            for size in (500, 504, 511, 512, 4002, 0xFFFF, 0x10000 + 4002):
                for cid, csn, vsn in triads:
                    driver = CIPDriver(path)
                    driver._session = 1
                    driver._cfg["extended forward open"] = large
                    driver._cfg["connection_size"] = size
                    driver._connection_size = size
                    randoms = iter([cid, csn, vsn])
                    with mock.patch("ciplink.cip_driver.urandom", lambda n: next(randoms)), \
                            mock.patch.object(CIPDriver, "send") as send:
                        driver._forward_open()
                    fo = send.call_args[0][0].build_message()
                    with mock.patch.object(CIPDriver, "send") as send:
                        driver._forward_close()
                    fc = send.call_args[0][0].build_message()
                    cases.append({"path": path, "large": large, "size": driver.connection_size, "cid": cid.hex(),
                                  "csn": csn.hex(), "vsn": vsn.hex(), "vid": driver._cfg["vid"].hex(),
                                  "forward_open": fo.hex(), "forward_close": fc.hex()})
    return cases


def fields(r):
    out = {
        "command": enc(r.command), "command_status": r.command_status, "service": enc(r.service),
        "service_status": r.service_status, "data": enc(r.data), "is_valid": r.is_valid(),
        "error": outcome(lambda: r.error),
    }
    try:
        te = response_error(r)
        out["response_error"] = {"ok": {"message": str(te), "kind": te.kind.value, "status": te.status, "ext": te.ext}}
    except Exception as err:
        out["response_error"] = {"err": type(err).__name__, "msg": str(err)}
    return out


def encap(cmd, status=0, session=0, length=0):
    return cmd + length.to_bytes(2, "little") + session.to_bytes(4, "little") + status.to_bytes(4, "little") + CTX + bytes(4)


def cip_replies(cmd, head_len):
    """crafted SendUnitData / SendRRData replies: head_len is the offset of the reply service"""
    head = encap(cmd).ljust(head_len, b"\x00")
    replies = [
        None, b"", b"\x70", cmd, cmd + b"\x00" * 6, cmd + b"\x00" * 9, encap(cmd)[:12], encap(cmd),
        encap(cmd, 0x64), encap(cmd, 0x65), encap(cmd, 0x01), encap(cmd, 0x1234), encap(cmd, 0x80000000),
        encap(cmd, 0xFFFFFFFF), encap(cmd, 0x69) + b"\x00" * 40,
        head, head + b"\xcc", head + b"\xcc\x00", head + b"\xcc\x00\x00", head + b"\xcc\x00\x00\x00",
        head + b"\xcc\x00\x00\x00\xc4\x00\x01\x00\x00\x00",
        head + b"\xcc\x00\x00\x01\x05\x00\xc4\x00",  # ext status words skipped
        head + b"\x8e\x00\x00\x00",
        head + b"\xcc\x00\x06\x00\x01\x02",
        head + b"\xd2\x00\x06\x00\x01\x02",  # read fragmented, partial data
        head + b"\xd3\x00\x06\x00",  # write fragmented
        head + b"\x8a\x00\x06\x00",  # multi-service
        head + b"\x83\x00\x06\x00",  # get attribute list
        head + b"\xd5\x00\x06\x00",  # get instance attribute list
        head + b"\xcc\x00\x04\x00",
        head + b"\xcc\x00\x05\x00",
        head + b"\xcc\x00\x0c\x00",
        head + b"\xcc\x00\xff\x01\x05\x21",
        head + b"\xcc\x00\xff\x01\x04\x21",
        head + b"\xcc\x00\xff\x01\x07\x21",
        head + b"\xcc\x00\xff\x01\x99\x99",
        head + b"\xcc\x00\xff\x02\x05\x21\x01\x00",
        head + b"\xcc\x00\x01\x01\x09\x01",
        head + b"\xcc\x00\x01\x01\x09",  # ext word truncated
        head + b"\xcc\x00\x01\x01",  # ext size without words
        head + b"\xd4\x00\x01\x01\x00\x01",  # forward open reply, unknown service
        head + b"\xdb\x00\x00\x00" + bytes(range(20)),  # large forward open reply
        head + b"\xcc\x00\x42\x00",  # unknown status
        head + b"\xcc\x00\x1e\x00",
        head + b"\x00\x00\x00\x00",  # service 0x00 not a known service
        head + b"\x8e\x00\x00\x02\x01\x00\x02\x00" + b"\x09",
        head + b"\xcc\x00\x00\x05",  # ext size beyond the data
        head + b"\xcc\x00\x08\x00\x01",
        head + b"\x8e\x00\x26\x00",
        head + b"\x8e\x00\x0f\x00",
    ]
    return replies


def reply_cases():
    cases = []
    for kind, cls, cmd, head_len in (("send_unit_data", SendUnitDataResponsePacket, b"\x70\x00", 46),
                                      ("send_rr_data", SendRRDataResponsePacket, b"\x6f\x00", 40)):
        for raw in cip_replies(cmd, head_len) + cip_replies(b"\x6f\x00" if cmd == b"\x70\x00" else b"\x70\x00", head_len):
            r = cls(None, raw)
            cases.append({"kind": kind, "raw": None if raw is None else raw.hex(), **fields(r)})
    for raw in [None, b"", b"\x65\x00", b"\x65\x00\x00\x00\x01\x00", encap(b"\x65\x00")[:8], encap(b"\x65\x00")[:11],
                encap(b"\x65\x00", 0, 0x11223344), encap(b"\x65\x00", 0, 0xFFFFFFFF) + b"\x01\x00\x00\x00",
                encap(b"\x65\x00", 0x69, 0x5), encap(b"\x65\x00", 0x2, 0)]:
        r = RegisterSessionResponsePacket(None, raw)
        cases.append({"kind": "register_session", "raw": None if raw is None else raw.hex(), **fields(r),
                      "session": r.session})
    for raw in [None, b"", encap(b"\x66\x00"), encap(b"\x66\x00", 0x64), encap(b"\x66\x00")[:10]]:
        r = UnRegisterSessionResponsePacket(None, raw)
        cases.append({"kind": "unregister_session", "raw": None if raw is None else raw.hex(), **fields(r)})
    return cases




def identity_item():
    name = b"1756-SIM/A"
    body = (b"\x01\x00" + b"\x0e\x00" + b"\x96\x00" + b"\x14\x06" + b"\x60\x30" + b"\x78\x56\x34\x12"
            + bytes([len(name)]) + name + b"\x03")
    sock = b"\x01\x00" + b"\x00\x02" + b"\xaf\x12" + b"\x0a\x00\x00\x05" + bytes(8)
    payload = sock + body
    return b"\x0c\x00" + len(payload).to_bytes(2, "little") + payload


def list_identity_cases():
    cases = []
    item = identity_item()
    good = encap(b"\x63\x00", 0, 0, 2 + len(item)) + b"\x01\x00" + item
    for raw in [None, b"", encap(b"\x63\x00"), encap(b"\x63\x00", 0x01), encap(b"\x63\x00", 0x64)[:12], good,
                good[:-1], good[:40], good[:26], good + b"\x00\x00"]:
        r = ListIdentityResponsePacket(None, raw)
        case = {"kind": "list_identity", "raw": None if raw is None else raw.hex(), **fields(r)}
        case["identity"] = enc(r.identity) if r.identity else None
        cases.append(case)
    return cases


def sub(status, data=b"", service=0xCC, ext=b""):
    return bytes([service, 0, status, len(ext) // 2]) + ext + data


def multi_body(subs, count=None, offsets=None):
    count = len(subs) if count is None else count
    if offsets is None:
        offsets, off = [], 2 + 2 * len(subs)
        for s in subs:
            offsets.append(off)
            off += len(s)
    return count.to_bytes(2, "little") + b"".join(o.to_bytes(2, "little") for o in offsets) + b"".join(subs)


def multi_reply_cases():
    cases = []
    head = encap(b"\x70\x00").ljust(46, b"\x00")
    ok1 = sub(0, b"\xc4\x00\x01\x00\x00\x00")
    ok2 = sub(0, b"\xca\x00\x00\x00\xc0\x3f")
    err = sub(0x04, ext=b"\x00\x00")
    frag = sub(0x06, b"\xc4\x00\x01\x00", service=0xD2)
    bodies = [
        (1, multi_body([ok1])), (2, multi_body([ok1, ok2])), (3, multi_body([ok1, err, ok2])),
        (2, multi_body([ok1, frag])), (3, multi_body([ok1, ok2])), (1, multi_body([ok1, ok2])),
        (2, multi_body([ok1, ok2], offsets=[6, 7])), (2, multi_body([ok1, b"\xcc\x00"])),
        (2, multi_body([ok1, ok2], offsets=[30, 6])), (1, b""), (1, b"\x01"), (2, b"\x02\x00\x06\x00"),
        (1, multi_body([b"\xcc\x00\x00\x00"])), (0, b"\x00\x00"), (1, multi_body([sub(0xFF, ext=b"\x05\x21")])),
        (1, multi_body([b"\xcc\x00\x00\x02\x01"])),
    ]
    for status in (0x00, 0x06, 0x1E, 0x04):
        for n, body in bodies:
            raws = [head + bytes([0x8A, 0, status, 0]) + body]
            for raw in raws:
                req = types.SimpleNamespace(requests=[types.SimpleNamespace(response_class=SendUnitDataResponsePacket)] * n)
                r = MultiServiceResponsePacket(req, raw)
                cases.append({"count": n, "raw": raw.hex(), **fields(r), "replies": [fields(s) for s in r.responses]})
    for raw in [None, encap(b"\x70\x00", 0x64), head + b"\x8a\x00\x00", head + b"\x8a\x00\x00\x01"]:
        req = types.SimpleNamespace(requests=[types.SimpleNamespace(response_class=SendUnitDataResponsePacket)])
        r = MultiServiceResponsePacket(req, raw)
        cases.append({"count": 1, "raw": None if raw is None else raw.hex(), **fields(r),
                      "replies": [fields(s) for s in r.responses]})
    return cases


def ttv_reply_cases():
    cases = []
    head = encap(b"\x70\x00").ljust(46, b"\x00")
    good_attrs = (b"\x01\x00\x00\x00\x07\x00" + b"\x02\x00\x00\x00\xfe\xff" + b"\x03\x00\x00\x00\x01\x02\x03\x04"
                  + b"\x04\x00\x00\x00\xff\xff\xff\xff" + b"\x0a\x00\x00\x00\x00\x00\x00\x80")
    good = b"\x05\x00" + good_attrs
    bodies = [
        (0, good), (0, good + b"\x00"), (0, good[:-1]), (0, good[:2]), (0, b""), (0x04, good),
        (0, b"\x05\x00" + b"\x02\x00\x00\x00\x07\x00" + good_attrs[6:]),
        (0, b"\x05\x00" + b"\x01\x00\x05\x00\x07\x00" + good_attrs[6:]),
        (0, b"\x09\x00" + good_attrs), (0x06, good),
    ]
    for status, body in bodies:
        raw = head + bytes([0x83, 0, status, 0]) + body
        r = TagTableVersionResponsePacket(None, raw)
        cases.append({"raw": raw.hex(), **fields(r), "value": enc(r.value)})
    for raw in [None, encap(b"\x70\x00", 0x64)]:
        r = TagTableVersionResponsePacket(None, raw)
        cases.append({"raw": None if raw is None else raw.hex(), **fields(r), "value": enc(r.value)})
    return cases


def sweep_reply_cases():
    """reviewer sweeps: every reply service byte, every general status, every truncation"""
    cases = []
    for kind, cls, cmd, head_len in (("send_unit_data", SendUnitDataResponsePacket, b"\x70\x00", 46),
                                      ("send_rr_data", SendRRDataResponsePacket, b"\x6f\x00", 40)):
        head = encap(cmd).ljust(head_len, b"\x00")
        raws = [head + bytes([service, 0, 0x06, 0]) + b"\x01" for service in range(256)]
        for status in range(256):
            raws.append(head + bytes([0xCC, 0, status, 0]))
            raws.append(head + bytes([0xCC, 0, status, 1, 0x05, 0x21]) + b"\x09")
            raws.append(head + bytes([0x8E, 0, status, 2, 0x00, 0x01, 0xAA, 0xBB]))
        full = head + b"\xcc\x00\xff\x02\x07\x21\x01\x00\xc4\x00\x01\x00\x00\x00"
        raws += [full[:n] for n in range(len(full))]
        for raw in raws:
            f = fields(cls(None, raw))
            if "ok" not in f["error"]:
                continue  # a truncated extended status raises in Python, covered by reply_cases
            cases.append({"kind": kind, "raw": raw.hex(), **f})
    reg = encap(b"\x65\x00", 0, 0x01020304) + b"\x01\x00\x00\x00"
    for n in range(len(reg)):
        r = RegisterSessionResponsePacket(None, reg[:n])
        cases.append({"kind": "register_session", "raw": reg[:n].hex(), **fields(r), "session": r.session})
    item = identity_item()
    good = encap(b"\x63\x00", 0, 0, 2 + len(item)) + b"\x01\x00" + item
    name_at = good.index(b"1756")
    odd = [good[:name_at - 1] + b"\x04\xff\xfe\x80\xc3\x03", good[:name_at - 1] + b"\x20AB",
           good[:name_at - 1] + b"\x00\x07", good[:name_at - 1] + b"\x00"]
    for n, raw in [(n, good[:n]) for n in range(len(good))] + [(None, raw) for raw in odd]:
        r = ListIdentityResponsePacket(None, raw)
        cases.append({"kind": "list_identity", "raw": raw.hex(), **fields(r),
                      "identity": enc(r.identity) if r.identity else None})
    return cases


def sweep_multi_reply_cases():
    cases = []
    head = encap(b"\x70\x00").ljust(46, b"\x00")
    ok1 = sub(0, b"\xc4\x00\x01\x00\x00\x00")
    bodies = [
        (1, multi_body([ok1], offsets=[0xFFFF])), (2, multi_body([ok1, ok1], offsets=[6, 0xFFFF])),
        (1, multi_body([ok1], offsets=[0])), (1, multi_body([ok1], offsets=[2])),
        (0, b"\x00\x00\x01\x02\x03"), (1, b"\x01\x00"), (1, b"\x01\x00\x04"),
        (2, multi_body([sub(0x1E, ext=b"\x01\x00"), sub(0x06, b"\x01", service=0xD2)])),
        (2, multi_body([sub(0x05, service=0x8E), sub(0xFF, ext=b"\x0a\x21\x00\x00")])),
        (3, multi_body([ok1, sub(0x04), sub(0x0F, service=0xCD)])),
        (0xFFFF, b"\xff\xff"),
    ]
    good = multi_body([ok1, sub(0x04, ext=b"\x00\x00"), sub(0, b"\x01\x02", service=0x83)])
    bodies += [(3, good[:n]) for n in range(len(good))]
    for status in (0x00, 0x06, 0x1E, 0x01):
        for n, body in bodies:
            raw = head + bytes([0x8A, 0, status, 0]) + body
            req = types.SimpleNamespace(requests=[types.SimpleNamespace(response_class=SendUnitDataResponsePacket)] * n)
            r = MultiServiceResponsePacket(req, raw)
            f, subs = fields(r), [fields(s) for s in r.responses]
            if "ok" not in f["error"] or any("ok" not in s["error"] for s in subs):
                continue
            cases.append({"count": n, "raw": raw.hex(), **f, "replies": subs})
    return cases


def sweep_ttv_reply_cases():
    cases = []
    head = encap(b"\x70\x00").ljust(46, b"\x00")
    good = (b"\x05\x00" + b"\x01\x00\x00\x00\x00\x80" + b"\x02\x00\x00\x00\xff\x7f"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00" + b"\x04\x00\x00\x00\xff\xff\xff\x7f"
            + b"\x0a\x00\x00\x00\x01\x00\x00\x00")
    bodies = [good[:n] for n in range(len(good) + 1)]
    bodies += [good[:2] + b"\x0a\x00" + good[4:], good[:-10] + b"\x0a\x00\x01\x00" + good[-6:]]
    for body in bodies:
        raw = head + bytes([0x83, 0, 0, 0]) + body
        r = TagTableVersionResponsePacket(None, raw)
        cases.append({"raw": raw.hex(), **fields(r), "value": enc(r.value)})
    return cases


def write_type_code_cases():
    from ciplink.cip import DataTypes
    names = list(DataTypes.attributes)
    names += [n.upper() for n in names] + ["Dint", "BOGUS", "", "STRING[10]", "dint ", "STRUCT", "UDT"]
    cases = []
    for name in names:
        ti = {"data_type_name": name, "tag_type": "atomic"}
        res = outcome(lambda: WriteTagRequestPacket(1, "a", 1, ti, 0, False, b"")._packed_data_type)
        cases.append({"type_name": name, "result": res})
    return cases


def main():
    reads, frags, writes, wfrags = tag_cases()
    write("packets.json", {
        "session": session_cases(),
        "generic_connected": generic_connected_cases(),
        "generic_unconnected": generic_unconnected_cases(),
        "read_tag": reads,
        "read_tag_fragmented": frags,
        "write_tag": writes,
        "write_tag_fragmented": wfrags,
        "read_modify_write": rmw_cases(),
        "tag_table_version": ttv_cases(),
        "multi_service": multi_cases(),
        "forward": forward_cases(),
        "replies": reply_cases() + list_identity_cases() + sweep_reply_cases(),
        "multi_replies": multi_reply_cases() + sweep_multi_reply_cases(),
        "tag_table_version_replies": ttv_reply_cases() + sweep_ttv_reply_cases(),
        "write_type_codes": write_type_code_cases(),
    })


if __name__ == "__main__":
    main()
