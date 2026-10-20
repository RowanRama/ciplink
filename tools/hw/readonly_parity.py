"""
Read-only hardware parity: the reference Python driver and the Rust-backed package do the same read-only calls on a
real controller, each on its own connection, one right after the other; their request frames and results are
compared.

Every request frame passes through a write guard first. Anything that is not a read raises before the frame is
sent: Write Tag (fragmented), Read-Modify-Write, Set_Attribute*, wall clock set, metadata authentication, and any
other unknown service.

    python tools/hw/readonly_parity.py --address 192.0.2.10 --wheel target/wheels/ciplink-...whl [--out DIR]
    python tools/hw/readonly_parity.py --self-test-guard        # proves the guard blocks writes, no network

Internally it runs itself as ``--run ref|rust`` in a subprocess per implementation (both packages are named
ciplink, so they cannot share a process).
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# connected (SendUnitData) services that only read
CONNECTED_READS = {0x01, 0x03, 0x0E, 0x4C, 0x52, 0x55}
DESCRIPTION_READ_PREFIX = bytes.fromhex("53042100490325000000")  # Logix metadata read (logix_metadata._READ_PREFIX)


class WriteBlocked(Exception):
    pass


def _check_connected(cip, where):
    if not cip:
        raise WriteBlocked(f"{where}: empty CIP message")
    service = cip[0]
    if service == 0x0A:  # multi-service: check every embedded service
        path_words = cip[1]
        body = cip[2 + 2 * path_words:]
        count = struct.unpack_from("<H", body)[0]
        offsets = [struct.unpack_from("<H", body, 2 + 2 * i)[0] for i in range(count)] + [len(body)]
        for i in range(count):
            _check_connected(body[offsets[i]:offsets[i + 1]], f"{where} multi[{i}]")
        return
    if service == 0x53 and cip.startswith(DESCRIPTION_READ_PREFIX):
        return
    if service not in CONNECTED_READS:
        raise WriteBlocked(f"{where}: connected service 0x{service:02x} is not a read")


def _check_unconnected(cip, where):
    service = cip[0]
    if service in (0x54, 0x5B, 0x4E):  # Forward Open, Large Forward Open, Forward Close: Connection Manager only
        if cip[1:6] != b"\x02\x20\x06\x24\x01":
            raise WriteBlocked(f"{where}: 0x{service:02x} not addressed to the Connection Manager")
        return
    if service == 0x52:  # Unconnected Send: check the wrapped message
        if cip[1:6] != b"\x02\x20\x06\x24\x01":
            raise WriteBlocked(f"{where}: Unconnected Send not addressed to the Connection Manager")
        size = struct.unpack_from("<H", cip, 8)[0]
        _check_unconnected(cip[10:10 + size], f"{where} wrapped")
        return
    if service in (0x01, 0x03, 0x0E):
        return
    raise WriteBlocked(f"{where}: unconnected service 0x{service:02x} is not a read")


def guard(frame):
    """raises WriteBlocked unless the encapsulation frame only reads"""
    command = struct.unpack_from("<H", frame)[0]
    if command in (0x0063, 0x0065, 0x0066):  # ListIdentity, RegisterSession, UnRegisterSession
        return
    if command == 0x0070:  # SendUnitData: 24 header + 16 CPF + 2 sequence
        return _check_connected(frame[46:], "SendUnitData")
    if command == 0x006F:  # SendRRData: 24 header + 16 CPF
        return _check_unconnected(frame[40:], "SendRRData")
    raise WriteBlocked(f"encapsulation command 0x{command:04x} not allowed")


def mask(frame):
    """the parts of a request frame that differ between connections: session, context, connection ids, FO triad"""
    f = bytearray(frame)
    f[4:8] = bytes(4)
    f[12:20] = bytes(8)
    command = struct.unpack_from("<H", f)[0]
    if command == 0x0070 and len(f) >= 40:
        f[36:40] = bytes(4)
    if command == 0x006F and len(f) > 46:
        if f[40] in (0x54, 0x5B):
            f[52:58] = bytes(6)  # T->O connection id, connection serial
            f[60:64] = bytes(4)  # originator serial
        elif f[40] == 0x4E:
            f[48:50] = bytes(2)
            f[52:56] = bytes(4)
    return bytes(f)


# ------------------------------------------------------------------------------------------------- one run

def _jsonable(value):
    if isinstance(value, (bytes, bytearray)):
        return {"bytes": bytes(value).hex()}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return repr(value)


def _result(tag):
    error = tag.error
    return {"tag": tag.tag, "value": _jsonable(tag.value), "type": tag.type,
            "error": None if error is None else str(error),
            "kind": None if error is None else tag.error_kind.value}


def run(impl, address):
    if impl == "ref":
        sys.path.insert(0, os.path.join(ROOT, "tools", "reference"))
        import reference

        reference.load()  # the reference driver as ciplink
    import ciplink
    from ciplink import LogixDriver

    frames = []

    def install(plc):
        original = plc._send

        def guarded(message):
            guard(message)  # raises before anything leaves the PC
            frames.append(message)
            original(message)
        plc._send = guarded

    out = {"impl": impl, "module": ciplink.__file__, "steps": []}

    def step(name, fn):
        start, cpu = time.perf_counter(), time.process_time()
        count = len(frames)
        try:
            value, error = fn(), None
        except Exception as err:  # recorded and compared, a WriteBlocked aborts the run below
            if isinstance(err, WriteBlocked) or "WriteBlocked" in repr(err.__cause__):
                raise
            value, error = None, f"{type(err).__name__}: {err}"
        out["steps"].append({
            "name": name, "value": _jsonable(value), "error": error,
            "frames": [mask(f).hex() for f in frames[count:]],
            "wall_ms": round(1e3 * (time.perf_counter() - start), 1),
            "cpu_ms": round(1e3 * (time.process_time() - cpu), 1),
        })
        return value

    # 1. full upload (controller + programs), reads of every user tag, plc time, tag table check
    plc = LogixDriver(address, init_tags=False)
    install(plc)
    step("open", lambda: plc.open())
    step("tag_list", lambda: len(plc.get_tag_list("*")))
    tags = sorted(plc.tags)
    out["tag_count"] = len(tags)
    step("tags", lambda: plc.tags_json)
    step("data_types", lambda: sorted(plc.data_types))
    step("info", lambda: {k: plc.info[k] for k in ("vendor", "product_type", "product_code", "revision",
                                                   "serial", "product_name", "keyswitch", "name")})

    def names(kind):
        picked = []
        for name in tags:
            t = plc.tags[name]
            if kind == "scalar" and not t["dim"]:
                picked.append(name)
            elif kind == "array" and t["dim"] == 1 and t["dimensions"][0] <= 2000:
                picked.append(f"{name}{{{t['dimensions'][0]}}}")
        return picked

    scalars, arrays = names("scalar"), names("array")
    step("read_scalars", lambda: [_result(r) for r in plc.read(*scalars)] if scalars else [])
    step("read_arrays", lambda: [_result(r) for r in plc.read(*arrays)] if arrays else [])
    step("read_scalars_again", lambda: [_result(r) for r in plc.read(*scalars)] if scalars else [])
    members = []
    for name in scalars:
        t = plc.tags[name]
        if t["tag_type"] == "struct" and "attributes" in t["data_type"]:
            members += [f"{name}.{a}" for a in t["data_type"]["attributes"][:3]]
    step("read_members", lambda: [_result(r) for r in plc.read(*members[:150])] if members else [])
    step("read_missing", lambda: [_result(r) for r in plc.read("NoSuchTag_x", "NoSuchTag_y.Member", f"{tags[0]}[99999]")])
    step("plc_time", lambda: sorted(plc.get_plc_time().value or {}))
    step("check_tag_table", lambda: plc.check_tag_table())
    step("descriptions", lambda: [_result(r) for r in plc.get_tag_descriptions(*tags[:10])])
    step("close", lambda: plc.close())

    # 2. lazy tags: definitions resolved on demand
    lazy = LogixDriver(address, lazy_tags=True)
    install(lazy)
    step("lazy_open", lambda: lazy.open())
    step("lazy_read", lambda: [_result(r) for r in lazy.read(*scalars[:40])] if scalars else [])
    step("lazy_close", lambda: lazy.close())

    # 3. tag cache file: cold (uploads, writes the local file), warm (loads it); the file stays on this PC
    cache = os.path.join(tempfile.mkdtemp(prefix=f"ciplink-hw-{impl}-"), "tags.json")
    for label in ("cache_cold", "cache_warm"):
        p = LogixDriver(address, tag_cache_file=cache)
        install(p)
        step(f"{label}_open", lambda: p.open())
        step(f"{label}_tags", lambda: len(p.tags))
        step(f"{label}_close", lambda: p.close())
    out["frames_total"] = len(frames)
    return out


# ------------------------------------------------------------------------------------------------- compare

def compare(ref, rust):
    report = {"steps": [], "frame_mismatch_steps": [], "result_mismatches": 0, "value_only_differences": 0}
    for a, b in zip(ref["steps"], rust["steps"]):
        same_frames = a["frames"] == b["frames"]
        first = None
        if not same_frames:
            first = next((i for i, (x, y) in enumerate(zip(a["frames"], b["frames"])) if x != y),
                         min(len(a["frames"]), len(b["frames"])))
            report["frame_mismatch_steps"].append({"step": a["name"], "first_frame": first,
                                                   "ref_frames": len(a["frames"]), "rust_frames": len(b["frames"]),
                                                   "ref": a["frames"][first][:400] if first < len(a["frames"]) else None,
                                                   "rust": b["frames"][first][:400] if first < len(b["frames"]) else None})
        diff_struct, diff_value = 0, 0
        if isinstance(a["value"], list) and a["value"] and isinstance(a["value"][0], dict) and "tag" in a["value"][0]:
            for x, y in zip(a["value"], b["value"] or []):
                if (x["tag"], x["type"], x["kind"], x["error"]) != (y["tag"], y["type"], y["kind"], y["error"]):
                    diff_struct += 1
                elif x["value"] != y["value"]:
                    diff_value += 1  # a live controller: values may change between the two runs
            if len(a["value"]) != len(b["value"] or []):
                diff_struct += 1
        elif a["value"] != b["value"] or a["error"] != b["error"]:
            diff_struct += 1
        report["result_mismatches"] += diff_struct
        report["value_only_differences"] += diff_value
        report["steps"].append({"step": a["name"], "frames": len(a["frames"]), "frames_identical": same_frames,
                                "result_mismatches": diff_struct, "value_differences": diff_value,
                                "ref_wall_ms": a["wall_ms"], "rust_wall_ms": b["wall_ms"],
                                "ref_cpu_ms": a["cpu_ms"], "rust_cpu_ms": b["cpu_ms"],
                                "ref_error": a["error"], "rust_error": b["error"]})
    return report


def self_test_guard():
    unit = b"\x70\x00" + bytes(22) + bytes(20) + b"\x01\x00"  # SendUnitData header, CPF and sequence
    rr = b"\x6f\x00" + bytes(22) + bytes(16)  # SendRRData header and CPF
    tag = b"\x02\x91\x01x\x00"

    def multi(*msgs):
        offsets = [2 + 2 * len(msgs) + sum(map(len, msgs[:i])) for i in range(len(msgs))]
        return (b"\x0a\x02\x20\x02\x24\x01" + struct.pack("<H", len(msgs))
                + b"".join(struct.pack("<H", o) for o in offsets) + b"".join(msgs))

    cases = (
        ("write tag", unit + b"\x4d" + tag + b"\xc4\x00\x01\x00" + bytes(4), True),
        ("write fragmented", unit + b"\x53" + tag + b"\xc4\x00\x01\x00" + bytes(8), True),
        ("RMW", unit + b"\x4e" + tag + b"\x04\x00" + bytes(8), True),
        ("RMW inside multi", unit + multi(b"\x4c" + tag + b"\x01\x00", b"\x4e" + tag + b"\x04\x00" + bytes(8)), True),
        ("set attribute list (set_plc_time)", unit + b"\x04\x02\x20\x8b\x24\x01" + bytes(14), True),
        ("auth challenge 0x4B", unit + b"\x4b\x02\x20\x64\x24\x01", True),
        ("unconnected set attribute", rr + b"\x10\x02\x20\x01\x24\x01", True),
        ("unconnected send wrapping a write",
         rr + b"\x52\x02\x20\x06\x24\x01\x0a\x04\x0a\x00" + b"\x4d" + tag + b"\xc4\x00", True),
        ("read tag", unit + b"\x4c" + tag + b"\x01\x00", False),
        ("reads inside multi", unit + multi(b"\x4c" + tag + b"\x01\x00", b"\x52" + tag + b"\x01\x00" + bytes(4)), False),
        ("symbol list", unit + b"\x55\x02\x20\x6b\x24\x00\x01\x00\x01\x00", False),
        ("description read", unit + DESCRIPTION_READ_PREFIX + bytes(8), False),
        ("forward open", rr + b"\x5b\x02\x20\x06\x24\x01" + bytes(36), False),
        ("unconnected send identity",
         rr + b"\x52\x02\x20\x06\x24\x01\x0a\x04\x06\x00" + b"\x01\x02\x20\x01\x24\x01", False),
    )
    for name, frame, blocked in cases:
        try:
            guard(frame)
            ok = not blocked
        except WriteBlocked:
            ok = blocked
        print(f"guard {'ok ' if ok else 'BAD'} {'blocks' if blocked else 'allows'} {name}")
        if not ok:
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address")
    parser.add_argument("--wheel")
    parser.add_argument("--out", default=os.path.join(ROOT, "target", "hw"))
    parser.add_argument("--run", choices=("ref", "rust"))
    parser.add_argument("--self-test-guard", action="store_true")
    args = parser.parse_args()
    if args.self_test_guard:
        return self_test_guard()
    if args.run:
        print(json.dumps(run(args.run, args.address)))
        return
    self_test_guard()
    os.makedirs(args.out, exist_ok=True)
    me = os.path.abspath(__file__)
    base = ["uv", "run", "--no-project", "--isolated", "--python", "3.12"]
    runs = {}
    for impl, extra in (("ref", []), ("rust", ["--with", os.path.abspath(args.wheel)])):
        proc = subprocess.run(base + extra + ["python", me, "--run", impl, "--address", args.address],
                              capture_output=True, text=True, cwd=ROOT)
        if proc.returncode:
            print(proc.stderr[-4000:])
            sys.exit(f"{impl} run failed")
        runs[impl] = json.loads(proc.stdout.strip().splitlines()[-1])
        with open(os.path.join(args.out, f"{impl}.json"), "w") as file:
            json.dump(runs[impl], file)
        print(f"{impl}: {runs[impl]['module']}, {runs[impl]['tag_count']} tags, {runs[impl]['frames_total']} frames")
    report = compare(runs["ref"], runs["rust"])
    with open(os.path.join(args.out, "report.json"), "w") as file:
        json.dump(report, file, indent=1)
    for s in report["steps"]:
        flag = "ok " if s["frames_identical"] and not s["result_mismatches"] else "DIFF"
        print(f"{flag} {s['step']:<20} frames {s['frames']:>4} identical={s['frames_identical']!s:<5} "
              f"mismatch={s['result_mismatches']} values={s['value_differences']}  "
              f"wall {s['ref_wall_ms']:>8} / {s['rust_wall_ms']:>8} ms  cpu {s['ref_cpu_ms']:>7} / {s['rust_cpu_ms']:>7} ms"
              + (f"  ref_err={s['ref_error']}" if s["ref_error"] else "") + (f"  rust_err={s['rust_error']}" if s["rust_error"] else ""))
    print(json.dumps({k: report[k] for k in ("result_mismatches", "value_only_differences")}),
          f"frame-mismatch steps: {[m['step'] for m in report['frame_mismatch_steps']]}")


if __name__ == "__main__":
    main()
