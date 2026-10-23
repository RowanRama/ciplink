"""
Acceptance test of the simulator and the Python package: the installed ``ciplink`` (the Rust-backed package) or,
with ``--reference``, the reference Python driver (tools/reference) against ``ciplink-sim``.

Builds the simulator bin (``cargo build -p ciplink-sim``) and starts it with the example configurations in this
directory, connects the Python LogixDriver and SLCDriver to 127.0.0.1:PORT, uploads the tags in several ways, reads
and writes every kind of tag and checks the results, the controller clock and the tag table change detection.  Last,
it runs the repo's online tests against the demo PLC's program (run_online_tests.py).  Run it from the repo root with
pytest and the package under test importable, e.g.::

    uv run --no-project --isolated -p 3.12 --with <wheel> --with pytest python tools/sim/check_python_against_sim.py
    uv run --no-project --isolated -p 3.12 --with pytest python tools/sim/check_python_against_sim.py --reference

One step is white-box (a session opened without its Forward Open through ``CIPDriver.open``); it runs with the
reference only, the Rust core has no such call.

Exits with status 1 and lists the failed checks if any.
"""

import copy
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HERE = os.path.dirname(os.path.abspath(__file__))
REFERENCE = "--reference" in sys.argv[1:]
if REFERENCE:
    sys.path.insert(0, os.path.join(ROOT, "tools", "reference"))
    import reference

    reference.load()

import ciplink  # noqa: E402
from ciplink import LogixDriver, SLCDriver  # noqa: E402
from ciplink.exceptions import CommError, ResponseError  # noqa: E402

FAILURES = []
CHECKS = 0


def check(what, actual, expected):
    global CHECKS
    CHECKS += 1
    if actual != expected:
        FAILURES.append(f"{what}: got {actual!r}, expected {expected!r}")


def check_true(what, condition):
    check(what, bool(condition), True)


def sim_bin():
    """the simulator bin, built once (cargo build -p ciplink-sim)"""
    if not getattr(sim_bin, "path", None):
        subprocess.run(["cargo", "build", "-q", "-p", "ciplink-sim"], cwd=ROOT, check=True)
        target = os.environ.get("CARGO_TARGET_DIR", os.path.join(ROOT, "target"))
        sim_bin.path = os.path.join(target, "debug", "ciplink-sim" + (".exe" if os.name == "nt" else ""))
    return sim_bin.path


class Sim:
    """the simulator bin serving a configuration on a free port, with its stdin command channel"""

    def __init__(self, config):
        if isinstance(config, dict):
            fd, self.config_file = tempfile.mkstemp(suffix=".json")
            with os.fdopen(fd, "w") as f:
                json.dump(config, f)
            path = self.config_file
        else:
            self.config_file, path = None, os.path.join(HERE, config)
        self.proc = subprocess.Popen(
            [sim_bin(), "--config", path, "--port", "0", "--exit-on-eof"],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
        )
        line = self.proc.stdout.readline()
        if not line.startswith("listening on "):
            raise RuntimeError(f"simulator did not start: {line!r}")
        self.address = line.split()[-1]

    def cmd(self, cmd, **kwargs):
        self.proc.stdin.write(json.dumps({"cmd": cmd, **kwargs}) + "\n")
        self.proc.stdin.flush()
        reply = json.loads(self.proc.stdout.readline())
        if "error" in reply:
            raise RuntimeError(f"simulator {cmd}: {reply['error']}")
        return reply["ok"]

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        if self.config_file:
            os.remove(self.config_file)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def load(name):
    with open(os.path.join(HERE, name)) as f:
        return json.load(f)


class Err:
    """an expected error, whose message contains ``text``"""

    def __init__(self, text):
        self.text = text

    def __repr__(self):
        return f"Err({self.text!r})"


def check_result(what, result, expected, data_type=None):
    if isinstance(expected, Err):
        check_true(f"{what} fails with {expected.text!r} (got {result.value!r}, {result.error!r})",
                   result.error is not None and expected.text in str(result.error))
        return
    check(f"{what} error", result.error, None)
    check(f"{what} value", result.value, expected)
    if data_type is not None:
        check(f"{what} type", result.type, data_type)


# ---- expected values of example_controller.json ----

LONG480 = load("example_controller.json")["tags"][21]["value"]
BOOL_ARY = [i in (0, 5, 31, 32, 45, 60, 95) for i in range(96)]


def atomic(**kw):
    return {"bool": False, "sint": 0, "int": 0, "dint": 0, "lint": 0, "real": 0.0, **kw}


def arrays(**kw):
    return {"bools": [False] * 64, "sints": [0] * 8, "ints": [0] * 4, "dints": [0] * 10, "lints": [0] * 4,
            "reals": [0.0] * 10, **kw}


def padded(**kw):
    return {"bool1": False, "sint": 0, "dint1": 0, "bool2": False, "dint2": 0, **kw}


def bools(**kw):
    return {**{f"b{i}": False for i in range(1, 17)}, "int": 0, **{f"bb{i}": False for i in range(1, 21)}, **kw}


def timer(**kw):
    return {"PRE": 0, "ACC": 0, "EN": False, "TT": False, "DN": False, **kw}


UDT2 = arrays(bools=[False] * 5 + [True] + [False] * 58, sints=[0, 0, -2, 0, 0, 0, 0, 0], ints=[0, 0, 0, 2],
              dints=[0] * 8 + [4, 0], lints=[0, 0, 100, 0], reals=[0.0, 88.5] + [0.0] * 8)
NESTED = {"udt1": atomic(dint=11), "udt_ary1": [atomic(), atomic(), atomic(sint=3), atomic(), atomic()],
          "udt2": arrays(), "udt3": padded(dint1=-1), "str1": "nested", "str_ary1": ["x", "y", "z"],
          "tmr": timer(PRE=1000, ACC=250, EN=True, TT=True), "udt4": bools(bb17=True)}
VALVE_READABLE = {"EnableIn": True, "EnableOut": True, "Cmd": True, "Mode": 2}


def reads(aoi_locals_refused=True):
    """(tag, expected value or Err, expected type) of example_controller.json"""
    valve = VALVE_READABLE if aoi_locals_refused else {**VALVE_READABLE, "Count": 17, "Busy": False}
    return [
        ("sint1", 100, "SINT"), ("int1", -1234, "INT"), ("dint1", 2147483647, "DINT"), ("lint1", -2 ** 63, "LINT"),
        ("usint1", 200, "USINT"), ("uint1", 60000, "UINT"), ("udint1", 4000000000, "UDINT"),
        ("ulint1", 2 ** 64 - 1, "ULINT"), ("real1", 3.25, "REAL"), ("lreal1", 1e100, "LREAL"),
        ("bool1", True, "BOOL"), ("bool2", False, "BOOL"),
        ("dint1.0", True, "BOOL"), ("dint1.31", False, "BOOL"), ("int1.1", True, "BOOL"), ("lint1.63", True, "BOOL"),
        ("dint_ary", 0, "DINT"), ("dint_ary{10}", [i * 100 for i in range(10)], "DINT[10]"),
        ("dint_ary[3]", 300, "DINT"), ("dint_ary[2]{3}", [200, 300, 400], "DINT[3]"),
        ("dint_2d[1,2]", 6, "DINT"), ("dint_2d[1,0]{6}", [4, 5, 6, 7, 8, 9], "DINT[6]"),
        ("dint_3d[1,2,3]", 23, "DINT"), ("dint_3d[0,0,0]{24}", list(range(24)), "DINT[24]"),
        ("real_ary{5}", [0.5, 1.5, 2.5, 3.5, 4.5], "REAL[5]"), ("sint_ary[5]{10}", list(range(5, 15)), "SINT[10]"),
        ("bool_ary[0]", True, "BOOL"), ("bool_ary[5]", True, "BOOL"), ("bool_ary[6]", False, "BOOL"),
        ("bool_ary[45]", True, "BOOL"), ("bool_ary[95]", True, "BOOL"), ("bool_ary{96}", BOOL_ARY, "BOOL[96]"),
        ("bool_ary[30]{4}", BOOL_ARY[30:34], "BOOL[4]"), ("bool_ary[32]{64}", BOOL_ARY[32:], "BOOL[64]"),
        ("big_ary{2000}", [1, 2, 3] + [0] * 1997, "DINT[2000]"), ("big_ary[2]", 3, "DINT"),
        ("str1", "Hello Logix", "STRING"), ("str20", "Lorem ipsum vivamus.", "STRING20"),
        ("str480", LONG480, "STRING480"), ("str_ary{4}", ["a", "bb", "", "dddd"], "STRING[4]"),
        ("str_ary[3]", "dddd", "STRING"),
        ("udt1", atomic(bool=True, sint=-1, int=1, dint=10, lint=100, real=1000.5), "AtomicUDT"),
        ("udt1.real", 1000.5, "REAL"), ("udt1.bool", True, "BOOL"), ("udt1.dint.3", True, "BOOL"),
        ("udt2", UDT2, "ArrayUDT"), ("udt2.bools{64}", UDT2["bools"], "BOOL[64]"), ("udt2.bools[5]", True, "BOOL"),
        ("udt2.reals[1]", 88.5, "REAL"), ("udt2.dints{10}", UDT2["dints"], "DINT[10]"),
        ("udt3", padded(bool1=True, dint1=-1, dint2=-1), "PaddedUDT"),
        ("udt4", bools(b4=True, bb20=True, int=7), "BoolsUDT"), ("udt4.bb20", True, "BOOL"),
        ("udt_ary{3}", [atomic(), atomic(dint=5, real=0.25), atomic(bool=True)], "AtomicUDT[3]"),
        ("udt_ary[1].dint", 5, "DINT"),
        ("nested", NESTED, "NestedUDT"), ("nested.udt_ary1[2].sint", 3, "SINT"),
        ("nested.str_ary1[1]", "y", "STRING20"), ("nested.tmr", NESTED["tmr"], "TIMER"),
        ("nested.tmr.ACC", 250, "DINT"), ("nested.udt4.bb17", True, "BOOL"),
        ("timer1", timer(PRE=5000, ACC=1234, EN=True, TT=True), "TIMER"), ("timer1.DN", False, "BOOL"),
        ("timer1.EN", True, "BOOL"), ("timers[1]", timer(PRE=1, DN=True), "TIMER"),
        ("timers{3}", [timer(), timer(PRE=1, DN=True), timer()], "TIMER[3]"),
        ("counter1", {"PRE": 10, "ACC": 3, "CU": True, "CD": False, "DN": False, "OV": False, "UN": False},
         "COUNTER"),
        ("control1", {"LEN": 8, "POS": 2, "EN": True, "EU": False, "DN": False, "EM": False, "ER": False,
                      "UL": False, "IN": False, "FD": False}, "CONTROL"),
        ("valve1", valve, "Valve"), ("valve1.Mode", 2, "DINT"), ("valve1.Cmd", True, "BOOL"),
        ("valve1.Count", Err("AOI local tag") if aoi_locals_refused else 17, None if aoi_locals_refused else "DINT"),
        ("valves[1].Mode", 2, "DINT"),
        ("proc1", {"EnableIn": True, "EnableOut": False, "Speed": 12.5, "Run": True}, "Proc"),
        ("holder.V", 5, "DINT"), ("holder.Valves[1].Mode", 4, "DINT"),
        ("Program:MainProgram.p_dint", 7, "DINT"), ("Program:MainProgram.p_str", "program scope", "STRING"),
        ("Program:MainProgram.p_udt", atomic(bool=True, sint=2, int=3, dint=4, lint=5, real=6.5), "AtomicUDT"),
        ("Program:MainProgram.p_ary[3]{4}", [3, 4, 5, 6], "INT[4]"),
        ("Program:MainProgram.p_valve.Mode", 1, "DINT"), ("Program:SecondProgram.flags[2]", True, "BOOL"),
        ("Program:SecondProgram.counter", 3, "DINT"),
        ("Local:1:I.Ch0Data", 4.5, "REAL"), ("Local:1:I", {"Fault": 0, "Ch0Data": 4.5, "Ch1Data": -1.25},
                                             "AB:1756_IF4:I:0"),
        ("ro_dint", 77, "DINT"), ("hidden_dint", Err("Permission denied"), None),
    ]


def writes(aoi_locals_refused=True):
    """(tag, value, expected read back or Err) of example_controller.json, one write() call each group"""
    return [
        [("sint1", -5, -5), ("int1", 32767, 32767), ("dint1", -2 ** 31, -2 ** 31), ("lint1", 2 ** 63 - 1, 2 ** 63 - 1),
         ("usint1", 0, 0), ("uint1", 1, 1), ("udint1", 123456789, 123456789), ("ulint1", 2 ** 63, 2 ** 63),
         ("real1", -0.125, -0.125), ("lreal1", 2.5e-300, 2.5e-300), ("bool2", True, True),
         ("dint_ary[2]{3}", [7, 8, 9], [7, 8, 9]), ("dint_2d[2,3]", 55, 55), ("dint_3d[1,0,1]", -7, -7),
         ("str1", "Changed", "Changed"), ("str20", "x" * 20, "x" * 20), ("str480", "y" * 480, "y" * 480),
         ("str_ary[1]", "zz", "zz"),
         ("udt1", atomic(sint=5, int=-5, dint=50, lint=-50, real=0.5), atomic(sint=5, int=-5, dint=50, lint=-50,
                                                                               real=0.5)),
         ("udt_ary[2]", atomic(bool=True, real=1.5), atomic(bool=True, real=1.5)),
         ("nested.udt_ary1[4].real", 2.5, 2.5), ("nested.str_ary1[2]", "q", "q"), ("nested.tmr.PRE", 99, 99),
         ("timer1.PRE", 7000, 7000), ("timer1.DN", True, True), ("counter1.ACC", 9, 9),
         ("timers[2]", timer(PRE=3, ACC=2, EN=True, DN=True), timer(PRE=3, ACC=2, EN=True, DN=True)),
         ("valve1.Cmd", False, False), ("valve1.Mode", 3, 3), ("proc1.Speed", 0.75, 0.75),
         ("valve1.Count", 1, Err("AOI local tag") if aoi_locals_refused else 1),
         ("Program:MainProgram.p_dint", 123, 123), ("Program:MainProgram.p_ary{10}", list(range(10, 20)),
                                                     list(range(10, 20))),
         ("Program:SecondProgram.flags[31]", True, True), ("Local:2:O.Ch0Data", 1.5, 1.5),
         ("ro_dint", 1, Err("Permission denied")), ("hidden_dint", 1, Err("Permission denied"))],
        # bits and BOOL arrays: masks (Read-Modify-Write) and whole words
        [("int1.0", False, False), ("sint1.6", True, True), ("bool_ary[6]", True, True),
         ("bool_ary[40]{5}", [True, False, True, False, True], [True, False, True, False, True]),
         ("bool_ary[64]{32}", [True] * 32, [True] * 32), ("udt1.dint.0", True, True)],
        # a fragmented write
        [("big_ary{2000}", list(range(2000)), list(range(2000)))],
    ]


def check_reads(plc, label, aoi_locals_refused=True):
    expected = reads(aoi_locals_refused)
    for tag, value, data_type in expected:
        check_result(f"{label} read {tag}", plc.read(tag), value, data_type)
    results = plc.read(*(tag for tag, _, _ in expected))  # all in one call: multi-service packets
    for (tag, value, data_type), result in zip(expected, results):
        check_result(f"{label} multi read {tag}", result, value, data_type)


def check_writes(plc, sim, label, aoi_locals_refused=True):
    for group in writes(aoi_locals_refused):
        results = plc.write(*((tag, value) for tag, value, _ in group))
        results = results if isinstance(results, list) else [results]
        for (tag, value, expected), result in zip(group, results):
            if isinstance(expected, Err):
                check_result(f"{label} write {tag}", result, expected)
                continue
            check(f"{label} write {tag} error", result.error, None)
            check_result(f"{label} read back {tag}", plc.read(tag), expected)
    # the simulator's own view of what was written
    check(f"{label} sim dint_ary", sim.cmd("value", path="dint_ary"), [0, 100, 7, 8, 9, 500, 600, 700, 800, 900])
    check(f"{label} sim udt1", sim.cmd("value", path="udt1"), atomic(sint=5, int=-5, dint=51, lint=-50, real=0.5))
    check(f"{label} sim timer1", sim.cmd("value", path="timer1"), timer(PRE=7000, ACC=1234, EN=True, TT=True,
                                                                         DN=True))
    check(f"{label} sim int1", sim.cmd("value", path="int1"), 32766)
    check(f"{label} sim bool_ary[1]", sim.cmd("value", path="bool_ary[1]"),
          [i in (0, 8, 10, 12, 13, 28) for i in range(32)])
    check(f"{label} sim big_ary", sim.cmd("value", path="big_ary"), list(range(2000)))
    check(f"{label} sim p_dint", sim.cmd("value", path="Program:MainProgram.p_dint"), 123)


EXPECTED_TAGS = {
    "sint1", "int1", "dint1", "lint1", "usint1", "uint1", "udint1", "ulint1", "real1", "lreal1", "bool1", "bool2",
    "dint_ary", "dint_2d", "dint_3d", "real_ary", "sint_ary", "bool_ary", "big_ary", "str1", "str20", "str480",
    "str_ary", "udt1", "udt2", "udt3", "udt4", "udt_ary", "nested", "timer1", "timers", "counter1", "control1",
    "valve1", "valves", "proc1", "holder", "ro_dint", "hidden_dint", "Local:1:I", "Local:2:O",
    "byte1", "word1", "dword1", "lword1", "word_ary", "bits_udt",
}
PROGRAM_TAGS = {"Program:MainProgram.p_dint", "Program:MainProgram.p_str", "Program:MainProgram.p_udt",
                "Program:MainProgram.p_valve", "Program:MainProgram.p_ary", "Program:SecondProgram.counter",
                "Program:SecondProgram.flags"}


def check_controller(plc, label):
    info = plc.info
    check(f"{label} info", {k: info.get(k) for k in ("vendor", "product_type", "product_code", "revision", "serial",
                                                     "product_name", "keyswitch", "name")},
          {"vendor": "Rockwell Automation/Allen-Bradley", "product_type": "Programmable Logic Controller",
           "product_code": 166, "revision": {"major": 33, "minor": 11}, "serial": "c0ffee01",
           "product_name": "1756-SIM/A", "keyswitch": "REMOTE RUN", "name": "SimPLC"})
    check(f"{label} programs", {p: v["routines"] for p, v in info["programs"].items()},
          {"MainProgram": ["MainRoutine", "Sub1"], "SecondProgram": ["MainRoutine"]})
    check(f"{label} tasks", set(info["tasks"]), {"MainTask", "Periodic"})
    check(f"{label} modules", info["modules"], {"Local": {"slots": {1: {"types": ["I"]}, 2: {"types": ["O"]}}}})
    check(f"{label} tags", set(plc.tags), EXPECTED_TAGS | PROGRAM_TAGS)
    check_true(f"{label} data types", {"AtomicUDT", "ArrayUDT", "PaddedUDT", "BoolsUDT", "STRING20", "STRING480",
                                       "NestedUDT", "STRING", "TIMER", "COUNTER", "CONTROL", "Valve", "Proc",
                                       "Holder", "AB:1756_IF4:I:0", "AB:1756_OF4:O:0"} <= set(plc.data_types))
    check(f"{label} big_ary dims", plc.tags["big_ary"]["dimensions"], [2000, 0, 0])
    check(f"{label} bool_ary dims", plc.tags["bool_ary"]["dimensions"], [96, 0, 0])
    check(f"{label} ro access", plc.tags["ro_dint"]["external_access"], "Read Only")
    check(f"{label} STRING20 is a string", plc.data_types["STRING20"].get("string"), 20)


def scenario_main():
    label = "main"
    with Sim("example_controller.json") as sim:
        with LogixDriver(sim.address) as plc:
            check_controller(plc, label)
            check(f"{label} connection size", plc.connection_size, 4000)
            check(f"{label} instance ids", plc._cfg["use_instance_ids"], True)
            check(f"{label} valve probe", plc.data_types["Valve"].get("aoi"),
                  {"whole_read": False, "readable": ["EnableIn", "EnableOut", "Cmd", "Mode"],
                   "refused": ["Count", "Busy"]})
            check(f"{label} proc probe", plc.data_types["Proc"].get("aoi", {}).get("whole_read"), True)
            check_reads(plc, label)
            check_writes(plc, sim, label)

            # identity, modules and the clock
            check(f"{label} module 1", plc.get_module_info(1)["product_name"], "1756-EN2T/D")
            check(f"{label} module 2", plc.get_module_info(2)["product_name"], "1756-IB16/A")
            try:
                plc.get_module_info(5)
                check_true(f"{label} module 5 is an error", False)
            except ResponseError:
                pass
            now = plc.get_plc_time()
            check(f"{label} get_plc_time error", now.error, None)
            check_true(f"{label} plc time is now", abs(now.value["microseconds"] - time.time() * 1e6) < 5e6)
            check(f"{label} set_plc_time", plc.set_plc_time(1_700_000_000_000_000).error, None)
            later = plc.get_plc_time().value["microseconds"]
            check_true(f"{label} plc time was set ({later})", 0 <= later - 1_700_000_000_000_000 < 5_000_000)

            # online edits: a new tag, then a deleted tag's instance ID reused by another
            check(f"{label} check_tag_table unchanged", plc.check_tag_table(), False)
            sim.cmd("add_tag", tag={"name": "new_tag", "type": "DINT", "value": 31})
            check(f"{label} check_tag_table after an edit", plc.check_tag_table(), True)
            check_result(f"{label} read new_tag", plc.read("new_tag"), 31, "DINT")
            old_id = plc.tags["sint1"]["instance_id"]
            sim.cmd("remove_tag", name="sint1")
            new_id = sim.cmd("add_tag", tag={"name": "reused", "type": "INT", "value": -9})
            check(f"{label} instance ID reused", new_id, old_id)
            # the change is seen by the read, which loads the tags again and parses its tags once more
            r1, r2 = plc.read("dint_ary[2]", "reused")
            check_result(f"{label} read after the reuse", r2, -9, "INT")
            check_result(f"{label} read along", r1, 7, "DINT")
            check_result(f"{label} deleted tag", plc.read("sint1"), Err("Tag doesn't exist"))
            sim.cmd("bump")
            check_result(f"{label} read after a bump", plc.read("dint_ary[2]"), 7, "DINT")

            # faults: a status for one tag, then a lost reply
            sim.cmd("fault", fault={"tag_status": {"tag": "dint_ary", "status": 5}})
            r1, r2 = plc.read("dint_ary[1]", "dint1")
            check_result(f"{label} injected status", r1, Err("Destination unknown"))
            check_result(f"{label} other tag in the packet", r2, -2 ** 31, "DINT")
            sim.cmd("clear_faults")

        with LogixDriver(sim.address, socket_timeout=1.0) as plc:
            sim.cmd("fault", fault={"drop_replies": 1})
            try:
                plc.read("dint1")
                check_true(f"{label} lost reply raises CommError", False)
            except CommError:
                pass
            check(f"{label} dropped connection", plc.connected, False)
            check_true(f"{label} reopen", plc.open())
            check_result(f"{label} read after reopening", plc.read("dint1"), -2 ** 31, "DINT")

        check(f"{label} list_identity", LogixDriver.list_identity(sim.address)["product_name"], "1756-SIM/A")


def scenario_upload_options():
    label = "upload"
    with Sim("example_controller.json") as sim:
        with LogixDriver(sim.address, init_program_tags=False) as plc:
            check(f"{label} controller tags only", set(plc.tags), EXPECTED_TAGS)
        with LogixDriver(sim.address, tag_namespace_filter="udt") as plc:
            check(f"{label} namespace filter", set(plc.tags), {"udt1", "udt2", "udt3", "udt4", "udt_ary"})
        with LogixDriver(sim.address, lazy_tags=True) as plc:
            check(f"{label} lazy has no tags", plc.tags, {})
            check_result(f"{label} lazy program tag", plc.read("Program:MainProgram.p_dint"), 7, "DINT")
            check_result(f"{label} lazy udt member", plc.read("nested.tmr.ACC"), 250, "DINT")
            check_result(f"{label} lazy AOI", plc.read("valve1"), VALVE_READABLE, "Valve")
            check(f"{label} lazy loaded", set(plc.tags), {"Program:MainProgram.p_dint", "nested", "valve1"})
            check_result(f"{label} lazy missing", plc.read("nope"), Err("Tag doesn't exist"))
        cache = os.path.join(tempfile.mkdtemp(), "tags.json")
        with LogixDriver(sim.address, tag_cache_file=cache) as plc:
            first = set(plc.tags)
        check_true(f"{label} cache file written", os.path.exists(cache))
        before = sim.cmd("requests")
        with LogixDriver(sim.address, tag_cache_file=cache) as plc:
            check(f"{label} cached tags", set(plc.tags), first)
            check_result(f"{label} read with cached tags", plc.read("udt1.real"), 1000.5, "REAL")
        used = sim.cmd("requests") - before
        check_true(f"{label} cache file saves the upload ({used} requests)", used < 15)
        sim.cmd("add_tag", program="MainProgram", tag={"name": "p_new", "type": "REAL", "value": 0.5})
        with LogixDriver(sim.address, tag_cache_file=cache) as plc:
            check(f"{label} cache file out of date", set(plc.tags), first | {"Program:MainProgram.p_new"})
            check_result(f"{label} read p_new", plc.read("Program:MainProgram.p_new"), 0.5, "REAL")


def variant(**changes):
    config = copy.deepcopy(load("example_controller.json"))
    for key, value in changes.items():
        if key == "revision":
            config["identity"]["revision"] = value
        else:
            config[key] = value
    return config


def scenario_variant(label, config, connection_size, use_ids, aoi_locals_refused=True):
    with Sim(config) as sim:
        with LogixDriver(sim.address) as plc:
            check(f"{label} connection size", plc.connection_size, connection_size)
            check(f"{label} instance ids", plc._cfg["use_instance_ids"], use_ids)
            check(f"{label} tags", set(plc.tags), EXPECTED_TAGS | PROGRAM_TAGS)
            check_reads(plc, label, aoi_locals_refused)
            check_writes(plc, sim, label, aoi_locals_refused)


def scenario_error_paths():
    """the reference driver's error branches the sim can trigger: error kinds, a refused Forward Open, the tag
    table version refused (reload backoff) and the tag table changing during a read and a write"""
    from ciplink.tag import ErrorKind

    label = "errors"
    with Sim("example_controller.json") as sim:
        with LogixDriver(sim.address) as plc:
            kinds = [
                ("hidden_dint read", plc.read("hidden_dint"), ErrorKind.ACCESS),
                ("ro_dint write", plc.write("ro_dint", 1), ErrorKind.ACCESS),
                ("AOI local read", plc.read("valve1.Count"), ErrorKind.ACCESS),
                ("missing tag read", plc.read("no_such_tag"), ErrorKind.NOT_FOUND),
                ("index out of range read", plc.read("dint_ary[10]"), ErrorKind.NOT_FOUND),
            ]
            sim.cmd("fault", fault={"tag_status": {"tag": "dint1", "status": 5}})
            kinds.append(("injected 0x05", plc.read("dint1"), ErrorKind.NOT_FOUND))
            sim.cmd("clear_faults")
            sim.cmd("fault", fault={"tag_status": {"tag": "dint1", "status": 0xFF, "ext": 0x2107}})
            kinds.append(("injected 0xFF/0x2107", plc.write("dint1", 1), ErrorKind.BAD_VALUE))
            sim.cmd("clear_faults")
            for what, result, kind in kinds:
                check(f"{label} {what} kind ({result.error})", result.error_kind, kind)

            # the tag table version refused: no reload, reads refused without a request for the backoff time
            sim.cmd("fault", fault={"service_status": {"service": 0x03, "class": 0xAC, "status": 0x10}})
            refused = plc.read("dint1")
            check(f"{label} version refused kind ({refused.error})", refused.error_kind, ErrorKind.REFUSED)
            check_true(f"{label} version refused message", "Tag table is being reloaded" in str(refused.error))
            sim.cmd("clear_faults")
            before = sim.cmd("requests")
            again = plc.read("dint1")
            check(f"{label} backed off kind", again.error_kind, ErrorKind.REFUSED)
            check(f"{label} backed off sends nothing", sim.cmd("requests"), before)
            time.sleep(2.1)  # _RELOAD_BACKOFF
            check_result(f"{label} read after the backoff", plc.read("dint1"), 2147483647, "DINT")

            # the tag table changes before every packet: the read and its retry both see an edit
            send = plc._send

            def bump_then_send(message):
                sim.cmd("bump")
                return send(message)

            plc._send = bump_then_send
            try:
                changed = plc.read("dint1", "int1")
                check(f"{label} changed twice kinds", [r.error_kind for r in changed], [ErrorKind.TABLE_CHANGED] * 2)
                written = plc.write("dint1", 5)
                check(f"{label} write during a change kind ({written.error})", written.error_kind,
                      ErrorKind.TABLE_CHANGED)
            finally:
                plc._send = send
            check_result(f"{label} read after the changes", plc.read("dint1"), 5, "DINT")

        # Large and standard Forward Open both refused: the open fails, the Large FO settings are kept
        sim.cmd("fault", fault={"service_status": {"service": 0x5B, "class": 0x06, "status": 0x01, "ext": 0x0113}})
        sim.cmd("fault", fault={"service_status": {"service": 0x54, "class": 0x06, "status": 0x01, "ext": 0x0113}})
        plc = LogixDriver(sim.address)
        try:
            plc.open()
            check_true(f"{label} refused Forward Open raises", False)
        except ResponseError as err:
            check_true(f"{label} refused Forward Open message ({err})", "Target did not connected" in str(err))
        check(f"{label} refused FO keeps the size", plc.connection_size, 4000)
        check(f"{label} refused FO keeps Large FO", plc._cfg["extended forward open"], True)
        check(f"{label} refused FO not connected", plc.connected, False)
        sim.cmd("clear_faults")
        try:
            check_true(f"{label} open after the refusal", plc.open())
            check_result(f"{label} read after the refusal", plc.read("dint1"), 5, "DINT")
            check(f"{label} Large FO after the refusal", plc.connection_size, 4000)
        finally:
            plc.close()

        if hasattr(ciplink, "_core"):
            return  # the rest is white-box: the Rust core's open() always makes the Forward Open

        # a lost Forward Open reply drops the connection, the next open reconnects
        plc = LogixDriver(sim.address, init_tags=False, socket_timeout=1.0)
        try:
            check_true(f"{label} session", super(LogixDriver, plc).open())  # no Forward Open yet
            sim.cmd("fault", fault={"drop_replies": 1})
            try:
                plc.read("dint1")
                check_true(f"{label} lost FO reply raises CommError", False)
            except CommError:
                pass
            check(f"{label} lost FO reply drops the connection", plc.connected, False)
            check_true(f"{label} reopen after the lost FO", plc.open())
            check(f"{label} name after the lost FO", plc.get_plc_name(), "SimPLC")
        finally:
            plc.close()


def scenario_micro800():
    label = "micro800"
    with Sim("example_micro800.json") as sim:
        # init_tags=False: on a Micro800 the reference driver's open() uploads the tag list before any Forward Open
        # (get_plc_name, which opens it on a Logix, is skipped), a SendUnitData without a connection that fails
        with LogixDriver(sim.address, init_tags=False) as plc:
            plc.get_tag_list()
            check(f"{label} product", plc.info["product_name"], "2080-LC50-48QWB")
            check(f"{label} micro800", plc._micro800, True)
            check(f"{label} tags", set(plc.tags), {"m_dint", "m_real", "m_bool", "m_ary", "m_uint"})
            expected = [("m_dint", 42, "DINT"), ("m_real", 2.5, "REAL"), ("m_bool", True, "BOOL"),
                        ("m_ary{5}", [1, 2, 3, 4, 5], "INT[5]"), ("m_uint", 65535, "UINT"), ("m_dint.5", True, "BOOL")]
            for (tag, value, data_type), result in zip(expected, plc.read(*(t for t, _, _ in expected))):
                check_result(f"{label} read {tag}", result, value, data_type)
            results = plc.write(("m_dint", -1), ("m_ary[1]{2}", [20, 30]), ("m_bool", False), ("m_uint.0", False))
            check(f"{label} writes", [r.error for r in results], [None] * 4)
            check(f"{label} read back", [r.value for r in plc.read("m_dint", "m_ary{5}", "m_bool", "m_uint")],
                  [-1, [1, 20, 30, 4, 5], False, 65534])
            check(f"{label} sim value", sim.cmd("value", path="m_ary"), [1, 20, 30, 4, 5])


def scenario_slc():
    label = "slc"
    config = load("example_slc.json")
    with Sim("example_slc.json") as sim:
        with SLCDriver(sim.address) as plc:
            expected = [
                ("N7:0", 10), ("N7:0{7}", [10, 20, 30, 40, 50, -32768, 32767]), ("N7:5", -32768), ("N7:99", 0),
                ("F8:0", 1.5), ("F8:0{3}", [1.5, -2.25, 1000.125]), ("B3:0/1", True), ("B3:0/2", False),
                ("B3/3", True), ("B3:2", -1), ("T4:0.ACC", 25), ("T4:0.PRE", 100), ("T4:0.EN", True),
                ("T4:0.DN", False), ("T4:1.ACC", 5), ("C5:0.ACC", 3), ("C5:0.PRE", 10), ("C5:0.CU", True),
                ("ST9:0", "Hello SLC"), ("ST9:2", "xyz"), ("A10:0", "AB"), ("A10:1", "C "),
                ("L12:0", 100000), ("L12:0{2}", [100000, -5]), ("S:1/5", True), ("S:1/4", False), ("I:0", 5),
                ("I:1", -1), ("O:1", 2),
            ]
            for tag, value in expected:
                check_result(f"{label} read {tag}", plc.read(tag), value)
            results = plc.read(*(tag for tag, _ in expected))
            for (tag, value), result in zip(expected, results):
                check_result(f"{label} multi read {tag}", result, value)
            changes = [("N7:10", 1234), ("N7:20{3}", [1, 2, 3]), ("F8:5", 3.5), ("B3:1/4", True), ("B3/21", True),
                       ("T4:2.PRE", 500), ("T4:2.ACC", 42), ("T4:2.EN", True), ("C5:1.PRE", 7),
                       ("ST9:1", "written"), ("A10:2", "XY"), ("L12:5", -123456), ("N7:0/15", True),
                       ("O:2", 3)]
            for (tag, value), result in zip(changes, plc.write(*changes)):
                check(f"{label} write {tag}", result.error, None)
                check_result(f"{label} read back {tag}", plc.read(tag), value)
            check(f"{label} N7:0 with bit 15", plc.read("N7:0").value, 10 - 32768)
            check(f"{label} sim B3:1", sim.cmd("value", path="B3:1"), 0b110000)
            check(f"{label} sim T4:2", sim.cmd("value", path="T4:2"),
                  {"PRE": 500, "ACC": 42, "EN": True, "TT": False, "DN": False})
            check(f"{label} sim ST9:1", sim.cmd("value", path="ST9:1"), "written")
            check(f"{label} processor type", plc.get_processor_type(), "1747-L552")
            sizes = {"O": 2, "I": 2, "S": 2, "B": 2, "T": 6, "C": 6, "R": 6, "N": 2, "F": 4, "ST": 84, "A": 2, "L": 4}
            check(f"{label} file directory", plc.get_file_directory(),
                  {f"{f['type']}{f['number']}": {"elements": f["elements"], "length": f["elements"] * sizes[f["type"]]}
                   for f in config["files"]})
            check(f"{label} datalog", plc.get_datalog_queue(2, 1), config["datalog"])
            check(f"{label} datalog drained", plc.get_datalog_queue(2, 1), [None, None])
            # PCCC errors: the reply's STS and EXT STS bytes as the error text
            bad = "Error code in EXT STS Byte (EXT STS 0x06)"
            for tag in ("N99:0", "N7:200", "N7:99{2}", "B3:100/0"):
                check(f"{label} read {tag} error", plc.read(tag).error, bad)
            check(f"{label} write N99:0 error", plc.write(("N99:0", 1)).error, bad)
        check(f"{label} list_identity", SLCDriver.list_identity(sim.address)["product_name"], "1747-L552/C D/16")


DESCRIPTIONS_CONFIG = {
    "metadata_auth": True,
    "types": [
        {"name": "Inner", "members": [{"name": "Acked", "type": "BOOL", "description": "Acked default"},
                                      {"name": "val", "type": "DINT"}]},
        {"name": "Outer", "members": [{"name": "Inner", "type": "Inner"}, {"name": "items", "type": "Inner", "dim": 3}]},
    ],
    "tags": [
        {"name": "Array", "type": "DINT", "dims": [30],
         "descriptions": {"": "Array text", "[0]": "Element text", "[0].1": "Bit text"}},
        {"name": "Scalar", "type": "DINT"},
        {"name": "Structs", "type": "Inner", "dims": [5], "descriptions": {"[0].Acked": "Member text"}},
        {"name": "Outer", "type": "Outer",
         "descriptions": {".Inner.val": "Nested text", ".items[2].acked": "Nested element"}},
        {"name": "Long", "type": "DINT", "descriptions": {"": "x" * 6000}},
    ],
    "programs": [{"name": "MainProgram", "routines": ["MainRoutine"],
                  "tags": [{"name": "Input", "type": "BOOL", "descriptions": {"": "Program text"}}]}],
}


def scenario_descriptions():
    """extended Descriptions, refused until the connection passes the metadata authentication"""
    label = "descriptions"
    expected = [
        ("Array[0]", "Element text"), ("Array[1]", "Array text"), ("Array[0].1", "Bit text"),
        ("Array[5].3", "Array text"), ("Scalar", Err("No description returned for language 0x007f")),
        ("Structs[0].Acked", "Member text"), ("Structs[2].Acked", "Acked default"),
        ("Structs[2].val", Err("No description returned")), ("Outer.Inner.val", "Nested text"),
        ("Outer.items[2].Acked", "Nested element"), ("Outer.items[1].Acked", "Acked default"),
        ("Program:MainProgram.Input", "Program text"),
        ("Missing", Err("doesn't exist")), ("Array[30]", Err("outside")),
    ]
    with Sim(DESCRIPTIONS_CONFIG) as sim:
        with LogixDriver(sim.address) as plc:
            check_result(f"{label} before authentication", plc.get_tag_description("Array[0]"),
                         Err("Permission denied"))
            check_result(f"{label} authenticate", plc.authenticate_metadata(), True)
            for tag, value in expected:
                result = plc.get_tag_description(tag)
                check(f"{label} {tag} name", result.tag, f"{tag}.@Description")
                check_result(f"{label} {tag}", result, value)
            batch = plc.get_tag_descriptions(*(tag for tag, _ in expected))
            for (tag, value), result in zip(expected, batch):
                check_result(f"{label} batch {tag}", result, value)
            # longer than the connection: read in pages
            long = [plc.get_tag_description("Long").value, plc.get_tag_descriptions("Long", "Array")[0].value]
            check(f"{label} paged description", [value == "x" * 6000 for value in long], [True, True])
            check_result(f"{label} other language", plc.get_tag_description("Array", language=0x0409),
                         Err("No description returned for language 0x0409"))
        with LogixDriver(sim.address) as plc:
            check_result(f"{label} a new connection is not authenticated", plc.get_tag_description("Array"),
                         Err("Permission denied"))


def scenario_online_tests():
    """the repo's online tests (tests/online) against the demo PLC's program, see run_online_tests.py"""
    options = ["--reference"] if REFERENCE else []
    result = subprocess.run([sys.executable, os.path.join(HERE, "run_online_tests.py"), *options, "-q", "-p",
                             "no:warnings"],
                            cwd=ROOT, capture_output=True, text=True)
    check(f"online tests against the demo program ({result.stdout.strip().splitlines()[-1:]})",
          result.returncode, 0)


def main():
    logging.basicConfig(level=logging.CRITICAL)
    sim_bin()
    scenarios = [
        ("main", scenario_main),
        ("upload options", scenario_upload_options),
        ("standard Forward Open (Large Forward Open unsupported)",
         lambda: scenario_variant("standard FO", variant(large_forward_open=False), 500, True)),
        ("no tag table version (names instead of instance IDs)",
         lambda: scenario_variant("no version", variant(tag_table_version=False), 4000, False)),
        ("v20 controller (names, AOI locals readable)",
         lambda: scenario_variant("v20", variant(revision=[20, 19], aoi_locals_refused=False), 4000, False, False)),
        ("error paths", scenario_error_paths),
        ("Micro800", scenario_micro800),
        ("descriptions and metadata authentication", scenario_descriptions),
        ("SLC 500", scenario_slc),
        ("tests/online against tests/pycomm3.L5X", scenario_online_tests),
    ]
    for name, scenario in scenarios:
        before = len(FAILURES)
        try:
            scenario()
        except Exception:
            FAILURES.append(f"{name}: {traceback.format_exc()}")
        print(f"{name}: {'ok' if len(FAILURES) == before else f'{len(FAILURES) - before} failed'}")
    print(f"{CHECKS} checks, {len(FAILURES)} failed")
    for failure in FAILURES:
        print(" -", failure)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
