"""
Writes tools/diff/scenarios.json, the scenarios of the differential parity harness
(crates/ciplink-sim/tests/differential.rs runs each with the reference Python driver and the Rust driver against
fresh, identically configured simulators and compares the request frames and the results).

Run from the repo root: ``python tools/diff/gen_scenarios.py`` (no dependencies).

A scenario is ``{"name", "config", "steps"}``.  ``config`` is ``{"file": "example_controller.json"}`` (in
tools/sim/), optionally with ``"merge"`` (merged into it, objects recursively, other values replaced),
``"extra_tags"`` and ``"extra_types"`` (appended), or ``{"inline": {...}}``.  Steps are driver calls (``open``,
``read``, ``write``, ...; see tools/diff/py_runner.py) or ``{"op": "sim", ...}``: a change of the simulator made by
the Rust test on both simulators, never sent to Python (``set``, ``add_tag``, ``remove_tag``, ``add_type``,
``bump``, ``download``, ``fault``, ``clear_faults``, ``bump_requests`` = bump the tag table before each of the next
``n`` requests).  Write values are plain JSON (an int, a float with a point, a str, a list, an object for a struct);
``{"$bytes": "hex"}`` is bytes.  Every scenario ends with a ``close``.
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CONTROLLER = {"file": "example_controller.json"}

# ---- reads of example_controller.json, by kind ----

ATOMIC = ["sint1", "int1", "dint1", "lint1", "usint1", "uint1", "udint1", "ulint1", "real1", "lreal1", "bool1", "bool2"]
BITS = ["dint1.0", "dint1.31", "int1.1", "lint1.63", "sint1.7", "udint1.5", "udt1.dint.3", "dint1.32", "real1.0"]
ARRAYS = ["dint_ary", "dint_ary{10}", "dint_ary[3]", "dint_ary[2]{3}", "real_ary{5}", "sint_ary[5]{10}",
          "dint_ary[9]{1}", "sint_ary{20}", "dint_ary[8]{5}", "dint_ary{0}"]
MULTIDIM = ["dint_2d[1,2]", "dint_2d[1,0]{6}", "dint_3d[1,2,3]", "dint_3d[0,0,0]{24}", "dint_2d", "dint_2d[2,3]",
            "dint_3d[1,0]", "dint_2d[3,0]"]
BOOL_ARRAYS = ["bool_ary[0]", "bool_ary[5]", "bool_ary[6]", "bool_ary[45]", "bool_ary[95]", "bool_ary{96}",
               "bool_ary[30]{4}", "bool_ary[32]{64}", "bool_ary[1]{3}", "bool_ary[31]{2}", "bool_ary", "bool_ary[96]",
               "Program:SecondProgram.flags[2]", "Program:SecondProgram.flags{32}", "udt2.bools{64}", "udt2.bools[5]"]
STRINGS = ["str1", "str20", "str480", "str_ary{4}", "str_ary[3]", "str_ary", "nested.str1", "nested.str_ary1[1]",
           "Program:MainProgram.p_str", "str1.LEN", "str1.DATA[0]", "str1.DATA{5}"]
UDTS = ["udt1", "udt1.real", "udt1.bool", "udt2", "udt2.reals[1]", "udt2.dints{10}", "udt3", "udt4", "udt4.bb20",
        "udt_ary{3}", "udt_ary[1].dint", "udt_ary[1]", "timer1", "timer1.DN", "timer1.EN", "timers[1]", "timers{3}",
        "counter1", "control1", "Local:1:I", "Local:1:I.Ch0Data", "Local:2:O"]
NESTED = ["nested", "nested.udt_ary1[2].sint", "nested.udt1", "nested.udt2.bools[3]", "nested.tmr", "nested.tmr.ACC",
          "nested.udt4.bb17", "nested.udt3", "holder", "holder.V", "holder.Valves[1].Mode", "holder.Valves[0]"]
AOIS = ["valve1", "valve1.Mode", "valve1.Cmd", "valve1.Count", "valve1.Busy", "valves[1].Mode", "valves[0]",
        "valves{2}", "proc1", "proc1.Speed", "Program:MainProgram.p_valve", "Program:MainProgram.p_valve.Count",
        "Program:MainProgram.p_valve.Mode", "holder.Valves[1].Count", "valve1.EnableIn"]
PROGRAM = ["Program:MainProgram.p_dint", "Program:MainProgram.p_udt", "Program:MainProgram.p_ary[3]{4}",
           "Program:MainProgram.p_ary{10}", "Program:SecondProgram.counter", "Program:MainProgram.nope",
           "Program:NoProgram.x"]
ERRORS = ["no_such_tag", "dint_ary[10]", "dint_ary[-1]", "dint_ary[1,2]", "dint_2d[3,4]", "udt1.nope", "dint1.x",
          "bool_ary[97]", "str_ary[4]", "dint_ary{11}", "dint_ary[5]{6}", "hidden_dint", "ro_dint", "", "dint1[0]",
          "udt1.real.40", "dint_ary[2", "1abc", "dint1.0.1", "Program:MainProgram"]
BIG = ["big_ary{2000}", "big_ary[2]", "big_ary[1990]{10}", "big_ary[500]{1000}", "str480", "nested"]

ALL_READS = ATOMIC + BITS + ARRAYS + MULTIDIM + BOOL_ARRAYS + STRINGS + UDTS + NESTED + AOIS + PROGRAM + BIG


def batch(n):
    """n reads, taken round the list of every kind (repeats included, as a caller might)"""
    return [ALL_READS[i % len(ALL_READS)] for i in range(n)]


# ---- writes ----

def atomic(**kw):
    return {"bool": False, "dint": 0, "int": 0, "lint": 0, "real": 0.0, "sint": 0, **kw}


def timer(**kw):
    return {"ACC": 0, "DN": False, "EN": False, "PRE": 0, "TT": False, **kw}


W_ATOMIC = [["sint1", -5], ["int1", 32767], ["dint1", -2147483648], ["lint1", 9223372036854775807], ["usint1", 0],
            ["uint1", 1], ["udint1", 123456789], ["ulint1", 9223372036854775808], ["real1", -0.125],
            ["lreal1", 2.5e-300], ["bool2", True], ["bool1", 0], ["real1", 3], ["lreal1", 1]]
W_ARRAYS = [["dint_ary[2]{3}", [7, 8, 9]], ["dint_2d[2,3]", 55], ["dint_3d[1,0,1]", -7], ["real_ary{5}", [1, 2, 3, 4.5, 5]],
            ["sint_ary[18]{2}", [-1, -2]], ["dint_ary{10}", list(range(10))], ["dint_2d[0,0]{12}", list(range(12))],
            ["Program:MainProgram.p_ary{10}", list(range(10, 20))]]
W_BITS = [["int1.0", False], ["sint1.6", True], ["dint1.31", True], ["lint1.0", False], ["udt1.dint.0", True],
          ["dint1.3", 1], ["udint1.31", False], ["int1.15", True]]
W_BOOL_RANGES = [["bool_ary[6]", True], ["bool_ary[40]{5}", [True, False, True, False, True]],
                 ["bool_ary[64]{32}", [True] * 32], ["bool_ary[0]{96}", [i % 3 == 0 for i in range(96)]],
                 ["bool_ary[30]{4}", [True, True, True, True]], ["Program:SecondProgram.flags[31]", True],
                 ["udt2.bools[5]", False], ["udt2.bools{64}", [True] * 64]]
W_STRINGS = [["str1", "Changed"], ["str20", "x" * 20], ["str480", "y" * 480], ["str_ary[1]", "zz"], ["str1", ""],
             ["nested.str_ary1[2]", "q"], ["Program:MainProgram.p_str", "from the harness"],
             ["str_ary{4}", ["w", "x", "y", "z"]]]
W_STRUCTS = [["udt1", atomic(sint=5, int=-5, dint=50, lint=-50, real=0.5)], ["udt_ary[2]", atomic(bool=True, real=1.5)],
             ["timers[2]", timer(PRE=3, ACC=2, EN=True, DN=True)], ["timer1.PRE", 7000], ["timer1.DN", True],
             ["counter1.ACC", 9], ["nested.udt_ary1[4].real", 2.5], ["nested.tmr.PRE", 99],
             ["Local:2:O.Ch0Data", 1.5], ["udt3", {"bool1": True, "bool2": True, "dint1": 1, "dint2": 2, "sint": 3}],
             ["Program:MainProgram.p_udt", atomic(dint=8)], ["holder.Valves[0].Mode", 9]]
W_BYTES = [["udt1", {"$bytes": "01ff0100" + "0a000000" + "6400000000000000" + "00007a44" + "00" * 8}],
           ["dint1", {"$bytes": "01020304"}], ["str1", {"$bytes": "414243"}], ["sint_ary{4}", {"$bytes": "01020304"}]]
W_AOI = [["valve1.Cmd", False], ["valve1.Mode", 3], ["proc1.Speed", 0.75], ["valve1.Count", 1], ["valve1.Busy", True],
         ["valve1", {"Cmd": True, "EnableIn": True, "EnableOut": False, "Mode": 4}], ["valves[1].Mode", 7],
         ["Program:MainProgram.p_valve.Count", 2]]
W_INVALID = [["sint1", 128], ["sint1", -129], ["usint1", -1], ["int1", 40000], ["dint1", 2147483648],
             ["udint1", -1], ["ulint1", -1], ["bool1", 2], ["bool1", "yes"], ["dint1", "12"], ["dint1", 1.5],
             ["real1", "x"], ["str20", "x" * 21], ["str1", 5], ["dint_ary{3}", [1, 2]], ["dint_ary{3}", 5],
             ["dint_ary[2]{3}", [1, 2, 3, 4]], ["udt1", {"nope": 1}], ["udt1", 5], ["udt1", {"dint": "x"}],
             ["ro_dint", 1], ["hidden_dint", 1], ["no_such_tag", 1], ["dint_ary[10]", 1], ["dint1.40", True],
             ["real1.0", True], ["bool_ary[0]{3}", [True, 2, False]], ["timer1.DN", 5],
             ["dint1", [1]], ["dint1", True]]


def read_back(items):
    return {"op": "read", "tags": [tag for tag, _ in items]}


def open_(**kw):
    return {"op": "open", **kw}


STATE = {"op": "state"}
CLOSE = {"op": "close"}


def sim(cmd, **kw):
    return {"op": "sim", "cmd": cmd, **kw}


def one_by_one(tags):
    return [{"op": "read", "tags": [t]} for t in tags] + [{"op": "read", "tags": tags}]


SCENARIOS = []


def scenario(name, steps, config=CONTROLLER):
    SCENARIOS.append({"name": name, "config": config, "steps": steps})


def variant(merge=None, **kw):
    config = {"file": "example_controller.json"}
    if merge:
        config["merge"] = merge
    config.update(kw)
    return config


# ---- connect ----

scenario("connect_full_upload", [open_(), {"op": "plc_info"}, {"op": "plc_name"}, STATE,
                                 {"op": "tag_info", "name": "udt1"}, {"op": "tag_info", "name": "nested.udt_ary1"},
                                 {"op": "tag_info", "name": "nope"}, {"op": "tag_info", "name": "valve1.Count"},
                                 {"op": "tag_list", "program": None, "cache": False}, CLOSE, STATE])
scenario("connect_no_program_tags", [open_(init_program_tags=False), STATE,
                                     {"op": "read", "tags": ["Program:MainProgram.p_dint", "dint1"]}])
scenario("connect_namespace_filter", [open_(tag_namespace_filter="udt"), STATE,
                                      {"op": "read", "tags": ["udt1", "dint1"]}])
scenario("connect_lazy_tags", [open_(lazy_tags=True), STATE,
                               {"op": "read", "tags": ["Program:MainProgram.p_dint"]},
                               {"op": "read", "tags": ["nested.tmr.ACC"]}, {"op": "read", "tags": ["valve1"]},
                               {"op": "read", "tags": ["nope"]}, {"op": "write", "items": [["udt1.dint", 3]]},
                               {"op": "tag_info", "name": "holder.Valves"}, STATE])
scenario("connect_init_tags_false", [open_(init_tags=False), STATE, {"op": "read", "tags": ["dint1"]},
                                     {"op": "tag_list", "program": "*"}, STATE, {"op": "read", "tags": ["dint1"]}])
scenario("connect_tag_cache_cold_warm", [
    open_(tag_cache_file=True), STATE, {"op": "cache_file"}, CLOSE,
    open_(tag_cache_file=True), STATE, {"op": "read", "tags": ["udt1.real", "valve1"]}, CLOSE,
    sim("add_tag", program="MainProgram", tag={"name": "p_new", "type": "REAL", "value": 0.5}),
    open_(tag_cache_file=True), STATE, {"op": "read", "tags": ["Program:MainProgram.p_new"]}, {"op": "cache_file"}])
scenario("connect_tag_cache_other_options", [open_(tag_cache_file=True, init_program_tags=False), STATE,
                                             {"op": "cache_file"}, CLOSE,
                                             open_(tag_cache_file=True), STATE, {"op": "cache_file"}])
scenario("connect_connection_size_500", [open_(connection_size=500), STATE, {"op": "read", "tags": ["big_ary{2000}"]}])
scenario("connect_standard_forward_open", [open_(), STATE, {"op": "read", "tags": batch(30)}],
         variant({"large_forward_open": False}))
scenario("connect_set_connection_size", [open_(), {"op": "set_connection_size", "value": 500},
                                         {"op": "read", "tags": batch(50)}, CLOSE, open_(new=False),
                                         {"op": "read", "tags": ["big_ary{2000}"]}])
scenario("connect_reopen", [open_(), CLOSE, open_(new=False), STATE, {"op": "read", "tags": ["dint1"]}])
scenario("connect_micro800", [open_(init_tags=False), {"op": "tag_list"}, STATE,
                              {"op": "read", "tags": ["m_dint", "m_real", "m_bool", "m_ary{5}", "m_uint", "m_dint.5"]},
                              {"op": "write", "items": [["m_dint", -1], ["m_ary[1]{2}", [20, 30]], ["m_bool", False],
                                                        ["m_uint.0", False]]},
                              {"op": "read", "tags": ["m_dint", "m_ary{5}", "m_bool", "m_uint"]},
                              {"op": "descriptions", "tags": ["m_dint"]}],
         {"file": "example_micro800.json"})
scenario("connect_micro800_init_tags", [open_(), STATE], {"file": "example_micro800.json"})
scenario("connect_no_tag_table_version", [open_(), STATE, {"op": "read", "tags": batch(40)},
                                          {"op": "write", "items": W_ATOMIC[:6]}, {"op": "check"}],
         variant({"tag_table_version": False}))
scenario("connect_v20", [open_(), STATE, {"op": "read", "tags": AOIS + ATOMIC},
                         {"op": "write", "items": W_AOI}, read_back(W_AOI)],
         variant({"identity": {"revision": [20, 19]}, "aoi_locals_refused": False}))
scenario("connect_no_multi_service", [open_(), {"op": "read", "tags": batch(12)}], variant({"multi_service": False}))
scenario("connect_forward_open_refused", [
    sim("fault", fault={"service_status": {"service": 0x5B, "class": 0x06, "status": 0x01, "ext": 0x0113}}),
    sim("fault", fault={"service_status": {"service": 0x54, "class": 0x06, "status": 0x01, "ext": 0x0113}}),
    open_(), sim("clear_faults"), open_(new=False), {"op": "read", "tags": ["dint1"]}])
scenario("connect_large_forward_open_refused", [
    sim("fault", fault={"service_status": {"service": 0x5B, "class": 0x06, "status": 0x08}}),
    open_(), STATE, {"op": "read", "tags": ["big_ary{2000}"]}])

# ---- reads ----

for name, tags in [("atomic", ATOMIC), ("bits", BITS), ("arrays", ARRAYS), ("multidim", MULTIDIM),
                   ("bool_arrays", BOOL_ARRAYS), ("strings", STRINGS), ("udts", UDTS), ("nested", NESTED),
                   ("aois", AOIS), ("program_scope", PROGRAM), ("errors", ERRORS), ("fragmented", BIG)]:
    scenario(f"read_{name}", [open_()] + one_by_one(tags))
scenario("read_fragmented_500", [open_(connection_size=500)] + one_by_one(BIG))
scenario("read_huge_array_chunks", [open_(), {"op": "read", "tags": ["huge{70000}"]},
                                    {"op": "read", "tags": ["huge[69990]{10}", "huge[65535]{2}"]},
                                    {"op": "write", "items": [["huge[65530]{10}", list(range(10))]]},
                                    {"op": "read", "tags": ["huge[65528]{12}"]}],
         variant(extra_tags=[{"name": "huge", "type": "DINT", "dims": [70000], "value": [1, 2, 3]}]))
for size in (500, 4000):
    for n in (1, 10, 200):
        scenario(f"read_batch_{n}_at_{size}", [open_(connection_size=size), {"op": "read", "tags": batch(n)}])

# ---- writes ----

for name, items in [("atomic", W_ATOMIC), ("arrays", W_ARRAYS), ("bit_masks", W_BITS), ("bool_ranges", W_BOOL_RANGES),
                    ("strings", W_STRINGS), ("structs", W_STRUCTS), ("bytes", W_BYTES), ("aois", W_AOI),
                    ("invalid", W_INVALID)]:
    scenario(f"write_{name}", [open_()] + [{"op": "write", "items": [item]} for item in items] +
             [{"op": "write", "items": items}, read_back(items)])
scenario("write_fragmented", [open_(), {"op": "write", "items": [["big_ary{2000}", list(range(2000))]]},
                              {"op": "read", "tags": ["big_ary[1995]{5}"]}])
scenario("write_fragmented_500", [open_(connection_size=500),
                                  {"op": "write", "items": [["big_ary{2000}", [-i for i in range(2000)]],
                                                            ["str480", "z" * 480]]},
                                  {"op": "read", "tags": ["big_ary[1995]{5}", "str480"]}])
MIXED = W_ATOMIC + W_ARRAYS + W_BITS + W_BOOL_RANGES + W_STRINGS + W_STRUCTS + W_AOI
for size in (500, 4000):
    scenario(f"write_batch_mixed_at_{size}", [open_(connection_size=size), {"op": "write", "items": MIXED},
                                              read_back(MIXED)])

# ---- tag table edits ----

scenario("table_edit_between_reads", [
    open_(), {"op": "read", "tags": ["dint_ary[2]"]},
    sim("add_tag", tag={"name": "new_tag", "type": "DINT", "value": 31}), {"op": "read", "tags": ["new_tag"]},
    sim("remove_tag", name="sint1"), sim("add_tag", tag={"name": "reused", "type": "INT", "value": -9}),
    {"op": "read", "tags": ["dint_ary[2]", "reused"]}, {"op": "read", "tags": ["sint1"]},
    sim("bump"), {"op": "read", "tags": ["dint_ary[2]"]}, STATE])
scenario("table_check_reload", [
    open_(), {"op": "check"}, sim("add_type", type={"name": "NewUDT", "members": [{"name": "a", "type": "DINT"}]}),
    sim("add_tag", tag={"name": "nu", "type": "NewUDT", "value": {"a": 4}}), {"op": "check"}, {"op": "check"},
    {"op": "read", "tags": ["nu", "nu.a"]}, STATE])
scenario("table_changed_during_read", [
    open_(), sim("bump_requests", n=50), {"op": "read", "tags": ["dint1", "int1"]},
    {"op": "write", "items": [["dint1", 5]]}, sim("clear_hook"), {"op": "read", "tags": ["dint1"]}])
scenario("table_changed_once_retry", [
    open_(), sim("bump_requests", n=1), {"op": "read", "tags": ["dint1", "udt1"]},
    sim("bump_requests", n=1), {"op": "write", "items": [["dint1", 6], ["int1.0", True]]},
    {"op": "read", "tags": ["dint1", "int1"]}])
scenario("table_download", [
    open_(), sim("download", config={"program_name": "Other", "tags": [{"name": "dint1", "type": "INT", "value": 3}]}),
    {"op": "read", "tags": ["dint1", "udt1"]}, STATE])
scenario("table_reload_backoff", [
    open_(), sim("fault", fault={"service_status": {"service": 0x03, "class": 0xAC, "status": 0x10}}),
    {"op": "read", "tags": ["dint1"]}, sim("clear_faults"), {"op": "read", "tags": ["dint1", "int1"]},
    {"op": "write", "items": [["dint1", 1]]}, {"op": "check"}, {"op": "sleep", "seconds": 2.1},
    {"op": "read", "tags": ["dint1"]}])
scenario("table_reload_fails", [
    open_(), sim("bump"), sim("fault", fault={"service_status": {"service": 0x55, "class": 0x6B, "status": 0x05}}),
    {"op": "read", "tags": ["dint1"]}, {"op": "read", "tags": ["dint1"]}, sim("clear_faults"),
    {"op": "sleep", "seconds": 2.1}, {"op": "read", "tags": ["dint1"]}, STATE])

# ---- errors ----

scenario("errors_injected_status", [
    open_(), sim("fault", fault={"tag_status": {"tag": "dint_ary", "status": 5}}),
    {"op": "read", "tags": ["dint_ary[1]", "dint1"]}, {"op": "read", "tags": ["dint_ary[1]"]}, sim("clear_faults"),
    sim("fault", fault={"tag_status": {"tag": "dint1", "status": 0xFF, "ext": 0x2107}}),
    {"op": "write", "items": [["dint1", 1]]}, {"op": "write", "items": [["dint1", 1], ["int1", 2]]},
    sim("clear_faults"), sim("fault", fault={"tag_status": {"tag": "udt1", "status": 0x10}}),
    {"op": "read", "tags": ["udt1", "udt1.dint"]}, {"op": "write", "items": [["udt1.dint.2", True]]}])
scenario("errors_access", [open_(), {"op": "read", "tags": ["hidden_dint"]}, {"op": "write", "items": [["ro_dint", 1]]},
                           {"op": "read", "tags": ["ro_dint", "hidden_dint", "valve1.Count"]}])
scenario("errors_lost_reply", [open_(init_tags=False, socket_timeout=1.0), sim("fault", fault={"drop_replies": 1}),
                               {"op": "read", "tags": ["dint1"]}, open_(new=False), {"op": "plc_name"}])

# ---- clock, generic messages, modules ----

US = 1_700_000_000_123_456
scenario("plc_time", [open_(init_tags=False), {"op": "set_plc_time", "us": US}, {"op": "get_plc_time", "near_us": US},
                      sim("fault", fault={"service_status": {"service": 0x03, "class": 0x8B, "status": 0x08}}),
                      {"op": "get_plc_time", "near_us": US}, {"op": "set_plc_time", "us": US}])
scenario("generic_messages", [
    open_(init_tags=False),
    {"op": "generic", "service": 0x01, "class_code": 0x01, "instance": 1, "connected": False, "name": "identity"},
    {"op": "generic", "service": 0x01, "class_code": 0x01, "instance": 1, "connected": True},
    {"op": "generic", "service": 0x01, "class_code": 0x01, "instance": 1, "connected": False, "unconnected_send": True},
    {"op": "generic", "service": 0x01, "class_code": 0x01, "instance": 1, "connected": False, "unconnected_send": True,
     "route_path": "bp/1"},
    {"op": "generic", "service": 0x0E, "class_code": 0x01, "instance": 1, "attribute": 7, "connected": True},
    {"op": "generic", "service": 0x03, "class_code": 0xAC, "instance": 1, "request_data": "0100" + "0100",
     "connected": True},
    {"op": "generic", "service": 0x0E, "class_code": "01", "instance": "01", "attribute": 1, "connected": True},
    {"op": "generic", "service": 0x33, "class_code": 0x01, "instance": 1, "connected": True, "name": "bad service"},
    {"op": "generic", "service": 0x01, "class_code": 0x77, "instance": 3, "connected": False, "name": "bad class"},
    {"op": "module_info", "slot": 0}, {"op": "module_info", "slot": 1}, {"op": "module_info", "slot": 2},
    {"op": "module_info", "slot": 5}])

# ---- descriptions ----

DESCRIPTIONS_CONFIG = {
    "kind": "logix",
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
DESCRIBED = ["Array[0]", "Array[1]", "Array[0].1", "Array[5].3", "Scalar", "Structs[0].Acked", "Structs[2].Acked",
             "Structs[2].val", "Outer.Inner.val", "Outer.items[2].Acked", "Outer.items[1].Acked",
             "Program:MainProgram.Input", "Missing", "Array[30]"]
scenario("descriptions", [open_(), {"op": "description", "tag": "Array[0]"}, {"op": "authenticate"}] +
         [{"op": "description", "tag": t} for t in DESCRIBED] +
         [{"op": "descriptions", "tags": DESCRIBED}, {"op": "description", "tag": "Long"},
          {"op": "descriptions", "tags": ["Long", "Array"]},
          {"op": "description", "tag": "Array", "language": 0x0409}, open_(), {"op": "description", "tag": "Array"}],
         {"inline": DESCRIPTIONS_CONFIG})
scenario("descriptions_at_500", [open_(connection_size=500), {"op": "authenticate"},
                                 {"op": "descriptions", "tags": DESCRIBED + ["Long"]}],
         {"inline": DESCRIPTIONS_CONFIG})

# ---- SLC ----

SLC = {"file": "example_slc.json"}
SLC_READS = ["N7:0", "N7:0{7}", "N7:5", "N7:99", "F8:0", "F8:0{3}", "B3:0/1", "B3:0/2", "B3/3", "B3:2", "T4:0.ACC",
             "T4:0.PRE", "T4:0.EN", "T4:0.DN", "T4:1.ACC", "C5:0.ACC", "C5:0.PRE", "C5:0.CU", "ST9:0", "ST9:2", "A10:0",
             "A10:1", "L12:0", "L12:0{2}", "S:1/5", "S:1/4", "I:0", "I:1", "O:1"]
SLC_WRITES = [["N7:10", 1234], ["N7:20{3}", [1, 2, 3]], ["F8:5", 3.5], ["B3:1/4", True], ["B3/21", True],
              ["T4:2.PRE", 500], ["T4:2.ACC", 42], ["T4:2.EN", True], ["C5:1.PRE", 7], ["ST9:1", "written"],
              ["A10:2", "XY"], ["L12:5", -123456], ["N7:0/15", True], ["O:2", 3]]
SLC_ERRORS = ["N99:0", "N7:200", "N7:99{2}", "B3:100/0", "X7:0", "N7", "N7:0.ACC", "nonsense", "R6:0.LEN", "T4:0"]
scenario("slc_reads", [open_(driver="slc")] + [{"op": "read", "tags": [t]} for t in SLC_READS] +
         [{"op": "read", "tags": SLC_READS}], SLC)
scenario("slc_writes", [open_(driver="slc")] + [{"op": "write", "items": [w]} for w in SLC_WRITES] +
         [{"op": "write", "items": SLC_WRITES}, read_back(SLC_WRITES), {"op": "read", "tags": ["N7:0"]}], SLC)
scenario("slc_errors", [open_(driver="slc")] + [{"op": "read", "tags": [t]} for t in SLC_ERRORS] +
         [{"op": "write", "items": [["N99:0", 1]]}, {"op": "write", "items": [["N7:0", 70000]]},
          {"op": "write", "items": [["N7:0", "x"]]}, {"op": "write", "items": [["F8:0", "x"]]}], SLC)
scenario("slc_misc", [open_(driver="slc"), {"op": "processor_type"}, {"op": "file_directory"},
                      {"op": "datalog", "count": 2, "queue": 1}, {"op": "datalog", "count": 2, "queue": 1}], SLC)


def main():
    for s in SCENARIOS:
        if s["steps"][-1] != CLOSE:
            s["steps"].append(CLOSE)
    names = [s["name"] for s in SCENARIOS]
    assert len(names) == len(set(names)), "duplicate scenario names"
    path = os.path.join(HERE, "scenarios.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"scenarios": SCENARIOS}, f, indent=1)
        f.write("\n")
    print(f"wrote {path} ({len(SCENARIOS)} scenarios, {sum(len(s['steps']) for s in SCENARIOS)} steps)")


if __name__ == "__main__":
    main()
