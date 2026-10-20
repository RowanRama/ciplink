"""
The Python half of the differential parity harness (crates/ciplink-sim/tests/differential.rs).

Runs steps of tools/diff/scenarios.json with the REFERENCE Python driver against a simulator the Rust test
serves over TCP.  The Rust test drives it over stdin/stdout, one JSON object per line each way:

    {"cmd": "begin", "path": "127.0.0.1:PORT", "dir": "<scratch dir of the scenario>"}
    {"cmd": "step", "step": {...}}        ->  {"result": <the step's result, tagged JSON>}
    {"cmd": "end"}                        ->  {"result": null}   (closes the driver)

Results use the fixture encoding of tools/fixtures/fixturelib.py ({"int": 1}, {"str": "a"}, ...), so int and
float, str and bytes stay distinct.  The reference package (tools/reference) is loaded as ``ciplink``; run from the
repo root, e.g. ``uv run --no-project --isolated --python 3.12 python tools/diff/py_runner.py``.
"""

import json
import math
import os
import sys
import time
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "reference"))

import reference  # noqa: E402

reference.load()

from ciplink import LogixDriver, SLCDriver  # noqa: E402
from ciplink.tag import Tag  # noqa: E402


def enc(value):
    """a Python value as tagged JSON"""
    if value is None:
        return None
    if isinstance(value, bool):
        return {"bool": value}
    if isinstance(value, int):
        return {"int": value}
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return {"float": repr(value)}
        return {"float": value}
    if isinstance(value, str):
        return {"str": value}
    if isinstance(value, (bytes, bytearray)):
        return {"bytes": bytes(value).hex()}
    if isinstance(value, (list, tuple)):
        return {"list": [enc(v) for v in value]}
    if isinstance(value, dict):
        return {"dict": [[str(k), enc(v)] for k, v in value.items()]}
    raise TypeError(f"cannot encode {value!r}")


def dec(value):
    """
    a write value of scenarios.json: plain JSON, {"$bytes": hex} for bytes; a struct's members sorted by name, the
    order the Rust side's JSON objects have
    """
    if isinstance(value, list):
        return [dec(v) for v in value]
    if isinstance(value, dict):
        if list(value) == ["$bytes"]:
            return bytes.fromhex(value["$bytes"])
        return {k: dec(value[k]) for k in sorted(value)}
    return value


def plain(value):
    """the JSON-able part of a tag or data type, as tags_json does it"""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items() if k not in ("type_class", "_struct_members")}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


def tag(t):
    """a Tag result: name, value, type, error message, kind, status, ext"""
    error = t.error
    return {
        "tag": t.tag,
        "value": enc(t.value),
        "type": t.type,
        "error": None if error is None else str(error),
        "kind": None if error is None else t.error_kind.value,
        "status": getattr(error, "status", None),
        "ext": getattr(error, "ext", None),
    }


def tags(result):
    """read and write return a Tag for one item, a list for several: always a list here"""
    return [tag(t) for t in ([result] if isinstance(result, Tag) else result)]


class Runner:
    def __init__(self):
        self.path = None
        self.dir = None
        self.driver = None

    def close(self):
        if self.driver is not None:
            try:
                self.driver.close()
            except Exception:
                pass
            self.driver = None

    def state(self):
        d = self.driver
        return {
            "connected": d.connected,
            "tags": enc(d.tags_json),
            "data_types": enc(plain(d.data_types)),
            "info": enc(d.info),
            "version": enc(d._tag_table_version),
            "use_ids": d._cfg["use_instance_ids"],
            "micro800": d._micro800,
            "name": d.name,
            "revision_major": d.revision_major,
            "str": str(d),
        }

    def new(self, step):
        self.close()
        kwargs = {}
        if "connection_size" in step:
            kwargs["connection_size"] = step["connection_size"]
        if "socket_timeout" in step:
            kwargs["socket_timeout"] = step["socket_timeout"]
        if step.get("driver") == "slc":
            self.driver = SLCDriver(self.path, **kwargs)
            return
        for key in ("init_tags", "init_program_tags", "tag_namespace_filter", "lazy_tags"):
            if key in step:
                kwargs[key] = step[key]
        if step.get("tag_cache_file"):
            kwargs["tag_cache_file"] = os.path.join(self.dir, "tag_cache.json")
        self.driver = LogixDriver(self.path, **kwargs)

    def run(self, step):
        """the result of a step: {"ok": ...} or {"err": exception class, "msg": message}"""
        try:
            return {"ok": self.call(step)}
        except Exception as err:
            return {"err": type(err).__name__, "msg": str(err)}

    def call(self, step):
        op = step["op"]
        d = self.driver
        if op == "open":
            if step.get("new", True):
                self.new(step)
            opened = self.driver.open()
            if step.get("driver") == "slc":
                return {"opened": opened, "connected": self.driver.connected}
            return {"opened": opened, "state": self.state()}
        if op == "close":
            if d is not None:
                d.close()
            return None
        if op == "state":
            return self.state()
        if op == "cache_file":
            # the formats differ (Rust writes its binary file): only whether there is one is compared
            return {"exists": True} if os.path.exists(os.path.join(self.dir, "tag_cache.json")) else None
        if op == "read":
            return tags(d.read(*step["tags"]))
        if op == "write":
            return tags(d.write(*[(t, dec(v)) for t, v in step["items"]]))
        if op == "check":
            return d.check_tag_table()
        if op == "tag_info":
            return enc(plain(d.get_tag_info(step["name"])))
        if op == "tag_list":
            return enc(plain(d.get_tag_list(step.get("program"), step.get("cache", True), step.get("filter", ""))))
        if op == "plc_info":
            return enc(d.get_plc_info())
        if op == "plc_name":
            return d.get_plc_name()
        if op == "module_info":
            return enc(d.get_module_info(step["slot"]))
        if op == "set_plc_time":
            return tag(d.set_plc_time(step["us"]))
        if op == "get_plc_time":
            t = d.get_plc_time()
            result = tag(t._replace(value=None))
            if t.value is not None:  # the clock runs: only whether it is near what was set is compared
                result["value"] = {"near": abs(t.value["microseconds"] - step["near_us"]) < 120_000_000}
            return result
        if op == "generic":
            kwargs = {k: step[k] for k in ("service", "connected", "unconnected_send", "name") if k in step}
            for k in ("class_code", "instance", "attribute"):
                if k in step:
                    kwargs[k] = bytes.fromhex(step[k]) if isinstance(step[k], str) else step[k]
            if "request_data" in step:
                kwargs["request_data"] = bytes.fromhex(step["request_data"])
            if "route_path" in step:
                kwargs["route_path"] = step["route_path"]
            return tag(d.generic_message(**kwargs))
        if op == "descriptions":
            return [tag(t) for t in d.get_tag_descriptions(*step["tags"])]
        if op == "description":
            return tag(d.get_tag_description(step["tag"], language=step.get("language", 0x007F)))
        if op == "authenticate":
            return tag(d.authenticate_metadata())
        if op == "file_directory":
            return enc(d.get_file_directory())
        if op == "datalog":
            return enc(d.get_datalog_queue(step["count"], step["queue"]))
        if op == "sleep":
            time.sleep(step["seconds"])
            return None
        if op == "set_connection_size":
            d.connection_size = step["value"]
            return d.connection_size
        if op == "processor_type":
            return d.get_processor_type()
        raise ValueError(f"unknown op {op!r}")


def main():
    runner = Runner()
    out = sys.stdout
    for line in sys.stdin:
        if not line.strip():
            continue
        request = json.loads(line)
        cmd = request["cmd"]
        try:
            if cmd == "begin":
                runner.close()
                runner.path, runner.dir = request["path"], request["dir"]
                result = None
            elif cmd == "step":
                result = runner.run(request["step"])
            elif cmd == "end":
                runner.close()
                result = None
            else:
                raise ValueError(f"unknown command {cmd!r}")
            answer = {"result": result}
        except Exception:
            answer = {"crash": traceback.format_exc()}
        out.write(json.dumps(answer) + "\n")
        out.flush()


if __name__ == "__main__":
    main()
