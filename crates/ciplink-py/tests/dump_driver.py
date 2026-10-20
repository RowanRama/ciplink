"""
What a LogixDriver shows its users, rendered as JSON: tags, data_types (type classes by repr), info, tags_json,
get_tag_info, get_tag_list, str/repr and a get_plc_time.  Run by the parity test with the package under test and,
as ``python dump_driver.py REFERENCE_DIR ADDRESS`` (REFERENCE_DIR = tools/reference), with the reference package.
"""

import datetime
import json
import sys


def render(obj):
    if isinstance(obj, dict):
        return {repr(k) if not isinstance(k, str) else k: render(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [render(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, bytes):
        return {"bytes": obj.hex()}
    return {"repr": repr(obj)}


def shared(tags, data_types):
    """which tag data types are the very dicts of data_types (the reference driver shares them)"""
    return sorted(name for name, tag in tags.items()
                  if isinstance(tag["data_type"], dict) and tag["data_type"] is data_types.get(tag["data_type"]["name"]))


def dump(LogixDriver, address):
    out = {"rust_core": hasattr(sys.modules["ciplink"], "_core")}
    with LogixDriver(address) as plc:
        out["tags"] = render(plc.tags)
        out["data_types"] = render(plc.data_types)
        out["shared"] = shared(plc.tags, plc.data_types)
        out["tags_json"] = render(plc.tags_json)
        info = dict(plc.info)
        out["info"] = render(info)
        out["str"] = str(plc)
        out["repr"] = repr(plc)
        out["name"] = plc.name
        out["revision_major"] = plc.revision_major
        out["tag_info"] = {name: render(plc.get_tag_info(name)) for name in (
            "udt1", "udt1.real", "nested.tmr.ACC", "Program:MainProgram.p_udt", "valve1", "bool_ary", "str20")}
        out["tag_info_is_tag"] = plc.get_tag_info("udt1") is plc.tags["udt1"]
        out["tag_list"] = render(plc.get_tag_list(program="MainProgram", cache=False))
        now = plc.get_plc_time(fmt="%Y", tz=datetime.timezone.utc)
        out["plc_time"] = [type(now.value["datetime"]).__name__, now.value["datetime"].tzinfo is not None,
                           now.value["string"] == now.value["datetime"].strftime("%Y"),
                           type(now.value["microseconds"]).__name__]
        out["module_info"] = render(plc.get_module_info(1))
        out["plc_info"] = render(plc.get_plc_info())
        out["generic"] = render(plc.generic_message(service=0x01, class_code=0x01, instance=1, connected=False,
                                                    name="identity"))
    return out


if __name__ == "__main__":
    sys.path.insert(0, sys.argv[1])
    import reference

    reference.load()
    from ciplink import LogixDriver

    print(json.dumps(dump(LogixDriver, sys.argv[2])))
