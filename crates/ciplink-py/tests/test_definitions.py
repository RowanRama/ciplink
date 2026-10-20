"""
The tag definitions the binding builds from the core (tags, data_types, tags_json, get_tag_info, get_tag_list) and
the tag cache file, against the simulator: shared data type dicts and type classes, objects kept until the
definitions change, incremental lazy loads, and the binary cache file with its load / ignore / re-validate rules.
"""

import gc
import json
import os
import sys
import weakref

import pytest

from conftest import REPO

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import Sim  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import DINT, ErrorKind, LogixDriver, RequestError  # noqa: E402

MAGIC = b"CIPLTAGC"


@pytest.fixture
def sim():
    with Sim("example_controller.json") as sim:
        yield sim


def struct_dicts(tags):
    """every data type dict reachable from tags, by id"""
    found = {}

    def walk(dt):
        if id(dt) in found:
            return
        found[id(dt)] = dt
        for member in dt["internal_tags"].values():
            if isinstance(member["data_type"], dict):
                walk(member["data_type"])

    for tag in tags.values():
        if isinstance(tag["data_type"], dict):
            walk(tag["data_type"])
    return found


def test_data_type_dicts_and_type_classes_are_shared(sim):
    with LogixDriver(sim.address) as plc:
        tags, types = plc.tags, plc.data_types
        assert tags is plc.tags and types is plc.data_types
        for tag in tags.values():
            if tag["tag_type"] == "struct":
                assert tag["data_type"] is types[tag["data_type_name"]]
                if not tag["dim"]:
                    assert tag["type_class"] is tag["data_type"]["type_class"]
        nested = types["NestedUDT"]["internal_tags"]
        assert nested["udt1"]["data_type"] is types["AtomicUDT"]
        assert nested["udt_ary1"]["type_class"].element_type is types["AtomicUDT"]["type_class"]
        assert tags["dint_ary"]["type_class"].element_type is DINT
        assert repr(tags["dint_ary"]["type_class"]) == "DINT[10]"
        members, bits = types["AtomicUDT"]["_struct_members"]
        assert [m.name for m, _ in members][1:] == ["sint", "int", "dint", "lint", "real"] and "bool" in bits  # after the host


def test_tags_are_read_only_attributes(sim):
    with LogixDriver(sim.address) as plc:
        with pytest.raises(AttributeError):
            plc.tags = {}
        with pytest.raises(AttributeError):
            plc.data_types = {}


def test_definitions_are_kept_until_they_change(sim):
    with LogixDriver(sim.address) as plc:
        tags, types = plc.tags, plc.data_types
        atomic = types["AtomicUDT"]
        assert plc.read("dint1", "udt1.real")[0].value == 2147483647
        assert not plc.check_tag_table()
        assert plc.tags is tags and plc.data_types is types
        sim.cmd("add_tag", program=None, tag={"name": "added", "type": "AtomicUDT", "value": {"dint": 5}})
        assert plc.check_tag_table()
        assert plc.read("added.dint").value == 5
        assert plc.tags is not tags and "added" in plc.tags
        # the data types were read again (a new tag table): new objects, as in the reference driver
        assert plc.tags["added"]["data_type"] is plc.data_types["AtomicUDT"]
        assert atomic["name"] == "AtomicUDT"


def test_lazy_loads_add_to_the_same_tags_dict(sim):
    with LogixDriver(sim.address, lazy_tags=True) as plc:
        assert plc.tags == {}
        plc.read("udt1")
        tags = plc.tags
        assert set(tags) == {"udt1"}
        atomic = tags["udt1"]["data_type"]
        plc.read("udt_ary[1]", "dint1")
        assert plc.tags is tags and set(tags) == {"udt1", "udt_ary", "dint1"}
        assert tags["udt_ary"]["data_type"] is atomic
        assert plc.get_tag_info("Program:MainProgram.p_dint")["data_type"] == "DINT"
        assert "Program:MainProgram.p_dint" in plc.tags


def test_tags_json_is_a_new_copy_without_type_classes(sim):
    with LogixDriver(sim.address) as plc:
        first = plc.tags_json
        text = json.dumps(first)
        assert "type_class" not in text and "_struct_members" not in text
        assert plc.tags_json == first and plc.tags_json is not first
        first["udt1"]["data_type"]["name"] = "changed"
        assert plc.tags["udt1"]["data_type"]["name"] == "AtomicUDT"
        assert plc.tags_json["udt1"]["data_type"]["name"] == "AtomicUDT"
        assert first["udt1"]["data_type"]["internal_tags"].keys() == plc.tags["udt1"]["data_type"]["internal_tags"].keys()


def test_get_tag_info_returns_the_dicts_of_tags(sim):
    with LogixDriver(sim.address) as plc:
        tags = plc.tags
        assert plc.get_tag_info("udt1") is tags["udt1"]
        assert plc.get_tag_info("UDT1") is tags["udt1"]
        assert plc.get_tag_info("dint_ary[3]") is tags["dint_ary"]
        assert plc.get_tag_info("nested.TMR.acc") is tags["nested"]["data_type"]["internal_tags"]["tmr"][
            "data_type"]["internal_tags"]["ACC"]
        assert plc.get_tag_info("program:MainProgram.p_udt.real")["data_type"] == "REAL"
        for name in ("nope", "udt1.nope", "Program:Nope.x"):
            with pytest.raises(RequestError) as err:
                plc.get_tag_info(name)
            assert err.value.args[0].kind is ErrorKind.NOT_FOUND, name
        with pytest.raises(RequestError) as err:
            plc.get_tag_info("dint1.x")
        assert err.value.args[0].kind is ErrorKind.BAD_REQUEST


def test_get_tag_list_dicts(sim):
    with LogixDriver(sim.address) as plc:
        listed = plc.get_tag_list(program="MainProgram", cache=False)
        assert {t["tag_name"] for t in listed} >= {"Program:MainProgram.p_udt", "Program:MainProgram.p_dint"}
        p_udt = next(t for t in listed if t["tag_name"] == "Program:MainProgram.p_udt")
        assert p_udt["data_type"] is plc.data_types["AtomicUDT"]
        cached = plc.get_tag_list(program="*")
        assert all(t is plc.tags[t["tag_name"]] for t in cached)


def test_a_driver_and_its_definitions_are_freed(sim):
    plc = LogixDriver(sim.address)
    plc.open()
    core = weakref.ref(plc._core)
    tags = plc.tags
    assert tags._owner() is plc._core
    plc.close()
    del plc
    gc.collect()
    assert core() is None  # no reference cycle through the tags dict
    assert tags._owner() is None


def test_shared_tags(sim):
    with LogixDriver(sim.address) as plc, LogixDriver(sim.address, init_tags=False) as plc2:
        plc2._tags = plc.tags
        assert set(plc2.tags) == set(plc.tags)
        assert plc2.read("udt1.dint").value == 10
        with pytest.raises(TypeError):
            plc2._tags = {"x": {}}
        plc2._tags = {}
        assert plc2.tags == {}


# ---- the tag cache file


def test_cache_file_is_binary_and_saves_the_upload(sim, tmp_path):
    path = tmp_path / "tags"
    with LogixDriver(sim.address, tag_cache_file=path) as plc:
        cold = json.dumps(plc.tags_json, sort_keys=True)
        types = json.dumps({repr(k): repr(v["type_class"]) for k, v in plc.data_types.items()}, sort_keys=True)
    data = path.read_bytes()
    assert data.startswith(MAGIC)
    before = sim.cmd("requests")
    with LogixDriver(sim.address, tag_cache_file=path) as plc:
        assert json.dumps(plc.tags_json, sort_keys=True) == cold
        assert json.dumps({repr(k): repr(v["type_class"]) for k, v in plc.data_types.items()}, sort_keys=True) == types
        assert plc.read("udt1.real").value == 1000.5
    assert sim.cmd("requests") - before < 15
    assert path.read_bytes() == data  # unchanged contents are not written again
    sim.cmd("add_tag", program="MainProgram", tag={"name": "p_new", "type": "REAL", "value": 0.5})
    with LogixDriver(sim.address, tag_cache_file=path) as plc:
        assert "Program:MainProgram.p_new" in plc.tags
    assert path.read_bytes() != data


@pytest.mark.parametrize("contents", [
    b"",
    b"not a cache file",
    MAGIC + b"\x01\x00",
    json.dumps({"version": 2, "scope": "*", "serial": "c0ffee01", "table_version": None, "symbols": [],
                "templates": []}).encode(),
])
def test_other_or_damaged_files_are_replaced(sim, tmp_path, contents):
    path = tmp_path / "tags"
    path.write_bytes(contents)
    with LogixDriver(sim.address, tag_cache_file=path) as plc:
        assert "udt1" in plc.tags
    assert path.read_bytes().startswith(MAGIC)


def test_a_damaged_body_is_ignored(sim, tmp_path):
    path = tmp_path / "tags"
    with LogixDriver(sim.address, tag_cache_file=path) as plc:
        want = set(plc.tags)
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    with LogixDriver(sim.address, tag_cache_file=path) as plc:
        assert set(plc.tags) == want
    assert path.read_bytes() != bytes(data)
