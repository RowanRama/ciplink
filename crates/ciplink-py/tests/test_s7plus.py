"""
S7PlusDriver against the S7comm-plus simulator (ciplink-sim with an ``"s7plus"`` config) on 127.0.0.1, over TLS:
browse, read and write shapes, asyncio, subscriptions, connection events, certificate pinning and errors.  Every
tag name here is invented.
"""

import asyncio
import os
import sys
import time

import pytest

from conftest import REPO

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import Sim  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import (  # noqa: E402
    CommError, ConnectionEvent, ErrorKind, RequestError, S7PlusDriver, Subscription, Tag,
)

CONFIG = {"s7plus": {
    "name": "PLC_Line1",
    "types": {"Recipe": {"members": {"Speed": "REAL", "Count": "DINT", "Name": "STRING[10]"}}},
    "dbs": [
        {"name": "Line1", "number": 5, "members": {
            "Conveyor": {"type": "STRUCT", "members": {
                "Speed": {"type": "REAL", "value": 1.5}, "Running": {"type": "BOOL", "value": True}}},
            "Count": {"type": "DINT", "value": -300},
            "Items": "ARRAY[1..250] OF UINT",
            "Flags": "ARRAY[0..15] OF BOOL",
            "Recipe": "Recipe",
            "Stamp": {"type": "DTL", "value": "2026-11-18T16:34:46.1"},
            "Label": {"type": "WSTRING[4]", "value": "OK"},
            "Status": {"type": "WORD", "value": 4660},
            "Hidden": {"type": "INT", "hmi_accessible": False}}},
    ],
    "areas": {"I": {"StartButton": {"type": "BOOL", "value": True}}, "Q": {"Motor": "BOOL"},
              "M": {"Mode": {"type": "INT", "value": 3}}},
}}


class S7Sim(Sim):
    """the simulator serving an S7comm-plus config; it prints its certificate fingerprint after the address"""

    def __init__(self, config):
        super().__init__(config)
        line = self.proc.stdout.readline()
        assert line.startswith("fingerprint "), line
        self.fingerprint = line.split()[-1]


def wait_for(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


@pytest.fixture(scope="module")
def sim():
    with S7Sim(CONFIG) as sim:
        yield sim


@pytest.fixture
def plc(sim):
    sim.cmd("clear_faults")
    with S7PlusDriver(sim.address, socket_timeout=5.0) as plc:
        yield plc


# ---- connect, browse, info


def test_open_exposes_name_fingerprint_and_info(sim, plc):
    assert plc.connected and plc.connection_state == "connected"
    assert plc.name == "PLC_Line1"
    assert plc.certificate_fingerprint == sim.fingerprint
    info = plc.get_plc_info()
    assert info["name"] == "PLC_Line1"
    assert info["max_read"] == 100 and info["max_write"] == 100
    assert "S7PlusDriver" in str(plc) and repr(plc) == f"S7PlusDriver(path={sim.address!r})"
    assert plc.socket_timeout == 5.0
    plc.socket_timeout = 3.0
    assert plc.socket_timeout == 3.0


def test_tags_types_and_tag_list(plc):
    tags = plc.tags
    assert list(tags) == ["Line1", "StartButton", "Motor", "Mode"]
    assert tags["Line1"]["kind"] == "data_block" and tags["Line1"]["lid"] == 5
    assert tags["Mode"]["type"] == "INT" and tags["Mode"]["kind"] == "elementary"
    line1 = plc.data_types[tags["Line1"]["type"]]["members"]
    assert line1["Items"]["dims"] == [250] and line1["Items"]["lower_bounds"] == [1]
    assert line1["Label"]["kind"] == "string" and line1["Label"]["string_length"] == 4
    assert line1["Recipe"]["kind"] == "struct"
    assert line1["Hidden"]["hmi_accessible"] is False

    names = [s["name"] for s in plc.tag_list()]
    assert "Line1.Conveyor.Speed" in names and "Line1.Recipe.Name" in names and "Mode" in names
    info = plc.get_tag_info('"Line1".Conveyor.Speed')
    assert info["type"] == "REAL" and info["access"].startswith("8A0E0005.") and info["crc"] != 0
    assert plc.get_tag_info("Line1.Items")["dims"] == [250]
    with pytest.raises(RequestError):
        plc.get_tag_info("Line1.Nope")
    assert plc.refresh_tags() is False


# ---- reads and writes


def test_read_shapes_and_values(plc):
    one = plc.read("Line1.Conveyor.Speed")
    assert type(one) is Tag and one == Tag("Line1.Conveyor.Speed", 1.5, "REAL", None)
    assert plc.read() == []
    many = plc.read("Line1.Count", "Line1.Status", "StartButton", "Mode", "Line1.Label", "Line1.Stamp",
                    "Line1.Conveyor")
    assert [t.value for t in many[:5]] == [-300, 4660, True, 3, "OK"]
    assert many[1].type == "WORD"
    assert many[5].value.startswith("2026-11-18T16:34:46.1")
    assert many[6].value == {"Speed": 1.5, "Running": True}
    items = plc.read("Line1.Items")
    assert items.type == "UINT[250]" and len(items.value) == 250


def test_reads_split_by_the_item_limit(plc):
    names = [f"Line1.Items[{i}]" for i in range(1, 251)]
    results = plc.read(*names)
    assert len(results) == 250 and all(r.error is None for r in results)


def test_write_shapes_and_errors(sim, plc):
    w = plc.write("Line1.Count", 17)
    assert w == Tag("Line1.Count", 17, "DINT", None)
    w = plc.write(("Line1.Conveyor.Speed", 2.5), ("Line1.Label", "Hi"), ("Line1.Items[3]", 7),
                  ("Line1.Recipe.Count", 70_000_000_000), ("Line1.Nope", 1), ("Line1.Conveyor", {}))
    assert [r.error for r in w[:3]] == [None, None, None]
    assert w[3].error.kind == ErrorKind.BAD_VALUE
    assert w[4].error.kind == ErrorKind.NOT_FOUND
    assert w[5].error.kind == ErrorKind.BAD_REQUEST
    assert sim.cmd("value", path="Line1.Count") == 17
    assert sim.cmd("value", path="Line1.Label") == "Hi"
    assert plc.read("Line1.Items[3]").value == 7
    assert plc.write() == []


def test_item_errors_are_per_tag(sim, plc):
    sim.cmd("fault", fault={"item_error": {"tag": "Line1.Count", "code": 0x810488000000FF80}})
    r = plc.read("Line1.Conveyor.Speed", "Line1.Count", "Line1.Nope")
    assert r[0].error is None
    assert r[1].error.kind == ErrorKind.DEVICE and "0x810488000000FF80" in r[1].error
    assert r[2].error.kind == ErrorKind.NOT_FOUND and r[2].value is None


# ---- asyncio, subscriptions, events


def test_async_reads_and_writes(sim, plc):
    async def main():
        w = await plc.write_async("Line1.Recipe.Speed", 4.5)
        one, two = await asyncio.gather(plc.read_async("Line1.Recipe.Speed"),
                                        plc.read_async("Mode", "Line1.Count"))
        return w, one, two, await plc.read_async(), await plc.write_async()

    w, one, two, none, none_w = asyncio.run(main())
    assert w == Tag("Line1.Recipe.Speed", 4.5, "REAL", None)
    assert one.value == 4.5
    assert two == plc.read("Mode", "Line1.Count")
    assert none == [] and none_w == []


def test_subscription_delivers_changes(sim, plc):
    with plc.subscribe("Mode", "Line1.Conveyor.Running", interval=0.05) as sub:
        assert isinstance(sub, Subscription) and sub.tags == ["Mode", "Line1.Conveyor.Running"]
        first = sub.recv(5)
        assert {t.tag for t in first} == {"Mode", "Line1.Conveyor.Running"}
        sim.cmd("set", path="Mode", value=42)
        changed = sub.recv(5)
        assert [(t.tag, t.value) for t in changed] == [("Mode", 42)]
    assert sub.closed


def test_connection_events_and_reconnect(sim):
    events = []
    with S7PlusDriver(sim.address, socket_timeout=5.0, keep_alive=0.05) as plc:
        plc.on_connection(events.append)
        sim.cmd("fault", fault={"close_connections": True})
        assert wait_for(lambda: [e.event for e in events][-1:] == ["connected"] and len(events) >= 2)
        assert all(isinstance(e, ConnectionEvent) for e in events)
        assert events[0].event == "disconnected"
        assert plc.read("Mode").error is None
    assert plc.connection_state == "closed"


# ---- pinning, refusal, errors


def test_pinned_certificate(sim):
    pin = sim.fingerprint.lower().replace(":", "")
    with S7PlusDriver(sim.address, tls_fingerprint=pin, reconnect=False) as plc:
        assert plc.read("Mode").value is not None
    wrong = "00" * 32
    plc = S7PlusDriver(sim.address, tls_fingerprint=wrong, reconnect=False)
    with pytest.raises(CommError, match="does not match"):
        plc.open()
    assert plc.certificate_fingerprint == sim.fingerprint
    with pytest.raises(RequestError):
        S7PlusDriver(sim.address, tls_fingerprint="not hex")


def test_refused_connection_and_closed_driver(sim):
    sim.cmd("fault", fault={"refuse_connections": True})
    try:
        plc = S7PlusDriver(sim.address, reconnect=False)
        assert plc.open() is False
        with pytest.raises(CommError):
            with S7PlusDriver(sim.address, reconnect=False):
                pass
    finally:
        sim.cmd("clear_faults")
    plc = S7PlusDriver(sim.address, reconnect=False)
    with pytest.raises(CommError):
        plc.read("Mode")
    with pytest.raises(ValueError):
        S7PlusDriver(sim.address, keep_alive=-1)
