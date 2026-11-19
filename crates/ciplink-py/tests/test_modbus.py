"""
ModbusDriver against the simulator binary (tools/sim/example_modbus.json) on 127.0.0.1, in both framings: Modbus
TCP (``tcp://``) and RTU frames over TCP (``rtu+tcp://``, as a serial gateway).  No serial port is opened.
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from conftest import REPO

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import sim_bin  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import (  # noqa: E402
    CommError, ConnectionEvent, ErrorKind, ModbusDriver, RequestError, ResponseError, Subscription, Tag,
)

MAP = os.path.join(REPO, "tools", "sim", "example_modbus_map.csv")


class ModbusSim:
    """the simulator bin serving example_modbus.json on a free port with one framing, and its command channel"""

    def __init__(self, framing):
        self.proc = subprocess.Popen(
            [sim_bin(), "--config", os.path.join(REPO, "tools", "sim", "example_modbus.json"), "--port", "0",
             "--framing", framing, "--exit-on-eof"],
            cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
        )
        line = self.proc.stdout.readline()
        if not line.startswith("listening on "):
            raise RuntimeError(f"simulator did not start: {line!r}")
        scheme = "tcp" if framing == "mbap" else "rtu+tcp"
        self.path = f"{scheme}://{line.split()[-1]}"

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


def wait_for(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


@pytest.fixture(scope="module", params=["mbap", "rtu"])
def sim(request):
    sim = ModbusSim(request.param)
    yield sim
    sim.close()


@pytest.fixture
def plc(sim):
    with ModbusDriver(sim.path, MAP) as plc:
        yield plc


def test_read_write_map_and_addresses(sim, plc):
    speed, run, fault, level, temp, totals, recipe, status, horn, valve = plc.read(
        "Pump1_Speed", "Pump1_Run", "Pump1_Fault", "Tank_Level", "Tank_Temp", "Totals", "Recipe", "Drive_Status",
        "Horn", "Valve2_Open")
    assert speed.type == "REAL" and speed.value == pytest.approx(123.456, rel=1e-6)
    assert (run.value, fault.value, horn.value, valve.value) == (True, True, False, False)
    assert level.type == "LREAL" and level.value == pytest.approx(52.3)
    assert temp.value == pytest.approx(25.0)
    assert totals == Tag("Totals", [120, 135, 99, 140], "UDINT", None)
    assert recipe == Tag("Recipe", "MIX-A", "STRING", None)
    assert status == Tag("Drive_Status", 5, "UINT", None)
    assert plc.read("Totals[2]", "Drive_Status.0", "hr0", "ir10:int16{2}") == [
        Tag("Totals[2]", 99, "UDINT", None),
        Tag("Drive_Status.0", True, "BOOL", None),
        Tag("hr0", 59769, "UINT", None),
        Tag("ir10:int16{2}", [523, 650], "INT", None),
    ]

    try:
        written = plc.write(("Pump1_Speed", 50.5), ("Horn", True), ("hr400:int32", -5), ("Totals[2]", 7))
        assert all(t.error is None for t in written)
        assert written[0] == Tag("Pump1_Speed", 50.5, "REAL", None)  # the caller's value object
        assert sim.cmd("registers", unit=1, area="holding", address=301, count=1) == [1 << 4]  # FC22
        assert [t.value for t in plc.read("Pump1_Speed", "Horn", "hr400:int32", "Totals")] == [
            50.5, True, -5, [120, 135, 7, 140]]
        assert plc.write(("Pump1_Run", False)) == Tag("Pump1_Run", False, "BOOL", None)
        assert sim.cmd("bits", unit=1, area="coil", address=0, count=1) == [False]
    finally:
        sim.cmd("set_registers", unit=1, area="holding", address=0, values=[59769, 17142])
        sim.cmd("set_registers", unit=1, area="holding", address=100, values=[0, 120, 0, 135, 0, 99, 0, 140])
        sim.cmd("set_registers", unit=1, area="holding", address=301, values=[0])
        sim.cmd("set_bits", unit=1, area="coil", address=0, values=[True])

    refused = plc.write(("Drive_Status", 3))  # writable = false in the map: nothing sent
    assert refused.value is None and refused.error_kind == ErrorKind.ACCESS
    too_big = plc.write(("hr0:int16", 70000))
    assert too_big.error_kind == ErrorKind.BAD_VALUE


def test_tags_property(sim):
    plc = ModbusDriver(sim.path, MAP)
    tags = plc.tags
    assert list(tags)[:3] == ["Pump1_Speed", "Pump1_Run", "Pump1_Fault"]
    assert tags["Tank_Level"] == {
        "name": "Tank_Level", "area": "input", "address": 10, "bit": None, "type": "int16", "cip_type": "LREAL",
        "count": 1, "order": None, "unit": None, "scale": 0.1, "offset": None, "units": "%",
        "description": "Tank level (0.1 % per count)", "writable": False,
    }
    assert tags["Horn"]["bit"] == 4 and tags["Valve2_Open"]["unit"] == 2
    assert tags["Pump1_Speed"]["order"] == "CDAB"
    assert ModbusDriver(sim.path).tags == {}  # no map: plain addresses only


def test_device_info(plc):
    info = plc.device_info()
    assert info == {
        "vendor_name": "ciplink", "product_code": "SIM-MB", "revision": "1.0", "vendor_url": None,
        "product_name": "ciplink-sim Modbus", "model_name": "MB-1", "user_application_name": None,
    }
    with pytest.raises(ResponseError) as e:
        plc.device_info(2)  # unit 2 has no FC43: exception 01
    assert e.value.args[0].status == 1 and e.value.args[0].kind == ErrorKind.BAD_REQUEST


def test_send_pdu(plc):
    assert plc.send_pdu(b"\x03\x00\x00\x00\x02") == bytes.fromhex("0304E97942F6")
    with pytest.raises(ResponseError) as e:
        plc.send_pdu(bytes.fromhex("160000FFFF0000"), unit=2)  # FC22 unsupported on unit 2
    assert e.value.args[0].status == 1


def test_exceptions_are_tag_errors(plc):
    hole, good = plc.read("hr505", "hr499")  # a hole of the device's map, merged with a good neighbour
    assert hole.value is None and hole.error_kind == ErrorKind.NOT_FOUND and hole.error.status == 2
    assert good == Tag("hr499", 0, "UINT", None)
    missing = plc.read("Nope")
    assert missing.error_kind == ErrorKind.NOT_FOUND
    assert plc.read("hr0.16").error_kind == ErrorKind.BAD_REQUEST


def test_read_async_and_subscribe(sim, plc):
    async def main():
        one = await plc.read_async("Drive_Status")
        many = await asyncio.gather(*(plc.read_async(f"hr{i}") for i in range(10)))
        written = await plc.write_async(("hr50", 9), ("hr51", 10))
        return one, many, written

    one, many, written = asyncio.run(main())
    assert one == Tag("Drive_Status", 5, "UINT", None)
    assert [t.error for t in many] == [None] * 10
    assert [t.value for t in written] == [9, 10]

    got = []
    with plc.subscribe("hr50", "Tank_Level", interval=0.05, callback=got.append) as sub:
        assert isinstance(sub, Subscription)
        assert wait_for(lambda: got)
        first = {t.tag: t.value for t in got[0]}
        assert first["hr50"] == 9 and first["Tank_Level"] == pytest.approx(52.3)
        sim.cmd("set_registers", unit=1, area="holding", address=50, values=[11])
        assert wait_for(lambda: any(t.tag == "hr50" and t.value == 11 for c in got for t in c))
    assert sub.closed

    async def iterate():
        with plc.subscribe("hr51", interval=0.05) as sub:
            async for tags in sub:
                return tags

    assert asyncio.run(iterate()) == [Tag("hr51", 10, "UINT", None)]


def test_connection_events_and_reconnect(sim):
    events = []
    plc = ModbusDriver(sim.path, MAP, keep_alive=None)
    plc.on_connection(events.append)
    assert plc.connection_state == "closed" and not plc.connected
    with pytest.raises(CommError):
        plc.read("hr0")  # not opened
    plc.open()
    assert plc.connected and plc.connection_state == "connected"
    assert wait_for(lambda: events)
    assert events[0] == ConnectionEvent("connected", None, None, None)
    sim.cmd("fault", fault={"close_connections": True})
    try:
        # the next read finds the link closed; the driver reconnects in the background
        assert wait_for(lambda: _ok(plc))
    finally:
        sim.cmd("clear_faults")
    assert "disconnected" in [e.event for e in events]
    plc.close()
    assert plc.connection_state == "closed"


def _ok(plc):
    try:
        return plc.read("hr1").error is None
    except CommError:
        return False


def test_bad_path_is_request_error():
    with pytest.raises(RequestError):
        ModbusDriver("10.0.0.5")  # a Logix path: no scheme
    with pytest.raises(RequestError):
        ModbusDriver("tcp://127.0.0.1", os.path.join(REPO, "no_such_map.csv"))
    with pytest.raises(RequestError):
        ModbusDriver("tcp://127.0.0.1", max_registers=200)
    with pytest.raises(ValueError):
        ModbusDriver("tcp://127.0.0.1", word_order="XYZW")


def test_keep_alive_auto(sim):
    ModbusDriver("rtu://COM99", keep_alive="auto")  # parsed only, never opened
    with pytest.raises(ValueError):
        ModbusDriver(sim.path, keep_alive=-1)
    plc = ModbusDriver(sim.path, keep_alive=0.1)
    plc.open()
    try:
        before = sim.cmd("requests")
        assert wait_for(lambda: sim.cmd("requests") >= before + 2)  # FC08 while idle
        assert plc.connected
    finally:
        plc.close()
    assert str(plc).startswith("ModbusDriver(")


def test_callback_threads_do_not_deadlock(plc):
    seen = threading.Event()

    def done(tags):
        plc.read("hr0")  # a callback may call the driver
        seen.set()

    with plc.subscribe("hr0", interval=0.05, callback=done):
        assert seen.wait(5)
