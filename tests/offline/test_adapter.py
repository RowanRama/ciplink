"""The adapter's Python binding on 127.0.0.1, free ports. Class 1 I/O is tested in Rust (crates/ciplink-sim/tests)."""
import threading
import time

import pytest

from ciplink import CIPDriver
from ciplink.adapter import Adapter
from ciplink.exceptions import RequestError


@pytest.fixture
def adapter():
    with Adapter(inputs={100: 8}, outputs={150: 4}, configs={199: 0}, bind="127.0.0.1", port=0, io_port=0,
                 identity=dict(product_name="Station", product_code=7, serial=0x1234),
                 app_name="Station", app_version="1.0") as a:
        yield a


def test_assemblies(adapter):
    adapter.set_input(100, b"\x01\x02")
    assert adapter.input(100) == b"\x01\x02" + bytes(6)  # shorter data leaves the rest zero
    assert adapter.output(150) == (bytes(4), False)  # nothing from a scanner yet
    assert adapter.config(199) == b""
    with pytest.raises(RequestError):
        adapter.set_input(101, b"")
    with pytest.raises(RequestError):
        adapter.output(100)  # an input, not an output
    assert adapter.connections() == []
    assert adapter.stats()["produced"] == 0


def test_identity_over_explicit_messages(adapter):
    host, port = adapter.address
    assert host == "127.0.0.1" and port and adapter.io_address[1]
    assert CIPDriver.list_identity(f"{host}:{port}")["product_name"] == "Station"
    with CIPDriver(f"{host}:{port}") as driver:
        identity = driver.get_identity()
    assert (identity["product_name"], identity["product_code"], identity["serial"]) == ("Station", 7, "00001234")


def test_bad_config_is_refused():
    with pytest.raises(RequestError):
        Adapter(inputs={100: 8}, outputs={100: 4}, port=0, io_port=0)  # one instance twice
    with pytest.raises(ValueError):
        Adapter(bind="not an address", port=0, io_port=0)


def test_stop_wakes_a_waiting_thread(adapter):
    assert adapter.next_event(0.05) is None
    got = []
    t = threading.Thread(target=lambda: got.append(adapter.next_event()))
    t.start()
    time.sleep(0.2)
    t0 = time.monotonic()
    adapter.stop()
    t.join(2)
    assert not t.is_alive() and time.monotonic() - t0 < 1 and got == [None]
    with pytest.raises(RuntimeError):
        adapter.input(100)
    adapter.stop()  # twice is fine


def test_browsers_read_the_app_line(adapter):
    adapter.set_detail("station 2")
    host, port = adapter.address
    with CIPDriver(f"{host}:{port}") as driver:
        app = driver.get_app()
        nodes = driver.browse_port("", 2, nodes=[host], workers=1)
    assert (app["name"], app["version"], app["detail"]) == ("Station", "1.0", "station 2")
    assert app["summary"] == "Station · station 2 · no connection"
    assert [(a["instance"], a["kind"], a["size"]) for a in app["assemblies"]] == [
        (100, "input", 8), (150, "output", 4), (199, "config", 0)]
    assert nodes[0]["app"] == app


def test_the_package_exports_the_adapter():
    import ciplink
    assert ciplink.Adapter is Adapter
