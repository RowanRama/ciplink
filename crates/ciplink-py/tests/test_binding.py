"""
What the binding adds over the core: GIL release, exceptions, value conversions, results, the raw passthrough
send, generic message decoding, tag sharing, logging, against the simulator.
"""

import logging
import os
import sys
import threading
import time

import pytest

from conftest import REPO

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import Sim  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import (  # noqa: E402
    CIPDriver, CommError, DINT, ErrorKind, LogixDriver, RequestError, ResponseError, SLCDriver, Tag, TagError, UINT,
)
from ciplink.cip import ClassCode, Services  # noqa: E402
from ciplink.custom_types import ModuleIdentityObject  # noqa: E402
from ciplink.packets import GenericConnectedRequestPacket, GenericUnconnectedRequestPacket  # noqa: E402


@pytest.fixture(scope="module")
def sim():
    with Sim("example_controller.json") as sim:
        yield sim


@pytest.fixture
def plc(sim):
    with LogixDriver(sim.address) as plc:
        yield plc


def test_a_network_call_releases_the_gil(sim, plc):
    sim.cmd("fault", fault={"delay_ms": 400})
    counts = []
    stop = threading.Event()

    def spin():
        n = 0
        while not stop.is_set():
            n += 1
        counts.append(n)

    thread = threading.Thread(target=spin)
    thread.start()
    try:
        start = time.perf_counter()
        assert plc.read("dint1").value == 2147483647
        assert time.perf_counter() - start >= 0.35
    finally:
        stop.set()
        thread.join()
        sim.cmd("clear_faults")
    assert counts[0] > 100_000  # the other thread ran while the read waited for its reply


def test_threads_share_one_driver(plc):
    results, errors = [], []

    def work():
        try:
            for _ in range(20):
                results.append(plc.read("dint_ary[3]", "udt1.real"))
        except Exception as err:  # pragma: no cover - reported below
            errors.append(err)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert {(a.value, b.value) for a, b in results} == {(300, 1000.5)}


def test_results_are_tags_with_tag_errors(plc):
    ok, missing = plc.read("dint1", "no_such_tag")
    assert type(ok) is Tag and ok == Tag("dint1", 2147483647, "DINT", None) and ok
    assert type(missing.error) is TagError and missing.error_kind is ErrorKind.NOT_FOUND
    assert not missing and missing.value is None
    assert plc.read() == [] and plc.write() == []


def test_a_write_returns_the_callers_value_object(plc):
    value = {"bool": True, "sint": 1, "int": 2, "dint": 3, "lint": 4, "real": 0.1}
    result = plc.write("udt1", value)
    assert result.value is value and result.type == "AtomicUDT" and result.error is None
    assert plc.read("udt1").value == {**value, "real": pytest.approx(0.1)}
    big = plc.write(("ulint1", 2 ** 64 - 1), ("lint1", -2 ** 63), ("bool2", 1), ("str1", "hé"))
    assert [r.error for r in big] == [None] * 4
    assert [r.value for r in plc.read("ulint1", "lint1", "bool2", "str1")] == [2 ** 64 - 1, -2 ** 63, True, "hé"]


def test_bad_write_values_are_per_tag_errors(plc):
    too_big, wrong_type = plc.write(("sint1", 1000), ("dint1", "text"))
    assert too_big.error_kind is ErrorKind.BAD_VALUE and too_big.value is None  # refused before sending
    assert wrong_type.error is not None
    with pytest.raises(TypeError):
        plc.write("dint1", object())


def test_exceptions_are_the_packages_classes(sim):
    with pytest.raises(RequestError):
        LogixDriver("127.0.0.1:99999")
    with pytest.raises(ValueError):
        LogixDriver(sim.address, connection_size=0)
    with pytest.raises(ValueError):
        LogixDriver(sim.address, socket_timeout=-1)
    with pytest.raises(CommError):
        LogixDriver("127.0.0.1:1", socket_timeout=0.5).open()
    with LogixDriver(sim.address) as plc:
        with pytest.raises(ResponseError):
            plc.get_module_info(9)
        with pytest.raises(RequestError) as err:
            plc.get_tag_info("nope")
        assert isinstance(err.value.args[0], TagError) and err.value.args[0].kind is ErrorKind.NOT_FOUND
        with pytest.raises(RequestError):
            plc.connection_size = 1000  # connected


def test_generic_message_decodes_with_its_data_type(plc):
    tag = plc.generic_message(service=Services.get_attributes_all, class_code=ClassCode.identity_object,
                              instance=1, connected=False, data_type=ModuleIdentityObject, name="who")
    assert tag.tag == "who" and tag.type is ModuleIdentityObject and tag.value["product_name"] == "1756-SIM/A"
    raw = plc.generic_message(service=0x0E, class_code=0x01, instance=1, attribute=1, data_type=UINT)
    assert raw.value == 1 and raw.error is None  # the vendor attribute, connected
    packet = plc.generic_message(service=0x0E, class_code=0x01, instance=1, attribute=1,
                                 return_response_packet=True)
    assert packet.value.data == b"\x01\x00"
    bad = plc.generic_message(service=0x0E, class_code=0x01, instance=1, attribute=99)
    assert not bad and bad.error


def test_send_passes_caller_packets_through(plc):
    connected = GenericConnectedRequestPacket(plc._sequence, service=b"\x0e", class_code=b"\x01", instance=1,
                                              attribute=1, data_type=UINT)
    response = plc.send(connected)
    assert response and response.value == 1
    unconnected = GenericUnconnectedRequestPacket(service=b"\x01", class_code=b"\x01", instance=b"\x01",
                                                  data_type=ModuleIdentityObject)
    response = plc.send(unconnected)
    assert response and response.value["serial"] == "c0ffee01"


def test_tags_have_type_classes_and_can_be_shared(sim, plc):
    udt1 = plc.tags["udt1"]
    assert udt1["data_type"] is plc.data_types["AtomicUDT"]
    value = plc.read("udt1").value
    assert udt1["type_class"].decode(bytes(udt1["type_class"].encode(value))) == value
    assert plc.tags["dint_ary"]["type_class"].element_type is DINT
    with LogixDriver(sim.address, init_tags=False) as plc2:
        assert plc2.tags == {}
        plc2._tags = plc.tags
        assert set(plc2.tags) == set(plc.tags)
        assert plc2.read("udt1.real").value == plc.read("udt1.real").value


def test_core_logs_to_the_reference_logger_names(sim, caplog):
    with caplog.at_level(logging.INFO, logger="ciplink"):
        with LogixDriver(sim.address, init_tags=False) as plc:
            plc.generic_message(service=0x0E, class_code=0x01, instance=1, attribute=1, name="vendor")
    names = {r.name for r in caplog.records}
    assert "ciplink.cip_driver.CIPDriver" in names and "ciplink.logix_driver.LogixDriver" in names
    assert any("Generic message 'vendor' completed" in r.getMessage() or '"vendor" completed' in r.getMessage()
               for r in caplog.records)


def test_cip_driver_and_identity(sim):
    with CIPDriver(sim.address) as cip:
        assert cip.connected
        tag = cip.generic_message(service=0x01, class_code=0x01, instance=1, connected=False,
                                  data_type=ModuleIdentityObject)
        assert tag.value["product_name"] == "1756-SIM/A"
    assert not cip.connected
    assert CIPDriver.list_identity(sim.address)["product_name"] == "1756-SIM/A"
    with pytest.raises(CommError):  # as the reference: the connection is refused
        LogixDriver.list_identity("127.0.0.1:1")


def test_slc_driver():
    with Sim("example_slc.json") as sim:
        with SLCDriver(sim.address) as plc:
            assert plc.read("N7:0").value == 10
            assert plc.read("N7:0", "F8:0")[1].value == 1.5
            value = [1, 2, 3]
            result = plc.write(("N7:20{3}", value))
            assert result.error is None and result.value is value
            assert plc.read("N7:20{3}").value == value
            assert plc.connection_size == 500
