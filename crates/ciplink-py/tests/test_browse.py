"""
Device browsing (ports, backplane slots and EtherNet/IP subnets, like RSWho) through the Python API, against the
simulator.
"""

import json
import os
import sys

import pytest

from conftest import REPO

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import HERE, Sim  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import CIPDriver, LogixDriver, ResponseError  # noqa: E402


@pytest.fixture(scope="module")
def sim():
    # the example controller in slot 0 of a 10-slot chassis, modules in slots 1 and 2, two drives on its network
    with open(os.path.join(HERE, "example_controller.json")) as f:
        config = json.load(f)
    config.update(ip="10.1.2.3", netmask="255.255.255.0", network=[
        {"ip": "10.1.2.40", "identity": {"product_name": "2198-H008-ERS2"}},
        {"ip": "10.1.2.200", "identity": {"product_name": "2198-H015-ERS2"}},
    ])
    with Sim(config) as sim:
        yield sim


def test_ports_and_backplane_of_the_device(sim):
    with CIPDriver(sim.address) as drv:
        assert drv.get_identity()["product_name"] == "1756-SIM/A"
        bp, enet = drv.get_ports()
        assert bp == {"number": 1, "type": 1, "type_name": "Backplane", "name": "Backplane", "address": "0",
                      "ip": None, "netmask": None, "nodes": [str(n) for n in range(10)]}
        assert (enet["type_name"], enet["address"], enet["ip"], enet["netmask"]) == \
            ("EtherNet/IP", "10.1.2.3", "10.1.2.3", "255.255.255.0")

        nodes = drv.browse_port("", bp)
        assert [n["route"] for n in nodes] == [f"1/{slot}" for slot in range(10)]
        names = [n["identity"] and n["identity"]["product_name"] for n in nodes]
        assert names[:4] == ["1756-SIM/A", "1756-EN2T/D", "1756-IB16/A", None]
        assert nodes[3]["error"]
        assert drv.browse_port("", 1, nodes=[1, 2], workers=1) == nodes[1:3]  # by port number, in order

        assert drv.get_identity("bp/2")["product_name"] == "1756-IB16/A"
        assert drv.get_ports("bp/2") == []  # no Port Object
        with pytest.raises(ResponseError):
            drv.get_identity("bp/5")


def test_the_ethernet_port_scans_its_subnet(sim):
    with CIPDriver(sim.address) as drv:
        enet = drv.get_ports()[1]
        assert (len(enet["nodes"]), enet["nodes"][0], enet["nodes"][-1]) == (254, "10.1.2.1", "10.1.2.254")
        found = [n for n in drv.iter_port("", enet) if n["identity"]]
        assert sorted((n["route"], n["identity"]["product_name"]) for n in found) == [
            ("2/10.1.2.200", "2198-H015-ERS2"), ("2/10.1.2.40", "2198-H008-ERS2")]
        nodes = drv.browse_port("", 2)  # by port number: its subnet
        assert [n["address"] for n in nodes] == enet["nodes"]
        assert "timeout" in nodes[0]["error"]


def test_logix_driver_browses_too(sim):
    with LogixDriver(sim.address, lazy_tags=True) as plc:
        assert plc.get_identity()["product_name"] == "1756-SIM/A"
        assert plc.get_identity("1/1")["product_name"] == "1756-EN2T/D"
        assert [p["number"] for p in plc.get_ports()] == [1, 2]


def test_iter_port_streams_and_stops_when_closed(sim):
    with CIPDriver(sim.address) as drv:
        nodes = drv.iter_port("", 2, workers=4)
        first = next(n for n in nodes if n["identity"])
        nodes.close()
        assert first["identity"]["product_name"] == "2198-H008-ERS2"
        assert drv.get_identity()["product_name"] == "1756-SIM/A"  # the driver's own connection is free

        def fail(node):
            raise KeyError("stop")

        with pytest.raises(KeyError):
            drv._core.scan_port("", 1, None, 2, fail)
