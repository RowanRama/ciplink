"""Gateway helper interoperability against a local OPC UA server, not a PLC."""

import asyncio

import pytest

from examples.linx_gateway_properties import browse, discover, property_node_ids, read_properties


def test_ua_reader_preserves_quality_and_finds_browsed_nodes():
    # The core pycomm3 package does not require this optional example dependency.
    asyncua = pytest.importorskip("asyncua")
    ua = asyncua.ua

    async def scenario():
        server = asyncua.Server()
        await server.init()
        server.set_endpoint("opc.tcp://127.0.0.1:0")
        server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
        index = await server.register_namespace("urn:test:gateway-properties")
        nodes = property_node_ids("plc", "Example", index, ("Description", "EngineeringUnit", "Max"))
        await server.nodes.objects.add_variable(ua.NodeId.from_string(nodes["Description"]),
                                                "Description", "HERE I AM WORLD")
        await server.nodes.objects.add_variable(ua.NodeId.from_string(nodes["EngineeringUnit"]),
                                                "EngineeringUnit", "")
        # Max is deliberately absent; BadNodeIdUnknown must not become a string
        # or a zero/empty property value. Configured empty strings remain valid.
        async with server:
            port = server.bserver._server.sockets[0].getsockname()[1]
            endpoint = "opc.tcp://127.0.0.1:{}".format(port)
            endpoints = await discover(endpoint)
            assert endpoints["endpoints"][0]["mode"] == "None_"
            children = await browse(endpoint)
            ids = {child["node_id"] for child in children["children"]}
            assert nodes["Description"] in ids
            result = await read_properties(endpoint, nodes)
            description = result["properties"]["Description"]
            assert description["good"] is True
            assert description["value"] == "HERE I AM WORLD"
            assert description["type"] == "String"
            assert result["properties"]["EngineeringUnit"]["value"] == ""
            assert result["properties"]["EngineeringUnit"]["good"] is True
            assert result["properties"]["Max"]["status"] == "BadNodeIdUnknown"
            assert result["properties"]["Max"]["good"] is False
            assert result["properties"]["Max"]["value"] is None
            assert result["namespace_array"][index] == "urn:test:gateway-properties"

    asyncio.run(scenario())


def test_gateway_reference_includes_scope_relative_area_and_program():
    nodes = property_node_ids("plc", "Program:Main.Example[2].Member", 3,
                              ("Description",), "Area/SubArea")
    assert nodes["Description"] == (
        "ns=3;s=Area/SubArea::[plc]Program:Main.Example[2].Member.@Description"
    )


def test_gateway_rejects_existing_property_suffix():
    with pytest.raises(ValueError, match="without an extended-property suffix"):
        property_node_ids("plc", "Example.@Description", 2, ("Description",))
