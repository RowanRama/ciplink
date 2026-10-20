"""Gateway helper interoperability against a local OPC UA server, not a PLC."""


import pytest

from examples.linx_gateway_properties import property_node_ids


def test_gateway_reference_includes_scope_relative_area_and_program():
    nodes = property_node_ids("plc", "Program:Main.Example[2].Member", 3,
                              ("Description",), "Area/SubArea")
    assert nodes["Description"] == (
        "ns=3;s=Area/SubArea::[plc]Program:Main.Example[2].Member.@Description"
    )


def test_gateway_rejects_existing_property_suffix():
    with pytest.raises(ValueError, match="without an extended-property suffix"):
        property_node_ids("plc", "Example.@Description", 2, ("Description",))
