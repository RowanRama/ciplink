"""Read Logix extended properties through FactoryTalk Linx Gateway OPC UA.

Requires Gateway 6.50+ with Professional activation and ``pip install asyncua``.
This uses OPC UA for metadata; it does not authenticate a pycomm3 CIP session.
The Gateway endpoint, FactoryTalk application scope and Linx shortcut must
already be configured. No PLC or Gateway settings are changed by this example.
"""

import argparse
import asyncio
import getpass
import json
from pathlib import Path
from typing import Any, Dict, Sequence
from urllib.parse import urlsplit


PROPERTIES = ("Description", "EngineeringUnit", "EngineeringLogging", "Min", "Max", "State0", "State1")


def property_node_ids(shortcut: str, tag: str, namespace_index: int,
                      properties: Sequence[str], area: str = "") -> Dict[str, str]:
    """Build scalar-namespace NodeIds using Rockwell's documented tag reference.

    The namespace index must be taken from the configured Gateway. The area is
    relative to its selected FactoryTalk Directory scope and may be empty.
    Program tags, members and elements use their normal Logix tag references.
    """
    if not shortcut or any(c in shortcut for c in "[]{}"):
        raise ValueError("Provide a Linx shortcut name without brackets")
    if not tag or ".@" in tag or any(c in tag for c in "{}\r\n"):
        raise ValueError("Provide a tag reference without an extended-property suffix")
    if not isinstance(namespace_index, int) or not 1 <= namespace_index <= 0xFFFF:
        raise ValueError("Provide the Gateway's namespace index, between 1 and 65535")
    if not properties or any(prop not in PROPERTIES for prop in properties):
        raise ValueError("Unknown extended property")
    if "::" in area or any(c in area for c in "[]{}\r\n"):
        raise ValueError("Provide a scope-relative area path without the :: separator")
    prefix = "ns={};s={}::[{}]{}.@".format(namespace_index, area, shortcut, tag)
    return {prop: prefix + prop for prop in properties}


async def _client(endpoint: str, security: str = None, username: str = None,
                  password: str = None):
    from asyncua import Client

    url = urlsplit(endpoint)
    if url.scheme != "opc.tcp" or not url.hostname:
        raise ValueError("Provide a configured opc.tcp:// endpoint")
    if url.username is not None or url.password is not None:
        raise ValueError("Endpoint URLs must not contain credentials; use --username")
    client = Client(endpoint, timeout=10)
    client.name = "pycomm3 extended-property investigation"
    if security:
        await client.set_security_string(security)
    if username:
        client.set_user(username)
        client.set_password(password)
    return client


async def discover(endpoint: str) -> Dict[str, Any]:
    """Read advertised endpoints without creating a data session."""
    client = await _client(endpoint)
    endpoints = await client.connect_and_get_server_endpoints()
    return {"endpoints": [{
        "url": ep.EndpointUrl, "policy": ep.SecurityPolicyUri,
        "mode": ep.SecurityMode.name,
        "user_tokens": [token.TokenType.name for token in ep.UserIdentityTokens],
    } for ep in endpoints]}


async def browse(endpoint: str, node_id: str = "i=85", security: str = None,
                 username: str = None, password: str = None) -> Dict[str, Any]:
    """Browse one level under a node, without reading every controller tag."""
    client = await _client(endpoint, security, username, password)
    async with client:
        references = await client.get_node(node_id).get_children_descriptions()
        return {"parent": node_id, "children": [{
            "node_id": ref.NodeId.to_string(), "name": ref.DisplayName.Text,
            "browse_name": ref.BrowseName.to_string(), "class": ref.NodeClass.name,
        } for ref in references]}


async def read_properties(endpoint: str, node_ids: Dict[str, str],
                          security: str = None, username: str = None,
                          password: str = None) -> Dict[str, Any]:
    """Read explicit property values, preserving bad or uncertain UA quality."""
    client = await _client(endpoint, security, username, password)
    async with client:
        namespace_array = await client.get_namespace_array()
        values = await client.read_attributes([client.get_node(node) for node in node_ids.values()])
        if len(values) != len(node_ids):
            raise ValueError("OPC UA server returned an incomplete read response")
        results = {}
        for (prop, node_id), value in zip(node_ids.items(), values):
            good = value.StatusCode.is_good()
            results[prop] = {
                "node_id": node_id, "status": value.StatusCode.name,
                "status_code": value.StatusCode.value, "good": good,
                "value": value.Value.Value if good and value.Value is not None else None,
                "type": value.Value.VariantType.name if value.Value is not None else None,
                "source_timestamp": value.SourceTimestamp.isoformat() if value.SourceTimestamp else None,
            }
        return {"endpoint": endpoint, "namespace_array": namespace_array, "properties": results}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("discover", "browse", "read"))
    parser.add_argument("endpoint", help="Configured opc.tcp:// Gateway endpoint URL")
    parser.add_argument("--node", default="i=85", help="Parent NodeId for one-level browsing")
    parser.add_argument("--shortcut", help="Linx shortcut name for property reads")
    parser.add_argument("--tag", help="Logix tag reference, without .@Property")
    parser.add_argument("--namespace-index", type=int, help="Configured Gateway namespace index")
    parser.add_argument("--area", default="", help="Area relative to the selected Gateway scope")
    parser.add_argument("--property", dest="properties", action="append", choices=PROPERTIES)
    parser.add_argument("--security", help="asyncua policy,mode,client-cert,client-key,server-cert string")
    parser.add_argument("--username", help="FactoryTalk user; password is prompted and never saved")
    parser.add_argument("--output", type=Path, help="Save the read report as JSON")
    args = parser.parse_args()
    if args.command == "read":
        if not args.shortcut or not args.tag or args.namespace_index is None:
            parser.error("read requires --shortcut, --tag and --namespace-index")
        nodes = property_node_ids(args.shortcut, args.tag, args.namespace_index,
                                  args.properties or ("Description",), args.area)
    password = getpass.getpass("FactoryTalk password: ") if args.username else None
    if args.command == "discover":
        result = asyncio.run(discover(args.endpoint))
    elif args.command == "browse":
        result = asyncio.run(browse(args.endpoint, args.node, args.security, args.username, password))
    else:
        result = asyncio.run(read_properties(args.endpoint, nodes, args.security, args.username, password))
    output = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
