"""Compare read-only metadata requests on four fresh CIP sessions.

This investigation targets a directly reachable controller IP. It compares
transport settings only; it does not authenticate a privileged connection.
Run with ``python -m examples.logix_metadata_transports IP --symbol-instance ID``.
"""

import argparse
import datetime
import ipaddress
import json
import os
import struct
from pathlib import Path
from typing import Any, Dict

from pycomm3 import CIPDriver
from pycomm3.cip import ClassCode, ConnectionManagerServices, PADDED_EPATH
from pycomm3.const import MSG_ROUTER_PATH
from pycomm3.logix_metadata import build_description_request
from pycomm3.packets import SendRRDataRequestPacket, SendUnitDataRequestPacket

from .logix_extended_properties import decode_cip_reply, extract_cip_reply


PROFILES = ("unconnected", "normal_504", "large_4000", "factorytalk_transport")
IDENTITY_READ = bytes.fromhex("010220012401")
METADATA_DIRECTORY_READ = bytes.fromhex("4b042100490325000000")
# Exact initial request for definition 1 from the successful FactoryTalk capture.
DEFINITION_READ = bytes.fromhex(
    "53042100490325000000010100000000000001002800490301000000000000000000"
)


def _open_transport(plc: CIPDriver, profile: str) -> None:
    if profile == "unconnected":
        return
    plc._cfg["csn"] = os.urandom(2)
    plc._cfg["connection_size"] = 4000 if profile == "large_4000" else 504
    plc._cfg["extended forward open"] = profile == "large_4000"
    if profile != "factorytalk_transport":
        if not plc._forward_open():
            raise RuntimeError("Forward Open failed")
        return

    # Match the captured transport, with fresh connection identities. The VID
    # and transport settings alone do not confer FactoryTalk session privileges.
    plc._cfg["vid"] = struct.pack("<H", 77)
    data = (
        bytes([6, 155]) + bytes(4) + plc._cfg["cid"] + plc._cfg["csn"]
        + plc._cfg["vid"] + plc._cfg["vsn"] + bytes([2, 0, 0, 0])
        + struct.pack("<IH", 2000000, 0x43F8) * 2 + bytes([0xA3])
    )
    route = PADDED_EPATH.encode(plc._cfg["cip_path"] + MSG_ROUTER_PATH, length=True)
    opened = plc.generic_message(
        service=ConnectionManagerServices.forward_open,
        class_code=ClassCode.connection_manager, instance=1,
        request_data=data, route_path=route, connected=False,
    )
    if not opened:
        raise RuntimeError(opened.error)
    if len(opened.value) < 4:
        raise RuntimeError("Missing Forward Open connection identifier")
    plc._target_cid = opened.value[:4]
    plc._target_is_connected = True


def _exchange(plc: CIPDriver, label: str, wire: bytes,
              connected: bool) -> Dict[str, Any]:
    request = (SendUnitDataRequestPacket(plc._sequence) if connected
               else SendRRDataRequestPacket())
    request.add(wire)
    response = plc.send(request)
    result = {"label": label, "request_cip_hex": wire.hex(),
              "driver_error": response.error,
              "response_enip_hex": response.raw.hex() if response.raw else None}
    if response.raw:
        try:
            result["reply"] = decode_cip_reply(extract_cip_reply(response.raw))
        except ValueError as error:
            result["framing_error"] = str(error)
    # A denied read is preserved as a status, never passed to a payload codec.
    return result


def compare_transports(ip: str, symbol_instance: int) -> Dict[str, Any]:
    """Repeat identical reads using independent, unauthenticated CIP sessions.

    The unconnected request addresses the controller at ``ip`` directly. Routed
    paths are rejected rather than accidentally testing a different endpoint.
    Symbol IDs come from tag discovery and may change after a project download.
    """
    ipaddress.IPv4Address(ip)
    description = build_description_request(symbol_instance)
    reads = (("Identity", IDENTITY_READ),
             ("Metadata definition directory", METADATA_DIRECTORY_READ),
             ("Metadata definition 1", DEFINITION_READ),
             ("Symbol Description", description))
    report = {"timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "ip": ip, "symbol_instance": symbol_instance, "profiles": []}
    for profile in PROFILES:
        record = {"profile": profile, "reads": []}
        report["profiles"].append(record)
        try:
            with CIPDriver(ip) as plc:
                _open_transport(plc, profile)
                for label, wire in reads:
                    record["reads"].append(_exchange(plc, label, wire, profile != "unconnected"))
        except Exception as error:
            record["transport_error"] = str(error)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ip", help="Direct controller IPv4 address; routing paths are unsupported")
    parser.add_argument("--symbol-instance", required=True, type=int,
                        help="Current controller tag's Symbol instance ID from tag discovery")
    parser.add_argument("--output", type=Path, help="Save full request/reply bytes as JSON")
    args = parser.parse_args()
    result = compare_transports(args.ip, args.symbol_instance)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for profile in result["profiles"]:
        statuses = ["{}={}".format(read["label"], read.get("reply", {}).get("general_status"))
                    for read in profile["reads"]]
        print("{}: {}".format(profile["profile"], profile.get("transport_error") or ", ".join(statuses)))
    if args.output:
        print("Saved exchanges to {}".format(args.output))


if __name__ == "__main__":
    main()
