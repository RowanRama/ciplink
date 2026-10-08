"""Read-only investigation of Logix extended properties; not a supported driver API.

Run from the repository root with ``python -m examples.logix_extended_properties``.
Description's captured layout is parsed by pycomm3.logix_metadata. This
diagnostic preserves raw exchanges and does not authenticate connections.
"""

import argparse
import datetime
import json
import struct
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Sequence

from pycomm3 import LogixDriver
from pycomm3.logix_metadata import build_description_request, decode_description_response
from pycomm3.cip import ClassCode, DataTypes, Services, UINT
from pycomm3.packets import SendUnitDataRequestPacket
from pycomm3.packets.util import get_service_status, request_path, tag_request_path


PROPERTIES = ("Description", "EngineeringUnit", "Min", "Max", "State0", "State1")


def decode_cip_reply(data: bytes) -> Dict[str, Any]:
    """Parse a CIP reply header, preserving additional status words and payload.

    ``data`` begins at the reply service byte, without encapsulation/CPF headers
    or the connected sequence counter. The additional-status size is in WORDs.
    A permission error is not a property value, even if it includes payload bytes.
    """
    if len(data) < 4:
        raise ValueError("Truncated CIP reply header")
    reply_service, reserved, status, word_count = data[:4]
    if not reply_service & 0x80 or reserved:
        raise ValueError("Expected a CIP reply service and zero reserved byte")
    payload_start = 4 + 2 * word_count
    if len(data) < payload_start:
        raise ValueError("Truncated CIP additional status")
    return {
        "reply_service": reply_service,
        "service": reply_service & 0x7F,
        "general_status": status,
        "status_text": "Success" if status == 0 else get_service_status(status),
        "additional_status": list(struct.unpack(
            "<{}H".format(word_count), data[4:payload_start]
        )),
        "data_hex": data[payload_start:].hex(),
        "cip_hex": data.hex(),
    }


def extract_cip_reply(packet: bytes) -> bytes:
    """Extract one reply from a complete SendRRData or SendUnitData frame.

    Walk CPF items instead of assuming a fixed offset. This accepts one complete
    encapsulation frame, not an Ethernet packet or an unreassembled TCP segment.
    """
    if len(packet) < 24:
        raise ValueError("Truncated EtherNet/IP header")
    command, length, _, status = struct.unpack_from("<HHII", packet)
    if len(packet) != 24 + length:
        raise ValueError("EtherNet/IP frame length mismatch")
    if command not in (0x6F, 0x70) or status:
        raise ValueError("Expected a successful SendRRData or SendUnitData frame")
    if length < 8:
        raise ValueError("Truncated CPF header")
    count = struct.unpack_from("<H", packet, 30)[0]
    offset = 32
    replies = []
    for _ in range(count):
        if offset + 4 > len(packet):
            raise ValueError("Truncated CPF item header")
        item_type, item_length = struct.unpack_from("<HH", packet, offset)
        offset += 4
        end = offset + item_length
        if end > len(packet):
            raise ValueError("Truncated CPF item data")
        if item_type in (0xB1, 0xB2):
            connected = item_type == 0xB1
            if connected != (command == 0x70):
                raise ValueError("CPF data item does not match encapsulation command")
            if connected and item_length < 2:
                raise ValueError("Missing connected sequence counter")
            replies.append(packet[offset + (2 if connected else 0):end])
        offset = end
    if offset != len(packet) or len(replies) != 1:
        raise ValueError("Expected exactly one CPF reply and no trailing bytes")
    return replies[0]


def decode_atomic_read(reply: Dict[str, Any]) -> Dict[str, Any]:
    """Parse one successful standard Read Tag scalar using its returned CIP type.

    This does not parse the vendor-specific description object's payload, nor
    assume that a property has the same type as its parent tag.
    """
    if reply["service"] != 0x4C or reply["general_status"]:
        raise ValueError("Expected a successful standard Read Tag reply")
    data = bytes.fromhex(reply["data_hex"])
    if len(data) < 2:
        raise ValueError("Missing Read Tag type code")
    type_code = UINT.decode(data[:2])
    code = 0xC1 if type_code & 0xFF == 0xC1 else type_code
    if code not in tuple(range(0xC1, 0xCC)) + (0xD0,):
        raise ValueError("Unsupported scalar type 0x{:04x}; preserve raw data".format(type_code))
    data_type = DataTypes.get_type(code)
    stream = BytesIO(data[2:])
    value = data_type.decode(stream)
    if stream.tell() != len(data) - 2:
        raise ValueError("Trailing scalar data; response may contain multiple elements")
    return {"type": data_type.__name__, "type_code": type_code, "value": value}


def _read_request(plc: LogixDriver, label: str, service: bytes,
                  path: bytes, data: bytes = b"") -> Dict[str, Any]:
    request = SendUnitDataRequestPacket(plc._sequence)
    request.add(service, path, data)
    response = plc.send(request)
    result = {
        "label": label,
        "request_cip_hex": request.message[2:].hex(),
        "response_enip_hex": response.raw.hex() if response.raw else None,
        "driver_error": response.error,
    }
    if response.raw:
        try:
            result["reply"] = decode_cip_reply(extract_cip_reply(response.raw))
        except ValueError as error:
            result["framing_error"] = str(error)
    reply = result.get("reply")
    if reply and reply["service"] == 0x4C and reply["general_status"] == 0:
        try:
            result["decoded"] = decode_atomic_read(reply)
        except Exception as error:
            result["decoding_error"] = str(error)
    return result


def probe(path: str, tags: Sequence[str], properties: Sequence[str] = PROPERTIES,
          description_object: bool = False) -> Dict[str, Any]:
    """Collect raw read-only exchanges for explicit controller-scoped base tags.

    RegisterSession, Forward Open/Close, identity and tag discovery accompany the
    reads. No tag writes, mode changes, clock changes or authentication attempts
    are performed. The description-object request exactly reproduces the captured
    Description query, with the selected Symbol instance in its payload.
    """
    if not tags or any(not tag or any(c in tag for c in ".[]{}") for tag in tags):
        raise ValueError("Specify controller-scoped base tags without members or indices")
    if not properties or any(prop not in PROPERTIES for prop in properties):
        raise ValueError("Unknown extended property")
    report = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "path": path,
        "requests": [],
    }
    with LogixDriver(path, init_tags=False) as plc:
        report["controller"] = {
            key: plc.info[key] for key in ("product_name", "revision", "keyswitch")
        }
        if plc._micro800:
            raise ValueError("This investigation targets ControlLogix/CompactLogix")
        definitions = {tag["tag_name"]: tag for tag in plc.get_tag_list()}
        for name in tags:
            if name not in definitions:
                raise ValueError("Controller tag does not exist: {}".format(name))
        for name in tags:
            instance = definitions[name]["instance_id"]
            # Symbolic addressing deliberately bypasses the driver's metadata
            # lookup, which treats @Description as a nonexistent UDT member.
            for suffix in ("",) + tuple(".@" + prop for prop in properties):
                target = name + suffix
                report["requests"].append(_read_request(
                    plc, target, Services.read_tag,
                    tag_request_path(target, {}, False), UINT.encode(1),
                ))
            report["requests"].append(_read_request(
                plc, name + " / Symbol attribute 11", Services.get_attribute_list,
                request_path(ClassCode.symbol_object, instance),
                UINT.encode(1) + UINT.encode(11),
            ))
            if description_object:
                wire = build_description_request(instance)
                report["requests"].append(_read_request(
                    plc, name + " / captured description read", wire[:1],
                    wire[1:10], wire[10:],
                ))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    reader = commands.add_parser("probe", help="Collect read-only PLC exchanges")
    reader.add_argument("path", help="PLC IP address or CIP routing path")
    reader.add_argument("--tag", action="append", required=True, help="Controller base tag")
    reader.add_argument("--property", dest="properties", choices=PROPERTIES, action="append")
    reader.add_argument("--description-object", action="store_true",
                        help="Also issue the captured class 0x349/service 0x53 Description read")
    reader.add_argument("--output", type=Path, help="Save raw exchanges as JSON")
    decoder = commands.add_parser("decode", help="Decode captured reply bytes without a PLC")
    decoder.add_argument("hex", help="CIP reply bytes, starting at the reply service")
    decoder.add_argument("--enip", action="store_true", help="Input is a complete encapsulation frame")
    decoder.add_argument("--description", action="store_true",
                         help="Also decode the captured single-page Description layout")
    args = parser.parse_args()
    if args.command is None:
        parser.error("Choose probe or decode")
    if args.command == "probe":
        result = probe(args.path, args.tag, args.properties or PROPERTIES, args.description_object)
    else:
        data = bytes.fromhex(args.hex)
        result = decode_cip_reply(extract_cip_reply(data) if args.enip else data)
        if args.description:
            if result["service"] != 0x53 or result["general_status"]:
                parser.error("Description decoding requires a successful metadata read reply")
            result["description"] = decode_description_response([bytes.fromhex(result["data_hex"])])
    output = json.dumps(result, indent=2)
    if args.command == "probe" and args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
        print("Saved {} read-only exchanges to {}".format(len(result["requests"]), args.output))
    else:
        print(output)


if __name__ == "__main__":
    main()
