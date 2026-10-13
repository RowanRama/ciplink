"""Read a tag Description."""

import argparse
import datetime
import json
import struct
import sys
from pathlib import Path

from pycomm3 import LogixDriver, LogixMetadataCredentials


def read_description(ip, tag, certificate=None, private_key=None):
    if certificate is None and private_key is None:
        credentials = LogixMetadataCredentials.bundled()
    elif certificate is None or private_key is None:
        raise ValueError("Supply both certificate and private key, or neither")
    else:
        credentials = LogixMetadataCredentials(certificate, private_key)
    with LogixDriver(ip) as plc:
        before = plc.get_tag_description(tag)
        authenticated = plc.authenticate_metadata(credentials)
        if not authenticated:
            raise RuntimeError(authenticated.error)
        description = plc.get_tag_description(tag)
        if not description:
            raise RuntimeError(description.error)
        return {
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "ip": ip, "tag": tag, "provider": "Python standard library",
            "python_bits": struct.calcsize("P") * 8,
            "before_authentication": before._asdict(),
            "authentication": authenticated._asdict(),
            "description": description._asdict(),
            "connection_size": plc._cfg["connection_size"],
            "large_forward_open": plc._cfg["extended forward open"],
            "optional_modules_loaded": sorted(set(sys.modules) & {
                "ctypes", "comtypes", "cryptography", "subprocess",
                "examples.linx_session_provider", "examples.logix_privileged_metadata",
            }),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ip", help="Controller address or pycomm3 routing path")
    parser.add_argument("--tag", required=True, help="Tag, member, or array element")
    parser.add_argument("--certificate", type=Path, help="Optional external signed public certificate")
    parser.add_argument("--private-key", type=Path, help="Optional matching external RSA DER private key")
    parser.add_argument("--output", type=Path, help="Optional report, excluding credentials and setup bytes")
    args = parser.parse_args()
    if (args.certificate is None) != (args.private_key is None):
        parser.error("--certificate and --private-key must be supplied together")
    report = read_description(args.ip, args.tag,
                              args.certificate.read_bytes() if args.certificate else None,
                              args.private_key.read_bytes() if args.private_key else None)
    if args.output:
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    print(report["description"]["tag"] + " = " + repr(report["description"]["value"]))
    if args.output:
        print("Saved", args.output)


if __name__ == "__main__":
    main()
