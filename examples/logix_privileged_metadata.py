"""Read a base tag Description with a fresh, Linx-assisted ciplink handshake.

Windows and the verified Linx 6.60 binary are required. The controller connection
belongs to ciplink; an isolated native helper computes its fresh challenge reply.
No FactoryTalk UI, existing authenticated connection, or captured completion is
used. The signed public credential must be supplied separately.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import queue
import subprocess
import threading
from pathlib import Path

from ciplink import LogixDriver
from ciplink.logix_auth import validate_metadata_certificate as validate_certificate
from .logix_metadata_transports import _exchange


FIRST_PREFIX = bytes.fromhex("4b0220642401")
COMPLETION_PREFIX = bytes.fromhex("4c02206424011400")


def validate_challenge(reply):
    if len(reply) != 134 or reply[:6] != bytes.fromhex("cb0000008000"):
        raise ValueError("Expected a successful length-prefixed 128-byte challenge")


class LinxSessionProvider:
    """Compute two setup requests using version-pinned installed Linx code.

    The helper owns native crypto objects and private material. This process
    exchanges only a public credential, a controller challenge and CIP requests.
    """

    def __init__(self, python32, certificate, timeout=15):
        validate_certificate(certificate)
        self.python32 = str(python32)
        self.certificate = certificate
        self.timeout = timeout
        self.process = None
        self.messages = queue.Queue()

    def __enter__(self):
        helper = Path(__file__).with_name("linx_session_provider.py")
        self.process = subprocess.Popen(
            [self.python32, str(helper)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        def receive():
            for line in self.process.stdout:
                self.messages.put(line)
            self.messages.put(None)
        threading.Thread(target=receive, daemon=True).start()
        return self

    def request(self, message, field):
        if self.process is None:
            raise RuntimeError("Native provider is not running")
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        try:
            line = self.messages.get(timeout=self.timeout)
        except queue.Empty as error:
            raise RuntimeError("Native session provider timed out") from error
        if line is None:
            self.process.wait(timeout=self.timeout)
            detail = self.process.stderr.read(4096).strip()
            raise RuntimeError("Native session provider failed: " + detail)
        result = json.loads(line)
        return bytes.fromhex(result[field])

    def first_request(self):
        wire = self.request({"certificate_hex": self.certificate.hex()}, "first_request_hex")
        if wire != FIRST_PREFIX + self.certificate:
            raise ValueError("Native provider returned a different certificate request")
        return wire

    def complete(self, reply):
        validate_challenge(reply)
        wire = self.request({"reply_hex": reply.hex()}, "completion_request_hex")
        if len(wire) != 28 or not wire.startswith(COMPLETION_PREFIX):
            raise ValueError("Native provider returned an unsupported completion")
        self.process.wait(timeout=self.timeout)
        if self.process.returncode:
            raise RuntimeError("Native provider did not close successfully")
        return wire

    def __exit__(self, *_):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.kill()
        self.process.communicate(timeout=self.timeout)
        self.process = None


def authenticate_connection(plc, provider):
    """Authenticate this driver's current CID; stop if either setup stage fails."""
    first = provider.first_request()
    if not plc._target_is_connected and not plc._forward_open():
        raise RuntimeError("Forward Open failed")
    started = _exchange(plc, "Certificate challenge", first, True)
    reply = started.get("reply", {})
    if reply.get("general_status") != 0 or reply.get("service") != 0x4B:
        raise RuntimeError("Certificate challenge rejected: {}".format(reply or started))
    completion = provider.complete(bytes.fromhex(reply["cip_hex"]))
    finished = _exchange(plc, "Generated challenge completion", completion, True)
    reply = finished.get("reply", {})
    if reply.get("general_status") != 0 or reply.get("service") != 0x4C:
        raise RuntimeError("Challenge completion rejected: {}".format(reply or finished))
    return [started, finished]


def read_description(ip, tag, python32, certificate):
    ipaddress.IPv4Address(ip)
    if not tag or any(char in tag for char in ".[]{}"):
        raise ValueError("Specify a controller-scoped base tag")
    validate_certificate(certificate)
    report = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ip": ip, "tag": tag, "certificate_sha256": hashlib.sha256(certificate).hexdigest(),
        "provider": "Installed Linx 6.60, version-pinned x86 native session ABI",
    }
    with LogixDriver(ip) as plc:
        report["symbol_instance"] = plc.get_tag_info(tag)["instance_id"]
        before = plc.get_tag_description(tag)
        report["before_authentication"] = before._asdict()
        with LinxSessionProvider(python32, certificate) as provider:
            report["setup"] = authenticate_connection(plc, provider)
        report["transport"] = {
            "connection_size": plc._cfg["connection_size"],
            "large_forward_open": plc._cfg["extended forward open"],
        }
        description = plc.get_tag_description(tag)
        report["description"] = description._asdict()
        if not description:
            raise RuntimeError("Authenticated Description read failed: " + str(description.error))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ip", help="Direct controller IPv4 address")
    parser.add_argument("--tag", required=True, help="Controller base tag name")
    parser.add_argument("--python32", required=True, type=Path, help="Installed 32-bit Python executable")
    parser.add_argument("--certificate", required=True, type=Path, help="Local signed public certificate bytes")
    parser.add_argument("--output", type=Path, help="Optional local report including setup traffic")
    args = parser.parse_args()
    certificate = args.certificate.read_bytes()
    output = None
    try:
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            output = args.output.open("x", encoding="utf-8")
        report = read_description(args.ip, args.tag, args.python32.resolve(), certificate)
        if output:
            output.write(json.dumps(report, indent=2) + "\n")
        print(report["description"]["tag"] + " = " + repr(report["description"]["value"]))
        if args.output:
            print("Saved", args.output)
    finally:
        if output:
            output.close()


if __name__ == "__main__":
    main()
