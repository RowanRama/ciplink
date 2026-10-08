"""Handshake sequencing and framing; synthetic data, no installed Linx or PLC."""
from types import SimpleNamespace
import struct

import pytest

from examples.logix_privileged_metadata import (
    FIRST_PREFIX, COMPLETION_PREFIX, authenticate_connection,
    validate_certificate, validate_challenge,
)


def certificate(claims=((3, 1), (11, 1))):
    size = 8 + 4 * len(claims) + 13 + 128
    return (struct.pack("<HHHH", size, 1, 1, len(claims))
            + b"".join(struct.pack("<HH", *claim) for claim in claims)
            + bytes.fromhex("02008080030001000181808000") + bytes(128 + 128))


def test_certificate_framing():
    assert validate_certificate(certificate()) == [(3, 1), (11, 1)]
    assert validate_certificate(certificate(((3, 1),))) == [(3, 1)]


@pytest.mark.parametrize("change", ["truncated", "length", "algorithm", "version", "claim"])
def test_rejects_unsupported_certificate(change):
    data = bytearray(certificate())
    if change == "truncated":
        data.pop()
    elif change == "length":
        data[0] -= 1
    elif change == "algorithm":
        data[16] = 3
    elif change == "version":
        data[2] = 2
    else:
        data[10] = 0
    with pytest.raises(ValueError):
        validate_certificate(bytes(data))


@pytest.mark.parametrize("reply", [
    bytes.fromhex("cb000900"), bytes.fromhex("cc0000008000") + bytes(128),
    bytes.fromhex("cb0000007f00") + bytes(128),
    bytes.fromhex("cb0000008000") + bytes(127),
])
def test_invalid_challenges_do_not_reach_native_provider(reply):
    with pytest.raises(ValueError):
        validate_challenge(reply)


class Provider:
    def __init__(self):
        self.challenges = []

    def first_request(self):
        return FIRST_PREFIX + certificate()

    def complete(self, reply):
        validate_challenge(reply)
        self.challenges.append(reply)
        # Distinct synthetic completions demonstrate which fresh challenge was
        # passed to the provider; these bytes are not a valid cryptographic proof.
        return COMPLETION_PREFIX + reply[6:26]


def test_fresh_challenge_drives_completion_on_same_driver(monkeypatch):
    provider = Provider()
    driver = SimpleNamespace(_target_is_connected=True)
    sent = []
    challenges = [bytes.fromhex("cb0000008000") + bytes([n]) * 128 for n in (1, 2)]

    def exchange(plc, label, wire, connected):
        assert plc is driver and connected
        sent.append(wire)
        return {"reply": {"general_status": 0, "service": wire[0],
                          "cip_hex": challenges[len(sent) // 2].hex() if wire[0] == 0x4B else "cc000000"}}

    monkeypatch.setattr("examples.logix_privileged_metadata._exchange", exchange)
    for _ in challenges:
        authenticate_connection(driver, provider)
    assert provider.challenges == challenges
    assert sent[1] != sent[3]
    assert sent[1:] == [COMPLETION_PREFIX + bytes([1]) * 20,
                        FIRST_PREFIX + certificate(), COMPLETION_PREFIX + bytes([2]) * 20]


def test_rejected_certificate_stops_before_completion(monkeypatch):
    provider = Provider()
    sent = []
    def exchange(plc, label, wire, connected):
        sent.append(wire)
        return {"reply": {"service": 0x4B, "general_status": 9}}
    monkeypatch.setattr("examples.logix_privileged_metadata._exchange", exchange)
    with pytest.raises(RuntimeError, match="Certificate challenge rejected"):
        authenticate_connection(SimpleNamespace(_target_is_connected=True), provider)
    assert len(sent) == 1 and not provider.challenges


def test_rejected_completion_is_not_reported_as_authenticated(monkeypatch):
    def exchange(plc, label, wire, connected):
        return {"reply": {"service": wire[0], "general_status": 0 if wire[0] == 0x4B else 9,
                          "cip_hex": (bytes.fromhex("cb0000008000") + bytes(128)).hex()}}
    monkeypatch.setattr("examples.logix_privileged_metadata._exchange", exchange)
    with pytest.raises(RuntimeError, match="Challenge completion rejected"):
        authenticate_connection(SimpleNamespace(_target_is_connected=True), Provider())


def test_failed_forward_open_sends_no_setup(monkeypatch):
    def unexpected(*args):
        raise AssertionError("No CIP request should be sent")
    monkeypatch.setattr("examples.logix_privileged_metadata._exchange", unexpected)
    driver = SimpleNamespace(_target_is_connected=False, _forward_open=lambda: False)
    with pytest.raises(RuntimeError, match="Forward Open failed"):
        authenticate_connection(driver, Provider())
