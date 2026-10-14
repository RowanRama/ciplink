"""Standalone authentication with synthetic keys; no PLC, DLLs or crypto packages."""

import json
import struct
from pathlib import Path
from unittest.mock import Mock

import pytest

from ciplink import LogixDriver, LogixMetadataCredentials
from ciplink.logix_auth import _DERReader
from .test_logix_extended_properties import enip


FIXTURE = json.loads(Path(__file__).with_name("logix_auth_synthetic_key.json").read_text())
KEY = bytes.fromhex(FIXTURE["pkcs1_der_hex"])
MODULUS = int(FIXTURE["modulus_hex"], 16)
VECTOR = FIXTURE["vectors"][0]
CHALLENGE = b"\x80\x00" + bytes.fromhex(VECTOR["ciphertext_le_hex"])
PROOF = bytes.fromhex(VECTOR["expected_sha1_hex"])
GRANTS = struct.pack("<HHIHI", 2, 3, 1, 11, 1)


def certificate(claims=((3, 1), (11, 1)), modulus=MODULUS):
    size = 8 + 4 * len(claims) + 13 + 128
    return (struct.pack("<HHHH", size, 1, 1, len(claims))
            + b"".join(struct.pack("<HH", *claim) for claim in claims)
            + bytes.fromhex("02008080030001000181808000")
            + modulus.to_bytes(128, "big") + bytes(128))


@pytest.fixture
def credentials():
    return LogixMetadataCredentials(certificate(), KEY)


@pytest.mark.parametrize("format_name", ["pkcs1_der_hex", "pkcs8_der_hex"])
def test_independent_rsa_vectors_and_fresh_challenges(format_name):
    # Vectors were sealed by an independent RSA implementation using PKCS #1
    # v1.5. In little-endian raw RSA, the first 20 bytes are the reversed message
    # suffix. Expected SHA-1 values therefore do not use this implementation.
    credentials = LogixMetadataCredentials(certificate(), bytes.fromhex(FIXTURE[format_name]))
    results = [credentials.answer_challenge(b"\x80\x00" + bytes.fromhex(vector["ciphertext_le_hex"]))
               for vector in FIXTURE["vectors"]]
    assert results == [bytes.fromhex(vector["expected_sha1_hex"]) for vector in FIXTURE["vectors"]]
    assert results[0] != results[1]
    assert credentials.answer_challenge(CHALLENGE) == results[0]  # Blinding preserves the result.


def test_credentials_do_not_expose_key_in_repr(credentials):
    assert repr(credentials) == "LogixMetadataCredentials(<redacted>)"
    assert credentials.certificate == certificate()


def test_requires_matching_key_and_metadata_claim():
    with pytest.raises(ValueError, match="does not match"):
        LogixMetadataCredentials(certificate(modulus=MODULUS ^ 1), KEY)
    with pytest.raises(ValueError, match="metadata access claim"):
        LogixMetadataCredentials(certificate(((3, 1),)), KEY)


@pytest.mark.parametrize("data", [b"", b"\x80\x00" + bytes(127), b"\x80\x00" + bytes(129),
                                  b"\x7f\x00" + bytes(128), b"\x80\x00" + MODULUS.to_bytes(128, "little")])
def test_rejects_malformed_or_out_of_range_challenges(credentials, data):
    with pytest.raises(ValueError):
        credentials.answer_challenge(data)


@pytest.mark.parametrize("data", [b"", KEY[:10], KEY[:-1], KEY + b"extra", b"\x30\x80\x00\x00",
                                  b"\x30\x82\x00\x01\x00", b"\x30\x81\x01\x00", bytes(2049)])
def test_rejects_invalid_private_key_der(data):
    with pytest.raises(ValueError):
        LogixMetadataCredentials(certificate(), data)


def der(tag, payload):
    size = len(payload)
    length = bytes([size]) if size < 128 else b"\x82" + size.to_bytes(2, "big")
    return bytes([tag]) + length + payload


@pytest.mark.parametrize("index", [0, 1, 2, 3, 4, 5, 6, 7, 8])
def test_rejects_inconsistent_private_key_components(index):
    reader = _DERReader(_DERReader(KEY).item(0x30))
    values = [reader.item(2) for _ in range(9)]
    values[index] = b"\x01" if index == 0 else b"\x00"
    malformed = der(0x30, b"".join(der(2, value) for value in values))
    with pytest.raises(ValueError):
        LogixMetadataCredentials(certificate(), malformed)


@pytest.mark.parametrize("data", [b"\x02\x01\x80", b"\x02\x02\x00\x01", b"\x02\x00"])
def test_rejects_negative_empty_and_noncanonical_integers(data):
    with pytest.raises(ValueError):
        _DERReader(data).integer()


@pytest.mark.parametrize("data", [b"", b"\x00\x00", GRANTS[:-1], GRANTS + b"extra",
                                  struct.pack("<HHI", 1, 3, 1), struct.pack("<HHI", 1, 11, 0),
                                  struct.pack("<HHIHI", 2, 11, 1, 11, 1)])
def test_requires_an_explicit_metadata_grant(credentials, data):
    credentials.validate_completion(GRANTS)
    with pytest.raises(ValueError):
        credentials.validate_completion(data)


@pytest.fixture
def plc():
    driver = LogixDriver("192.168.1.100", init_tags=False)
    driver._target_is_connected = True
    return driver


def replies(plc, first_status=0, second_status=0, first_header=None, grants=GRANTS):
    requests = []
    def send(request):
        wire = request.build_message()[2:]
        requests.append(wire)
        if len(requests) == 1:
            assert wire == bytes.fromhex("4b0220642401") + certificate()
            reply = first_header or bytes([0xCB, 0, first_status, 0])
            reply += CHALLENGE if first_status == 0 else b""
        else:
            assert wire == bytes.fromhex("4c02206424011400") + PROOF
            reply = bytes([0xCC, 0, second_status, 0]) + (grants if second_status == 0 else b"")
        return request.response_class(request, enip(reply))
    plc.send = Mock(side_effect=send)
    return requests


def test_driver_authenticates_the_same_connection(plc, credentials):
    requests = replies(plc)
    result = plc.authenticate_metadata(credentials)
    assert result and result.value is True and result.type == "BOOL"
    assert len(requests) == 2


@pytest.mark.parametrize("first,second,count", [(9, 0, 1), (0, 9, 2)])
def test_driver_stops_on_rejected_handshake(plc, credentials, first, second, count):
    requests = replies(plc, first, second)
    result = plc.authenticate_metadata(credentials)
    assert not result and "rejected" in result.error
    assert len(requests) == count


def test_driver_rejects_the_wrong_service_reply(plc, credentials):
    requests = replies(plc, first_header=bytes.fromhex("cc000000"))
    result = plc.authenticate_metadata(credentials)
    assert not result and "reply header" in result.error and len(requests) == 1


def test_driver_does_not_treat_authentication_as_metadata_permission(plc, credentials):
    replies(plc, grants=struct.pack("<HHI", 1, 3, 1))
    result = plc.authenticate_metadata(credentials)
    assert not result and "did not grant metadata access" in result.error


def test_driver_does_not_send_completion_on_a_changed_connection(plc, credentials, monkeypatch):
    requests = replies(plc)
    original = LogixMetadataCredentials.answer_challenge
    def answer(self, data):
        proof = original(self, data)
        plc._target_cid = b"\x01\x02\x03\x04"
        return proof
    monkeypatch.setattr(LogixMetadataCredentials, "answer_challenge", answer)
    result = plc.authenticate_metadata(credentials)
    assert not result and "connection changed" in result.error and len(requests) == 1


def test_invalid_credentials_send_no_network_requests(plc):
    plc.send = Mock(side_effect=AssertionError("Unexpected network request"))
    assert not plc.authenticate_metadata(object())
    plc.send.assert_not_called()


def test_forward_open_failure_sends_no_handshake(plc, credentials):
    plc._target_is_connected = False
    plc._forward_open = Mock(return_value=False)
    plc.send = Mock(side_effect=AssertionError("Unexpected setup request"))
    assert not plc.authenticate_metadata(credentials)
    plc.send.assert_not_called()
