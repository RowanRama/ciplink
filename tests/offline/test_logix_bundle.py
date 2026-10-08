"""RFC 8439 vectors and synthetic credential bundles; no real credentials."""

import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from examples.bundle_logix_metadata import render_bundle
from pycomm3 import LogixDriver, LogixMetadataCredentials
from pycomm3._logix_bundle_codec import (
    _block, _decrypt, _encrypt, _poly1305, open_credentials, seal_credentials,
)
from .test_logix_auth import KEY, CHALLENGE, PROOF, certificate, replies


def test_chacha20_block_rfc8439_section_2_3_2():
    # https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert _block(bytes(range(32)), bytes.fromhex("000000090000004a00000000"), 1) == expected


def test_poly1305_rfc8439_section_2_5_2():
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    assert _poly1305(b"Cryptographic Forum Research Group", key).hex() == "a8061dc1305136c6c22b8baf0c0127a9"


def test_aead_rfc8439_section_2_8_2():
    # Independent normative vector, including a partial final block and AAD.
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                 b"sunscreen would be it.")
    expected = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
    )
    assert _encrypt(key, nonce, plaintext, aad) == expected
    assert _decrypt(key, nonce, expected, aad) == plaintext


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 63, 64, 65])
def test_encryption_boundaries(size):
    key, nonce = bytes(range(32)), bytes(range(12))
    plaintext = bytes(range(size))
    assert _decrypt(key, nonce, _encrypt(key, nonce, plaintext, b""), b"") == plaintext


def test_bundle_roundtrip_and_randomized_nonce():
    key = bytes(range(32))
    first, second = [seal_credentials(certificate(), KEY, key) for _ in range(2)]
    assert first != second
    assert KEY not in first and certificate() not in first
    cert, private = open_credentials(first, key)
    assert cert == certificate() and private == KEY
    assert LogixMetadataCredentials(cert, private).answer_challenge(CHALLENGE) == PROOF


@pytest.mark.parametrize("position", [0, 4, 16, -1])
def test_bundle_tampering_is_rejected_before_use(position):
    key = bytes(range(32))
    data = bytearray(seal_credentials(certificate(), KEY, key))
    data[position] ^= 1
    with pytest.raises(ValueError):
        open_credentials(bytes(data), key)


def test_wrong_decryption_key_is_rejected():
    data = seal_credentials(certificate(), KEY, bytes(range(32)))
    with pytest.raises(ValueError, match="authentication failed"):
        open_credentials(data, bytes(reversed(range(32))))


def test_generated_module_hides_plaintext_and_reconstructs_credentials():
    source = render_bundle(certificate(), KEY)
    assert KEY.hex() not in source and certificate().hex() not in source
    namespace = {"__name__": "pycomm3._synthetic_bundle", "__package__": "pycomm3"}
    exec(compile(source, "<synthetic-bundle>", "exec"), namespace)
    cert, private = namespace["load"]()
    assert cert == certificate() and private == KEY
    assert source != render_bundle(certificate(), KEY)


def test_default_driver_uses_bundled_credentials(monkeypatch):
    module = SimpleNamespace(load=lambda: (certificate(), KEY))
    monkeypatch.setitem(sys.modules, "pycomm3._logix_metadata_bundle", module)
    plc = LogixDriver("192.168.1.100", init_tags=False)
    plc._target_is_connected = True
    requests = replies(plc)
    assert plc.authenticate_metadata().value is True
    assert len(requests) == 2


def test_missing_bundle_sends_no_authentication_requests(monkeypatch):
    monkeypatch.setitem(sys.modules, "pycomm3._logix_metadata_bundle", None)
    plc = LogixDriver("192.168.1.100", init_tags=False)
    plc.send = Mock(side_effect=AssertionError("Unexpected network request"))
    result = plc.authenticate_metadata()
    assert not result and "bundle is missing" in result.error
    plc.send.assert_not_called()
