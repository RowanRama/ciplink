"""Experimental Logix metadata authentication using only the Python standard library.

Credentials can be supplied by the caller or parsed from the local sealed
bundle. No Rockwell binary, COM server or optional crypto package is used.
The observed protocol uses raw, little-endian 1024-bit RSA and SHA-1; it is not
TLS, CIP Security, or a general-purpose RSA implementation.
"""

import hashlib
import math
import secrets
import struct


__all__ = ["LogixMetadataCredentials"]


def validate_metadata_certificate(certificate):
    """Validate the two observed public credential layouts, not their signature.

    The controller validates the issuer signature during authentication.
    """
    if not isinstance(certificate, bytes) or len(certificate) not in (281, 285):
        raise ValueError("Expected an observed 281- or 285-byte public certificate")
    size, version, issuer, count = struct.unpack_from("<HHHH", certificate)
    if size + 128 != len(certificate) or version != 1 or issuer != 1 or count not in (1, 2):
        raise ValueError("Unsupported public certificate header")
    claims = [struct.unpack_from("<HH", certificate, 8 + 4 * i) for i in range(count)]
    if any(level != 1 for _, level in claims):
        raise ValueError("Unsupported certificate claim layout")
    key_start = 8 + 4 * count
    if certificate[key_start:key_start + 13] != bytes.fromhex("02008080030001000181808000"):
        raise ValueError("Unsupported certificate public-key layout")
    if key_start + 13 + 128 != size:
        raise ValueError("Certificate public-key length mismatch")
    return claims


class _DERReader:
    """Strict, bounded DER reader for a plain RSA private key only."""

    def __init__(self, data):
        self.data = data
        self.position = 0

    def item(self, tag):
        position = self.position
        if position + 2 > len(self.data) or self.data[position] != tag:
            raise ValueError("Invalid RSA private-key DER structure")
        length = self.data[position + 1]
        position += 2
        if length & 0x80:
            count = length & 0x7F
            if not 1 <= count <= 2 or position + count > len(self.data):
                raise ValueError("Invalid RSA private-key DER length")
            encoded = self.data[position:position + count]
            if encoded[0] == 0:
                raise ValueError("Noncanonical RSA private-key DER length")
            length = int.from_bytes(encoded, "big")
            if length < 128:
                raise ValueError("Noncanonical RSA private-key DER length")
            position += count
        end = position + length
        if end > len(self.data):
            raise ValueError("Truncated RSA private-key DER")
        self.position = end
        return self.data[position:end]

    def integer(self):
        encoded = self.item(2)
        if not encoded or encoded[0] & 0x80:
            raise ValueError("RSA key integers must be nonnegative")
        if len(encoded) > 1 and encoded[0] == 0 and not encoded[1] & 0x80:
            raise ValueError("Noncanonical RSA key integer")
        return int.from_bytes(encoded, "big")


def _private_numbers(data):
    if not isinstance(data, bytes) or not 1 <= len(data) <= 2048:
        raise ValueError("Supply an unencrypted PKCS #1 or PKCS #8 RSA private key in DER format")
    outer = _DERReader(data)
    inner = _DERReader(outer.item(0x30))
    if outer.position != len(data):
        raise ValueError("Unexpected data after RSA private key")
    version = inner.integer()
    if inner.position < len(inner.data) and inner.data[inner.position] == 0x30:
        # PKCS #8 PrivateKeyInfo wraps the PKCS #1 key in an OCTET STRING.
        if version != 0 or inner.item(0x30) != bytes.fromhex("06092a864886f70d0101010500"):
            raise ValueError("Unsupported PKCS #8 RSA algorithm or version")
        wrapped = inner.item(4)
        if inner.position != len(inner.data):
            raise ValueError("Unexpected PKCS #8 private-key fields")
        wrapper = _DERReader(wrapped)
        inner = _DERReader(wrapper.item(0x30))
        if wrapper.position != len(wrapped):
            raise ValueError("Unexpected data after PKCS #8 RSA key")
        version = inner.integer()
    numbers = [version] + [inner.integer() for _ in range(8)]
    if inner.position != len(inner.data) or numbers[0] != 0:
        raise ValueError("Only a two-prime PKCS #1 RSA private key is supported")
    _, n, e, d, p, q, dp, dq, coefficient = numbers
    if n.bit_length() != 1024 or e != 65537 or not 1 < d < n or p <= 2 or q <= 2 or p == q:
        raise ValueError("Unsupported RSA private-key parameters")
    if p * q != n:
        raise ValueError("Inconsistent RSA private-key modulus")
    order = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    if (e * d) % order != 1 or dp != d % (p - 1) or dq != d % (q - 1) or coefficient * q % p != 1:
        raise ValueError("Inconsistent RSA private-key components")
    return n, e, d


def _inverse(value, modulus):
    # pow(value, -1, modulus) requires Python 3.8; support ciplink's older Pythons.
    previous, current = 0, 1
    remainder, next_remainder = modulus, value
    while next_remainder:
        quotient = remainder // next_remainder
        previous, current = current, previous - quotient * current
        remainder, next_remainder = next_remainder, remainder - quotient * next_remainder
    if remainder != 1:
        raise ValueError("RSA blinding factor is not invertible")
    return previous % modulus


class LogixMetadataCredentials:
    """Caller-provided credential and matching PKCS #1 or PKCS #8 DER key.

    Keep unwrapped keys out of logs. The credential alone cannot complete the
    handshake. The optional sealed bundle uses reversible obfuscation.
    RSA blinding is used because Python integer
    operations are not constant-time.
    """

    __slots__ = ("_certificate", "_n", "_e", "_d")

    def __init__(self, certificate, private_key_der):
        claims = validate_metadata_certificate(certificate)
        if (11, 1) not in claims:
            raise ValueError("Certificate lacks the observed metadata access claim")
        n, e, d = _private_numbers(private_key_der)
        key_start = 8 + 4 * len(claims)
        public_modulus = int.from_bytes(certificate[key_start + 13:key_start + 141], "big")
        if n != public_modulus:
            raise ValueError("Private key does not match the signed certificate")
        self._certificate, self._n, self._e, self._d = certificate, n, e, d

    def __repr__(self):
        return "LogixMetadataCredentials(<redacted>)"

    @classmethod
    def bundled(cls):
        """Load the generated Python credential bundle without external files."""
        try:
            from ._logix_metadata_bundle import load
        except ModuleNotFoundError as error:
            if error.name != __package__ + "._logix_metadata_bundle":
                raise
            raise ValueError("Metadata credential bundle is missing; supply credentials or generate the bundle") from None
        certificate, private_key = load()
        return cls(certificate, private_key)

    @property
    def certificate(self):
        return self._certificate

    def answer_challenge(self, data):
        """Return the 20-byte proof for a successful service 0x4B reply payload."""
        if not isinstance(data, bytes) or len(data) != 130 or data[:2] != b"\x80\x00":
            raise ValueError("Expected a length-prefixed 128-byte metadata challenge")
        ciphertext = int.from_bytes(data[2:], "little")
        if ciphertext >= self._n:
            raise ValueError("Metadata challenge is outside the RSA modulus")
        for _ in range(128):
            factor = secrets.randbelow(self._n - 3) + 2
            if math.gcd(factor, self._n) == 1:
                break
        else:
            raise ValueError("Could not generate an RSA blinding factor")
        blinded = ciphertext * pow(factor, self._e, self._n) % self._n
        plain = pow(blinded, self._d, self._n) * _inverse(factor, self._n) % self._n
        if pow(plain, self._e, self._n) != ciphertext:
            raise ValueError("RSA challenge calculation failed verification")
        return hashlib.sha1(plain.to_bytes(128, "little")[:20]).digest()

    def validate_completion(self, data):
        """Require the metadata claim in the controller's granted-claims reply."""
        if not isinstance(data, bytes) or len(data) < 2:
            raise ValueError("Missing metadata authentication grants")
        count = struct.unpack_from("<H", data)[0]
        if not 1 <= count <= 64 or len(data) != 2 + count * 6:
            raise ValueError("Malformed metadata authentication grants")
        grants = [struct.unpack_from("<HI", data, 2 + index * 6) for index in range(count)]
        if len({claim for claim, level in grants}) != count:
            raise ValueError("Duplicate metadata authentication grant")
        if (11, 1) not in grants:
            raise ValueError("Controller did not grant metadata access")
