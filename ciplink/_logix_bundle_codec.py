"""Local credential bundling with RFC 8439 ChaCha20-Poly1305.

Only the Python standard library is used. Embedding the reconstruction material in
the same package provides obfuscation, not secrecy from someone with the code.
This implementation is scoped to small, locally generated credential bundles.
"""

import hmac
import secrets
import struct


_HEADER = b"LMK1"
_MASK = 0xFFFFFFFF


def _rotate(value, count):
    return ((value << count) | (value >> (32 - count))) & _MASK


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & _MASK
    state[d] = _rotate(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotate(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK
    state[d] = _rotate(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK
    state[b] = _rotate(state[b] ^ state[c], 7)


def _block(key, nonce, counter):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Bundle key must contain 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != 12 or not 0 <= counter <= _MASK:
        raise ValueError("Invalid bundle nonce or counter")
    initial = list(struct.unpack("<4I", b"expand 32-byte k"))
    initial += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    state = initial[:]
    for _ in range(10):
        for indices in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            _quarter(state, *indices)
    return struct.pack("<16I", *[(value + original) & _MASK for value, original in zip(state, initial)])


def _crypt(key, nonce, data):
    output = bytearray()
    for counter, offset in enumerate(range(0, len(data), 64), 1):
        stream = _block(key, nonce, counter)
        output.extend(value ^ stream[index] for index, value in enumerate(data[offset:offset + 64]))
    return bytes(output)


def _poly1305(data, key):
    if len(key) != 32:
        raise ValueError("Invalid bundle authenticator key")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    accumulator = 0
    for offset in range(0, len(data), 16):
        value = int.from_bytes(data[offset:offset + 16] + b"\x01", "little")
        accumulator = (accumulator + value) * r % ((1 << 130) - 5)
    return ((accumulator + s) % (1 << 128)).to_bytes(16, "little")


def _tag(key, nonce, ciphertext, associated):
    mac_data = associated + bytes((-len(associated)) % 16)
    mac_data += ciphertext + bytes((-len(ciphertext)) % 16)
    mac_data += struct.pack("<QQ", len(associated), len(ciphertext))
    return _poly1305(mac_data, _block(key, nonce, 0)[:32])


def _encrypt(key, nonce, plaintext, associated):
    ciphertext = _crypt(key, nonce, plaintext)
    return ciphertext + _tag(key, nonce, ciphertext, associated)


def _decrypt(key, nonce, encrypted, associated):
    if len(encrypted) < 16:
        raise ValueError("Truncated credential bundle")
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    if not hmac.compare_digest(tag, _tag(key, nonce, ciphertext, associated)):
        raise ValueError("Credential bundle authentication failed")
    return _crypt(key, nonce, ciphertext)


def seal_credentials(certificate, private_key, key):
    if len(certificate) not in (281, 285) or not 1 <= len(private_key) <= 2048:
        raise ValueError("Unsupported credential bundle lengths")
    # Every generated module uses a newly generated key and random nonce.
    nonce = secrets.token_bytes(12)
    payload = struct.pack("<HH", len(certificate), len(private_key)) + certificate + private_key
    return _HEADER + nonce + _encrypt(key, nonce, payload, _HEADER)


def open_credentials(bundle, key):
    if not isinstance(bundle, bytes) or not 36 <= len(bundle) <= 4096 or bundle[:4] != _HEADER:
        raise ValueError("Unsupported encrypted credential bundle")
    payload = _decrypt(key, bundle[4:16], bundle[16:], _HEADER)
    if len(payload) < 4:
        raise ValueError("Truncated credential bundle payload")
    certificate_size, key_size = struct.unpack_from("<HH", payload)
    if certificate_size not in (281, 285) or not 1 <= key_size <= 2048:
        raise ValueError("Unsupported credential bundle payload lengths")
    if len(payload) != 4 + certificate_size + key_size:
        raise ValueError("Credential bundle payload length mismatch")
    return payload[4:4 + certificate_size], payload[4 + certificate_size:]
