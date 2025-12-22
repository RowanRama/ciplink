import pytest
from pycomm3.cip.pccc import PCCC_STRING, PCCC_ASCII

def test_pccc_string_odd_length_padding():
    """
    Verifies that odd-length strings are padded with a null byte in the payload
    but the length header remains the original (unpadded) length.
    Fixes Issue #314.
    """
    # Case 1: Odd length string "123" (3 bytes)
    # Expected: Length=3 (0x0300), Data="12" (0x3231) + "3\x00" (0x0033)
    # Note: SLC swaps bytes, so "12" -> 0x3231, "3\0" -> 0x0033

    target_value = "123"
    encoded = PCCC_STRING.encode(target_value)

    # Header: UINT length of 3 (unpadded) -> b'\x03\x00'
    assert encoded[0:2] == b'\x03\x00'

    # Payload: "123" + pad "\x00" -> "123\x00"
    # Swapped: "12" (0x32 0x31) -> 0x31 0x32 -> b'\x31\x32'
    # "3\0" (0x33 0x00) -> 0x00 0x33 -> b'\x00\x33'
    # Result: b'\x32\x31\x00\x33'

    expected_payload = b'\x32\x31\x00\x33'
    assert encoded[2:6] == expected_payload


def test_pccc_string_decode_truncation():
    """
    Verifies that decoding respects the length header and strips garbage data.
    Fixes Issue #230.
    """
    # Simulate a packet from PLC: Length=3, Payload="ABC" followed by garbage/nulls
    # "ABC" -> b'ABC' padded to b'ABC\x00'
    # Swapped: 'AB' -> 'BA' (0x4241), 'C\x00' -> '\x00C' (0x0043)
    # Payload: b'\x42\x41\x00\x43'
    # Garbage: 78 more bytes of 0xFF

    # Construct the raw stream (Length 3 + 4 bytes valid + garbage)
    stream_data = b'\x03\x00' + b'\x42\x41\x00\x43' + (b'\xFF' * 78)

    decoded = PCCC_STRING.decode(stream_data)

    # Should return exactly "ABC", ignoring the padding null and the garbage
    assert decoded == "ABC"


def test_pccc_ascii_padding():
    """
    Verifies that ASCII strings (file type A) are space-padded to 2 bytes.
    """
    # Case 1: Single char "A"
    # Pad to "A " -> b'A '
    # Swap: b' A'
    assert PCCC_ASCII.encode("A") == b' A'

    # Case 2: Empty string ""
    # Pad to "  " -> b'  '
    # Swap: b'  '
    assert PCCC_ASCII.encode("") == b'  '
