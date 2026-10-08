"""Isolated, version-pinned Linx session provider. No private key export."""
import ctypes as C
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

def main():
    if C.sizeof(C.c_void_p) != 4:
        raise RuntimeError('Run this worker with 32-bit Python')
    root = Path(r'C:\Program Files (x86)\Rockwell Software\RSLinx Enterprise')
    common = Path(r'C:\Program Files (x86)\Common Files\Rockwell')
    handles = [os.add_dll_directory(str(path)) for path in (root, common)]
    path = root / 'cip.dll'
    if hashlib.sha256(path.read_bytes()).hexdigest() != 'dcc05896076158174222f18aaf807440e23922c6efc24ce6946c5478f8286356':
        raise RuntimeError('Unsupported CIP binary; internal ABI has not been verified')
    library = C.CDLL(str(path))
    ole = C.OleDLL('ole32')
    ole.CoInitializeEx(None, 0)
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_uint32]
    kernel.VirtualAlloc.restype = C.c_void_p
    kernel.VirtualProtect.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32, C.POINTER(C.c_uint32)]
    kernel.VirtualProtect.restype = C.c_int
    kernel.VirtualFree.argtypes = [C.c_void_p, C.c_size_t, C.c_uint32]
    kernel.VirtualFree.restype = C.c_int
    bridges = []
    def thiscall(rva, count):
        # cdecl(this, args...) -> verified MSVC x86 thiscall method. The DLL
        # receives ECX=this and removes its explicit arguments from the stack.
        code = bytearray(b'\x55\x8b\xec\x8b\x4d\x08')
        for index in reversed(range(count)):
            code += b'\xff\x75' + bytes([12 + index * 4])
        code += b'\xb8' + struct.pack('<I', library._handle + rva) + b'\xff\xd0\xc9\xc3'
        address = kernel.VirtualAlloc(None, len(code), 0x3000, 4)
        if not address:
            raise C.WinError(C.get_last_error())
        C.memmove(address, bytes(code), len(code))
        previous = C.c_uint32()
        if not kernel.VirtualProtect(address, len(code), 0x20, C.byref(previous)):
            raise C.WinError(C.get_last_error())
        bridges.append(address)
        return C.CFUNCTYPE(C.c_int, *([C.c_void_p] * (count + 1)))(address)

    construct = thiscall(0x1e1a20, 0)
    initialize = thiscall(0x1e2b70, 4)
    first_request = thiscall(0x1e1da0, 2)
    process_challenge = thiscall(0x1e20c0, 2)
    completion_request = thiscall(0x1e26e0, 2)
    destroy = thiscall(0x1e1bb0, 0)
    state = C.create_string_buffer(0x34)
    construct(state)
    try:
        message = json.loads(sys.stdin.readline())
        certificate = bytes.fromhex(message['certificate_hex'])
        if len(certificate) not in (281, 285) or struct.unpack_from('<H', certificate)[0] + 128 != len(certificate):
            raise ValueError('Expected an observed signed certificate')
        certificate_buffer = C.create_string_buffer(certificate, len(certificate))
        # Pointer to the installed provider's opaque blob, passed directly to its
        # session object. Python does not parse, save or expose this material.
        result = initialize(state, library._handle + 0x234c48, 0x4f8,
                            certificate_buffer, len(certificate))
        if result != 0:
            raise RuntimeError('Native session initialization failed: {}'.format(result))
        request, request_size = C.create_string_buffer(1024), C.c_uint32(1024)
        if first_request(state, request, C.byref(request_size)) != 0:
            raise RuntimeError('Native first request generation failed')
        print(json.dumps({'first_request_hex': request.raw[:request_size.value].hex()}), flush=True)
        message = json.loads(sys.stdin.readline())
        reply = bytes.fromhex(message['reply_hex'])
        if len(reply) != 134 or reply[:6] != bytes.fromhex('cb0000008000'):
            raise ValueError('Expected a successful fresh challenge reply')
        reply_buffer = C.create_string_buffer(reply, len(reply))
        result = process_challenge(state, reply_buffer, len(reply))
        if result != 0:
            raise RuntimeError('Native challenge processing failed: {}'.format(result))
        request_size.value = 1024
        if completion_request(state, request, C.byref(request_size)) != 0:
            raise RuntimeError('Native completion request generation failed')
        completion = request.raw[:request_size.value]
        if len(completion) != 28 or completion[:8] != bytes.fromhex('4c02206424011400'):
            raise RuntimeError('Unexpected completion request layout')
        print(json.dumps({'completion_request_hex': completion.hex()}), flush=True)
    finally:
        destroy(state)
        for address in bridges:
            kernel.VirtualFree(address, 0, 0x8000)
        ole.CoUninitialize()

if __name__ == "__main__":
    main()

