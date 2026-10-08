"""Replay the two observed client setup requests on fresh Logix sessions.

This diagnostic requires a local PCAP and explicit request frame numbers. It
compares isolated requests with the pair in order, then reads metadata. It does
not generate the session-dependent completion or authenticate autonomously.
No captured authorization bytes are embedded in the example.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import struct
import subprocess
from pathlib import Path

from pycomm3 import CIPDriver
from pycomm3.logix_metadata import build_description_request, decode_description_response

from .logix_extended_properties import extract_cip_reply
from .logix_metadata_transports import (
    DEFINITION_READ, IDENTITY_READ, METADATA_DIRECTORY_READ, _exchange, _open_transport,
)


def capture_requests(capture: Path, frames, tshark: str):
    """Select complete ENIP request frames and reject unobserved setup layouts."""
    if len(frames) != 2 or frames[0] < 1 or frames[1] <= frames[0]:
        raise ValueError('Choose two distinct request frames in capture order')
    command = [tshark, '-r', str(capture), '-Y',
               'frame.number == {} || frame.number == {}'.format(*frames),
               '-T', 'fields', '-e', 'frame.number', '-e', 'tcp.payload', '-e', 'tcp.stream']
    packets = subprocess.run(command, capture_output=True, text=True, check=True)
    selected = {}
    for line in packets.stdout.splitlines():
        number, payload, stream = line.split('\t')
        enip = bytes.fromhex(payload.replace(':', ''))
        selected[int(number)] = (enip, extract_cip_reply(enip), stream)
    if set(selected) != set(frames):
        raise ValueError('Both selected frames must contain complete TCP ENIP messages')
    first, second = (selected[number] for number in frames)
    # Requests must originate on the same connected CIP session, not be replies
    # or fragments taken from separate FactoryTalk connections.
    if first[2] != second[2] or first[0][4:8] != second[0][4:8]:
        raise ValueError('Setup requests must belong to the same ENIP session')
    if (first[0][:2] != b'\x70\x00' or second[0][:2] != b'\x70\x00'
            or first[0][32:42] != second[0][32:42]):
        raise ValueError('Setup requests must address the same connected CIP connection')
    request, completion = first[1], second[1]
    if not request.startswith(bytes.fromhex('4b0220642401')) or len(request) not in (287, 291):
        raise ValueError('First frame is not an observed class 0x64 setup request')
    if struct.unpack_from('<H', request, 6)[0] + 128 != len(request) - 6:
        raise ValueError('First setup request has an unobserved payload layout')
    if not completion.startswith(bytes.fromhex('4c02206424011400')) or len(completion) != 28:
        raise ValueError('Second frame is not the observed class 0x64 completion request')
    return [request, completion], hashlib.sha256(capture.read_bytes()).hexdigest()


def compare_setup(ip: str, instance: int, capture: Path, frames, tshark: str):
    ipaddress.IPv4Address(ip)
    description = build_description_request(instance)
    requests, digest = capture_requests(capture, frames, tshark)
    cases = [('baseline', []), ('first_request_only', [0]),
             ('second_request_only', [1]), ('both_requests_in_order', [0, 1])]
    report = {'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'ip': ip, 'symbol_instance': instance, 'capture_sha256': digest,
              'capture_request_frames': list(frames), 'cases': []}
    for name, steps in cases:
        case = {'case': name, 'exchanges': []}
        report['cases'].append(case)
        try:
            with CIPDriver(ip) as plc:
                _open_transport(plc, 'factorytalk_transport')
                case['exchanges'].append(_exchange(plc, 'Identity before setup', IDENTITY_READ, True))
                for step in steps:
                    item = _exchange(plc, 'Captured setup frame {}'.format(frames[step]), requests[step], True)
                    case['exchanges'].append(item)
                    if 'reply' not in item:
                        raise RuntimeError('No complete setup reply; stopping this session')
                for label, wire in [('Metadata directory', METADATA_DIRECTORY_READ),
                                    ('Definition 1', DEFINITION_READ),
                                    ('Description', description), ('Identity after setup', IDENTITY_READ)]:
                    item = _exchange(plc, label, wire, True)
                    case['exchanges'].append(item)
                    reply = item.get('reply', {})
                    if label == 'Description' and reply.get('general_status') == 0:
                        item['decoded'] = decode_description_response([bytes.fromhex(reply['data_hex'])])
                        if item['decoded'] is not None and item['decoded']['instance_id'] != instance:
                            raise ValueError('Description reply refers to a different Symbol instance')
        except Exception as error:
            case['error'] = str(error)
        print(name + ': ' + ', '.join('{}=0x{:02X}'.format(x['label'], x['reply']['general_status'])
                                     for x in case['exchanges'] if 'reply' in x), flush=True)
        if case.get('error'):
            print('  error:', case['error'], flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ip', help='Direct controller IPv4 address')
    parser.add_argument('--symbol-instance', required=True, type=int)
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--setup-frames', required=True, type=int, nargs=2, metavar=('FIRST', 'SECOND'))
    parser.add_argument('--tshark', default='tshark', help='Path to tshark if it is not on PATH')
    parser.add_argument('--output', required=True, type=Path, help='Local JSON; includes captured setup bytes')
    args = parser.parse_args()
    # Validate destination before any controller traffic.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as output:
        result = compare_setup(args.ip, args.symbol_instance, args.capture, args.setup_frames, args.tshark)
        output.write(json.dumps(result, indent=2) + '\n')
    print('Saved', args.output)


if __name__ == '__main__':
    main()
