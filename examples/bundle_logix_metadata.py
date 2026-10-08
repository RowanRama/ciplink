"""Generate a sealed, obfuscated Python credential module for this package.

The result can parse itself without FactoryTalk or optional crypto libraries.
Anyone with the package can reverse this obfuscation and recover the credentials.
"""

import argparse
import ast
import base64
import secrets
from pathlib import Path

from pycomm3 import LogixMetadataCredentials
from pycomm3._logix_bundle_codec import seal_credentials


def render_bundle(certificate, private_key):
    LogixMetadataCredentials(certificate, private_key)
    key = secrets.token_bytes(32)
    encrypted = seal_credentials(certificate, private_key, key)
    encoded = base64.b85encode(encrypted).decode("ascii")
    blocks = [encoded[offset:offset + 80] for offset in range(0, len(encoded), 80)]
    permutation = list(range(len(blocks)))
    secrets.SystemRandom().shuffle(permutation)
    shuffled = [blocks[index] for index in permutation]
    order = tuple(permutation.index(index) for index in range(len(blocks)))
    first, second = secrets.token_bytes(32), secrets.token_bytes(32)
    third = bytes(a ^ b ^ c for a, b, c in zip(key, first, second))
    masks = tuple(base64.b85encode(part).decode("ascii") for part in (first, second, third))
    source = '\n'.join([
        '"""Generated sealed metadata credentials; reversible local obfuscation."""',
        'import base64',
        'from ._logix_bundle_codec import open_credentials',
        '',
        '_BLOCKS = (',
        *['    {!r},'.format(block) for block in shuffled],
        ')',
        '_ORDER = {!r}'.format(order),
        '_MATERIAL = {!r}'.format(masks),
        '',
        '',
        'def load():',
        '    data = base64.b85decode("".join(_BLOCKS[index] for index in _ORDER))',
        '    parts = [base64.b85decode(value) for value in _MATERIAL]',
        '    if len(parts) != 3 or any(len(part) != 32 for part in parts):',
        '        raise ValueError("Invalid bundled credential material")',
        '    material = bytes(a ^ b ^ c for a, b, c in zip(*parts))',
        '    return open_credentials(data, material)',
        '',
    ])
    ast.parse(source)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).resolve().parents[1] / "pycomm3" / "_logix_metadata_bundle.py")
    args = parser.parse_args()
    source = render_bundle(args.certificate.read_bytes(), args.private_key.read_bytes())
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(source)
    print("Saved encrypted credential module:", args.output)


if __name__ == "__main__":
    main()
