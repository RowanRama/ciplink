"""Metadata, authentication and credential-bundle fixtures: ciplink.logix_metadata, ciplink.logix_auth and
ciplink._logix_bundle_codec.

Only the synthetic test key from tools/reference/tests/offline is written out; the bundled credentials appear as SHA-1 digests.
"""

import hashlib
import json
import os
import struct

from fixturelib import ROOT, enc, outcome, write

from ciplink import logix_metadata as md
from ciplink import logix_auth as auth
from ciplink import _logix_bundle_codec as codec

OFFLINE = os.path.join(ROOT, "tools", "reference", "tests", "offline")
CAPTURE = json.load(open(os.path.join(OFFLINE, "logix_metadata_capture.json"), encoding="utf-8"))
SYNTH = json.load(open(os.path.join(OFFLINE, "logix_auth_synthetic_key.json"), encoding="utf-8"))
KEY = bytes.fromhex(SYNTH["pkcs1_der_hex"])
KEY8 = bytes.fromhex(SYNTH["pkcs8_der_hex"])
MODULUS = int(SYNTH["modulus_hex"], 16)


def page(data=b"", first=True, last=True, offset=0, version=1, reserved=0, flags=None):
    if flags is None:
        flags = int(first) | (int(last) << 1)
    return struct.pack("<BBHI", version, flags, reserved, offset) + data


def record(instance, value, *, path="", class_id=0x6B, owner=(0, 0), language=0x7F, kind=1, prop=1):
    raw_path = path.encode("utf-8")
    header = (struct.pack("<HIIHH", class_id, instance, *owner, len(raw_path))
              + raw_path + struct.pack("<HHIIIIH", language, prop, 123, 4, 5, 6, kind))
    if kind != 1:
        return header
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return header + struct.pack("<H", len(raw)) + raw


def field(identifier, kind, payload, context=(1, 2, 3)):
    return struct.pack("<HIIIH", identifier, *context, kind) + payload


# --- metadata ---------------------------------------------------------------------------------------------------

def description_request_cases():
    cases = []
    kwargs = [
        {}, {"language": 0x0409}, {"offset": 490}, {"offset": 0xFFFFFFFF}, {"path": "[0]"}, {"path": "[0].1"},
        {"path": "café"}, {"class_id": 0x6C, "owner_context": (0xEF20, 0)},
        {"owner_context": (0xFFFFFFFF, 0xFFFF)}, {"class_id": 0xFFFF}, {"language": 0}, {"language": 0xFFFF},
        {"class_id": -1}, {"class_id": 0x10000}, {"owner_context": (-1, 0)}, {"owner_context": (0, 65536)},
        {"owner_context": (2 ** 32, 0)}, {"language": -1}, {"language": 0x10000}, {"offset": -1},
        {"offset": 2 ** 32}, {"path": "a" * 65535}, {"path": "a" * 65536}, {"path": "é" * 32768},
    ]
    for instance in (1063, 1, 0xFFFFFFFF, 0, -1, 2 ** 32):
        for kw in kwargs if instance == 1063 else [{}]:
            args = {"instance_id": instance, **kw}
            if "owner_context" in args:
                args["owner_context"] = list(args["owner_context"])
            result = outcome(md.build_description_request, instance,
                             **{k: (tuple(v) if k == "owner_context" else v) for k, v in kw.items()})
            if "path" in kw and len(kw["path"]) > 1000:
                args["path_repeat"] = [kw["path"][0], len(kw["path"])]
                del args["path"]
                if "ok" in result:
                    result = {"ok_sha1": hashlib.sha1(bytes.fromhex(result["ok"]["bytes"])).hexdigest()}
            cases.append({"args": args, "result": result})
    return cases


def index_request_cases():
    cases = []
    for language, offset in [(0x7F, 0), (0x409, 15), (0, 0xFFFFFFFF), (0xFFFF, 1), (-1, 0), (0x10000, 0),
                             (0x7F, -1), (0x7F, 2 ** 32)]:
        cases.append({"language": language, "offset": offset,
                      "result": outcome(md.build_description_index_request, language, offset)})
    return cases


def page_cases():
    raws = [b"", b"\x01\x03", bytes.fromhex("0203000000000000"), bytes.fromhex("0104000000000000"),
            bytes.fromhex("0103010000000000"), page(), page(b"abc"), page(b"x", first=False, offset=490),
            page(b"y", last=False), page(flags=0), page(flags=0x80), page(version=0), page(reserved=0x100),
            page(b"\x00" * 3, offset=0xFFFFFFFF), bytes.fromhex(CAPTURE["description"]["page_hex"])]
    return [{"raw": raw.hex(), "result": outcome(md.decode_metadata_page, raw)} for raw in raws]


def page_sets():
    desc = bytes.fromhex(CAPTURE["description"]["page_hex"])
    sets = [[], [page(b"", first=False)], [page(b"abc", last=False)],
            [page(b"a", last=False), page(b"b", first=False, offset=5)],
            [page(b"a"), page(b"b", first=False, offset=1)],
            [page(b"", last=False), page(b"", first=False)],
            [page(b"")], [page(b"abc")], [page(b"ab", last=False), page(b"", first=False, offset=2)],
            [page(b"ab", last=False), page(b"cd", first=False, last=False, offset=2),
             page(b"ef", first=False, offset=4)],
            [page(b"ab", last=False), page(b"cd", first=True, offset=2)],
            [page(b"ab", last=False), page(b"cd", first=False, last=False, offset=2)],
            [b"\x01\x03", page()], [desc]]
    sets += [[bytes.fromhex(raw) for raw in d["pages_hex"]] for d in CAPTURE["definitions"]]
    defn45 = next(d for d in CAPTURE["definitions"] if d["id"] == 45)
    sets.append([bytes.fromhex(defn45["pages_hex"][0])])
    return sets


def assemble_cases():
    return [{"pages": [p.hex() for p in pages], "result": outcome(md.assemble_metadata_pages, pages)}
            for pages in page_sets()[:16]]


def definition_payloads():
    payloads = []
    for code, count in [(0xC1, 3), (0xC2, 2), (0xC3, 2), (0xC4, 1), (0xC5, 1), (0xC6, 2), (0xC7, 1), (0xC8, 1),
                        (0xC9, 1), (0xCA, 2), (0xCB, 1), (0xC3, 0), (0xC0, 1), (0xCC, 1), (0x1C3, 1)]:
        size = {0xC1: 1, 0xC2: 1, 0xC3: 2, 0xC4: 4, 0xC5: 8, 0xC6: 1, 0xC7: 2, 0xC8: 4, 0xC9: 8,
                0xCA: 4, 0xCB: 8}.get(code, 1)
        raw = bytes((i * 37 + 1) % 256 for i in range(size * count))
        if code == 0xCA:
            raw = struct.pack("<2f", 1.5, -2.25)[:size * count]
        if code == 0xCB:
            raw = struct.pack("<d", 0.1)
        payloads.append(field(19, 2, struct.pack("<HH", code, count) + raw))
    text = field(9, 1, struct.pack("<H", 4) + b"Name")
    payloads += [
        text, text + field(19, 2, struct.pack("<HH", 0xC3, 2) + b"\x01\x00\xff\xff"),
        text + text, text + field(10, 3, b""), text + field(10, 0, b""), text[:-1], text + b"\x00",
        field(9, 1, struct.pack("<H", 2) + b"\xff\xfe"), field(9, 1, struct.pack("<H", 0)),
        field(9, 1, struct.pack("<H", 3) + "é".encode("utf-8") + b"!"),
        field(19, 2, struct.pack("<HH", 0xC4, 2) + b"\x00" * 7), b"",
        field(0xFFFF, 1, struct.pack("<H", 1) + b"x", context=(0xFFFFFFFF, 0, 7)),
    ]
    # utf-8 edges: surrogate, overlong, above U+10FFFF, truncated sequence, noncharacter, BOM, NUL, C1 controls
    for raw in (b"\xed\xa0\x80", b"\xc0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82", b"\xef\xbf\xbf",
                b"\xef\xbb\xbfA", b"\x00", b"\xc2\x80\xc2\x9f", "\U0001F600".encode("utf-8"), bytes(range(0x80, 0xA0))):
        payloads.append(field(9, 1, struct.pack("<H", len(raw)) + raw))
    # a text field after an atomic one, and an atomic count far beyond the data
    payloads.append(field(19, 2, struct.pack("<HH", 0xC8, 1) + b"\x01\x02\x03\x04") + text)
    payloads.append(field(19, 2, struct.pack("<HH", 0xCB, 0xFFFF) + b"\x00" * 8))
    return payloads


def definition_cases():
    cases = []
    for pages in page_sets():
        cases.append({"pages": [p.hex() for p in pages], "encoding": "utf-8",
                      "result": outcome(md.decode_definition_response, pages)})
    for payload in definition_payloads():
        for encoding in ("utf-8", "latin-1", "cp1252", "ascii"):
            pages = [page(payload)]
            cases.append({"pages": [p.hex() for p in pages], "encoding": encoding,
                          "result": outcome(md.decode_definition_response, pages, encoding)})
    # encoding=None keeps text as bytes
    for payload in definition_payloads():
        pages = [page(payload)]
        cases.append({"pages": [p.hex() for p in pages], "encoding": None,
                      "result": outcome(md.decode_definition_response, pages, None)})
    return cases


def description_payloads():
    desc = bytes.fromhex(CAPTURE["description"]["page_hex"])[8:]
    raw = record(425, "café", path="[10]")
    out = [desc, desc + b"unexpected", desc[:36] + b"\x00\x00", raw, raw + record(1, None, kind=4),
           record(1, None, kind=4), record(1, "x", kind=2), record(1, "x", prop=2), record(1, "x", kind=0),
           record(0x84FE0592, "Acked", class_id=0x6C, owner=(0xEF20, 0xFFFF)),
           record(7, "café".encode("cp1252")), record(7, b"\x81"), record(7, b"\xff\xfe\x80"),
           record(9, "a", path="é"), record(1, "a") + record(2, "b") + record(3, None, kind=4), b"",
           record(1, None, kind=4) + record(2, "b"), record(1, "x", prop=0), record(1, "x", kind=3),
           record(1, b"\xed\xa0\x80"), record(1, b""), record(1, "x", path="\U0001F600"),
           record(1, "x", path="\u00e9")[:12] + b"\x05\x00ab"]
    # a path that is not utf-8 text
    out.append(struct.pack("<HIIHH", 0x6B, 1, 0, 0, 1) + b"\xff" + struct.pack("<HHIIIIH", 0x7F, 1, 1, 0, 0, 0, 4))
    return out


def description_cases():
    response, records = [], []
    sets = [[page(p)] for p in description_payloads()]
    sets += [[bytes.fromhex(CAPTURE["missing_description_page_hex"])], [bytes.fromhex(CAPTURE["description"]["page_hex"])]]
    rec = record(425, "Text twelve", path="[12]")
    sets += [[page(rec[:15], last=False), page(rec[15:], first=False, offset=15)], []]
    desc = bytes.fromhex(CAPTURE["description"]["page_hex"])[8:]
    raw = record(425, "café", path="[10]")
    for pages in [[page(desc[:end])] for end in range(1, len(desc))] + [[page(raw[:end])] for end in range(1, len(raw))]:
        response.append({"pages": [p.hex() for p in pages], "encoding": "utf-8",
                         "result": outcome(md.decode_description_response, pages)})
    for pages in sets:
        hexes = [p.hex() for p in pages]
        for encoding in ("utf-8", "cp1252", "latin-1"):
            response.append({"pages": hexes, "encoding": encoding,
                             "result": outcome(md.decode_description_response, pages, encoding)})
        for encoding, max_records in (("utf-8", None), (None, None), ("utf-8", 1), ("utf-8", 2), ("utf-8", 0)):
            records.append({"pages": hexes, "encoding": encoding, "max_records": max_records,
                            "result": outcome(md.decode_description_records, pages, encoding,
                                              max_records=max_records)})
    return response, records


# --- auth -------------------------------------------------------------------------------------------------------

def certificate(claims=((3, 1), (11, 1)), modulus=MODULUS, size_delta=0, version=1, issuer=1, count=None,
                key_header="02008080030001000181808000", tail=128):
    size = 8 + 4 * len(claims) + 13 + 128 + size_delta
    return (struct.pack("<HHHH", size, version, issuer, len(claims) if count is None else count)
            + b"".join(struct.pack("<HH", *claim) for claim in claims)
            + bytes.fromhex(key_header) + modulus.to_bytes(128, "big") + bytes(tail))


def certificate_cases():
    certs = [certificate(), certificate(((11, 1),)), certificate(((3, 1),)), certificate(((11, 2),)),
             certificate(((3, 1), (11, 1), (4, 1))), certificate(size_delta=1), certificate(version=2),
             certificate(issuer=0), certificate(count=0), certificate(key_header="02008080030001000181808001"),
             certificate(tail=127), certificate(tail=129), b"", bytes(281), bytes(285),
             certificate(((3, 1), (11, 1)))[:-4] + b"\x00" * 4, certificate(((11, 1),), size_delta=-1, tail=129),
             certificate(count=3), certificate(count=1, size_delta=4), certificate(((11, 1), (11, 1))),
             certificate(((11, 1), (3, 0))), certificate(((11, 1),), size_delta=4, tail=132)]
    return [{"certificate": c.hex(), "result": outcome(auth.validate_metadata_certificate, c)} for c in certs]


def der(tag, payload):
    size = len(payload)
    length = bytes([size]) if size < 128 else (b"\x81" + bytes([size]) if size < 256 else
                                               b"\x82" + size.to_bytes(2, "big"))
    return bytes([tag]) + length + payload


def key_values():
    reader = auth._DERReader(auth._DERReader(KEY).item(0x30))
    return [reader.item(2) for _ in range(9)]


def key_cases():
    values = key_values()
    keys = [KEY, KEY8, b"", KEY[:10], KEY[:-1], KEY + b"extra", b"\x30\x80\x00\x00", b"\x30\x82\x00\x01\x00",
            b"\x30\x81\x01\x00", bytes(2049), b"\x30\x00", b"\x31\x00", b"\x30\x83\x00\x00\x01\x00",
            b"\x30\x81\x7f" + bytes(127), b"\x30\x82\x00\x80" + bytes(128), KEY8[:-1], KEY8 + b"\x00",
            der(0x30, b"".join(der(2, v) for v in values) + der(2, b"\x00")),
            der(0x30, b"".join(der(2, v) for v in values[:8]))]
    for index in range(9):
        changed = list(values)
        changed[index] = b"\x01" if index == 0 else b"\x00"
        keys.append(der(0x30, b"".join(der(2, v) for v in changed)))
    # PKCS #8 variants: wrong version, wrong algorithm, trailing fields, trailing data inside the octet string
    algorithm = der(0x30, bytes.fromhex("06092a864886f70d0101010500"))
    keys += [der(0x30, der(2, b"\x01") + algorithm + der(4, KEY)),
             der(0x30, der(2, b"\x00") + der(0x30, bytes.fromhex("06092a864886f70d0101010400")) + der(4, KEY)),
             der(0x30, der(2, b"\x00") + algorithm + der(4, KEY) + der(2, b"\x00")),
             der(0x30, der(2, b"\x00") + algorithm + der(4, KEY + b"\x00")),
             der(0x30, der(2, b"\x00") + algorithm + der(4, der(0x30, der(2, b"\x00") + algorithm + der(4, KEY))))]
    # a two-prime key with e = 3 and with a different version
    keys.append(der(0x30, b"".join(der(2, v) for v in [values[0], values[1], b"\x03"] + values[3:])))
    keys.append(der(0x30, b"".join(der(2, v) for v in [b"\x00\x80"] + values[1:])))
    keys.append(der(0x30, b"".join(der(2, v) for v in [b"\x00\x00"] + values[1:])))
    keys.append(der(0x30, b"".join(der(2, v) for v in [b"\x80"] + values[1:])))
    keys.append(der(0x30, b"".join(der(2, v) for v in [b""] + values[1:])))
    # PKCS #8 without its octet string, a non-sequence inside it, a truncated algorithm, a 2048-byte junk key
    keys += [der(0x30, der(2, b"\x00") + algorithm),
             der(0x30, der(2, b"\x00") + algorithm + der(4, der(2, b"\x00"))),
             der(0x30, der(2, b"\x00") + b"\x30\x0d\x06"),
             der(0x30, der(2, b"\x00") + algorithm + b"\x05" + der(4, KEY)[1:]),
             b"\x30\x82\x07\xfc" + bytes(2044), der(0x30, der(2, b"\x00\x00") + algorithm + der(4, KEY))]
    cases = []
    for k in keys:
        for cert in (certificate(), certificate(modulus=MODULUS ^ 1), certificate(((3, 1),)))[:3 if k in (KEY, KEY8) else 1]:
            cases.append({"certificate": cert.hex(), "key": k.hex(),
                          "result": outcome(lambda: (auth.LogixMetadataCredentials(cert, k), None)[1])})
    return cases


def challenge_cases():
    creds = auth.LogixMetadataCredentials(certificate(), KEY)
    data = [b"\x80\x00" + bytes.fromhex(v["ciphertext_le_hex"]) for v in SYNTH["vectors"]]
    data += [b"\x80\x00" + bytes(128), b"\x80\x00" + b"\x01" + bytes(127), b"\x80\x00" + (12345).to_bytes(128, "little"),
             b"\x80\x00" + (MODULUS - 1).to_bytes(128, "little"), b"", b"\x80\x00" + bytes(127),
             b"\x80\x00" + bytes(129), b"\x7f\x00" + bytes(128), b"\x80\x01" + bytes(128),
             b"\x80\x00" + MODULUS.to_bytes(128, "little"), b"\x80\x00" + b"\xff" * 128]
    return [{"data": d.hex(), "result": outcome(creds.answer_challenge, d)} for d in data]


def completion_cases():
    grants = struct.pack("<HHIHI", 2, 3, 1, 11, 1)
    data = [grants, struct.pack("<HHI", 1, 11, 1), b"", b"\x00", b"\x00\x00", grants[:-1], grants + b"extra",
            struct.pack("<HHI", 1, 3, 1), struct.pack("<HHI", 1, 11, 0), struct.pack("<HHIHI", 2, 11, 1, 11, 1),
            struct.pack("<HHIHI", 2, 11, 1, 11, 2), struct.pack("<H", 64) + b"".join(
                struct.pack("<HI", i, 1) for i in range(64)),
            struct.pack("<H", 65) + b"".join(struct.pack("<HI", i, 1) for i in range(65)),
            struct.pack("<HHI", 1, 11, 0x10001), struct.pack("<HHIHI", 2, 3, 1, 3, 2),
            struct.pack("<H", 64) + b"".join(struct.pack("<HI", 63 - i if i else 11, 1) for i in range(64)),
            struct.pack("<H", 0xFFFF) + bytes(6)]
    creds = auth.LogixMetadataCredentials(certificate(), KEY)
    return [{"data": d.hex(), "result": outcome(creds.validate_completion, d)} for d in data]


# --- bundle -----------------------------------------------------------------------------------------------------

def bundle_cases():
    key = bytes(range(32))
    nonce = bytes(range(12))
    cert = certificate()

    def sealed(payload, header=b"LMK1", k=key):
        return header + nonce + codec._encrypt(k, nonce, payload, header)

    good = sealed(struct.pack("<HH", len(cert), len(KEY)) + cert + KEY)
    bundles = [good, sealed(struct.pack("<HH", 285, 1) + certificate(((3, 1), (11, 1), (4, 1))) + b"\x01")]
    for position in (0, 4, 16, len(good) - 1):
        tampered = bytearray(good)
        tampered[position] ^= 1
        bundles.append(bytes(tampered))
    bundles += [good[:35], b"LMK1" + bytes(32), b"XXXX" + good[4:], sealed(b""), sealed(b"\x00\x00\x00"),
                sealed(struct.pack("<HH", 280, 1) + bytes(281)), sealed(struct.pack("<HH", 281, 0) + bytes(281)),
                sealed(struct.pack("<HH", 281, 2049) + bytes(281 + 2049)),
                sealed(struct.pack("<HH", 281, 1) + bytes(281)), sealed(struct.pack("<HH", 281, 1) + bytes(283)),
                sealed(struct.pack("<HH", 281, 2) + bytes(283), header=b"LMK2"),
                sealed(struct.pack("<HH", 281, 1) + bytes(282), k=bytes(reversed(range(32))))]
    cases = [{"bundle_pad": [good.hex(), size], "key": key.hex(),
              "result": outcome(codec.open_credentials, good + bytes(size - len(good)), key)} for size in (4096, 4097)]
    for b in bundles:
        for k in (key, bytes(reversed(range(32)))):
            cases.append({"bundle": b.hex(), "key": k.hex(), "result": outcome(codec.open_credentials, b, k)})
    return cases


def bundled():
    from ciplink._logix_metadata_bundle import load
    cert, key = load()
    creds = auth.LogixMetadataCredentials.bundled()
    assert creds.certificate == cert
    return {"certificate_sha1": hashlib.sha1(cert).hexdigest(), "key_sha1": hashlib.sha1(key).hexdigest(),
            "certificate_len": len(cert), "claims": [list(c) for c in auth.validate_metadata_certificate(cert)]}


def main():
    response, records = description_cases()
    write("metadata_auth.json", {
        "synthetic": {"pkcs1": KEY.hex(), "pkcs8": KEY8.hex(), "modulus": "%x" % MODULUS,
                      "certificate": certificate().hex()},
        "bundled": bundled(),
        "description_request": description_request_cases(),
        "index_request": index_request_cases(),
        "page": page_cases(),
        "assemble": assemble_cases(),
        "definition": definition_cases(),
        "description_response": response,
        "description_records": records,
        "certificate": certificate_cases(),
        "credentials": key_cases(),
        "challenge": challenge_cases(),
        "completion": completion_cases(),
        "bundle": bundle_cases(),
    })


if __name__ == "__main__":
    main()
