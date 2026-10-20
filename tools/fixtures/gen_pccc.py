"""PCCC/SLC fixtures: data file addresses, PCCC strings, write values, request messages and reply decoding."""

from unittest import mock

from fixturelib import enc, outcome, write

from ciplink.cip import UINT
from ciplink.cip.pccc import PCCC_ASCII, PCCC_STRING, PCCC_CT, PCCC_DATA_TYPE, PCCC_DATA_SIZE
from ciplink.slc_driver import (
    SLCDriver, parse_tag, writeable_value, request_status, get_bit, _parse_read_reply, _parse_file0, _get_sys0_info,
)

ADDRESSES = [
    # integer / float / long / binary words, bits, counts
    "N7:0", "n7:0", "N7:255", "N7:256", "N7:1000", "N0:0", "N1:0", "N255:255", "N256:0", "N7:0/0", "N7:0/5",
    "N7:0/15", "N7:0/16", "N7:0/3x", "N7:0{10}", "N7:0{0}", "N7:0{1}", "N7:0/3{2}", "N7:0{}", "N7:0{a}",
    "N7:", "N7", "N:0", "N7:0 ", " N7:0", "N7:0000", "N007:001", "N7:1234", "N1234:0",
    "F8:0", "F8:10{4}", "F8:0/3", "L9:0", "L9:2{3}", "l9:0/31", "L9:0/31", "B3:0", "B3:0/15", "B3:1{2}",
    # B file bit form
    "B3/0", "B3/10", "B3/17", "B3/4095", "B3/4096", "B3/10{2}", "b3/16", "B0/1", "B256/1", "B3/12345",
    # timers, counters, control
    "T4:0.ACC", "T4:0.PRE", "T4:0.EN", "T4:0.TT", "T4:0.DN", "t4:0.acc", "T4:255.DN", "T4:256.DN", "T0:0.ACC",
    "T4:0xACC", "T4:0/ACC", "T4:0.CU", "C5:3.ACC", "C5:0.CU", "C5:0.CD", "C5:0.OV", "C5:0.UN", "C5:0.UA",
    "C5:0.DN", "C5:0.PRE", "C5:0.EN", "T4:0", "C5:0", "T4:0.ACC{2}", "T4:0.XYZ", "R6:0", "R6:0.LEN",
    # inputs / outputs
    "I:0", "I1:0", "I5:0", "O:0", "O0:3", "o:2", "I:0/0", "I:0/15", "I:0/16", "I:0.1", "I:0.1/3", "I:0.999",
    "I:0{4}", "O:0/3{2}", "I:256", "I1234:0", "I:0.1234", "I:0/123",
    # status
    "S:0", "S:1/15", "S:1/5", "s:23", "S:256", "S:1/16", "S:0{3}", "S:1/5{2}", "S2:0",
    # strings / ascii
    "ST9:0", "ST9:0{1}", "ST9:0{2}", "ST9:0{3}", "st9:1", "ST9:256", "ST0:0", "ST9:12345", "ST9:0/1",
    "A10:0", "A10:0{4}", "A10:255", "A10:256", "A10:1234", "a10:3",
    # garbage
    "", "X7:0", "N7:-1", "MG1:0", "PD1:0", "N7:0\n", "T4:0\n",
    # regex corners: '.' separator backtracking, newline, Unicode case folding (long s, dotless i)
    "T4:0.ACC\n", "T4:12ACC", "T4:1234ACC", "T4:1\nACC", "T4:300ACC", "ſ:1", "ı:0", "ſT9:0",
    "N7:0{99}", "B3/0010", "I:0.1{2}", "A10:0/1", "S:1{2}", "S:1/5{0}", "I:0.1/3{4}", "O5:1.2/3",
    # review: more malformed and corner forms
    "T4:0.ACCX", "T4:0..ACC", "T4:0.Acc", "c5:0.dn", "T4:0{.ACC", "T4:0.ACC/1", "T4:00012ACC", "T4:0ACC",
    "T4:.ACC", "T255:255.UA", "C5:9999DN", "N7:0/5/6", "N7:0{1}{2}", "N7:0/", "N7:0/05", "N7:0/015",
    "N7:0{007}", "N7:0{ 1}", "N7:0{1 }", "N7 :0", "N7:0}", "N7:0{", "I:0./3", "I:.1", "I0000:0", "O:0.1.2",
    "I:0/3.1", "I:0.1/", "I:0.", "O255:255.999/15", "ST9:0{1}x", "ST9:0{0}", "ST9:0{01}", "A10:0{0}",
    "B3/0{0}", "B3/", "B3:", "S:", "S:1/", "S:1/015", "ST9:0/", "A10:0010", "B3/4080", "N7:255{2}",
    "ı:0.1/3", "ſ:1/15", "B3/4095{1}", "F8:0/15{3}",
]


def norm_tag(tag):
    """parse_tag's dict with numbers as ints and absent keys as None"""
    if tag is None:
        return None
    sub = tag.get("sub_element")
    pos = tag.get("pos_number")
    return {
        "file_type": tag["file_type"],
        "file_number": int(tag["file_number"]),
        "element_number": int(tag["element_number"]),
        "pos_number": None if pos is None else int(pos),
        "sub_element": None if sub is None else int(sub),
        "address_field": tag["address_field"],
        "element_count": tag["element_count"],
        "tag": tag["tag"],
    }


def parse_cases():
    return [{"address": a, "result": norm_tag(parse_tag(a))} for a in ADDRESSES]


STRING_VALUES = ["", "A", "AB", "ABC", "123", "café", "€", "€A", "x" * 82, "x" * 100, "y" * 81, None, 0, 5,
                 False, True, 1.5, b"ab", [1]]


def string_cases():
    cases = []
    for cls in (PCCC_ASCII, PCCC_STRING):
        for value in STRING_VALUES:
            cases.append({"type": cls.__name__, "op": "encode", "value": enc(value),
                          "result": outcome(cls.encode, value)})
        raws = [b"", b"A", b"BA", b"BAC", b"\x00\x41", b"\xe9\x00", b"\x03\x00", b"\x03\x00\x42\x41\x00\x43" + b"\xff" * 78,
                b"\x01", b"\x05\x00\x42\x41", b"\x00\x00", b"\xff\xff" + bytes(82), b"\x02\x00\xe9\x63\x41"]
        for raw in raws:
            cases.append({"type": cls.__name__, "op": "decode", "raw": raw.hex(), "result": outcome(cls.decode, raw)})
    return cases


WRITE_CASES = [
    ("N7:0", 1), ("N7:0", -1), ("N7:0", 32767), ("N7:0", 32768), ("N7:0", -32769), ("N7:0", 1.5), ("N7:0", True),
    ("N7:0", "abc"), ("N7:0", None), ("N7:0", b"\x01\x02\x03\x04"), ("N7:0", b""), ("N7:0", [1]),
    ("N7:0{3}", [1, 2, 3]), ("N7:0{3}", [1, 2, 3, 4]), ("N7:0{3}", [1, 2]), ("N7:0{3}", [1, "a", 3]),
    ("N7:0{3}", 5), ("N7:0{0}", 5), ("N7:0{1}", 5), ("N7:0{2}", "ab"),
    ("N7:0/5", True), ("N7:0/5", False), ("N7:0/5", 1), ("N7:0/5", 0), ("N7:0/5", "x"), ("N7:0/5", ""),
    ("N7:0/5", 7), ("N7:0/5", 0.0), ("N7:0/15", True), ("N7:0/0", True), ("N7:0/5", []), ("N7:0/5", [0]),
    ("B3/17", True), ("B3/17", False), ("B3/4095", True), ("B3:0", 0x7FFF),
    ("F8:0", 1.5), ("F8:0", 1), ("F8:0", 1e39), ("F8:0", "x"), ("F8:0", True), ("F8:0{2}", [1.5, -2]),
    ("F8:0/3", True),
    ("L9:0", 70000), ("L9:0", 2**31), ("L9:0{2}", [1, -1]), ("L9:0/20", True), ("R6:0", 5),
    ("T4:0.PRE", 1000), ("T4:0.ACC", 7), ("T4:0.ACC", 1.5), ("T4:0.DN", True), ("T4:0.EN", True), ("T4:0.TT", 0),
    ("C5:3.ACC", 7), ("C5:0.CU", True), ("C5:0.UA", True), ("C5:0.PRE", 40000),
    ("I:0", 3), ("I:0/3", True), ("O:0.1", 5), ("O:0.1/2", True), ("O:0{2}", [1, 2]), ("S:1/5", True), ("S:3", 9),
    ("ST9:0", "hello"), ("ST9:0", ""), ("ST9:0", None), ("ST9:0", 5), ("ST9:0", 0), ("ST9:0", "€"),
    ("ST9:0{2}", ["abc", "de"]), ("ST9:0{2}", ["abc"]), ("ST9:0{2}", "abc"),
    ("A10:0", "AB"), ("A10:0", "A"), ("A10:0", "ABC"), ("A10:0", ""), ("A10:0", None), ("A10:0", 3),
    ("A10:0{2}", ["ab", "cd"]),
    # review: string values for multi-element files, bit truthiness, timer words, I/O positions
    ("A10:0{2}", "abcd"), ("A10:0{2}", "a"), ("ST9:0{2}", "xy"), ("N7:0{2}", [True, False]), ("N7:0{2}", []),
    ("N7:0{2}", "1"), ("N7:0{2}", "12"), ("N7:0/5", -0.0), ("N7:0/5", "0"), ("N7:0/5", [[]]), ("B3/0", "0"),
    ("T4:0.PRE", True), ("T4:0.ACC", -1), ("T4:0.ACC", 40000), ("T4:0.ACC", "x"), ("T4:0.DN", 0),
    ("I:0.1/3", True), ("O:0.300", 1), ("B3/4080", True), ("L9:0/31", True), ("S:1/5{0}", True),
    ("N7:0{0}", [1, 2]), ("F8:0", -0.0), ("F8:0", float("inf")), ("L9:0", -2**31), ("L9:0", -2**31 - 1),
    ("A10:0", "€"), ("A10:0", "éèx"), ("ST9:0", "z" * 83),
]


def writeable_cases():
    return [{"address": a, "value": enc(v), "result": outcome(writeable_value, parse_tag(a), v)} for a, v in WRITE_CASES]


class _Sent(Exception):
    pass


def _capture(call):
    """the message the driver adds to its request ({"ok": bytes}), or the error raised before sending"""
    sent = []

    def send(request):
        sent.append(request._added[0])
        raise _Sent()

    with mock.patch.object(SLCDriver, "send", side_effect=send):
        try:
            call()
        except _Sent:
            return {"ok": enc(sent[0])}
        except Exception as err:
            return {"err": type(err).__name__, "msg": str(err)}
    return {"err": "NotSent", "msg": ""}


def _driver():
    driver = SLCDriver("1.2.3.4/0")
    driver._target_is_connected = True
    return driver


READ_ADDRESSES = [a for a in ADDRESSES] + ["N7:0{127}", "N7:0{128}", "ST9:0{3}", "T4:0{42}", "T4:0{43}",
                                           "F8:0{63}", "F8:0{64}", "I:0.300", "I:0.255", "I:0.254"]


def read_request_cases():
    cases = []
    for address in READ_ADDRESSES:
        driver = _driver()
        result = _capture(lambda: driver._read_tag(address))
        cases.append({"address": address, "result": result})
    return cases


def write_request_cases():
    cases = []
    for address, value in WRITE_CASES + [("N7:0/3{2}", [1, 1]), ("X7:0", 1), ("N7:0{200}", list(range(200))),
                                         ("N7:0{127}", list(range(127))), ("N7:0{128}", list(range(128))),
                                         ("I:0.300", 1), ("N7:0", b"\x01"), ("N7:0", b"\x01\x02")]:
        driver = _driver()
        result = _capture(lambda: driver._write_tag(address, value))
        cases.append({"address": address, "value": enc(value), "result": result})
    return cases


READ_REPLIES = [
    ("N7:0", b"\x01\x00"), ("N7:0", b"\xff\xff"), ("N7:0", b"\x01\x00\x02\x00\x03\x00"), ("N7:0", b""),
    ("N7:0", b"\x01"), ("N7:0", b"\x01\x00\x02"), ("N7:0{3}", b"\x01\x00\x02\x00\x03\x00"), ("N7:0{3}", b"\x01\x00"),
    ("N7:0/5", b"\x20\x00"), ("N7:0/5", b"\xdf\xff"), ("N7:0/15", b"\x00\x80"), ("N7:0/5", b""), ("N7:0/5", b"\x20"),
    ("N7:0/5", b"\x20\x00\x00\x00"),
    ("B3/17", b"\x02\x00"), ("B3/17", b"\x00\x00"), ("B3/4095", b"\x00\x80"),
    ("F8:0", b"\x00\x00\xc0\x3f"), ("F8:0{2}", b"\x00\x00\xc0\x3f\x00\x00\x80\xbf"), ("F8:0", b"\x00\x00\xc0"),
    ("F8:0/3", b"\x08\x00\x00\x00"), ("L9:0", b"\x70\x11\x01\x00"), ("L9:0/16", b"\x00\x00\x01\x00"),
    ("R6:0", b"\x01\x00\x02\x00\x03\x00"), ("R6:0", b"\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00"),
    ("T4:0.ACC", b"\x00\xa0\xe8\x03\x07\x00"), ("T4:0.PRE", b"\x00\xa0\xe8\x03\x07\x00"),
    ("T4:0.DN", b"\x00\xa0\xe8\x03\x07\x00"), ("T4:0.TT", b"\x00\xa0\xe8\x03\x07\x00"),
    ("T4:0.EN", b"\x00\xa0\xe8\x03\x07\x00"), ("T4:0.ACC", b"\x00\xa0\xe8\x03"), ("T4:0.PRE", b"\x00\xa0"),
    ("T4:0.ACC", b"\x00\xa0\xe8\x03\x07"), ("C5:0.CU", b"\x00\x80\x00\x00\x00\x00"),
    ("C5:0.UA", b"\x00\x04\x00\x00\x00\x00"), ("T4:0", b"\x00\xa0\xe8\x03\x07\x00"),
    ("T4:0{2}", b"\x00\xa0\xe8\x03\x07\x00\x01\x00\x02\x00\x03\x00"),
    ("I:0/3", b"\x08\x00"), ("O:0.1", b"\x05\x00"), ("S:1/5", b"\x20\x00"), ("S:3", b"\x09\x00"),
    ("ST9:0", b"\x05\x00" + PCCC_STRING.encode("hello")[2:]), ("ST9:0", PCCC_STRING.encode("hello")),
    ("ST9:0{2}", PCCC_STRING.encode("abc") + PCCC_STRING.encode("de")), ("ST9:0", b"\x03\x00\x42\x41\x00\x43"),
    ("ST9:0", b"\x03"), ("ST9:0", PCCC_STRING.encode("ab") + b"\x01"),
    ("A10:0", b"\x42\x41"), ("A10:0{2}", b"\x42\x41\x44\x43"), ("A10:0", b"\x42"), ("A10:0", b"\x42\x41\x43"),
    ("A10:0", b"\xe9\x00"),
]


def read_reply_cases():
    cases = []
    for address, data in READ_REPLIES:
        tag = parse_tag(address)
        cases.append({"address": address, "data": data.hex(),
                      "result": outcome(lambda: _parse_read_reply(tag, data).value)})
    return cases


def status_cases():
    raws = [bytes(58), bytes(59), bytes(61), bytes(58) + b"\x10", bytes(58) + b"\x10\x00\x00\x07",
            bytes(58) + b"\xf0\x00\x00", bytes(58) + b"\xf0\x00\x00\x07", bytes(58) + b"\xf0\x00\x00\x07\x08",
            bytes(58) + b"\x55\x00\x00", bytes(58) + b"\x01", bytes(58) + b"\x90", bytes(58) + b"\xff"]
    raws += [bytes(58) + bytes([code]) for code in (0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80)]
    return [{"raw": raw.hex(), "result": request_status(mock.Mock(raw=raw))} for raw in raws]


def _reply(extra=b"", sts=0):
    raw = bytearray(61)
    raw[58] = sts
    return mock.Mock(raw=bytes(raw) + extra)


def processor_type_cases():
    driver = _driver()
    request = _capture(driver.get_processor_type)
    replies = [
        _reply(b"\x00" * 5 + b"1766-LEC   " + b"\x00" * 3), _reply(b"\x00" * 5 + b"1747-L552  "),
        _reply(b"\x00" * 5 + b"  1763-L16\x1f"), _reply(b"\x00" * 5 + b"\x1c\x0bA\xc3\xa9\xff\xfeB  \x85"),
        _reply(b"\x00" * 5 + b"\xff\xfe"), _reply(b"\x00" * 5 + b"   "), _reply(), _reply(b"\x00" * 5 + b"17"),
        _reply(b"\x00" * 5 + b"1766-LEC   ", sts=0x10), _reply(b"\x00" * 5 + b"\xe2\x82\xac12345678\xe2\x82"),
        _reply(b"\x00" * 5 + b"A\xc2\xa0"),
    ]
    out = []
    for reply in replies:
        with mock.patch.object(SLCDriver, "send", return_value=reply):
            out.append({"raw": reply.raw.hex(), "result": enc(driver.get_processor_type())})
    return [{"request": request}], out


def datalog_cases():
    driver = _driver()
    requests = [{"queue": q, "result": _capture(lambda: driver._get_datalog(q))} for q in (0, 1, 5, 255, 256, -1)]
    replies = []
    for reply in (_reply(b"abc"), _reply(b"\xff\xfe"), _reply(b"caf\xc3\xa9"), _reply(), _reply(b"abc", sts=0x10)):
        with mock.patch.object(SLCDriver, "send", return_value=reply):
            replies.append({"raw": reply.raw.hex(), "result": enc(driver._get_datalog(0))})
    return requests, replies


PLC_TYPES = ["1761-L16", "1763-L16", "1762-L24", "1764-LSP", "1766-LEC", "1747-L552", "", "176", "1766"]


def sys0_cases():
    return [{"plc_type": p, "result": enc(_get_sys0_info(p))} for p in PLC_TYPES]


def file_dir_size_cases():
    cases = []
    for plc in PLC_TYPES[:6]:
        info = _get_sys0_info(plc)
        driver = _driver()
        request = _capture(lambda: driver._get_file_directory_size(info))
        replies = []
        for reply in (_reply(UINT.encode(20000)), _reply(UINT.encode(100)), _reply(), _reply(b"\x01"),
                      _reply(UINT.encode(20000), sts=0x10), _reply(UINT.encode(65535) + b"\x01")):
            with mock.patch.object(SLCDriver, "send", return_value=reply):
                replies.append({"raw": reply.raw.hex(), "result": enc(driver._get_file_directory_size(info))})
        cases.append({"plc_type": plc, "request": request, "replies": replies})
    return cases


def file_dir_read_cases():
    cases = []
    scenarios = [
        (520, b"\x01", [510, 10]), (0x50, b"\x02", [0x50]), (0xA0, b"\x03", [0x50, 0x50]), (5, b"\x01", [5]),
        (200, b"\x01", [0x50, 0x50, 0x28]), (0x51, b"\x01", [0x50, 1]), (0, b"\x01", []), (-5, b"\x01", []),
        (10, b"\x01", [3, 3, 4]), (600, b"\x01", [600]), (0x200, b"\x01", [0x1FE, 2]),
    ]
    for size, file_type, lengths in scenarios:
        driver = _driver()
        sent = []

        def send(request, _replies=iter(lengths)):
            sent.append(request._added[0])
            return _reply(bytes(next(_replies)))

        with mock.patch.object(SLCDriver, "send", side_effect=send):
            result = outcome(driver._read_whole_file_directory, {"size": size, "file_type": file_type})
        cases.append({"size": size, "file_type": file_type.hex(), "reply_lengths": lengths,
                      "requests": [s.hex() for s in sent], "result": result})
    # a PCCC error on a chunk
    driver = _driver()
    with mock.patch.object(SLCDriver, "send", return_value=_reply(sts=0x10)):
        cases.append({"size": 10, "file_type": "01", "reply_lengths": [], "requests": [], "status_error": True,
                      "result": outcome(driver._read_whole_file_directory, {"size": 10, "file_type": b"\x01"})})
    return cases


def _rows(*rows, row_size=10):
    return b"".join((bytes([code]) + UINT.encode(size)).ljust(row_size, b"\x00") for code, size in rows)


def file0_cases():
    cases = []
    samples = [
        ({"file_position": 0, "row_size": 10}, _rows((0x83, 20), (0x84, 20), (0x85, 20), (0x89, 20), (0x8A, 20), (0x86, 20))),
        ({"file_position": 0, "row_size": 10}, _rows((0x82, 20), (0x83, 20), (0x84, 20), (0x81, 0), (0x89, 20), (0x8A, 20))),
        ({"file_position": 0, "row_size": 10}, _rows((0x82, 6), (0x83, 6), (0x84, 66), (0x85, 2), (0x86, 30),
                                                     (0x87, 12), (0x88, 18), (0x89, 200), (0x8A, 40), (0x8D, 168),
                                                     (0x8E, 4), (0x91, 8), (0x92, 100), (0x93, 92), (0x94, 24),
                                                     (0x00, 5), (0x99, 7), (0x89, 3))),
        ({"file_position": 4, "row_size": 8}, b"\xaa\xbb\xcc\xdd" + _rows((0x82, 2), (0x83, 2), (0x89, 10), row_size=8)),
        ({"file_position": 3, "row_size": 10}, b"\x00" * 3 + _rows((0x89, 10)) + b"\x89"),
        ({"file_position": 3, "row_size": 10}, b"\x00" * 3 + _rows((0x89, 10)) + b"\x89\x01"),
        ({"file_position": 3, "row_size": 10}, b"\x00" * 3 + _rows((0x89, 10)) + b"\x00"),
        ({"file_position": 50, "row_size": 10}, _rows((0x89, 10))),
        ({"file_position": 0, "row_size": 10}, b""),
        ({"file_position": 0, "row_size": 10}, _rows((0x83, 2), (0x83, 4), (0x82, 2))),
        # review: reserved rows before the input file, unknown codes, odd sizes, 1-byte rows
        ({"file_position": 0, "row_size": 10}, _rows((0x81, 0), (0x83, 2), (0x84, 3))),
        ({"file_position": 0, "row_size": 10}, _rows((0x84, 2), (0x83, 2), (0x81, 0), (0x81, 0), (0x8D, 85))),
        ({"file_position": 0, "row_size": 3}, _rows((0x89, 0xFFFF), (0x8A, 7), (0x92, 49), row_size=3)),
        ({"file_position": 0, "row_size": 1}, bytes([0x89, 0x01, 0x00])),
        ({"file_position": 0, "row_size": 2}, bytes([0x89, 0x05, 0x00, 0x89])),
        ({"file_position": 1, "row_size": 10}, bytes([0x83]) + _rows((0x83, 2), (0x89, 2))),
    ]
    for info, data in samples:
        cases.append({"file_position": info["file_position"], "row_size": info["row_size"], "data": data.hex(),
                      "result": outcome(_parse_file0, info, data)})
    return cases


def bit_cases():
    return [{"value": v, "idx": i, "result": get_bit(v, i)} for v in (0, 1, 0x20, -1, 0x8000, -32768, 0x7FFFFFFF)
            for i in (0, 1, 5, 15, 31)]


def tables():
    return [{"name": k, "code": PCCC_DATA_TYPE[k][0], "size": PCCC_DATA_SIZE[k]}
            for k in PCCC_DATA_TYPE if isinstance(k, str)] + [{"ct": k, "value": v} for k, v in PCCC_CT.items()]


proc_requests, proc_replies = processor_type_cases()
dl_requests, dl_replies = datalog_cases()

write("pccc.json", {
    "tables": tables(),
    "parse_tag": parse_cases(),
    "strings": string_cases(),
    "writeable_value": writeable_cases(),
    "read_request": read_request_cases(),
    "write_request": write_request_cases(),
    "read_reply": read_reply_cases(),
    "request_status": status_cases(),
    "processor_type_request": proc_requests,
    "processor_type_reply": proc_replies,
    "datalog_request": dl_requests,
    "datalog_reply": dl_replies,
    "sys0_info": sys0_cases(),
    "file_directory_size": file_dir_size_cases(),
    "file_directory_read": file_dir_read_cases(),
    "parse_file0": file0_cases(),
    "get_bit": bit_cases(),
})
