"""
Shared helpers for the fixture generators.

The generators run the reference Python driver (tools/reference/ciplink_ref, ciplink 0.2.0 from commit 9159540,
loaded as ``ciplink`` by tools/reference/reference.py) and write what it does as JSON fixtures; the Rust tests
(crates/ciplink/tests/) must reproduce them exactly.  Run them from the repo root in an environment without the
Rust-backed package, e.g. ``uv run --no-project --isolated --python 3.12 python tools/fixtures/gen_codec.py``.

Values are written tagged so Python's types survive JSON: {"bool": b}, {"int": n}, {"float": x}, {"str": s},
{"bytes": hex}, {"list": [...]}, {"dict": [[key, value], ...]} and null for None.
"""

import json
import math
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIXTURES = os.path.join(ROOT, "crates", "ciplink", "tests", "fixtures")
sys.path.insert(0, os.path.join(ROOT, "tools", "reference"))  # reference.py and its tests (``tests.offline``)
sys.path.append(ROOT)  # examples/

import reference  # noqa: E402

reference.load()  # every generator imports fixturelib before ciplink


def enc(value):
    """a Python value as tagged JSON"""
    if value is None:
        return None
    if isinstance(value, bool):
        return {"bool": value}
    if isinstance(value, int):
        return {"int": value}
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return {"float": repr(value)}
        return {"float": value}
    if isinstance(value, str):
        return {"str": value}
    if isinstance(value, (bytes, bytearray)):
        return {"bytes": bytes(value).hex()}
    if isinstance(value, (list, tuple)):
        return {"list": [enc(v) for v in value]}
    if isinstance(value, dict):
        return {"dict": [[str(k), enc(v)] for k, v in value.items()]}
    raise TypeError(f"cannot encode {value!r}")


def outcome(fn, *args, **kwargs):
    """{"ok": tagged result} or {"err": exception class name, "msg": message} of calling fn"""
    try:
        return {"ok": enc(fn(*args, **kwargs))}
    except Exception as err:  # the class name is the contract, the message is informative
        return {"err": type(err).__name__, "msg": str(err)}


def write(name, data):
    os.makedirs(FIXTURES, exist_ok=True)
    path = os.path.join(FIXTURES, name)
    with open(path, "w", encoding="utf-8", newline="\n") as file:
        json.dump(data, file, indent=1, ensure_ascii=False)
        file.write("\n")
    count = sum(len(v) for v in data.values() if isinstance(v, list))
    print(f"wrote {os.path.relpath(path, ROOT)} ({count} cases)")
