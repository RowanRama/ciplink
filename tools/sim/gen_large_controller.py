"""
Writes large_controller.json: a simulator configuration with about 2000 tags and 150 structure types (UDTs nested
three levels deep, arrays of them, strings, timers and AOIs with local tags) across the controller and eight
programs, for the tag definition benchmarks (crates/ciplink-py/bench/tags_bench.py).  Deterministic::

    python tools/sim/gen_large_controller.py
"""

import copy
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
ATOMIC = ["BOOL", "SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "REAL", "LREAL"]
PREDEFINED = ["TIMER", "COUNTER", "CONTROL", "STRING"]


def member(rng, name, types):
    typ = rng.choice(types)
    m = {"name": name, "type": typ}
    if rng.random() < 0.25:
        m["dim"] = 64 if typ == "BOOL" else rng.choice([2, 4, 5, 10, 16])
    return m


def config():
    rng = random.Random(20261020)
    with open(os.path.join(HERE, "example_controller.json")) as f:
        base = json.load(f)
    cfg = {k: copy.deepcopy(base[k]) for k in ("kind", "identity", "slot", "program_name", "modules", "tasks",
                                               "system_tags")}
    types = []
    strings = [f"STR{n}" for n in (8, 16, 24, 32, 40, 48, 64, 82, 100, 120)]
    types += [{"name": name, "string": int(name[3:])} for name in strings]
    leaves = [f"Leaf{i:03}" for i in range(60)]
    for name in leaves:
        types.append({"name": name, "members": [member(rng, f"m{j}", ATOMIC) for j in range(rng.randint(3, 12))]})
    aois = [f"Aoi{i:02}" for i in range(15)]
    for name in aois:
        members = [member(rng, f"In{j}", ATOMIC) for j in range(rng.randint(2, 6))]
        members += [dict(member(rng, f"Loc{j}", ATOMIC), local=True) for j in range(rng.randint(1, 4))]
        types.append({"name": name, "aoi": True, "members": members})
    mids = [f"Mid{i:03}" for i in range(45)]
    for name in mids:
        pool = leaves + strings + PREDEFINED + ATOMIC
        types.append({"name": name, "members": [member(rng, f"s{j}", pool) for j in range(rng.randint(4, 10))]})
    tops = [f"Top{i:03}" for i in range(30)]
    for name in tops:
        pool = mids + leaves + ATOMIC + ["TIMER"]
        types.append({"name": name, "members": [member(rng, f"t{j}", pool) for j in range(rng.randint(3, 8))]})
    cfg["types"] = types

    pool = ATOMIC * 6 + leaves + mids + tops + aois + strings + PREDEFINED

    def tag(name):
        typ = rng.choice(pool)
        t = {"name": name, "type": typ}
        r = rng.random()
        if r < 0.15:
            t["dims"] = [rng.choice([32, 64, 96])] if typ == "BOOL" else [rng.choice([2, 3, 5, 10, 20, 50])]
        elif r < 0.18 and typ != "BOOL":
            t["dims"] = [rng.randint(2, 4), rng.randint(2, 5)]
        elif r < 0.19 and typ != "BOOL":
            t["dims"] = [2, 2, rng.randint(2, 3)]
        return t

    cfg["tags"] = [tag(f"Tag{i:04}") for i in range(1600)]
    cfg["programs"] = [
        {"name": f"Program{p}", "routines": ["MainRoutine", "Sub"], "tags": [tag(f"p{p}_{i:03}") for i in range(50)]}
        for p in range(8)
    ]
    return cfg


if __name__ == "__main__":
    out = os.path.join(HERE, "large_controller.json")
    with open(out, "w") as f:
        json.dump(config(), f, indent=1)
        f.write("\n")
    cfg = config()
    print(f"wrote {out}: {len(cfg['tags']) + sum(len(p['tags']) for p in cfg['programs'])} tags, "
          f"{len(cfg['types'])} types")
