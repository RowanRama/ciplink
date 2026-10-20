"""
CPU per call of the Rust-backed package against the reference Python driver, both reading from ``ciplink-sim``:
a read of 200 DINT tags, a read of REAL[10000] (fragmented) and a write of 200 DINT tags (connection size 4000).
The simulator runs in its own process, so ``time.process_time`` counts the client's CPU only; wall time is shown
too.  Run from anywhere with the Rust-backed package importable::

    uv run --no-project --isolated --python 3.12 --with <wheel> python crates/ciplink-py/bench/cpu_bench.py

The reference driver (tools/reference) runs in a subprocess with the same script (``--driver REFERENCE_DIR ADDRESS``).
The in-memory baseline of the roadmap (the reference driver with its send() replaced by an in-memory controller,
a throwaway script, not in the repo) was 14.6 ms for the 200-DINT read and 10.8 ms for REAL[10000].
"""

import copy
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REFERENCE = os.path.join(REPO, "tools", "reference")
NAMES = [f"T{i}" for i in range(200)]
CASES = [  # (label, calls)
    ("read 200 DINT tags", 200),
    ("read REAL[10000]", 50),
    ("write 200 DINT tags", 200),
]


def bench(plc):
    calls = {
        "read 200 DINT tags": lambda: plc.read(*NAMES),
        "read REAL[10000]": lambda: plc.read("Big{10000}"),
        "write 200 DINT tags": lambda: plc.write(*[(n, 7) for n in NAMES]),
    }
    out = {}
    for label, n in CASES:
        fn = calls[label]
        result = fn()
        assert all(result) if isinstance(result, list) else result, result
        cpu, wall = time.process_time(), time.perf_counter()
        for _ in range(n):
            fn()
        out[label] = ((time.process_time() - cpu) / n * 1e3, (time.perf_counter() - wall) / n * 1e3)
    return out


def run_driver(address):
    from ciplink import LogixDriver

    with LogixDriver(address, connection_size=4000) as plc:
        return bench(plc)


def config():
    with open(os.path.join(REPO, "tools", "sim", "example_controller.json")) as f:
        base = json.load(f)
    cfg = copy.deepcopy(base)
    cfg["programs"] = []
    cfg["tags"] = [{"name": n, "type": "DINT", "value": i} for i, n in enumerate(NAMES)]
    cfg["tags"].append({"name": "Big", "type": "REAL", "dims": [10000], "value": [1.5] * 10000})
    return cfg


def main():
    sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
    import ciplink  # the package under test

    from check_python_against_sim import Sim

    assert hasattr(ciplink, "_core"), "run with the Rust-backed package"
    with Sim(config()) as sim:
        new = run_driver(sim.address)
        ref = subprocess.run([sys.executable, __file__, "--driver", REFERENCE, sim.address], capture_output=True,
                             text=True, check=True)
        old = json.loads(ref.stdout)
    print(f"{'':<24} {'reference CPU':>14} {'Rust CPU':>10} {'speed-up':>9}   {'ref wall':>9} {'Rust wall':>9}")
    for label, _ in CASES:
        (oc, ow), (nc, nw) = old[label], new[label]
        print(f"{label:<24} {oc:11.3f} ms {nc:7.3f} ms {oc / max(nc, 1e-9):8.1f}x   {ow:6.3f} ms {nw:6.3f} ms")
    print("in-memory baseline of the reference driver (roadmap): 14.6 ms (200 DINT), 10.8 ms (REAL[10000])")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--driver"]:
        sys.path.insert(0, sys.argv[2])
        import reference

        reference.load()  # the reference package as ciplink
        print(json.dumps(run_driver(sys.argv[3])))
    else:
        main()
