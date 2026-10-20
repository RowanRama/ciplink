"""
Tag definition costs of the Rust-backed package against the reference Python driver, both connected to
``ciplink-sim`` serving tools/sim/large_controller.json (2000 tags, 160 structure types, written by
tools/sim/gen_large_controller.py): the open with its tag list upload, the first and a repeated ``plc.tags``,
``plc.data_types``, ``plc.tags_json``, ``get_tag_info`` and the opens through the tag cache file.  Run from anywhere
with the Rust-backed package importable::

    uv run --no-project --isolated --python 3.12 --with <wheel> python crates/ciplink-py/bench/tags_bench.py

The reference driver (tools/reference) runs in a subprocess with the same script (``--driver REFERENCE_DIR ADDRESS
DIR``).  Each row is the median of ``REPEAT`` runs, wall time (the per-call rows: the best of ``timeit`` repeats).
The simulator is the release build, run in its own process.  Both drivers build the tag dicts during the open (the
Rust-backed one from what its core uploaded), so the first ``plc.tags`` costs no more than the next.
"""

import gc
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import timeit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REFERENCE = os.path.join(REPO, "tools", "reference")
REPEAT = 7
ROWS = [  # (key, label, unit)
    ("open", "open (upload, tag dicts)", "ms"),
    ("tags_first", "first plc.tags", "us"),
    ("tags_again", "repeat plc.tags", "ns"),
    ("data_types", "repeat plc.data_types", "ns"),
    ("tags_json", "plc.tags_json", "ms"),
    ("tag_info_base", "get_tag_info, tag", "us"),
    ("tag_info_member", "get_tag_info, member", "us"),
    ("open_cold_file", "open, no cache file (writes it)", "ms"),
    ("open_warm_file", "open from the cache file", "ms"),
    ("warm_total", "open from the cache file + plc.tags", "ms"),
]


def info_names(tags):
    """(tags, members one or two levels down) of every tenth tag"""
    names, members = [], []
    for name, tag in list(tags.items())[::10]:
        names.append(name)
        path, info = name, tag
        for _ in range(2):
            if info["tag_type"] != "struct":
                break
            attrs = info["data_type"]["attributes"]
            if not attrs:
                break
            attr = attrs[len(attrs) // 2]
            path, info = f"{path}.{attr}", info["data_type"]["internal_tags"][attr]
            members.append(path)
    return names, members


def timed(fn):
    start = time.perf_counter()
    result = fn()
    return time.perf_counter() - start, result


def per_call(stmt, **names):
    """seconds per execution of ``stmt``, the best of 5 timeit repeats"""
    number = 2000
    return min(timeit.repeat(stmt, globals=names, number=number, repeat=5)) / number


def measure(address, workdir):
    from ciplink import LogixDriver

    runs = {key: [] for key, _, _ in ROWS}
    cache_file = os.path.join(workdir, "tag_cache")
    for i in range(REPEAT):
        tags = plc = None  # freed here, not inside a timed step
        gc.collect()
        plc = LogixDriver(address)
        t, _ = timed(plc.open)
        runs["open"].append(t)
        start = time.perf_counter()
        tags = plc.tags
        runs["tags_first"].append(time.perf_counter() - start)
        runs["tags_again"].append(per_call("plc.tags", plc=plc))
        runs["data_types"].append(per_call("plc.data_types", plc=plc))
        t, _ = timed(lambda: plc.tags_json)
        runs["tags_json"].append(t)
        names, members = info_names(tags)
        runs["tag_info_base"].append(per_call("for n in names: info(n)", names=names, info=plc.get_tag_info) / len(names))
        runs["tag_info_member"].append(per_call("for n in names: info(n)", names=members, info=plc.get_tag_info)
                                       / len(members))
        plc.close()

        if os.path.exists(cache_file):
            os.remove(cache_file)
        tags = plc = None
        gc.collect()
        plc = LogixDriver(address, tag_cache_file=cache_file)
        t, _ = timed(plc.open)
        runs["open_cold_file"].append(t)
        plc.close()
        plc = None
        gc.collect()
        plc = LogixDriver(address, tag_cache_file=cache_file)
        t, _ = timed(plc.open)
        runs["open_warm_file"].append(t)
        start = time.perf_counter()
        tags = plc.tags
        runs["warm_total"].append(t + time.perf_counter() - start)
        assert len(tags) == 2000, len(tags)
        plc.close()
    return {key: statistics.median(values) for key, values in runs.items()}


def sim_release_bin():
    subprocess.run(["cargo", "build", "-q", "--release", "-p", "ciplink-sim"], cwd=REPO, check=True)
    target = os.environ.get("CARGO_TARGET_DIR", os.path.join(REPO, "target"))
    return os.path.join(target, "release", "ciplink-sim" + (".exe" if os.name == "nt" else ""))


def main():
    sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
    import ciplink  # the package under test

    import check_python_against_sim
    from check_python_against_sim import Sim

    assert hasattr(ciplink, "_core"), "run with the Rust-backed package"
    check_python_against_sim.sim_bin.path = sim_release_bin()
    with Sim("large_controller.json") as sim, tempfile.TemporaryDirectory() as workdir:
        ref = subprocess.run([sys.executable, __file__, "--driver", REFERENCE, sim.address, workdir],
                             capture_output=True, text=True)
        if ref.returncode:
            sys.exit(ref.stderr)
        old = json.loads(ref.stdout)
        new = measure(sim.address, workdir)
    scale = {"ms": 1e3, "us": 1e6, "ns": 1e9}
    print(f"{'':<40} {'reference':>12} {'Rust-backed':>12} {'speed-up':>9}")
    for key, label, unit in ROWS:
        o, n = old[key] * scale[unit], new[key] * scale[unit]
        print(f"{label:<40} {o:9.2f} {unit} {n:9.2f} {unit} {o / max(n, 1e-12):8.1f}x")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--driver"]:
        sys.path.insert(0, sys.argv[2])
        import reference

        reference.load()  # the reference package as ciplink
        print(json.dumps(measure(sys.argv[3], sys.argv[4])))
    else:
        main()
