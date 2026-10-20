"""
Runs the repo's online tests (tests/online, written for the pycomm3 demo PLC) with the installed ``ciplink`` (or,
with ``--reference``, the reference Python driver of tools/reference) against ``ciplink-sim`` loaded with that PLC's
program, tests/pycomm3.L5X (converted by l5x_to_config.py as the v20 1769-L23E demo controller, which lets clients
read AOI local tags).  Run it from the repo root with pytest and the package under test importable, e.g.::

    uv run --no-project --isolated --python 3.12 --with pytest --with <wheel> python tools/sim/run_online_tests.py

``--reference`` (and any pytest options) go after the script name.  test_demo_plc.py is not run: it checks the demo
PLC's I/O modules and task, which the L5X export does not hold, and UDP discovery of the real network.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

from l5x_to_config import convert  # noqa: E402


def main():
    config, _ = convert(os.path.join(ROOT, "tests", "pycomm3.L5X"), revision="20.19",
                        product_name="1769-L23E-QBFC1 LOGIX5323E-QBFC1", product_code=89, serial="c00fa09b",
                        aoi_locals_readable=True)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)
    subprocess.run(["cargo", "build", "-q", "-p", "ciplink-sim"], cwd=ROOT, check=True)
    target = os.environ.get("CARGO_TARGET_DIR", os.path.join(ROOT, "target"))
    binary = os.path.join(target, "debug", "ciplink-sim" + (".exe" if os.name == "nt" else ""))
    sim = subprocess.Popen(
        [binary, "--config", path, "--port", "0", "--exit-on-eof"],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    try:
        line = sim.stdout.readline()
        if not line.startswith("listening on "):
            raise RuntimeError(f"simulator did not start: {line!r}")
        # the demo's ladder logic latches bits 45 and 60 (OTL) after the exported memory image was taken
        word1 = [i in (13, 28) for i in range(32)]
        for tag in ("read_bool_ary1[1]", "Program:pycomm3.read_prog_bool_ary1[1]"):
            sim.stdin.write(json.dumps({"cmd": "set", "path": tag, "value": word1}) + "\n")
            sim.stdin.flush()
            reply = json.loads(sim.stdout.readline())
            if "error" in reply:
                raise RuntimeError(f"cannot set {tag}: {reply['error']}")
        env = {**os.environ, "PLCPATH": line.split()[-1]}
        tests = [os.path.join("tests", "online", name) for name in ("test_reads.py", "test_writes.py")]
        options = [arg for arg in sys.argv[1:] if arg != "--reference"]
        pytest = ["-m", "pytest"]
        if len(options) < len(sys.argv[1:]):  # the reference registered as ciplink before pytest imports the tests
            pytest = ["-c", "import sys, pytest; sys.path.insert(0, 'tools/reference'); import reference; "
                            "reference.load(); sys.exit(pytest.main(sys.argv[1:]))"]
        return subprocess.run([sys.executable, *pytest, "-q", "-p", "no:cacheprovider", *tests, *options],
                              cwd=ROOT, env=env).returncode
    finally:
        sim.stdin.close()
        sim.wait(10)
        os.remove(path)


if __name__ == "__main__":
    sys.exit(main())
