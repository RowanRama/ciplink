"""
The simulator acceptance checks (tools/sim/check_python_against_sim.py) against the Rust-backed package, in this
interpreter; the last scenario (the repo's online tests against the demo PLC's program) runs tests/online with it.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile

from conftest import REPO, run_pytest

SIM_DIR = os.path.join(REPO, "tools", "sim")


def load_script():
    spec = importlib.util.spec_from_file_location("check_python_against_sim",
                                                  os.path.join(SIM_DIR, "check_python_against_sim.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # ciplink is already imported: the package under test
    return module


def online_tests(check, sim_bin):
    """run_online_tests.py, with tests/online run in a subprocess of this interpreter"""
    sys.path.insert(0, SIM_DIR)
    try:
        from l5x_to_config import convert
    finally:
        sys.path.remove(SIM_DIR)
    config, _ = convert(os.path.join(REPO, "tests", "pycomm3.L5X"), revision="20.19",
                        product_name="1769-L23E-QBFC1 LOGIX5323E-QBFC1", product_code=89, serial="c00fa09b",
                        aoi_locals_readable=True)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)
    sim = subprocess.Popen([sim_bin(), "--config", path, "--port", "0", "--exit-on-eof"], cwd=REPO,
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        line = sim.stdout.readline()
        word1 = [i in (13, 28) for i in range(32)]
        for tag in ("read_bool_ary1[1]", "Program:pycomm3.read_prog_bool_ary1[1]"):
            sim.stdin.write(json.dumps({"cmd": "set", "path": tag, "value": word1}) + "\n")
            sim.stdin.flush()
            assert "error" not in json.loads(sim.stdout.readline())
        tests = [os.path.join("tests", "online", name) for name in ("test_reads.py", "test_writes.py")]
        result = run_pytest(REPO, "-q", "-p", "no:warnings", *tests,
                            env={"PLCPATH": line.split()[-1]})
        check(f"online tests against the demo program ({result.stdout.strip().splitlines()[-1:]})",
              result.returncode, 0)
    finally:
        sim.stdin.close()
        sim.wait(10)
        os.remove(path)


REFERENCE_CHECKS = 2970  # the reference driver's count (``check_python_against_sim.py --reference``)
WHITE_BOX_CHECKS = 4  # the lost Forward Open reply step, run with the reference only (see the script)


def test_simulator_checks(capsys):
    script = load_script()
    script.scenario_online_tests = lambda: online_tests(script.check, script.sim_bin)
    script.main()
    out = capsys.readouterr().out
    print(out)
    assert not script.FAILURES, out
    assert script.CHECKS == REFERENCE_CHECKS - WHITE_BOX_CHECKS, out
