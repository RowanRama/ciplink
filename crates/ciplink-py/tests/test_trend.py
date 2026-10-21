"""
Controller-side trends through the Python API, against the simulator's trend object.
"""

import datetime
import os
import sys
import time

import pytest

from conftest import REPO

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import Sim  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import CommError, LogixDriver, RequestError, Trend, TrendPen, TrendSample  # noqa: E402


@pytest.fixture(scope="module")
def sim():
    with Sim("example_controller.json") as sim:
        yield sim


@pytest.fixture
def plc(sim):
    with LogixDriver(sim.address, lazy_tags=True, socket_timeout=0.5) as plc:
        yield plc


def collect(trend, n, timeout=2.0):
    samples, deadline = [], time.monotonic() + timeout
    while len(samples) < n and time.monotonic() < deadline:
        samples.extend(trend.read())
        time.sleep(0.005)
    return samples


def test_trends_atomic_tags_members_elements_and_bits(plc):
    tags = ["sint1", "int1", "dint1", "usint1", "uint1", "udint1", "real1", "bool1", "timer1.ACC", "timer1.DN",
            "timer1.EN", "udt4.b4", "udt4.bb20", "dint_ary[3]", "bool_ary[31]", "bool_ary[33]", "dint_ary[1].2",
            "Program:MainProgram.p_dint"]
    with plc.trend(*tags, period_ms=5) as trend:
        assert isinstance(trend, Trend)
        assert trend.pens[0] == TrendPen("sint1", "SINT")
        assert [p.data_type for p in trend.pens][7:] == ["BOOL", "DINT"] + ["BOOL"] * 4 + ["DINT"] + ["BOOL"] * 3 \
            + ["DINT"]
        samples = collect(trend, 3)
        expected = plc.read(*tags)
        assert trend.running
    assert not trend.running
    assert len(samples) >= 3
    first = samples[0]
    assert isinstance(first, TrendSample)
    assert first.values == tuple(t.value for t in expected)
    assert first.timestamp_us == trend.start_time_us + first.elapsed_us
    assert first.timestamp.tzinfo == datetime.timezone.utc
    assert abs((samples[1].elapsed_us - first.elapsed_us) - 5000) < 128


def test_samples_follow_tag_changes(sim, plc):
    with plc.trend("dint_ary[5]", period_ms=2, duration=10) as trend:
        collect(trend, 1)
        sim.cmd("set", path="dint_ary[5]", value=-77)
        deadline = time.monotonic() + 2
        values = set()
        while -77 not in values and time.monotonic() < deadline:
            values.update(s.values[0] for s in trend.read())
            time.sleep(0.005)
    sim.cmd("set", path="dint_ary[5]", value=500)
    assert -77 in values


def test_a_trend_with_a_duration_stops_by_itself(plc):
    trend = plc.trend("dint1", period_ms=5, duration=0.05)
    deadline = time.monotonic() + 2
    while trend.running and time.monotonic() < deadline:
        time.sleep(0.005)
    assert not trend.running
    samples = trend.read()
    assert len(samples) >= 8
    assert trend.received_samples == len(samples)
    assert trend.dropped_samples == 0
    trend.close()


def test_capacity_bounds_the_unread_samples(plc):
    with plc.trend("dint1", period_ms=1, capacity=5) as trend:
        deadline = time.monotonic() + 2
        while trend.received_samples < 30 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert len(trend.read()) == 5
        assert trend.dropped_samples >= 25


@pytest.mark.parametrize("tags", [("lint1",), ("lreal1",), ("str1",), ("udt1",), ("dint_ary{2}",), ("nope",), ()])
def test_unsupported_pens_are_request_errors(plc, tags):
    with pytest.raises(RequestError):
        plc.trend(*tags)


def test_bad_options_raise(plc):
    with pytest.raises(ValueError):
        plc.trend("dint1", duration=0)
    with pytest.raises(RequestError):
        plc.trend("dint1", capacity=0)


def test_a_lost_connection_is_raised_after_the_samples(sim, plc):
    trend = plc.trend("dint1", period_ms=5)
    collect(trend, 1)
    sim.cmd("fault", fault={"drop_replies": 1000})
    try:
        deadline = time.monotonic() + 3
        while trend.running and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        sim.cmd("clear_faults")
    assert isinstance(trend.error, CommError)
    with pytest.raises(CommError):
        for _ in range(2):  # what arrived before the failure, then the error
            trend.read()
    with pytest.raises(CommError):
        trend.close()
