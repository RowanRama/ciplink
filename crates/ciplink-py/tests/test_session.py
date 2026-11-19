"""
The session API against the simulator: asyncio reads and writes, callers packed into one read, subscriptions,
connection events and reconnect, closing with work pending, and the callback and GIL rules.
"""

import asyncio
import gc
import os
import sys
import threading
import time

import pytest

from conftest import REPO

sys.path.insert(0, os.path.join(REPO, "tools", "sim"))
from check_python_against_sim import Sim  # noqa: E402

sys.path.remove(os.path.join(REPO, "tools", "sim"))

from ciplink import CommError, ConnectionEvent, LogixDriver, SLCDriver, Subscription, Tag  # noqa: E402


def wait_for(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


@pytest.fixture(scope="module")
def sim():
    with Sim("example_controller.json") as sim:
        yield sim


@pytest.fixture
def plc(sim):
    with LogixDriver(sim.address) as plc:
        yield plc


# ---- asyncio reads and writes


def test_read_async_shapes_results_as_read(plc):
    async def main():
        one = await plc.read_async("dint1")
        two = await plc.read_async("dint1", "dint_ary[3]")
        none = await plc.read_async()
        return one, two, none

    one, two, none = asyncio.run(main())
    assert type(one) is Tag and one == plc.read("dint1")
    assert two == plc.read("dint1", "dint_ary[3]")
    assert none == []


def test_read_async_gathers_into_shared_reads(sim, plc):
    tags = ["dint1", "int1", "sint1", "real1", "dint_ary[1]"] * 4
    expected = [plc.read(t).value for t in tags]
    sim.cmd("fault", fault={"delay_ms": 50})
    try:
        before = sim.cmd("requests")

        async def main():
            return await asyncio.gather(*(plc.read_async(t) for t in tags))

        results = asyncio.run(main())
        sent = sim.cmd("requests") - before
    finally:
        sim.cmd("clear_faults")
    assert [r.value for r in results] == expected
    assert all(r.error is None for r in results)
    assert sent < len(tags)  # the reads queued behind the first went out together


def test_write_async_then_read_async(plc):
    value = [7, 8, 9]

    async def main():
        written = await plc.write_async("dint_ary{3}", value)
        both = await plc.write_async(("dint_ary[5]", 55), ("int1", 12))
        read = await plc.read_async("dint_ary{3}", "dint_ary[5]", "int1")
        return written, both, read

    try:
        written, both, read = asyncio.run(main())
        assert written.error is None and written.value is value  # the caller's object, as write gives
        assert [r.error for r in both] == [None, None]
        assert [r.value for r in read] == [value, 55, 12]
    finally:
        plc.write(("dint_ary{3}", [0, 100, 200]), ("dint_ary[5]", 500), ("int1", -1234))


def test_writes_keep_their_order_between_tasks(plc):
    async def main():
        writes = [plc.write_async("dint_ary[6]", i) for i in range(10)]
        read = plc.read_async("dint_ary[6]")
        await asyncio.gather(*writes)
        return await read

    try:
        assert asyncio.run(main()).value == 9  # the read was queued after every write
    finally:
        plc.write("dint_ary[6]", 600)


def test_read_async_raises_the_packages_errors(sim):
    plc = LogixDriver(sim.address)  # never opened: the core's own error, as read raises it

    async def main():
        return await plc.read_async("dint1")

    with pytest.raises(CommError):
        plc.read("dint1")
    with pytest.raises(CommError):
        asyncio.run(main())


def test_threads_and_tasks_share_one_driver(sim, plc):
    errors, results = [], []

    def work():
        try:
            for _ in range(20):
                results.append(plc.read("dint_ary[3]", "udt1.real"))
        except Exception as err:  # pragma: no cover - reported below
            errors.append(err)

    async def tasks():
        return await asyncio.gather(*(plc.read_async("dint_ary[3]", "udt1.real") for _ in range(40)))

    threads = [threading.Thread(target=work) for _ in range(3)]
    for t in threads:
        t.start()
    task_results = asyncio.run(tasks())
    for t in threads:
        t.join()
    assert not errors
    assert {(a.value, b.value) for a, b in results + task_results} == {(300, 1000.5)}


# ---- subscriptions


def test_subscribe_callback_gets_changes(sim, plc):
    got = []
    sub = plc.subscribe("dint_ary[7]", "dint1", interval=0.05, callback=got.append)
    try:
        assert wait_for(lambda: got)
        assert sorted(t.tag for t in got[0]) == ["dint1", "dint_ary[7]"]  # the first delivery has every tag
        plc.write("dint_ary[7]", 77)
        assert wait_for(lambda: any(t.tag == "dint_ary[7]" and t.value == 77 for c in got[1:] for t in c))
        assert all(t.tag == "dint_ary[7]" for c in got[1:] for t in c)  # only what changed
    finally:
        sub.close()
        plc.write("dint_ary[7]", 700)
    assert sub.closed


def test_subscribe_iterates_and_reports_quality(sim, plc):
    with plc.subscribe("dint_ary[8]", interval=0.05) as sub:
        assert isinstance(sub, Subscription) and sub.tags == ["dint_ary[8]"]
        first = next(iter(sub))
        assert first[0].value == 800 and first[0].error is None
        sim.cmd("fault", fault={"tag_status": {"tag": "dint_ary", "status": 5}})
        try:
            failed = sub.recv(timeout=5)
            assert failed is not None and failed[0].error is not None and failed[0].value is None
        finally:
            sim.cmd("clear_faults")
        good = sub.recv(timeout=5)
        assert good is not None and good[0].error is None and good[0].value == 800
    assert sub.closed and list(sub) == []


def test_subscribe_async_iterator(sim, plc):
    async def main():
        sub = plc.subscribe("dint_ary[9]", interval=0.05)
        seen = []
        async for tags in sub:
            seen.append(tags[0].value)
            if len(seen) == 1:
                await plc.write_async("dint_ary[9]", 99)
            else:
                sub.close()  # ends the loop
        return seen

    try:
        assert asyncio.run(asyncio.wait_for(main(), 10)) == [900, 99]
    finally:
        plc.write("dint_ary[9]", 900)


def test_closing_the_driver_ends_async_iteration(sim):
    plc = LogixDriver(sim.address)
    plc.open()

    async def main():
        sub = plc.subscribe("dint1", interval=0.05)
        count = 0
        async for _ in sub:
            count += 1
            plc.close()
        return count, sub.closed

    assert asyncio.run(asyncio.wait_for(main(), 10)) == (1, True)


# ---- connection events and reconnect


def test_connection_events_and_reconnect(sim):
    events = []
    plc = LogixDriver(sim.address, keep_alive=None)
    plc.on_connection(events.append)
    assert plc.connection_state == "closed"
    try:
        assert plc.open()
        assert wait_for(lambda: events) and events[0] == ConnectionEvent("connected", None, None, None)
        assert plc.connection_state == "connected"

        sim.cmd("fault", fault={"refuse_connections": True})
        sim.cmd("fault", fault={"close_connections": True})
        with pytest.raises(CommError):
            plc.read("dint1")  # the request that finds the link lost returns its error
        assert plc.connection_state == "reconnecting"
        start = time.perf_counter()
        with pytest.raises(CommError, match="not connected, reconnecting"):
            plc.read("dint1")  # fails fast while reconnecting
        assert time.perf_counter() - start < 0.5

        async def fails():
            return await plc.read_async("dint1")

        with pytest.raises(CommError, match="reconnecting"):
            asyncio.run(fails())
        assert wait_for(lambda: sum(e.event == "reconnecting" for e in events) >= 2)

        sim.cmd("clear_faults")
        assert wait_for(lambda: plc.connection_state == "connected", timeout=15)
        assert plc.read("dint1").value == 2147483647
    finally:
        sim.cmd("clear_faults")
        plc.close()

    kinds = [e.event for e in events]
    assert kinds[:3] == ["connected", "disconnected", "reconnecting"] and kinds[-1] == "connected"
    assert events[1].error  # why the link was lost
    attempts = [e for e in events if e.event == "reconnecting"]
    assert [e.attempt for e in attempts[:3]] == [1, 2, 3][:len(attempts[:3])]
    assert attempts[0].delay == pytest.approx(0.1)
    assert all(b.delay >= a.delay for a, b in zip(attempts, attempts[1:]))  # backoff doubles
    plc.on_connection(None)


def test_close_stops_reconnecting(sim):
    events = []
    plc = LogixDriver(sim.address, keep_alive=None)
    plc.on_connection(events.append)
    plc.open()
    try:
        sim.cmd("fault", fault={"refuse_connections": True})
        sim.cmd("fault", fault={"close_connections": True})
        with pytest.raises(CommError):
            plc.read("dint1")
        assert wait_for(lambda: any(e.event == "reconnecting" for e in events))
        plc.close()
        assert plc.connection_state == "closed"
        seen = len(events)
        time.sleep(0.4)
        assert len(events) == seen  # no attempts after close
    finally:
        sim.cmd("clear_faults")


def test_reconnect_can_be_turned_off(sim):
    plc = LogixDriver(sim.address, reconnect=False, keep_alive=None)
    plc.open()
    try:
        sim.cmd("fault", fault={"close_connections": True})
        with pytest.raises(CommError):
            plc.read("dint1")
        assert plc.connection_state == "closed"
    finally:
        sim.cmd("clear_faults")
        plc.close()


def test_bad_session_options_are_value_errors(sim):
    with pytest.raises(ValueError):
        LogixDriver(sim.address, keep_alive=0)
    with pytest.raises(ValueError):
        SLCDriver(sim.address, keep_alive=float("nan"))
    with LogixDriver(sim.address) as plc:
        with pytest.raises(ValueError):
            plc.subscribe("dint1", interval=0)


# ---- closing with work pending


def test_close_fails_pending_requests(sim):
    plc = LogixDriver(sim.address)
    plc.open()
    sub = plc.subscribe("dint1", interval=10)
    assert sub.recv(timeout=5)  # its first poll is done
    sim.cmd("fault", fault={"delay_ms": 300})
    try:
        async def main():
            first = asyncio.ensure_future(plc.read_async("dint1"))
            await asyncio.sleep(0.1)  # in flight on the session thread
            queued = [asyncio.ensure_future(plc.read_async(t)) for t in ("int1", "sint1")]
            queued.append(asyncio.ensure_future(plc.write_async("dint_ary[2]", 1)))
            await asyncio.sleep(0.02)
            await asyncio.get_running_loop().run_in_executor(None, plc.close)
            return await asyncio.gather(first, *queued, return_exceptions=True)

        first, *queued = asyncio.run(main())
    finally:
        sim.cmd("clear_faults")
    assert first.value == 2147483647  # the request in flight finished
    assert all(isinstance(r, CommError) and "driver closed" in str(r) for r in queued)
    assert sub.closed and sub.recv(timeout=0.1) is None
    assert plc.connection_state == "closed"
    with LogixDriver(sim.address) as again:
        assert again.read("dint_ary[2]").value == 200  # the queued write was never sent


# ---- callbacks and the GIL


def test_callbacks_can_call_the_driver_synchronously(sim, plc):
    got = []
    done = threading.Event()

    def on_changes(tags):
        got.append(plc.read("dint_ary[4]").value)  # a blocking call from the callback thread
        done.set()

    with plc.subscribe("dint1", interval=0.05, callback=on_changes):
        assert done.wait(5)
    assert got[0] == 400

    results = []
    finished = threading.Event()

    def done_cb(tags, error):
        results.append((plc.read("dint1").value, tags[0].value, error))
        finished.set()

    plc._core.read_async(["int1"], done_cb)
    assert finished.wait(5)
    assert results == [(2147483647, -1234, None)]


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_a_raising_callback_is_reported_and_dropped(sim, plc):
    calls = []

    def bad(tags):
        calls.append(tags)
        raise ValueError("callback bug")

    seen = []
    with plc.subscribe("dint1", interval=0.05, callback=bad):
        assert wait_for(lambda: calls)
        with plc.subscribe("int1", interval=0.05, callback=seen.append):  # the callback thread carries on
            assert wait_for(lambda: seen)


def test_deleting_the_driver_in_a_callback(sim):
    holder = [LogixDriver(sim.address)]
    holder[0].open()
    finished = threading.Event()

    def done(tags, error):
        holder.clear()  # the last reference: the driver is dropped on its own callback thread
        gc.collect()
        finished.set()

    holder[0]._core.read_async(["dint1"], done)
    assert finished.wait(5)


def test_dropping_a_driver_with_a_pending_callback_does_not_hang(sim):
    plc = LogixDriver(sim.address)
    plc.open()
    started = threading.Event()
    calls = []

    def slow(tags, error):
        started.set()
        time.sleep(0.2)
        calls.append(error)

    plc._core.read_async(["dint1"], slow)
    plc._core.read_async(["dint1"], lambda tags, error: calls.append(error))
    assert started.wait(5)
    start = time.perf_counter()
    del plc  # holds the GIL while the next callback waits for it
    gc.collect()
    assert time.perf_counter() - start < 5
    assert len(calls) == 2  # every callback already queued ran before the drop returned


def test_blocking_waits_release_the_gil(sim, plc):
    counts = []
    stop = threading.Event()

    def spin():
        n = 0
        while not stop.is_set():
            n += 1
        counts.append(n)

    with plc.subscribe("dint1", interval=10) as sub:
        sub.recv(timeout=5)  # the first delivery
        thread = threading.Thread(target=spin)
        thread.start()
        try:
            assert sub.recv(timeout=0.3) is None  # nothing changes
        finally:
            stop.set()
            thread.join()
    assert counts[0] > 100_000


# ---- SLC


def test_slc_async_subscribe_and_events():
    with Sim("example_slc.json") as sim:
        events = []
        plc = SLCDriver(sim.address)
        plc.on_connection(events.append)
        with plc:
            async def main():
                one = await plc.read_async("N7:0")
                both = await asyncio.gather(plc.read_async("N7:0", "F8:0"), plc.read_async("N7:1"))
                written = await plc.write_async(("N7:20{3}", [4, 5, 6]))
                return one, both, written

            one, (both, other), written = asyncio.run(main())
            assert one.value == 10 and both[1].value == 1.5 and other == plc.read("N7:1")
            assert written.error is None and plc.read("N7:20{3}").value == [4, 5, 6]
            with plc.subscribe("N7:0", interval=0.05) as sub:
                assert sub.recv(timeout=5)[0].value == 10
            assert plc.connection_state == "connected"
        assert plc.connection_state == "closed"
        assert [e.event for e in events] == ["connected"]
