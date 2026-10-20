# Python tests

These tests use the public API of the installed `ciplink` package (the Rust-backed one built from `python/` and
`crates/ciplink-py`).  Run them from the repo root against a built wheel, e.g.:

```sh
uv run --no-project --isolated -p 3.12 --with target/wheels/<wheel> --with pytest python -m pytest tests/offline
```

| Directory | What | Needs |
|---|---|---|
| `offline/` | path parsing, data types and custom types, packets, tags, credentials and metadata helpers, the examples, socket and transport lifecycle through the public API | nothing |
| `online/` | reads and writes of every kind of tag in `pycomm3.L5X` | a PLC loaded with `pycomm3.L5X`, its path in `PLCPATH`; or `tools/sim/run_online_tests.py`, which loads the project into the simulator |

## Where the other tests went

`offline/` used to hold the whole test suite of the pure-Python driver.  Most of those tests were white-box: they
patched the driver's internals (`_sock`, `send`, `_forward_open`, `_target_is_connected`, `_info`, `_read_tag`,
`Socket`...) with scripted replies, or imported private helpers (`encode_value`, `_RELOAD_BACKOFF`,
`logix_descriptions`).  The Rust core replaced those internals, so the tests no longer apply to the package.  Their
behaviour is still checked, against the code that now does the work:

- **The full original suite** moved, unchanged, to `tools/reference/tests` with the reference driver it tests
  (`tools/reference/ciplink_ref`).  The fixture generators reuse its scripted controllers.
- **Rust fixtures.** `tools/fixtures/gen_*.py` run the scenarios of those tests on the reference driver and record
  every request frame, reply and result as JSON (`crates/ciplink/tests/fixtures`).  The Rust tests in
  `crates/ciplink/tests` replay them and must produce the same bytes and results.
- **Differential harness.** `crates/ciplink-sim/tests/differential.rs` runs 69 scenarios (reads, writes, uploads,
  online edits, faults, Micro800, SLC) with the reference and the Rust driver against identical simulators, and
  requires byte-identical request frames and identical results.
- **Binding tests.** `crates/ciplink-py/tests` check the package against the simulator: the binding itself, the tag
  definitions and cache file, parity of what users read (`plc.tags`, `data_types`, `info`...) with the reference, and
  the simulator acceptance checks of `tools/sim/check_python_against_sim.py`.

What stayed in `offline/` are the tests that use only the public API: they passed unchanged against both drivers.
