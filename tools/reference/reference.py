"""
Makes the reference Python driver (tools/reference/ciplink_ref, the pure-Python ciplink 0.2.0 that the Rust core
was ported from) importable as ``ciplink``.

The reference is the spec for the wire behaviour: the fixture generators (tools/fixtures), the Python half of the
differential harness (tools/diff/py_runner.py) and the parity tests run it.  It is registered under its original
name, so its module, logger and class names are the ones it always had (fixtures and logs stay byte-identical)::

    import reference
    reference.load()        # before anything imports ciplink
    from ciplink import LogixDriver

``load()`` refuses to run after another ``ciplink`` (the installed Rust-backed package) was imported.
"""

import importlib.util
import os
import sys

PACKAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ciplink_ref")


def load():
    """registers the reference package as ``ciplink`` in sys.modules and returns it"""
    loaded = sys.modules.get("ciplink")
    if loaded is not None:
        if os.path.dirname(os.path.abspath(loaded.__file__)) == PACKAGE:
            return loaded
        raise RuntimeError(f"ciplink is already imported from {loaded.__file__}, not the reference")
    spec = importlib.util.spec_from_file_location("ciplink", os.path.join(PACKAGE, "__init__.py"),
                                                  submodule_search_locations=[PACKAGE])
    module = importlib.util.module_from_spec(spec)
    sys.modules["ciplink"] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules["ciplink"]
        raise
    return module
