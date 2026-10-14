import pytest
from ciplink import LogixDriver
import os


@pytest.fixture(scope="session")
def plc():
    with LogixDriver(os.environ["PLCPATH"]) as plc_:
        yield plc_
