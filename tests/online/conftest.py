import pytest
from pycomm3 import LogixDriver
import os


@pytest.fixture(scope="session")
def plc():
    with LogixDriver(os.environ["PLCPATH"]) as plc_:
        yield plc_
