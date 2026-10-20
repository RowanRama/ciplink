"""Tests for the SLCDriver

The methods and functions in the slc_driver.py file are extraordinarily
difficult to test.
"""


import pytest
from ciplink.exceptions import ResponseError

from ciplink.slc_driver import SLCDriver, _parse_read_reply

CONNECT_PATH = '192.168.1.100/1'



def test__parse_read_reply_raises_dataerror_if_exception():
    driver = SLCDriver(CONNECT_PATH)

    with pytest.raises(ResponseError):
        _parse_read_reply('bad', 'data')
