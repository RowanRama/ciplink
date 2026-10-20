"""Tests for the logix_driver.py file.

The Logix Driver is beholden to the CIPDriver interface. Only tests
which bind it to that interface should be allowed here. Tests binding
to another interface such as Socket are an anti-pattern.

There are quite a few methods in the LogixDriver which are difficult to
read or test due to both code clarity issues and it being inconvenient.

Also the vast majority of methods are private, I think that private 
methods should not be tested directly, but rather, their effects on
public methods should be tested.

pytest --cov=ciplink --cov-branch tests/offline/
----------- coverage: platform linux, python 3.8.1-final-0 -----------
Name                           Stmts   Miss Branch BrPart  Cover
----------------------------------------------------------------
ciplink/logix_driver.py                   798    718    346      0     7%

We're currently at 7% test coverage, I would like to increase that to >=50%
and then continue to do so for the rest of the modules.
"""
from unittest import mock


from ciplink.exceptions import CommError
from ciplink.logix_driver import LogixDriver

CONNECT_PATH = '192.168.1.100/1'

def test_logix_context_manager_calls_open_and_close():
    with mock.patch.object(LogixDriver, 'open') as mock_open, \
            mock.patch.object(LogixDriver, 'close') as mock_close:
        with LogixDriver(CONNECT_PATH, init_info=False, init_tags=False):
            pass

        assert mock_open.called
        assert mock_close.called


def test__exit__returns_false_on_commerror():
    ld = LogixDriver(CONNECT_PATH, init_tags=False)
    with mock.patch.object(LogixDriver, 'close', side_effect=CommError):
        assert ld.__exit__(None, None, None) is False


def test__exit__returns_true_on_no_error_and_no_exc_type():
    with mock.patch.object(LogixDriver, 'close'):
        ld = LogixDriver(CONNECT_PATH, init_info=False, init_tags=False)
        assert ld.__exit__(None, None, None) is True


def test__exit__returns_false_on_no_error_and_exc_type():
    with mock.patch.object(LogixDriver, 'close'):
        ld = LogixDriver(CONNECT_PATH, init_info=False, init_tags=False)
        assert ld.__exit__('Some Exc Type', None, None) is False


def test__repr___ret_str():
    ld = LogixDriver(CONNECT_PATH, init_info=False, init_tags=False)
    _repr = repr(ld)
    assert _repr
    assert isinstance(_repr, str)


def test_default_logix_tags_are_empty_dict():
    """Show that LogixDriver tags are an empty dict on init."""
    ld = LogixDriver(CONNECT_PATH, init_info=False, init_tags=False)
    assert ld.tags == dict()


def test_logix_connected_false_on_init_with_false_init_params():
    ld = LogixDriver(CONNECT_PATH, init_info=False, init_tags=False)
    assert ld.connected is False


# TODO: all of the tag list associated tests

