import importlib.util
import logging
from pathlib import Path
from unittest import mock

import pytest

from pycomm3 import Tag
from pycomm3.logger import configure_default_logger, LOG_VERBOSE


def test_star_import_skips_submodules():
    ns = {}
    exec('from pycomm3 import *', ns)
    assert 'map' not in ns and 'logger' not in ns and 'util' not in ns
    assert 'LogixDriver' in ns and 'DINT' in ns and 'configure_default_logger' in ns


@pytest.fixture
def restore_loggers():
    loggers = [logging.getLogger(), logging.getLogger('pycomm3')]
    saved = [(lg, lg.level, lg.handlers[:]) for lg in loggers]
    yield
    for lg, level, handlers in saved:
        for h in lg.handlers[:]:
            if h not in handlers:
                lg.removeHandler(h)
                h.close()
        lg.setLevel(level)


@pytest.mark.parametrize('logger', [None, ''])
def test_configure_default_logger_twice_logs_once(restore_loggers, capsys, logger):
    configure_default_logger(logger=logger)
    configure_default_logger(logger=logger)
    logging.getLogger('pycomm3').info('hello')
    assert capsys.readouterr().out.count('hello') == 1


def test_configure_default_logger_drops_previous_file_handler(restore_loggers, tmp_path):
    configure_default_logger(filename=str(tmp_path / 'a.log'))
    configure_default_logger()
    assert not any(isinstance(h, logging.FileHandler) for h in logging.getLogger('pycomm3').handlers)


def test_logger_verbose_any_arg_count():
    records = []
    h = logging.Handler(level=1)
    h.emit = records.append
    lg = logging.getLogger('pycomm3.test_verbose')
    lg.addHandler(h)
    lg.setLevel(LOG_VERBOSE)
    try:
        lg.verbose('plain')
        lg.verbose('%s and %s', 'a', 'b')
    finally:
        lg.removeHandler(h)
        lg.setLevel(logging.NOTSET)
    assert [r.getMessage() for r in records] == ['plain', 'a and b']
    assert all(r.levelno == LOG_VERBOSE for r in records)
    assert all(r.funcName == 'test_logger_verbose_any_arg_count' for r in records)


def _load_example(name):
    path = Path(__file__).parents[2] / 'examples' / f'{name}.py'
    spec = importlib.util.spec_from_file_location(f'_example_{name}', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_example_upload_eds_get_file_name():
    upload_eds = _load_example('upload_eds')
    driver = mock.Mock()
    driver.generic_message.return_value = Tag('x', (['f.eds'], ['eng'], [4]), None, None)
    assert upload_eds.get_file_name(driver) == 'f.eds'


def test_example_generic_messaging_led_status(capsys):
    generic_messaging = _load_example('generic_messaging')
    with mock.patch.object(generic_messaging, 'CIPDriver') as driver_cls:
        device = driver_cls.return_value.__enter__.return_value
        device.generic_message.return_value = Tag('x', 96, 'INT', None)
        generic_messaging.enbt_ok_led_status()
    assert capsys.readouterr().out == 'solid green\n'


def test_extend_codes_path_errors():
    from pycomm3.cip import EXTEND_CODES
    assert 'out of memory' not in EXTEND_CODES[0x04][0x0000]
    assert 'path' in EXTEND_CODES[0x04][0x0000]
    assert 'instance' in EXTEND_CODES[0x05][0x0000]
