# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Ian Ottoway <ian@ottoway.dev>
# Copyright (c) 2014 Agostino Ruscito <ruscito@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import functools
import logging
import sys

__all__ = ["configure_default_logger", "LOG_VERBOSE"]

LOG_VERBOSE = 5


_logger = logging.getLogger("pycomm3")
_logger.addHandler(logging.NullHandler())


logging.addLevelName(LOG_VERBOSE, "VERBOSE")
logging.Logger.verbose = functools.partialmethod(logging.Logger.log, LOG_VERBOSE)  # keeps the caller's funcName

_handlers = []  # (logger, handler) pairs added by the last configure_default_logger call


def configure_default_logger(level: int = logging.INFO, filename: str = None, logger: str = None):
    """
    Helper method to configure basic logging.  `level` will set the logging level.
    To enable the verbose logging (where the contents of every packet sent/received is logged)
    import the `LOG_VERBOSE` level from the `pycomm3.logger` module. The default level is `logging.INFO`.

    To log to a file in addition to the terminal, set `filename` to the desired log file.

    By default this method only configures the 'pycomm3' logger, to also configure your own logger,
    set the `logger` argument to the name of the logger you wish to also configure.  For the root logger
    use an empty string (``''``).

    Each call replaces the handlers set up by the previous call.
    """
    for _log, _handler in _handlers:
        _log.removeHandler(_handler)
        _handler.close()
    _handlers.clear()

    loggers = [logging.getLogger('pycomm3'), ]
    if logger == '':
        loggers.append(logging.getLogger())
    elif logger:
        loggers.append(logging.getLogger(logger))

    formatter = logging.Formatter(
        fmt="{asctime} [{levelname}] {name}.{funcName}(): {message}", style="{"
    )
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    handlers = [handler]

    if filename:
        file_handler = logging.FileHandler(filename, encoding="utf-8")
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    for _log in loggers:
        _log.setLevel(level)

    if logger == '':
        loggers = loggers[1:]  # pycomm3 propagates to the root logger, so only root gets the handlers

    for _log in loggers:
        for _handler in handlers:
            _log.addHandler(_handler)
            _handlers.append((_log, _handler))
