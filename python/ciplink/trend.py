"""
Controller-side trends: the controller samples a set of tags at a fixed period (down to 1 ms) into a buffer and
the driver uploads the samples in batches, like a Studio 5000 trend.  Start one with :meth:`LogixDriver.trend`.

The trend runs in the Rust core (``ciplink._core.Trend``) on a connection of its own, with a worker thread
uploading the samples; :meth:`Trend.read` takes them.  A pen can be any tag, member or array element of up to 32
bits (BOOL, SINT, INT, DINT, USINT, UINT, UDINT, REAL) or a bit (``Tag.3``); 64-bit types cannot be trended.
"""

import datetime
from typing import List, NamedTuple, Optional, Tuple, Union

__all__ = ["Trend", "TrendPen", "TrendSample"]

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


class TrendPen(NamedTuple):
    tag: str
    #: the type sampled, ``BOOL`` for a bit or a BOOL array element
    data_type: str


class TrendSample(NamedTuple):
    #: controller time of the sample, microseconds since 1970 UTC
    timestamp_us: int
    #: time since the trend started, microseconds
    elapsed_us: int
    #: one value per pen, in pen order
    values: Tuple[Union[bool, int, float], ...]

    @property
    def timestamp(self) -> datetime.datetime:
        """the controller time of the sample as a UTC datetime"""
        return _EPOCH + datetime.timedelta(microseconds=self.timestamp_us)


class Trend:
    """
    A running controller-side trend.  Use it as a context manager, or call :meth:`close`: closing stops the
    trend, deletes it in the controller and closes its connection.  The controller also deletes the trend of a
    connection that drops, so a trend never outlives its process.
    """

    def __init__(self, core):
        self._core = core
        self._pens = tuple(TrendPen(*pen) for pen in core.pens)

    @property
    def pens(self) -> Tuple[TrendPen, ...]:
        return self._pens

    @property
    def period_ms(self) -> float:
        return self._core.period_us / 1000

    @property
    def start_time_us(self) -> int:
        """controller time the trend started, microseconds since 1970 UTC"""
        return self._core.start_time_us

    @property
    def running(self) -> bool:
        """True until the trend is closed, its duration is over, or it failed"""
        return self._core.running

    @property
    def received_samples(self) -> int:
        """samples uploaded so far, including dropped ones"""
        return self._core.received

    @property
    def dropped_samples(self) -> int:
        """samples dropped because ``capacity`` samples were waiting to be read"""
        return self._core.dropped

    @property
    def error(self) -> Optional[Exception]:
        """why the trend failed, None if it has not"""
        return self._core.error

    def read(self) -> List[TrendSample]:
        """
        Takes the samples uploaded since the last read, oldest first.  Once the trend failed and every sample was
        taken, raises its error.
        """
        return [TrendSample(*sample) for sample in self._core.read()]

    def close(self):
        """Stops the trend and waits for its cleanup; raises the trend's error if it failed."""
        self._core.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.close()
        except Exception:
            if exc_type is None:
                raise
        return False

    def __repr__(self):
        return f"{self.__class__.__name__}({', '.join(p.tag for p in self._pens)}, period_ms={self.period_ms})"
