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


from enum import Enum
from typing import NamedTuple, Any, Optional
from reprlib import repr as _r


__all__ = ["Tag", "ErrorKind", "TagError"]


class ErrorKind(str, Enum):
    """what kind of failure a :attr:`Tag.error` is, see :attr:`Tag.error_kind`"""

    NOT_FOUND = "not_found"  #: no such tag, member, element or bit
    BAD_VALUE = "bad_value"  #: the write value does not fit the type (rejected locally or by the controller)
    BAD_REQUEST = "bad_request"  #: malformed request: syntax, element count, bit on a REAL, path size
    ACCESS = "access"  #: exists but is not accessible: privilege, AOI local tag, keyswitch or password
    REFUSED = "refused"  #: nothing was done and it may work later: reload backoff, state conflict, busy
    TABLE_CHANGED = "table_changed"  #: the tag table changed during the request, the result was discarded
    COMM = "comm"  #: the request or reply was lost or could not be parsed
    DEVICE = "device"  #: any other controller status
    OTHER = "other"  #: an error that was not classified


class TagError(str):
    """
    A :attr:`Tag.error` message that also carries its ``kind`` (:class:`ErrorKind`), and the CIP general
    ``status`` and first extended status word ``ext`` of a controller error (else ``None``)
    """

    def __new__(cls, message: str, kind: ErrorKind, status: Optional[int] = None, ext: Optional[int] = None):
        self = super().__new__(cls, message)
        self.kind, self.status, self.ext = ErrorKind(kind), status, ext
        return self

    def __reduce__(self):
        return self.__class__, (str(self), self.kind, self.status, self.ext)


class Tag(NamedTuple):
    tag: str  #: tag name of tag read/written or request name (generic message)
    value: Any  #: value read/written, may be ``None`` on error
    type: Optional[str] = None  #: data type of tag
    error: Optional[str] = None  #: error message if unsuccessful, else ``None``

    def __bool__(self):
        """
        ``True`` if both ``value`` is not ``None`` and ``error`` is ``None``, ``False`` otherwise
        """
        return self.value is not None and self.error is None

    @property
    def error_kind(self) -> Optional[ErrorKind]:
        """the :class:`ErrorKind` of ``error``, ``None`` if there is no error"""
        if self.error is None:
            return None
        return self.error.kind if isinstance(self.error, TagError) else ErrorKind.OTHER

    def __str__(self):
        return f"{self.tag}, {_r(self.value)}, {self.type}, {self.error}"

    def __repr__(self):
        return f"{self.__class__.__name__}(tag={self.tag!r}, value={self.value!r}, type={self.type!r}, error={self.error!r})"
