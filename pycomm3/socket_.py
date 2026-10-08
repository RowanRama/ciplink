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

import logging
import socket
import struct

from .exceptions import CommError
from .const import HEADER_SIZE


class Socket:
    __log = logging.getLogger(f"{__module__}.{__qualname__}")

    def __init__(self, timeout=5.0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self._receive_buffer = bytearray()

    def connect(self, host, port):
        try:
            self.sock.connect((socket.gethostbyname(host), port))
        except socket.error as err:
            raise CommError(f"Failed to open socket to {host}:{port}") from err

    def send(self, msg, timeout=0):
        if timeout != 0:
            self.sock.settimeout(timeout)
        total_sent = 0
        while total_sent < len(msg):
            try:
                sent = self.sock.send(msg[total_sent:])
                if sent == 0:
                    raise CommError("socket connection broken.")
                total_sent += sent
            except socket.error as err:
                raise CommError("socket connection broken.") from err
        return total_sent

    def settimeout(self, timeout):
        self.sock.settimeout(timeout)

    def receive(self, timeout=0):
        """Receive one encapsulation frame, retaining bytes for subsequent frames."""
        try:
            if timeout != 0:
                self.sock.settimeout(timeout)
            while True:
                if len(self._receive_buffer) >= HEADER_SIZE:
                    frame_size = HEADER_SIZE + struct.unpack_from("<H", self._receive_buffer, 2)[0]
                    if len(self._receive_buffer) >= frame_size:
                        frame = bytes(self._receive_buffer[:frame_size])
                        del self._receive_buffer[:frame_size]
                        return frame

                chunk = self.sock.recv(4096)
                if not chunk:
                    raise CommError("socket connection closed before a complete frame was received")
                self._receive_buffer.extend(chunk)
        except socket.error as err:
            raise CommError("socket connection broken") from err

    def close(self):
        self.sock.close()
