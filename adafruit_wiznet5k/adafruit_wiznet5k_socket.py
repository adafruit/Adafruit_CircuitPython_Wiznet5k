# The MIT License (MIT)
#
# Copyright (c) 2019 ladyada for Adafruit Industries
# Modified by Brent Rubell for Adafruit Industries, 2020
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
`adafruit_wiznet5k_socket`
================================================================================

A socket compatible interface with the Wiznet5k module.

* Author(s): ladyada, Brent Rubell

"""
import gc
import time
from micropython import const
from adafruit_wiznet5k import adafruit_wiznet5k

_the_interface = None   # pylint: disable=invalid-name
def set_interface(iface):
    """Helper to set the global internet interface."""
    global _the_interface   # pylint: disable=global-statement, invalid-name
    _the_interface = iface

def htonl(x):
    """Convert 32-bit positive integers from host to network byte order."""
    return (((x)<<24 & 0xFF000000) | ((x)<< 8 & 0x00FF0000) | \
            ((x)>> 8 & 0x0000FF00) | ((x)>>24 & 0x000000FF))

def htons(x):
    """Convert 16-bit positive integers from host to network byte order."""
    return ( (((x)<<8)&0xFF00) | (((x)>>8)&0xFF) )

def ntohl(x):
    """Convert 32-bit positive integers from network to host byte order."""
    return htons(x)

SOCK_STREAM     = const(0x21) # TCP
SOCK_DGRAM      = const(0x02) # UDP
AF_INET         = const(3)
NO_SOCKET_AVAIL = const(255)
MAX_PACKET = const(4000)

# keep track of sockets we allocate
sockets = []

class socket:
    """A simplified implementation of the Python 'socket' class
    for connecting to a Wiznet5k module.

    :param int family: Socket address (and protocol) family.
    :param int type: Socket type.
    :param int proto: Socket protocol number, usually zero.
    :param int fileno: If specified, values for family, type, and proto are auto-detected.
                       NOTE: fileno is not implemented in this simplified implementation.
    """
    def __init__(self, family=AF_INET, type=SOCK_STREAM, proto=0, fileno=0):
        if family != AF_INET:
            raise RuntimeError("Only AF_INET family supported by W5K modules.")
        self._sock_type = type
        self._buffer = b''

        self._socknum = _the_interface.get_socket(sockets)
        sockets.append(self._socknum)


    @property
    def socknum(self):
        """Returns the socket number of the socket object.

        """
        return self._socknum

    @property
    def connected(self):
        """Returns whether or not we are connected to the socket.
        """
        if (self._socknum >= _the_interface.max_sockets):
            return 0
        else:
            status = _the_interface.socket_status(self._socknum)
            print(status)
            result = status in (adafruit_wiznet5k.SNSR_SOCK_CLOSED,
                                    adafruit_wiznet5k.SNSR_SOCK_LISTEN,
                                    adafruit_wiznet5k.SNSR_SOCK_CLOSE_WAIT,
                                    adafruit_wiznet5k.SNSR_SOCK_FIN_WAIT)
            if result:
                self.close()
                return result
            return result

    def gethostbyname(self, address):
        raise NotImplementedError("Not implemented in this version of Wiznet5k.")

    def connect(self, address):
        """Connect to a remote socket at address. (The format of address depends on the address family — see above.)
        :param tuple address: Remote socket as a (host, port) tuple.

        """
        host, port = address
        if not _the_interface.socket_connect(self._socknum, host, port, conn_mode=self._sock_type):
            raise RuntimeError("Failed to connect to host", host)
        self._buffer = b''

    def send(self, data):
        """Send data to the socket. The socket must be connected to
        a remote socket.
        :param bytearray data: Desired data to send to the socket.

        """
        _the_interface.socket_write(self._socknum, data)
        gc.collect()

    def recv(self, bufsize=0):
        """Reads some bytes from the connected remote address.
        :param int bufsize: Maximum number of bytes to receive.

        """
        assert _the_interface.link_status, "Ethernet cable disconnected!"
        if bufsize == 0:
            # read everything on the socket
            while True:
                if self._sock_type == SOCK_STREAM:
                    avail = self.available()
                elif self._sock_type == SOCK_DGRAM:
                    avail = _the_interface._udp_remaining()
                if avail:
                    if self._sock_type == SOCK_STREAM:
                        self._buffer += _the_interface.socket_read(self._socknum, avail)
                    elif self._sock_type == SOCK_DGRAM:
                        self._buffer += _the_interface.read_udp(self._socknum, avail)
                else:
                    break
            gc.collect()
            ret = self._buffer
            self._buffer = b''
            gc.collect()
            return ret
        stamp = time.monotonic()

        to_read = bufsize - len(self._buffer)
        received = []
        while to_read > 0:
            if self._sock_type == SOCK_STREAM:
                avail = self.available()
            elif self._sock_type == SOCK_DGRAM:
                avail = _the_interface._udp_remaining()
            if avail:
                stamp = time.monotonic()
                if self._sock_type == SOCK_STREAM:
                    recv = _the_interface.socket_read(self._socknum, min(to_read, avail))[1]
                elif self._sock_type == SOCK_DGRAM:
                    recv = _the_interface.read_udp(self._socknum, min(to_read, avail))[1]
                received.append(recv)
                to_read -= len(recv)
                gc.collect()
            if self._timeout > 0 and time.monotonic() - stamp > self._timeout:
                break
        self._buffer = received

        ret = None
        if len(self._buffer) == bufsize:
            ret = self._buffer
            self._buffer = b''
        else:
            ret = self._buffer[:bufsize]
            self._buffer = self._buffer[bufsize:]
        gc.collect()
        print(ret)
        return ret

    def readline(self):
        """Attempt to return as many bytes as we can up to
        but not including '\n'"""
        stamp = time.monotonic()
        while b'\n' not in self._buffer:
            if self._sock_type == SOCK_STREAM:
                avail = self.available()
                self._buffer += _the_interface.read(self._socknum, avail)[1]
            elif self._sock_type == SOCK_DGRAM:
                avail = _the_interface._udp_remaining()
                self._buffer += _the_interface.read_udp(self._socknum, avail)[1]
            elif self._timeout > 0 and time.monotonic() - stamp > self._timeout:
                self.close()
                raise RuntimeError("Didn't receive response, failing out...")
        firstline = self._buffer.split(b'\n', 1)
        gc.collect()
        # clear tmp data buffer
        self._buffer = b''
        return firstline[0]

    def close(self):
        """Closes the socket.

        """
        _the_interface.socket_close(self._socknum)
        sockets.remove(self._socknum)

    def avail_udp(self):
        return _the_interface._udp_remaining()

    def available(self):
        """Returns how many bytes of data are available to be read.

        """
        return _the_interface.socket_available(self._socknum, self._sock_type)


    def settimeout(self, value):
        """Sets socket read timeout.
        :param int value: Socket read timeout, in seconds.

        """
        if value is None:
            value = 0.0
        self._timeout = value

    def gettimeout(self):
        """Return the timeout in seconds (float) associated
        with socket operations, or None if no timeout is set.

        """
        if value == 0.0:
            return None
        return self._timeout