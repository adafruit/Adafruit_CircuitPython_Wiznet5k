# The MIT License (MIT)
#
# Copyright 2018 Paul Stoffregen
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

* Author(s): Paul Stoffregen, ladyada, Brent Rubell

"""
from micropython import const
import time

# SNSR
SOCK_CLOSED      = 0x00;
SOCK_INIT        = 0x13;
SOCK_LISTEN      = 0x14;
SOCK_SYNSENT     = 0x15;
SOCK_SYNRECV     = 0x16;
SOCK_ESTABLISHED = 0x17;
SOCK_FIN_WAIT    = 0x18;
SOCK_CLOSING     = 0x1A;
SOCK_TIME_WAIT   = 0x1B;
SOCK_CLOSE_WAIT  = 0x1C;
SOCK_LAST_ACK    = 0x1D;
SOCK_UDP         = 0x22;
SOCK_IPRAW       = 0x32;
SOCK_MACRAW      = 0x42;
SOCK_PPPOE       = 0x5F;

class SOCKET:
    """A simplified implementation of the Python 'socket' class
    for connecting to a Wiznet5k module.
    TODO: Document interface param.
    TODO: Document protocol param.

    """
    def __init__(self, interface, protocol=SOCK_TCP):
        # check hardware compatibility, throw err if hardware not detected
        assert interface.chip != None, "No Wiznet module detected."
        self._interface = interface
        status = bytearray(self._interface.max_sockets)

        # check all the hardware sockets, allocate closed sockets
        for sock in range(0, self._interface.max_sockets):
            status[sock] = self._interface._read_snsr(sock)[0]
            if status[sock] == SOCK_CLOSED:
                # TODO: makesocket
                print("making new socket...!")
    
    def _make_socket(self, sock):
        """Creates a new Wiznet5k socket.
        :param int sock: Socket number
        """
        # TODO: (?) EthernetServer::server_port[s] = 0;
        time.sleep(0.250)
        self._interface._write_snmr(sock, protocol)
        self._interface._write_snir(sock, 0xFF)
