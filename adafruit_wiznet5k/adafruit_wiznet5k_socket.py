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

# SNSR Commands
SNSR_SOCK_CLOSED      = const(0x00)
SNSR_SOCK_INIT        = const(0x13)
SNSR_SOCK_LISTEN      = const(0x14)
SNSR_SOCK_SYNSENT     = const(0x15)
SNSR_SOCK_SYNRECV     = const(0x16)
SNSR_SOCK_ESTABLISHED = const(0x17)
SNSR_SOCK_FIN_WAIT    = const(0x18)
SNSR_SOCK_CLOSING     = const(0x1A)
SNSR_SOCK_TIME_WAIT   = const(0x1B)
SNSR_SOCK_CLOSE_WAIT  = const(0x1C)
SNSR_SOCK_LAST_ACK    = const(0x1D)
SNSR_SOCK_UDP         = const(0x22)
SNSR_SOCK_IPRAW       = const(0x32)
SNSR_SOCK_MACRAW      = const(0x42)
SNSR_SOCK_PPPOE       = const(0x5F)

# Sock Commands (CMD)
CMD_SOCK_OPEN      = const(0x01)
CMD_SOCK_LISTEN    = const(0x02)
CMD_SOCK_CONNECT   = const(0x04)
CMD_SOCK_DISCON    = const(0x08)
CMD_SOCK_CLOSE     = const(0x10)
CMD_SOCK_SEND      = const(0x20)
CMD_SOCK_SEND_MAC  = const(0x21)
CMD_SOCK_SEND_KEEP = const(0x22)
CMD_SOCK_RECV      = const(0x40)

# Socket registers
SNMR_CLOSE  = const(0x00);
SNMR_TCP    = const(0x01);
SNMR_UDP    = const(0x02);
SNMR_IPRAW  = const(0x03);
SNMR_MACRAW = const(0x04);
SNMR_PPPOE  = const(0x05);

LOCAL_PORT = 49152 # 49152 - 65535

class SOCKET:
    """A simplified implementation of the Python 'socket' class
    for connecting to a Wiznet5k module.

    """
    def __init__(self, interface, port=68, protocol=SNMR_TCP):
        # check hardware compatibility, throw err if hardware not detected
        assert interface.chip != None, "No Wiznet module detected."
        self._iface = interface
        self._protocol = protocol
        self._port = port
        status = bytearray(self._iface.max_sockets)

        # check all the hardware sockets, allocate closed sockets
        #for sock in range(0, self._iface.max_sockets):
        for sock in range(0, 1): # DEBUG ONLY TODO REMOVE!
            status[sock] = self._iface._read_snsr(sock)[0]
            if status[sock] == SNSR_SOCK_CLOSED:
                # print("w5k socket begin, protocol={}, port={}".format(self._protocol, self._port))
                self._make_socket(sock)

    def _make_socket(self, sock):
        """Creates a new Wiznet5k socket.
        :param int sock: Socket number
        """
        # print("W5k socket {}\n".format(sock))
        time.sleep(0.00025)

        self._iface._write_snmr(sock, self._protocol)
        self._iface._write_snir(sock, 0xFF)

        if self._port > 0:
            # write to socket source port
            self._iface._write_sock_port(sock, self._port)
        else:
            # if source port is not set, set the local port number
            self._iface._write_sock_port(sock, LOCAL_PORT)

        # verify socket write?
        # self._iface._read_socket(sock, 0x0004)
        # self._iface._read_socket(sock, 0x0005)

        # open the socket
        self._iface._write_sncr(sock, CMD_SOCK_OPEN)
        while(self._iface._read_sncr(sock)):
            print('1')
        print('2')
