# The MIT License (MIT)
#
# Copyright (c) April 25, 2009 Jordan Terrell (blog.jordanterrell.com)
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
`adafruit_wiznet5k_dhcp`
================================================================================

Pure-Python implementation of Jordan Terrell's DHCP library v0.3

* Author(s): Jordan Terrell, Brent Rubell

"""
from time import monotonic
from micropython import const
from random import randrange

# DHCP State Machine
STATE_DHCP_START     = const(0x00)
STATE_DHCP_DISCOVER  = const(0x01)
STATE_DHCP_REQUEST   = const(0x02)
STATE_DHCP_LEASED    = const(0x03)
STATE_DHCP_REREQUEST = const(0x04)
STATE_DHCP_RELEASE   = const(0x05)

# DHCP Message OP Codes
DHCP_BOOT_REQUEST    = const(0x01)
DHCP_BOOT_REPLY      = const(0x02)

DHCP_HTYPE10MB       = const(0x01)
DHCP_HTYPE100MB      = const(0x02)

DHCP_HLENETHERNET    = const(0x06)
DHCP_HOPS            = const(0x00)

class DHCP:
    """TODO!
    :param sock: Socket-like object
    :param list mac_address: Hardware MAC.
    :param int timeout:
    :param int timeout_response: DHCP Response timeout

    """
    def __init__(self, sock, mac_address, timeout, timeout_response):
        self._lease_time = 0
        self._t1 = 0
        self._t2 =0
        self._timeout = timeout
        self._response_timeout = timeout_response
        self._mac_address = mac_address
        self._sock = socket

        self._dhcp_state = STATE_DHCP_START
        res = request_dhcp_lease()
        return res

    def send_dhcp_message(self, state, time):
        buff = bytearray(32)
        # Connect UDP socket to broadcast address / dhcp port 67
        self._sock.connect((255, 255, 255, 255), 67)

        # OP
        buff[0] = DHCP_BOOT_REQUEST
        # HTYPE
        buff[1] = DHCP_HTYPE10MB
        # HLEN
        buff[2] = DHCP_HLENETHERNET
        # HOPS
        buff[3] = DHCP_HOPS

        # Transaction ID (xid)


    def request_dhcp_lease(self):
        # select an initial transaction id
        self._transaction_id = randrange(1, 2000)
        self._init_transaction_id = self._transaction_id

        start = monotonic()

        while self._dhcp_state != STATE_DHCP_LEASED:
            if self._dhcp_state == STATE_DHCP_START:
                self._transaction_id += 1
                self.send_dhcp_message(state, time)
                # Send Discover message TODO
                # send_DHCP_MESSAGE(DHCP_DISCOVER, ((millis() - startTime) / 1000));
                self._dhcp_state = STATE_DHCP_DISCOVER
