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
from adafruit_wiznet5k_socket import htonl


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

MAGIC_COOKIE         = const(0x63825363)
MAX_DHCP_OPT         = const(0x10)

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
        self._sock = sock(type=SOCK_DGRAM)

        self._dhcp_state = STATE_DHCP_START
        res = request_dhcp_lease()
        return res

    def send_dhcp_message(self, state, time_elapsed):
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
        xid = htonl(self._transaction_id)
        buff[4:7] = xid[0:3]

        # seconds elapsed
        buff[8] = ((time_elapsed & 0xff00) >> 8)
        buff[9] = (time_elapsed & 0x00ff)

        # flags
        flags = htons(0x8000)
        buff[10:11] = flags[0:1]
        
        # TODO: Possibly perform a socket send here, Arduino impl. writes to TX buffer.
        #L163-L170
        sock.send(buff)

        buff_2 = bytearray(32)
        
        # Magic Cookie
        buff_2[0] = ((MAGIC_COOKIE >> 24)& 0xFF)
        buff_2[1] = ((MAGIC_COOKIE >> 16)& 0xFF)
        buff_2[2] = ((MAGIC_COOKIE >> 8)& 0xFF)
        buff_2[3] = (MAGIC_COOKIE& 0xFF)

        # DHCP Message Type
        buff_2[4] = 53
        buff_2[5] = 0x01
        buff_2[6] = state

        # Client Identifier
        buff_2[7] = 61
        buff_2[8] = 0x07
        buff_2[9] = 0x01
        for mac in range(0, len(self._mac_address)):
            buff_2[10+mac] = self._mac_address[mac]
        
        # host name
        buff_2[16] = 12
        # len(hostname)
        buff_2[16] = len(b"WIZnet") + 6
        buff_2[17:23] = b"WIZnet"
        # last 3 bytes of MAC address
        buff_2[24:25] = mac_address[3]
        buff_2[26:27] = mac_address[4]
        buff_2[28:29] = mac_address[5]

        # L198-L199: Transmit buffer? TODO?
        sock.send(buff_2)

        buff_3 = bytearray(32)

        if state == STATE_DHCP_REQUEST:
            # Local IP
            buff_3[0] = 50
            buff_3[1] = 0x04
            # TODO: This is the DHCP Local IP, should be 000.000.000.000, ensure!
            buff_3[2] = 0
            buff_3[3] = 0
            buff_3[4] = 0
            buff_3[5] = 0
            # DHCP Server IP
            buff_3[6] = 54
            buff_3[7] = 0x04
            buff_3[8] = 0
            buff_3[9] = 0
            buff_3[10] = 0
            buff_3[11] = 0

            # Write buff_3 to tx buffer? TODO
            sock.send(buff_4)
        
        buff_4 = bytearray(32)
        buff_4[0] = 55
        buff_4[1] = 0x06
        # subnet mask
        buff_4[2] = 1
        # routers on subnet
        buff_4[3] = 3
        # DNS
        buff_4[4] = 6
        # domain name
        buff_4[5] = 15
        # Renewal (T1) value
        buff_4[6] = 58
        # Rebinding (T2) value
        buff_4[7] = 59
        buff_4[8] = 255

        # TODO: Write to tx buffer
        sock.send(buff_4)


    def request_dhcp_lease(self):
        # select an initial transaction id
        self._transaction_id = randrange(1, 2000)

