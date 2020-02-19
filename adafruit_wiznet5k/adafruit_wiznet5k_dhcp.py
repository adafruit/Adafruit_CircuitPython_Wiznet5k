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
import time
from micropython import const
from random import randrange
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket
from adafruit_wiznet5k.adafruit_wiznet5k_socket import htonl, htons


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
    def __init__(self, eth, mac_address, timeout=1, timeout_response=1):
        self._lease_time = 0
        self._t1 = 0
        self._t2 =0
        self._timeout = timeout
        self._response_timeout = timeout_response
        self._mac_address = mac_address

        # Initalize a new UDP socket for DHCP
        socket.set_interface(eth)
        self._sock = socket.socket(type=socket.SOCK_DGRAM)

        self._dhcp_state = STATE_DHCP_START


    def send_dhcp_message(self, state, time_elapsed):
        buff = bytearray(317)
        # Connect UDP socket to broadcast address / dhcp port 67
        SERVER_ADDR = 255, 255, 255, 255
        self._sock.connect((SERVER_ADDR, 67))

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
        xid = xid.to_bytes(4, 'l')
        buff[4:7] = xid

        # seconds elapsed
        buff[8] = ((int(time_elapsed) & 0xff00) >> 8)
        buff[9] = (int(time_elapsed) & 0x00ff)

        # flags
        flags = htons(0x8000)
        # TODO: little endian
        flags = flags.to_bytes(2, 'b')
        buff[10] = flags[1]
        buff[11] = flags[0]

        # NOTE: Skipping cidaddr/yiaddr/siaddr/giaddr
        # as they're already set to 0.0.0.0

        # chaddr
        buff[28:34] = self._mac_address

        # NOTE:  192 octets of 0's, BOOTP legacy

        # Magic Cookie
        buff[236] = ((MAGIC_COOKIE >> 24)& 0xFF)
        buff[237] = ((MAGIC_COOKIE >> 16)& 0xFF)
        buff[238] = ((MAGIC_COOKIE >> 8)& 0xFF)
        buff[239] = (MAGIC_COOKIE& 0xFF)


        # Option - DHCP Message Type
        buff[240] = 53
        buff[241] = 0x01
        buff[242] = state


        # Option - Client Identifier
        buff[243] = 61
        # Length
        buff[244] = 0x07
        # HW Type - ETH
        buff[245] = 0x01
        # Client MAC Address
        for mac in range(0, len(self._mac_address)):
            buff[246+mac] = self._mac_address[mac]

        # Option - Host Name
        buff[252] = 12
        buff[253] = len(b"Wiznet") + 6
        # NOTE/TODO: This appends invalid ? chars. onto hostname instead of string
        buff[254:266] = b"Wizneteeeeee"

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

        buff[266] = 55
        buff[267] = 0x06
        # subnet mask
        buff[268] = 1
        # routers on subnet
        buff[269] = 3
        # DNS
        buff[270] = 6
        # domain name
        buff[271] = 15
        # renewal (T1) value
        buff[272] = 58
        # rebinding (T2) value
        buff[273] = 59
        buff[274] = 255

        self._sock.send(buff)


    def request_dhcp_lease(self):
        # select an initial transaction id
        self._transaction_id = randrange(1, 2000)

        result = 0
        msg_type = 0
        start_time = time.monotonic()

        while self._dhcp_state != STATE_DHCP_LEASED:
            if self._dhcp_state == STATE_DHCP_START:
                self._transaction_id += 1
                self.send_dhcp_message(STATE_DHCP_DISCOVER, ((time.monotonic() - start_time) / 1000))
                self._dhcp_state = STATE_DHCP_DISCOVER
                break

            # TODO: Add Discover State!
        
            if msg_type == 255:
                msg_type = 0
                self._dhcp_state = STATE_DHCP_START
            
            if (result != 1 and ((time.monotonic() - start_time > self._timeout))):
                break
        
        self._transaction_id+=1
        self._last_check_lease_ms = time.monotonic()
        return result
