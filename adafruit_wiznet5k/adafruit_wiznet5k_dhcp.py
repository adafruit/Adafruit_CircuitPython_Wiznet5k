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
from adafruit_wiznet5k.adafruit_wiznet5k_socket import htonl, htons, ntohl


# DHCP State Machine
STATE_DHCP_START     = const(0x00)
STATE_DHCP_DISCOVER  = const(0x01)
STATE_DHCP_REQUEST   = const(0x02)
STATE_DHCP_LEASED    = const(0x03)
STATE_DHCP_REREQUEST = const(0x04)
STATE_DHCP_RELEASE   = const(0x05)

# DHCP Message Types
DHCP_DISCOVER = const(1)
DHCP_OFFER    = const(2)
DHCP_REQUEST  = const(3)
DHCP_DECLINE  = const(4)
DHCP_ACK      = const(5)
DHCP_NAK      = const(6)
DHCP_RELEASE  = const(7)
DHCP_INFORM   = const(8)

# DHCP Message OP Codes
DHCP_BOOT_REQUEST    = const(0x01)
DHCP_BOOT_REPLY      = const(0x02)

DHCP_HTYPE10MB       = const(0x01)
DHCP_HTYPE100MB      = const(0x02)

DHCP_HLENETHERNET    = const(0x06)
DHCP_HOPS            = const(0x00)

MAGIC_COOKIE         = const(0x63825363)
MAX_DHCP_OPT         = const(0x10)

BROADCAST_SERVER_ADDR = 255, 255, 255, 255
DHCP_SERVER_PORT      = const(67)

_buff = bytearray(317)

class DHCP:
    """TODO!
    :param eth: Wiznet 5k object
    :param list mac_address: Hardware MAC.
    :param int timeout: Packet parsing timeout.
    :param int timeout_response: DHCP Response timeout.
    :param bool debug: Enable debugging output.

    """

    def __init__(self, eth, mac_address, timeout=1, timeout_response=1, debug=True):
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
        self._debug = debug

        # DHCP packet attributes
        self._initial_xid = 0


    def send_dhcp_message(self, state, time_elapsed):
        # Connect UDP Socket
        self._sock.connect((BROADCAST_SERVER_ADDR, DHCP_SERVER_PORT))

        # OP
        _buff[0] = DHCP_BOOT_REQUEST
        # HTYPE
        _buff[1] = DHCP_HTYPE10MB
        # HLEN
        _buff[2] = DHCP_HLENETHERNET
        # HOPS
        _buff[3] = DHCP_HOPS

        # Transaction ID (xid)
        self._initial_xid = htonl(self._transaction_id)
        self._initial_xid = self._initial_xid.to_bytes(4, 'l')
        _buff[4:7] = self._initial_xid


        # seconds elapsed
        _buff[8] = ((int(time_elapsed) & 0xff00) >> 8)
        _buff[9] = (int(time_elapsed) & 0x00ff)

        # flags
        flags = htons(0x8000)
        flags = flags.to_bytes(2, 'b')
        _buff[10] = flags[1]
        _buff[11] = flags[0]

        # NOTE: Skipping cidaddr/yiaddr/siaddr/giaddr
        # as they're already set to 0.0.0.0

        # chaddr
        _buff[28:34] = self._mac_address

        # NOTE:  192 octets of 0's, BOOTP legacy

        # Magic Cookie
        _buff[236] = ((MAGIC_COOKIE >> 24)& 0xFF)
        _buff[237] = ((MAGIC_COOKIE >> 16)& 0xFF)
        _buff[238] = ((MAGIC_COOKIE >> 8)& 0xFF)
        _buff[239] = (MAGIC_COOKIE& 0xFF)


        # Option - DHCP Message Type
        _buff[240] = 53
        _buff[241] = 0x01
        _buff[242] = state


        # Option - Client Identifier
        _buff[243] = 61
        # Length
        _buff[244] = 0x07
        # HW Type - ETH
        _buff[245] = 0x01
        # Client MAC Address
        for mac in range(0, len(self._mac_address)):
            _buff[246+mac] = self._mac_address[mac]

        # Option - Host Name
        _buff[252] = 12
        _buff[253] = len(b"Wiznet") + 6
        # NOTE/TODO: This appends invalid ? chars. onto hostname instead of string
        _buff[254:266] = b"Wizneteeeeee"

        _buff_3 = bytearray(32)
        if state == STATE_DHCP_REQUEST:
            # Local IP
            _buff_3[0] = 50
            _buff_3[1] = 0x04
            # TODO: This is the DHCP Local IP, should be 000.000.000.000, ensure!
            _buff_3[2] = 0
            _buff_3[3] = 0
            _buff_3[4] = 0
            _buff_3[5] = 0
            # DHCP Server IP
            _buff_3[6] = 54
            _buff_3[7] = 0x04
            _buff_3[8] = 0
            _buff_3[9] = 0
            _buff_3[10] = 0
            _buff_3[11] = 0

        _buff[266] = 55
        _buff[267] = 0x06
        # subnet mask
        _buff[268] = 1
        # routers on subnet
        _buff[269] = 3
        # DNS
        _buff[270] = 6
        # domain name
        _buff[271] = 15
        # renewal (T1) value
        _buff[272] = 58
        # rebinding (T2) value
        _buff[273] = 59
        _buff[274] = 255

        # Send DHCP packet
        self._sock.send(_buff)

    def parse_dhcp_response(self, response_timeout, transaction_id):
        """Parse DHCP response from DHCP server.
        Returns DHCP packet type.

        :param int response_timeout: Time to wait for server to return packet, in seconds.
        :param int transaction_id: ID from DHCP transaction
        """
        start_time = time.monotonic()
        if self._debug:
            print("* Parsing DHCP Response")
        packet_sz = self._sock.available()
        while (packet_sz <= 0):
            if self._debug:
                print(" * Waiting for packet...")
            if (time.monotonic() - start_time) > response_timeout:
                return 255
            time.sleep(0.05)
        if self._debug:
            print("* DHCP packet available, {} bytes".format(packet_sz))
        # re-allocate and zero-out global packet buffer
        _buff = bytearray(packet_sz)
        _buff = self._sock.recv(packet_sz)[0]

        # Check OP, if valid, let's parse the packet out!
        assert _buff[0] == DHCP_BOOT_REPLY, "Malformed Packet - DHCP message OP is not expected BOOT Reply."


        # Client Hardware Address (CHADDR)
        chaddr = bytearray(6)
        for mac in range(0, len(chaddr)):
            chaddr[mac] = _buff[28+mac]

        if chaddr != 0:
            xid = _buff[4:8]
            if bytes(xid) < self._initial_xid:
                return 0, transaction_id

        secs = _buff[8]
        flags = _buff[9]

        # Client IP Address (CIADDR)
        ciaddr = _buff[10:14]

        # Your IP Address (YIADDR)
        yiaddr = _buff[15:19]

        # Server IP Address (SIADDR)
        siaddr = _buff[20:24]

        # Gateway IP Address (GIADDR)
        giaddr = _buff[25:29]

        # NOTE: Next 192 octets are 0's for BOOTP legacy

        # DHCP Message Type
        msg_type = _buff[242]
        # DHCP Server ID
        dhcp_server_id = _buff[245:249]
        # Lease Time, in seconds
        lease_time = int.from_bytes(_buff[251:255], 'l')
        # T1 value
        t1 = int.from_bytes(_buff[257:261], 'l')
        # T2 value
        t2 = int.from_bytes(_buff[263:267], 'l')
        # Subnet Mask
        subnet_mask = _buff[269:273]

        return msg_type, transaction_id

    def request_dhcp_lease(self):
        # select an initial transaction id
        self._transaction_id = randrange(1, 2000)

        result = 0
        msg_type = 0
        start_time = time.monotonic()

        while self._dhcp_state != STATE_DHCP_LEASED:
            if self._dhcp_state == STATE_DHCP_START:
                self._transaction_id += 1
                if self._debug:
                    print("* Sending DISCOVER")
                self.send_dhcp_message(STATE_DHCP_DISCOVER, ((time.monotonic() - start_time) / 1000))
                self._dhcp_state = STATE_DHCP_DISCOVER
            elif self._dhcp_state == STATE_DHCP_DISCOVER:
                xid = 0
                msg_type, xid = self.parse_dhcp_response(self._timeout, xid)
                if msg_type == DHCP_OFFER:
                    # use the _transaction_id the offer returned,
                    # rather than the current one
                    self._transaction_id = xid
                    if self._debug:
                        print("* Sending REQUEST")
                    self.send_dhcp_message(STATE_DHCP_REQUEST, ((time.monotonic() - start_time) / 1000))
                    self._dhcp_state = STATE_DHCP_REQUEST
                break

        
            if msg_type == 255:
                msg_type = 0
                self._dhcp_state = STATE_DHCP_START
            
            if (result != 1 and ((time.monotonic() - start_time > self._timeout))):
                break
        
        self._transaction_id+=1
        self._last_check_lease_ms = time.monotonic()
        return result
