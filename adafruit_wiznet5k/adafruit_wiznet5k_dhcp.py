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
from random import randrange
from micropython import const
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket
from adafruit_wiznet5k.adafruit_wiznet5k_socket import htonl, htons

# pylint: disable=bad-whitespace

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
DHCP_BOOT_REQUEST = const(0x01)
DHCP_BOOT_REPLY   = const(0x02)

DHCP_HTYPE10MB  = const(0x01)
DHCP_HTYPE100MB = const(0x02)

DHCP_HLENETHERNET = const(0x06)
DHCP_HOPS         = const(0x00)

MAGIC_COOKIE = const(0x63825363)
MAX_DHCP_OPT = const(0x10)

# Default DHCP Server port
DHCP_SERVER_PORT   = const(67)
# DHCP Lease Time, in seconds
DEFAULT_LEASE_TIME = const(900)

BROADCAST_SERVER_ADDR = 255, 255, 255, 255
_BUFF = bytearray(317)

# pylint: enable=bad-whitespace


class DHCP:
    """W5k DHCP Client implementation.
    :param eth: Wiznet 5k object
    :param list mac_address: Hardware MAC.
    :param int timeout: Packet parsing timeout.
    :param int timeout_response: DHCP Response timeout.
    :param bool debug: Enable debugging output.

    """

    # pylint: too-many-arguments, too-many-instance-attributes
    def __init__(self, eth, mac_address, timeout=1, timeout_response=1):
        self._lease_time = 0
        self._t1 = 0
        self._t2 = 0
        self._timeout = timeout
        self._response_timeout = timeout_response
        self._mac_address = mac_address

        # Initalize a new UDP socket for DHCP
        socket.set_interface(eth)
        self._sock = socket.socket(type=socket.SOCK_DGRAM)
        self._sock.settimeout(timeout)

        self._dhcp_state = STATE_DHCP_START
        self._initial_xid = 0
        self._transaction_id = 0

        self.dhcp_server_ip = 0
        self.local_ip = 0
        self.gateway_ip = 0
        self.subnet_mask = 0
        self.dns_server_ip = 0

    def send_dhcp_message(self, state, time_elapsed):
        """Assemble and send a DHCP message packet to a socket.
        :param int state: DHCP Message state.
        :param float time_elapsed: Number of seconds elapsed since client
                                  attempted to acquire/renew a lease.
        """
        # OP
        _BUFF[0] = DHCP_BOOT_REQUEST
        # HTYPE
        _BUFF[1] = DHCP_HTYPE10MB
        # HLEN
        _BUFF[2] = DHCP_HLENETHERNET
        # HOPS
        _BUFF[3] = DHCP_HOPS

        # Transaction ID (xid)
        self._initial_xid = htonl(self._transaction_id)
        self._initial_xid = self._initial_xid.to_bytes(4, 'l')
        _BUFF[4:7] = self._initial_xid

        # seconds elapsed
        _BUFF[8] = ((int(time_elapsed) & 0xff00) >> 8)
        _BUFF[9] = (int(time_elapsed) & 0x00ff)

        # flags
        flags = htons(0x8000)
        flags = flags.to_bytes(2, 'b')
        _BUFF[10] = flags[1]
        _BUFF[11] = flags[0]

        # NOTE: Skipping cidaddr/yiaddr/siaddr/giaddr
        # as they're already set to 0.0.0.0

        # chaddr
        _BUFF[28:34] = self._mac_address

        # NOTE:  192 octets of 0's, BOOTP legacy

        # Magic Cookie
        _BUFF[236] = ((MAGIC_COOKIE >> 24)& 0xFF)
        _BUFF[237] = ((MAGIC_COOKIE >> 16)& 0xFF)
        _BUFF[238] = ((MAGIC_COOKIE >> 8)& 0xFF)
        _BUFF[239] = (MAGIC_COOKIE& 0xFF)

        # Option - DHCP Message Type
        _BUFF[240] = 53
        _BUFF[241] = 0x01
        _BUFF[242] = state

        # Option - Client Identifier
        _BUFF[243] = 61
        # Length
        _BUFF[244] = 0x07
        # HW Type - ETH
        _BUFF[245] = 0x01
        # Client MAC Address
        for mac in range(0, len(self._mac_address)):
            _BUFF[246+mac] = self._mac_address[mac]

        # Option - Host Name
        _BUFF[252] = 12
        _BUFF[253] = len(b"Wiznet") + 6
        # NOTE/TODO: This appends invalid ? chars. onto hostname instead of string
        _BUFF[254:266] = b"Wizneteeeeee"

        if state == DHCP_REQUEST:
            # Set the parsed local IP addr
            _BUFF[266] = 50
            _BUFF[267] = 0x04

            _BUFF[268:272] = self.local_ip
            # Set the parsed dhcp server ip addr
            _BUFF[272] = 54
            _BUFF[273] = 0x04
            _BUFF[274:278] = self.dhcp_server_ip

        _BUFF[278] = 55
        _BUFF[279] = 0x06
        # subnet mask
        _BUFF[280] = 1
        # routers on subnet
        _BUFF[281] = 3
        # DNS
        _BUFF[282] = 6
        # domain name
        _BUFF[283] = 15
        # renewal (T1) value
        _BUFF[284] = 58
        # rebinding (T2) value
        _BUFF[285] = 59
        _BUFF[286] = 255

        # Send DHCP packet
        self._sock.send(_BUFF)

    def parse_dhcp_response(self, response_timeout):
        """Parse DHCP response from DHCP server.
        Returns DHCP packet type.

        :param int response_timeout: Time to wait for server to return packet, in seconds.
        """
        print("CHECKING PACKET SIZE..")
        start_time = time.monotonic()
        packet_sz = 0
        while packet_sz <= 0:
            packet_sz = self._sock.available()
            if (time.monotonic() - start_time) > response_timeout:
                return 255
            time.sleep(0.05)
        # re-allocate and zero-out global packet buffer
        _BUFF = bytearray(packet_sz)
        _BUFF = self._sock.recv(packet_sz)[0]

        # Check OP, if valid, let's parse the packet out!
        assert _BUFF[0] == DHCP_BOOT_REPLY, "Malformed Packet - \
            DHCP message OP is not expected BOOT Reply."


        # Client Hardware Address (CHADDR)
        chaddr = bytearray(6)
        for mac, _ in enumerate(chaddr):
            chaddr[mac] = _BUFF[28+mac]

        if chaddr != 0:
            xid = _BUFF[4:8]
            if bytes(xid) < self._initial_xid:
                return 0, 0

        # Your IP Address (YIADDR)
        self.local_ip = _BUFF[16:20]

        # Gateway IP Address (GIADDR)
        self.gateway_ip = _BUFF[20:24]

        # NOTE: Next 192 octets are 0's for BOOTP legacy

        # DHCP Message Type
        msg_type = _BUFF[242]
        # DHCP Server ID
        self.dhcp_server_ip = _BUFF[245:249]
        # Lease Time, in seconds
        self._lease_time = int.from_bytes(_BUFF[251:255], 'l')
        # T1 value
        self._t1 = int.from_bytes(_BUFF[257:261], 'l')
        # print("T1: ", self._t1)
        # T2 value
        self._t2 = int.from_bytes(_BUFF[263:267], 'l')
        # print("T2: ", self._t2)
        # Subnet Mask
        self.subnet_mask = _BUFF[269:273]
        # DNS Server
        self.dns_server_ip = _BUFF[285:289]

        return msg_type, xid

    def request_dhcp_lease(self):
        """Request to renew or acquire a DHCP lease.

        """
        # select an initial transaction id
        self._transaction_id = randrange(1, 2000)

        result = 0
        msg_type = 0
        start_time = time.monotonic()

        while self._dhcp_state != STATE_DHCP_LEASED:
            if self._dhcp_state == STATE_DHCP_START:
                self._transaction_id += 1
                self._sock.connect((BROADCAST_SERVER_ADDR, DHCP_SERVER_PORT))
                self.send_dhcp_message(STATE_DHCP_DISCOVER,
                                       ((time.monotonic() - start_time) / 1000))
                self._dhcp_state = STATE_DHCP_DISCOVER
            elif self._dhcp_state == STATE_DHCP_DISCOVER:
                msg_type, xid = self.parse_dhcp_response(self._timeout)
                print(msg_type)
                if msg_type == DHCP_OFFER:
                    # use the _transaction_id the offer returned,
                    # rather than the current one
                    self._transaction_id = self._transaction_id.from_bytes(xid, 'l')
                    self.send_dhcp_message(DHCP_REQUEST, ((time.monotonic() - start_time) / 1000))
                    self._dhcp_state = STATE_DHCP_REQUEST
            elif STATE_DHCP_REQUEST:
                msg_type, xid = self.parse_dhcp_response(self._timeout)
                if msg_type == DHCP_ACK:
                    self._dhcp_state = STATE_DHCP_LEASED
                    result = 1
                    if self._lease_time == 0:
                        self._lease_time = DEFAULT_LEASE_TIME
                    if self._t1 == 0:
                        # T1 is 50% of _lease_time
                        self._t1 = self._lease_time >> 1
                    if self._t2 == 0:
                        # T2 is 87.5% of _lease_time
                        self._t2 = self._lease_time - (self._lease_time >> 3)
                    self._renew_in_sec = self._t1
                    self._rebind_in_sec = self._t2
                elif msg_type == DHCP_NAK:
                    self._dhcp_state = STATE_DHCP_START

                if msg_type == 255:
                    msg_type = 0
                    self._dhcp_state = STATE_DHCP_START

            if (result != 1 and ((time.monotonic() - start_time > self._timeout))):
                break

        self._transaction_id += 1
        self._last_check_lease_ms = time.monotonic()
        return result
