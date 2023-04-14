# SPDX-FileCopyrightText: 2009 Jordan Terrell (blog.jordanterrell.com)
# SPDX-FileCopyrightText: 2020 Brent Rubell for Adafruit Industries
# SPDX-FileCopyrightText: 2021 Patrick Van Oosterwijck @ Silicognition LLC
#
# SPDX-License-Identifier: MIT

"""
`adafruit_wiznet5k_dhcp`
================================================================================

Pure-Python implementation of Jordan Terrell's DHCP library v0.3

* Author(s): Jordan Terrell, Brent Rubell

"""
from __future__ import annotations

try:
    from typing import TYPE_CHECKING, Optional, Union, Tuple, Sequence

    if TYPE_CHECKING:
        from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K
except ImportError:
    pass


import gc
import time
from random import randint
from micropython import const
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket
from adafruit_wiznet5k.adafruit_wiznet5k_socket import htonl, htons


# DHCP State Machine
_STATE_DHCP_START = const(0x00)
_STATE_DHCP_DISCOVER = const(0x01)
_STATE_DHCP_REQUEST = const(0x02)
_STATE_DHCP_LEASED = const(0x03)
_STATE_DHCP_REREQUEST = const(0x04)
_STATE_DHCP_RELEASE = const(0x05)
_STATE_DHCP_WAIT = const(0x06)
_STATE_DHCP_DISCONN = const(0x07)

# DHCP wait time between attempts
_DHCP_WAIT_TIME = const(60)

# DHCP Message Types
_DHCP_DISCOVER = const(1)
_DHCP_OFFER = const(2)
_DHCP_REQUEST = const(3)
_DHCP_DECLINE = const(4)
_DHCP_ACK = const(5)
_DHCP_NAK = const(6)
_DHCP_RELEASE = const(7)
_DHCP_INFORM = const(8)

# DHCP Message OP Codes
_DHCP_BOOT_REQUEST = const(0x01)
_DHCP_BOOT_REPLY = const(0x02)

_DHCP_HTYPE10MB = const(0x01)
_DHCP_HTYPE100MB = const(0x02)

_DHCP_HLENETHERNET = const(0x06)
_DHCP_HOPS = const(0x00)

_MAGIC_COOKIE = b"c\x82Sc"  # Four bytes 99.130.83.99
_MAX_DHCP_OPT = const(0x10)

# Default DHCP Server port
_DHCP_SERVER_PORT = const(67)
# DHCP Lease Time, in seconds
_DEFAULT_LEASE_TIME = const(900)
_BROADCAST_SERVER_ADDR = (255, 255, 255, 255)

# DHCP Response Options
_MSG_TYPE = 53
_SUBNET_MASK = 1
_ROUTERS_ON_SUBNET = 3
_DNS_SERVERS = 6
_DHCP_SERVER_ID = 54
_T1_VAL = 58
_T2_VAL = 59
_LEASE_TIME = 51
_OPT_END = 255

# Packet buffer size
_BUFF_SIZE = const(318)

class DHCP:
    """W5k DHCP Client implementation."""

    # pylint: disable=too-many-arguments, too-many-instance-attributes, invalid-name
    def __init__(
        self,
        eth: WIZNET5K,
        mac_address: Sequence[Union[int, bytes]],
        hostname: Optional[str] = None,
        response_timeout: float = 30.0,
        debug: bool = False,
    ) -> None:
        """
        :param adafruit_wiznet5k.WIZNET5K eth: Wiznet 5k object
        :param Sequence[Union[int, bytes]] mac_address: Hardware MAC address.
        :param Optional[str] hostname: The desired hostname, with optional {} to fill
            in the MAC address, defaults to None.
        :param float response_timeout: DHCP Response timeout in seconds, defaults to 30.
        :param bool debug: Enable debugging output.
        """
        self._debug = debug
        self._response_timeout = response_timeout

        # Prevent buffer overrun in send_dhcp_message()
        if len(mac_address) != 6:
            raise ValueError("The MAC address must be 6 bytes.")
        self._mac_address = mac_address

        # Set socket interface
        socket.set_interface(eth)
        self._eth = eth
        self._sock = None

        # DHCP state machine
        self._dhcp_state = _STATE_DHCP_START
        self._initial_xid = 0
        self._transaction_id = 0
        self._start_time = 0

        # DHCP server configuration
        self.dhcp_server_ip = _BROADCAST_SERVER_ADDR
        self.local_ip = 0
        self.gateway_ip = 0
        self.subnet_mask = 0
        self.dns_server_ip = 0

        # Lease configuration
        self._lease_time = 0
        self._last_lease_time = 0
        self._renew_in_sec = 0
        self._rebind_in_sec = 0
        self._t1 = 0
        self._t2 = 0

        # Select an initial transaction id
        self._transaction_id = randint(1, 0x7FFFFFFF)

        # Host name
        mac_string = "".join("{:02X}".format(o) for o in mac_address)
        self._hostname = bytes(
            (hostname or "WIZnet{}").split(".")[0].format(mac_string)[:42], "utf-8"
        )

    # pylint: disable=too-many-statements
    def send_dhcp_message(
        self,
        state: int,
        time_elapsed: float,
        renew: bool = False,
    ) -> None:
        """
        Assemble and send a DHCP message packet to a socket.

        :param int state: DHCP Message state.
        :param float time_elapsed: Number of seconds elapsed since DHCP process started
        :param bool renew: Set True for renew and rebind, defaults to False
        """
        buff = bytearray(_BUFF_SIZE)
        # OP
        buff[0] = _DHCP_BOOT_REQUEST
        # HTYPE
        buff[1] = _DHCP_HTYPE10MB
        # HLEN
        buff[2] = _DHCP_HLENETHERNET
        # HOPS
        buff[3] = _DHCP_HOPS

        # Transaction ID (xid)
        self._initial_xid = htonl(self._transaction_id)
        self._initial_xid = self._initial_xid.to_bytes(4, "big")
        buff[4:8] = self._initial_xid

        # seconds elapsed
        buff[8] = (int(time_elapsed) & 0xFF00) >> 8
        buff[9] = int(time_elapsed) & 0x00FF

        # flags
        flags = htons(0x8000)
        flags = flags.to_bytes(2, "big")
        buff[10] = flags[1]
        buff[11] = flags[0]

        # NOTE: Skipping ciaddr/yiaddr/siaddr/giaddr
        # as they're already set to 0.0.0.0
        # Except when renewing, then fill in ciaddr
        if renew:
            buff[12:16] = bytes(self.local_ip)

        # chaddr
        buff[28:34] = self._mac_address

        # NOTE:  192 octets of 0's, BOOTP legacy

        # Magic Cookie
        buff[236:240] = _MAGIC_COOKIE

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
        for mac, val in enumerate(self._mac_address):
            buff[246 + mac] = val

        # Option - Host Name
        buff[252] = 12
        hostname_len = len(self._hostname)
        after_hostname = 254 + hostname_len
        buff[253] = hostname_len
        buff[254:after_hostname] = self._hostname

        if state == _DHCP_REQUEST and not renew:
            # Set the parsed local IP addr
            buff[after_hostname] = 50
            buff[after_hostname + 1] = 0x04
            buff[after_hostname + 2 : after_hostname + 6] = bytes(self.local_ip)
            # Set the parsed dhcp server ip addr
            buff[after_hostname + 6] = 54
            buff[after_hostname + 7] = 0x04
            buff[after_hostname + 8 : after_hostname + 12] = bytes(self.dhcp_server_ip)

        buff[after_hostname + 12] = 55
        buff[after_hostname + 13] = 0x06
        # subnet mask
        buff[after_hostname + 14] = 1
        # routers on subnet
        buff[after_hostname + 15] = 3
        # DNS
        buff[after_hostname + 16] = 6
        # domain name
        buff[after_hostname + 17] = 15
        # renewal (T1) value
        buff[after_hostname + 18] = 58
        # rebinding (T2) value
        buff[after_hostname + 19] = 59
        buff[after_hostname + 20] = 255

        # Send DHCP packet
        self._sock.send(buff)

    # pylint: disable=too-many-branches, too-many-statements
    def parse_dhcp_response(
        self,
    ) -> Tuple[int, bytearray]:
        """Parse DHCP response from DHCP server.

        :return Tuple[int, bytearray]: DHCP packet type and ID.
        """
        # store packet in buffer
        buff = bytearray(self._sock.recv(_BUFF_SIZE))
        if self._debug:
            print("DHCP Response: ", buff)

        # -- Parse Packet, FIXED -- #
        # Validate OP
        if buff[0] != _DHCP_BOOT_REPLY:
            raise RuntimeError(
                "Malformed Packet - \
            DHCP message OP is not expected BOOT Reply."
            )

        xid = buff[4:8]
        if bytes(xid) != self._initial_xid:
            raise ValueError("DHCP response ID mismatch.")

        self.local_ip = tuple(buff[16:20])
        # Check that there is a server ID.
        if buff[28:34] == b"\x00\x00\x00\x00\x00\x00":
            raise ValueError("No DHCP server ID in the response.")

        if buff[236:240] != _MAGIC_COOKIE:
            raise ValueError("No DHCP Magic Cookie in the response.")

        # -- Parse Packet, VARIABLE -- #
        ptr = 240
        while buff[ptr] != _OPT_END:
            if buff[ptr] == _MSG_TYPE:
                ptr += 1
                opt_len = buff[ptr]
                ptr += opt_len
                msg_type = buff[ptr]
                ptr += 1
            elif buff[ptr] == _SUBNET_MASK:
                ptr += 1
                opt_len = buff[ptr]
                ptr += 1
                self.subnet_mask = tuple(buff[ptr : ptr + opt_len])
                ptr += opt_len
            elif buff[ptr] == _DHCP_SERVER_ID:
                ptr += 1
                opt_len = buff[ptr]
                ptr += 1
                self.dhcp_server_ip = tuple(buff[ptr : ptr + opt_len])
                ptr += opt_len
            elif buff[ptr] == _LEASE_TIME:
                ptr += 1
                opt_len = buff[ptr]
                ptr += 1
                self._lease_time = int.from_bytes(buff[ptr : ptr + opt_len], "big")
                ptr += opt_len
            elif buff[ptr] == _ROUTERS_ON_SUBNET:
                ptr += 1
                opt_len = buff[ptr]
                ptr += 1
                self.gateway_ip = tuple(buff[ptr : ptr + 4])
                ptr += opt_len
            elif buff[ptr] == _DNS_SERVERS:
                ptr += 1
                opt_len = buff[ptr]
                ptr += 1
                self.dns_server_ip = tuple(buff[ptr : ptr + 4])
                ptr += opt_len  # still increment even though we only read 1 addr.
            elif buff[ptr] == _T1_VAL:
                ptr += 1
                opt_len = buff[ptr]
                ptr += 1
                self._t1 = int.from_bytes(buff[ptr : ptr + opt_len], "big")
                ptr += opt_len
            elif buff[ptr] == _T2_VAL:
                ptr += 1
                opt_len = buff[ptr]
                ptr += 1
                self._t2 = int.from_bytes(buff[ptr : ptr + opt_len], "big")
                ptr += opt_len
            elif buff[ptr] == 0:
                break
            else:
                # We're not interested in this option
                ptr += 1
                opt_len = buff[ptr]
                ptr += 1
                # no-op
                ptr += opt_len

        if self._debug:
            print(
                "Msg Type: {}\nSubnet Mask: {}\nDHCP Server IP: {}\nDNS Server IP: {}\
                  \nGateway IP: {}\nLocal IP: {}\nT1: {}\nT2: {}\nLease Time: {}".format(
                    msg_type,
                    self.subnet_mask,
                    self.dhcp_server_ip,
                    self.dns_server_ip,
                    self.gateway_ip,
                    self.local_ip,
                    self._t1,
                    self._t2,
                    self._lease_time,
                )
            )

        gc.collect()
        return msg_type, xid

    # pylint: disable=too-many-branches, too-many-statements
    def _dhcp_state_machine(self) -> None:
        """
        DHCP state machine without wait loops to enable cooperative multitasking.
        This state machine is used both by the initial blocking lease request and
        the non-blocking DHCP maintenance function.
        """
        if self._eth.link_status:
            if self._dhcp_state == _STATE_DHCP_DISCONN:
                self._dhcp_state = _STATE_DHCP_START
        else:
            if self._dhcp_state != _STATE_DHCP_DISCONN:
                self._dhcp_state = _STATE_DHCP_DISCONN
                self.dhcp_server_ip = _BROADCAST_SERVER_ADDR
                self._last_lease_time = 0
                reset_ip = (0, 0, 0, 0)
                self._eth.ifconfig = (reset_ip, reset_ip, reset_ip, reset_ip)
                if self._sock is not None:
                    self._sock.close()
                    self._sock = None

        if self._dhcp_state == _STATE_DHCP_START:
            self._start_time = time.monotonic()
            self._transaction_id = (self._transaction_id + 1) & 0x7FFFFFFF
            try:
                self._sock = socket.socket(type=socket.SOCK_DGRAM)
            except RuntimeError:
                if self._debug:
                    print("* DHCP: Failed to allocate socket")
                self._dhcp_state = _STATE_DHCP_WAIT
            else:
                self._sock.settimeout(self._response_timeout)
                self._sock.bind(("", 68))
                self._sock.connect(
                    (".".join(map(str, self.dhcp_server_ip)), _DHCP_SERVER_PORT)
                )
                if self._last_lease_time == 0 or time.monotonic() > (
                    self._last_lease_time + self._lease_time
                ):
                    if self._debug:
                        print("* DHCP: Send discover to {}".format(self.dhcp_server_ip))
                    self.send_dhcp_message(
                        _STATE_DHCP_DISCOVER, (time.monotonic() - self._start_time)
                    )
                    self._dhcp_state = _STATE_DHCP_DISCOVER
                else:
                    if self._debug:
                        print("* DHCP: Send request to {}".format(self.dhcp_server_ip))
                    self.send_dhcp_message(
                        _DHCP_REQUEST, (time.monotonic() - self._start_time), True
                    )
                    self._dhcp_state = _STATE_DHCP_REQUEST

        elif self._dhcp_state == _STATE_DHCP_DISCOVER:
            if self._sock._available():  # pylint: disable=protected-access
                if self._debug:
                    print("* DHCP: Parsing OFFER")
                try:
                    msg_type, xid = self.parse_dhcp_response()
                except ValueError as error:
                    if self._debug:
                        print(error)
                else:
                    if msg_type == _DHCP_OFFER:
                        # Check if transaction ID matches, otherwise it may be an offer
                        # for another device
                        if htonl(self._transaction_id) == int.from_bytes(xid, "big"):
                            if self._debug:
                                print(
                                    "* DHCP: Send request to {}".format(
                                        self.dhcp_server_ip
                                    )
                                )
                            self._transaction_id = (
                                self._transaction_id + 1
                            ) & 0x7FFFFFFF
                            self.send_dhcp_message(
                                _DHCP_REQUEST, (time.monotonic() - self._start_time)
                            )
                            self._dhcp_state = _STATE_DHCP_REQUEST
                        else:
                            if self._debug:
                                print("* DHCP: Received OFFER with non-matching xid")
                    else:
                        if self._debug:
                            print("* DHCP: Received DHCP Message is not OFFER")

        elif self._dhcp_state == _STATE_DHCP_REQUEST:
            if self._sock._available():  # pylint: disable=protected-access
                if self._debug:
                    print("* DHCP: Parsing ACK")
                try:
                    msg_type, xid = self.parse_dhcp_response()
                except ValueError as error:
                    if self._debug:
                        print(error)
                else:
                    # Check if transaction ID matches, otherwise it may be
                    # for another device
                    if htonl(self._transaction_id) == int.from_bytes(xid, "big"):
                        if msg_type == _DHCP_ACK:
                            if self._debug:
                                print("* DHCP: Successful lease")
                            self._sock.close()
                            self._sock = None
                            self._dhcp_state = _STATE_DHCP_LEASED
                            self._last_lease_time = self._start_time
                            if self._lease_time == 0:
                                self._lease_time = _DEFAULT_LEASE_TIME
                            if self._t1 == 0:
                                # T1 is 50% of _lease_time
                                self._t1 = self._lease_time >> 1
                            if self._t2 == 0:
                                # T2 is 87.5% of _lease_time
                                self._t2 = self._lease_time - (self._lease_time >> 3)
                            self._renew_in_sec = self._t1
                            self._rebind_in_sec = self._t2
                            self._eth.ifconfig = (
                                self.local_ip,
                                self.subnet_mask,
                                self.gateway_ip,
                                self.dns_server_ip,
                            )
                            gc.collect()
                        else:
                            if self._debug:
                                print("* DHCP: Received DHCP Message is not ACK")
                    else:
                        if self._debug:
                            print("* DHCP: Received non-matching xid")

        elif self._dhcp_state == _STATE_DHCP_WAIT:
            if time.monotonic() > (self._start_time + _DHCP_WAIT_TIME):
                if self._debug:
                    print("* DHCP: Begin retry")
                self._dhcp_state = _STATE_DHCP_START
                if time.monotonic() > (self._last_lease_time + self._rebind_in_sec):
                    self.dhcp_server_ip = _BROADCAST_SERVER_ADDR
                if time.monotonic() > (self._last_lease_time + self._lease_time):
                    reset_ip = (0, 0, 0, 0)
                    self._eth.ifconfig = (reset_ip, reset_ip, reset_ip, reset_ip)

        elif self._dhcp_state == _STATE_DHCP_LEASED:
            if time.monotonic() > (self._last_lease_time + self._renew_in_sec):
                self._dhcp_state = _STATE_DHCP_START
                if self._debug:
                    print("* DHCP: Time to renew lease")

        if self._dhcp_state in (
            _STATE_DHCP_DISCOVER,
            _STATE_DHCP_REQUEST,
        ) and time.monotonic() > (self._start_time + self._response_timeout):
            self._dhcp_state = _STATE_DHCP_WAIT
            if self._sock is not None:
                self._sock.close()
                self._sock = None

    def request_dhcp_lease(self) -> bool:
        """Request to renew or acquire a DHCP lease."""
        if self._dhcp_state in (_STATE_DHCP_LEASED, _STATE_DHCP_WAIT):
            self._dhcp_state = _STATE_DHCP_START

        while self._dhcp_state not in (_STATE_DHCP_LEASED, _STATE_DHCP_WAIT):
            self._dhcp_state_machine()

        return self._dhcp_state == _STATE_DHCP_LEASED

    def maintain_dhcp_lease(self) -> None:
        """Maintain DHCP lease"""
        self._dhcp_state_machine()
