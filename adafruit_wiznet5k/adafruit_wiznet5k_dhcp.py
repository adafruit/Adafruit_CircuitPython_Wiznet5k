# SPDX-FileCopyrightText: 2009 Jordan Terrell (blog.jordanterrell.com)
# SPDX-FileCopyrightText: 2020 Brent Rubell for Adafruit Industries
# SPDX-FileCopyrightText: 2021 Patrick Van Oosterwijck @ Silicognition LLC
#
# SPDX-License-Identifier: MIT

"""
`adafruit_wiznet5k_dhcp`
================================================================================

Pure-Python implementation of Jordan Terrell's DHCP library v0.3

* Author(s): Jordan Terrell, Brent Rubell, Martin Stephens

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

# DHCP State Machine
STATE_INIT = const(0x01)
STATE_SELECTING = const(0x02)
STATE_REQUESTING = const(0x03)
STATE_BOUND = const(0x04)
STATE_RENEWING = const(0x05)
STATE_REBINDING = const(0x06)

# DHCP Message Types
DHCP_DISCOVER = const(1)
DHCP_OFFER = const(2)
DHCP_REQUEST = const(3)
DHCP_DECLINE = const(4)
DHCP_ACK = const(5)
DHCP_NAK = const(6)
DHCP_RELEASE = const(7)
DHCP_INFORM = const(8)

# DHCP Message OP Codes
DHCP_BOOT_REQUEST = const(0x01)
DHCP_BOOT_REPLY = const(0x02)

DHCP_HTYPE10MB = const(0x01)
DHCP_HTYPE100MB = const(0x02)

DHCP_HLENETHERNET = const(0x06)
DHCP_HOPS = const(0x00)

MAGIC_COOKIE = b"c\x82Sc"  # Four bytes 99.130.83.99
MAX_DHCP_OPT = const(0x10)

# Default DHCP Server port
DHCP_SERVER_PORT = const(67)
# DHCP Lease Time, in seconds
DEFAULT_LEASE_TIME = const(900)
BROADCAST_SERVER_ADDR = (255, 255, 255, 255)
UNASSIGNED_IP_ADDR = (0, 0, 0, 0)

# DHCP Response Options
MSG_TYPE = 53
SUBNET_MASK = 1
ROUTERS_ON_SUBNET = 3
DNS_SERVERS = 6
DHCP_SERVER_ID = 54
T1_VAL = 58
T2_VAL = 59
LEASE_TIME = 51
OPT_END = 255

# Packet buffer
BUFF_LENGTH = 318
_BUFF = bytearray(BUFF_LENGTH)


class DHCP:
    """Wiznet5k DHCP Client.

    Implements a DHCP client using a finite state machine (FSM). This allows the DHCP client
    to run in a non-blocking mode suitable for CircuitPython.

    The DHCP client obtains a lease and maintains it. The process of obtaining the initial
    lease is best run in a blocking mode, as several messages must be exchanged with the DHCP
    server. Once the lease has been allocated, lease maintenance can be performed in
    non-blocking mode as nothing needs to be done until it is time to reallocate the
    lease. Renewing or rebinding is a simpler process which may be repeated periodically
    until successful. If the lease expires, the client attempts to obtain a new lease in
    blocking mode when the maintenance routine is run.

    In most circumstances, call `DHCP.request_lease` in blocking mode to obtain a
    lease, then periodically call `DHCP.maintain_lease` in non-blocking mode so that the
    FSM can check whether the lease needs to be renewed, and can then renew it.

    Since DHCP uses UDP, messages may be lost. The DHCP protocol uses exponential backoff
    for retrying. Retries occur after 4, 8, and 16 seconds (the final retry isfollowed by
    a wait of 32 seconds) so it will take about a minute to decide that no DHCP server
    is available.

    Use of DHCP relay agents is not implemented. The DHCP server must be on the same
    physical network as the client.

    The DHCP client cannot check whether the allocated IP address is already in use because
    the ARP protocol is not available. Therefore, it is possible that the IP address has been
    statically assigned to another device. In most cases, the DHCP server will make this
    check before allocating an address, but some do not.

    The DHCPRELEASE message is not implemented. The DHCP protocol does not require it and
    DHCP servers can handle disappearing clients and clients that ask for 'replacement'
    IP addressed.
    """

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
        self._dhcp_state = STATE_INIT
        self._transaction_id = randint(1, 0x7FFFFFFF)
        self._start_time = 0
        self._next_resend = 0
        self._retries = 0
        self._max_retries = 0
        self._blocking = False
        self._renew = False

        # DHCP binding configuration
        self.dhcp_server_ip = BROADCAST_SERVER_ADDR
        self.local_ip = UNASSIGNED_IP_ADDR
        self.gateway_ip = UNASSIGNED_IP_ADDR
        self.subnet_mask = UNASSIGNED_IP_ADDR
        self.dns_server_ip = UNASSIGNED_IP_ADDR

        # Lease configuration
        self._lease_time = 0
        self._t1 = 0
        self._t2 = 0

        # Host name
        mac_string = "".join("{:02X}".format(o) for o in mac_address)
        self._hostname = bytes(
            (hostname or "WIZnet{}").split(".")[0].format(mac_string)[:42], "utf-8"
        )

    def request_dhcp_lease(self) -> bool:
        """Request to renew or acquire a DHCP lease."""
        self._dhcp_state_machine(blocking=True)
        return self._dhcp_state == STATE_BOUND

    def maintain_dhcp_lease(self) -> None:
        """Maintain DHCP lease"""
        self._dhcp_state_machine()

    def _dsm_reset(self) -> None:
        """Close the socket and set attributes to default values used by the
        state machine INIT state."""
        self._socket_release()
        self.dhcp_server_ip = BROADCAST_SERVER_ADDR
        self._eth.ifconfig = (
            UNASSIGNED_IP_ADDR,
            UNASSIGNED_IP_ADDR,
            UNASSIGNED_IP_ADDR,
            UNASSIGNED_IP_ADDR,
        )
        self.gateway_ip = UNASSIGNED_IP_ADDR
        self.local_ip = UNASSIGNED_IP_ADDR
        self.subnet_mask = UNASSIGNED_IP_ADDR
        self.dns_server_ip = UNASSIGNED_IP_ADDR
        self._renew = False
        self._retries = 0
        self._increment_transaction_id()
        self._start_time = int(time.monotonic())

    def _socket_release(self) -> None:
        """Close the socket if it exists."""
        if self._sock:
            self._sock.close()
            self._sock = None

    def _socket_setup(self, timeout: int = 5) -> None:
        """I'll get to it."""
        self._socket_release()
        stop_time = time.monotonic() + timeout
        while not time.monotonic() > stop_time:
            try:
                self._sock = socket.socket(type=socket.SOCK_DGRAM)
            except RuntimeError:
                if self._debug:
                    print("DHCP client failed to allocate socket")
                    if self._blocking:
                        print("Retrying…")
                    else:
                        return
            else:
                self._sock.settimeout(self._response_timeout)
                self._sock.bind((None, 68))
                self._sock.connect((self.dhcp_server_ip, DHCP_SERVER_PORT))
                return
        raise RuntimeError(
            "DHCP client failed to allocate socket. Retried for {} seconds.".format(
                timeout
            )
        )

    def _increment_transaction_id(self) -> None:
        """Increment the transaction ID and roll over from 0x7fffffff to 0."""
        self._transaction_id = (self._transaction_id + 1) & 0x7FFFFFFF

    def _next_retry_time(self, *, interval: int = 4) -> int:
        """Calculate a retry stop time.

        The interval is calculated as an exponential fallback with a random variation to
        prevent DHCP packet collisions. This timeout is intended to be compared with
        time.monotonic(). Uses self._retries as the exponent, and increments this value
        each time it is called.

        :param int interval: The base retry interval in seconds. Defaults to 4 as per the
            DHCP standard for Ethernet connections.

        :returns int: The timeout in time.monotonic() seconds.

        :raises ValueError: If the calculated interval is < 1 second.
        """
        delay = int(2**self._retries * interval + randint(-1, 1) + time.monotonic())
        if delay < 1:
            raise ValueError("Retry delay must be >= 1 second")
        self._retries += 1
        return delay

    def _send_message_set_next_state(
        self,
        *,
        message_type: int,
        next_state: int,
        max_retries: int,
    ) -> None:
        """I'll get to it"""
        self._generate_dhcp_message(message_type=message_type)
        self._sock.send(_BUFF)
        self._retries = 0
        self._max_retries = max_retries
        self._next_resend = self._next_retry_time()
        self._dhcp_state = next_state

    def _handle_dhcp_message(self) -> None:
        # pylint: disable=too-many-branches
        while True:
            while time.monotonic() < self._next_resend:
                if self._sock.available():
                    _BUFF = self._sock.recv()
                    try:
                        msg_type = self._parse_dhcp_response()
                    except ValueError as error:
                        if self._debug:
                            print(error)
                    else:
                        if (
                            self._dhcp_state == STATE_SELECTING
                            and msg_type == DHCP_OFFER
                        ):
                            self._send_message_set_next_state(
                                message_type=DHCP_REQUEST,
                                next_state=STATE_REQUESTING,
                                max_retries=3,
                            )
                            return
                        if self._dhcp_state == STATE_REQUESTING:
                            if msg_type == DHCP_NAK:
                                self._dhcp_state = STATE_INIT
                                return
                            if msg_type == DHCP_ACK:
                                if self._lease_time == 0:
                                    self._lease_time = DEFAULT_LEASE_TIME
                                self._t1 = self._start_time + self._lease_time // 2
                                self._t2 = (
                                    self._start_time
                                    + self._lease_time
                                    - self._lease_time // 8
                                )
                                self._lease_time += self._start_time
                                self._increment_transaction_id()
                                self._renew = False
                                self._sock.close()
                                self._sock = None
                                self._dhcp_state = STATE_BOUND
                            return
                if not self._blocking:
                    return
            self._next_resend = self._next_retry_time()
            if self._retries > self._max_retries:
                raise RuntimeError(
                    "No response from DHCP server after {}".format(self._max_retries)
                )
            if not self._blocking:
                return

    def _dhcp_state_machine(self, *, blocking: bool = False) -> None:
        """I'll get to it"""

        global _BUFF  # pylint: disable=global-variable-not-assigned, global-statement
        self._blocking = blocking

        while self._eth.link_status:
            if self._dhcp_state == STATE_BOUND:
                now = time.monotonic()
                if now < self._t1:
                    return
                if now > self._lease_time:
                    self._blocking = True
                    self._dhcp_state = STATE_INIT
                elif now > self._t2:
                    self._dhcp_state = STATE_REBINDING
                else:
                    self._dhcp_state = STATE_RENEWING

            if self._dhcp_state == STATE_RENEWING:
                self._renew = True
                self._socket_setup()
                self._start_time = time.monotonic()
                self._send_message_set_next_state(
                    message_type=DHCP_REQUEST,
                    next_state=STATE_REQUESTING,
                    max_retries=3,
                )

            if self._dhcp_state == STATE_REBINDING:
                self._renew = True
                self.dhcp_server_ip = BROADCAST_SERVER_ADDR
                self._socket_setup()
                self._send_message_set_next_state(
                    message_type=DHCP_REQUEST,
                    next_state=STATE_REQUESTING,
                    max_retries=3,
                )

            if self._dhcp_state == STATE_INIT:
                self._dsm_reset()
                self._send_message_set_next_state(
                    message_type=DHCP_DISCOVER,
                    next_state=STATE_SELECTING,
                    max_retries=3,
                )

            if self._dhcp_state == STATE_SELECTING:
                self._max_retries = 3
                self._handle_dhcp_message()

            if self._dhcp_state == STATE_REQUESTING:
                self._max_retries = 3
                self._handle_dhcp_message()
            if not self._blocking:
                break
        self._blocking = False

    def _generate_dhcp_message(
        self,
        *,
        message_type: int,
        broadcast: bool = False,
        renew: bool = False,
    ) -> None:
        """
        Assemble a DHCP message. The content will vary depending on which type of
            message is being sent and whether the lease is new or being renewed.

        :param int message_type: Type of message to generate.
        :param bool broadcast: Used to set the flag requiring a broadcast reply from the
            DHCP server. Defaults to False to match DHCP standard.
        :param bool renew: Set True for renewing and rebinding operations, defaults to False.
        """

        def option_data(
            pointer: int, option_code: int, option_data: Union[Tuple[int, ...], bytes]
        ) -> int:
            """Helper function to set DHCP option data for a DHCP
            message.

            :param int pointer: Pointer to start of a DHCP option.
            :param int option_code: Type of option to add.
            :param Tuple[int] option_data: The data for the option.

            :returns int: Pointer to next option.
            """
            global _BUFF  # pylint: disable=global-variable-not-assigned
            _BUFF[pointer] = option_code
            data_length = len(option_data)
            pointer += 1
            _BUFF[pointer] = data_length
            pointer += 1
            data_end = pointer + data_length
            _BUFF[pointer:data_end] = option_data
            return data_end

        _BUFF[:] = b"\x00" * BUFF_LENGTH
        # OP.HTYPE.HLEN.HOPS
        _BUFF[0:4] = (DHCP_BOOT_REQUEST, DHCP_HTYPE10MB, DHCP_HLENETHERNET, DHCP_HOPS)
        # Transaction ID (xid)
        _BUFF[4:8] = self._transaction_id.to_bytes(4, "big")
        # seconds elapsed
        _BUFF[8:10] = int(time.monotonic() - self._start_time).to_bytes(2, "big")
        # flags (only bit 0 is used)
        if broadcast:
            _BUFF[10] = 0b10000000
        if renew:
            _BUFF[12:16] = bytes(self.local_ip)
        # chaddr
        _BUFF[28:34] = self._mac_address
        # Magic Cookie
        _BUFF[236:240] = MAGIC_COOKIE

        # Set DHCP options.
        pointer = 240

        # Option - DHCP Message Type
        pointer = option_data(
            pointer=pointer, option_code=53, option_data=(message_type,)
        )
        # Option - Host Name
        pointer = option_data(
            pointer=pointer, option_code=12, option_data=self._hostname
        )
        if message_type == DHCP_REQUEST:
            # Request subnet mask, router and DNS server.
            pointer = option_data(
                pointer=pointer, option_code=55, option_data=(1, 3, 6)
            )
            # Set Requested IP Address to offered IP address.
            pointer = option_data(
                pointer=pointer, option_code=50, option_data=self.local_ip
            )
            # Set Server ID to chosen DHCP server IP address.
            pointer = option_data(
                pointer=pointer, option_code=54, option_data=self.dhcp_server_ip
            )
        _BUFF[pointer] = 0xFF

    def _parse_dhcp_response(
        self,
    ) -> int:
        """Parse DHCP response from DHCP server.

        Check that the message is for this client. Extract data from the fixed positions
         in the first 236 bytes of the message, then cycle through the options for
         additional data.

        :returns Tuple[int, bytearray]: DHCP packet type and ID.

        :raises ValueError: Checks that the message is a reply, the transaction ID
        matches, a client ID exists and the 'magic cookie' is set. If any of these tests
        fail or no message type is found in the options, raises a ValueError.
        """
        # pylint: disable=too-many-branches
        def option_data(pointer: int) -> Tuple[int, int, bytes]:
            """Helper function to extract DHCP option data from a
            response.

            :param int pointer: Pointer to start of a DHCP option.

            :returns Tuple[int, int, bytes]: Pointer to next option,
                option type, and option data.
            """
            global _BUFF  # pylint: disable=global-variable-not-assigned
            data_type = _BUFF[pointer]
            pointer += 1
            data_length = _BUFF[pointer]
            pointer += 1
            data_end = pointer + data_length
            data = _BUFF[pointer:data_end]
            return data_end, data_type, data

        global _BUFF  # pylint: disable=global-variable-not-assigned
        # Validate OP
        if _BUFF[0] != DHCP_BOOT_REPLY:
            raise ValueError("DHCP message OP is not expected BOOTP Reply.")
        # Confirm transaction IDs match.
        xid = _BUFF[4:8]
        if xid != self._transaction_id.to_bytes(4, "big"):
            raise ValueError("DHCP response ID mismatch.")
        # Set the IP address to Claddr
        self.local_ip = tuple(_BUFF[16:20])
        # Check that there is a client ID.
        if _BUFF[28:34] == b"\x00\x00\x00\x00\x00\x00":
            raise ValueError("No client hardware MAC address in the response.")
        # Check for the magic cookie.
        if _BUFF[236:240] != MAGIC_COOKIE:
            raise ValueError("No DHCP Magic Cookie in the response.")

        # Parse options
        msg_type = None
        ptr = 240
        while _BUFF[ptr] != OPT_END:
            ptr, data_type, data = option_data(ptr)
            if data_type == MSG_TYPE:
                msg_type = data[0]
            elif data_type == SUBNET_MASK:
                self.subnet_mask = tuple(data)
            elif data_type == DHCP_SERVER_ID:
                self.dhcp_server_ip = tuple(data)
            elif data_type == LEASE_TIME:
                self._lease_time = int.from_bytes(data, "big")
            elif data_type == ROUTERS_ON_SUBNET:
                self.gateway_ip = tuple(data[:4])
            elif data_type == DNS_SERVERS:
                self.dns_server_ip = tuple(data[:4])
            elif data_type == T1_VAL:
                self._t1 = int.from_bytes(data, "big")
            elif data_type == T2_VAL:
                self._t2 = int.from_bytes(data, "big")
            elif data_type == 0:
                break

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
        if msg_type is None:
            raise ValueError("No valid message type in response.")
        return msg_type

    # # pylint: disable=too-many-branches, too-many-statements
    # def _dhcp_state_machine(self) -> None:
    #     """
    #     DHCP state machine without wait loops to enable cooperative multitasking.
    #     This state machine is used both by the initial blocking lease request and
    #     the non-blocking DHCP maintenance function.
    #     """
    #     if self._eth.link_status:
    #         if self._dhcp_state == STATE_DHCP_DISCONN:
    #             self._dhcp_state = STATE_DHCP_START
    #     else:
    #         if self._dhcp_state != STATE_DHCP_DISCONN:
    #             self._dhcp_state = STATE_DHCP_DISCONN
    #             self.dhcp_server_ip = BROADCAST_SERVER_ADDR
    #             self._last_lease_time = 0
    #             reset_ip = (0, 0, 0, 0)
    #             self._eth.ifconfig = (reset_ip, reset_ip, reset_ip, reset_ip)
    #             if self._sock is not None:
    #                 self._sock.close()
    #                 self._sock = None
    #
    #     if self._dhcp_state == STATE_DHCP_START:
    #         self._start_time = time.monotonic()
    #         self._transaction_id = (self._transaction_id + 1) & 0x7FFFFFFF
    #         try:
    #             self._sock = socket.socket(type=socket.SOCK_DGRAM)
    #         except RuntimeError:
    #             if self._debug:
    #                 print("* DHCP: Failed to allocate socket")
    #             self._dhcp_state = STATE_DHCP_WAIT
    #         else:
    #             self._sock.settimeout(self._response_timeout)
    #             self._sock.bind((None, 68))
    #             self._sock.connect((self.dhcp_server_ip, DHCP_SERVER_PORT))
    #             if self._last_lease_time == 0 or time.monotonic() > (
    #                 self._last_lease_time + self._lease_time
    #             ):
    #                 if self._debug:
    #                     print("* DHCP: Send discover to {}".format(self.dhcp_server_ip))
    #                 # self.send_dhcp_message(
    #                 #     STATE_DHCP_DISCOVER, (time.monotonic() - self._start_time)
    #                 # )
    #                 self._dhcp_state = STATE_DHCP_DISCOVER
    #             else:
    #                 if self._debug:
    #                     print("* DHCP: Send request to {}".format(self.dhcp_server_ip))
    #                 # self.send_dhcp_message(
    #                 #     DHCP_REQUEST, (time.monotonic() - self._start_time), True
    #                 # )
    #                 self._dhcp_state = STATE_DHCP_REQUEST
    #
    #     elif self._dhcp_state == STATE_DHCP_DISCOVER:
    #         if self._sock.available():
    #             if self._debug:
    #                 print("* DHCP: Parsing OFFER")
    #             msg_type, xid = None, None  # self.parse_dhcp_response()
    #             if msg_type == DHCP_OFFER:
    #                 # Check if transaction ID matches, otherwise it may be an offer
    #                 # for another device
    #                 if htonl(self._transaction_id) == int.from_bytes(xid, "big"):
    #                     if self._debug:
    #                         print(
    #                             "* DHCP: Send request to {}".format(self.dhcp_server_ip)
    #                         )
    #                     self._transaction_id = (self._transaction_id + 1) & 0x7FFFFFFF
    #                     # self.send_dhcp_message(
    #                     #     DHCP_REQUEST, (time.monotonic() - self._start_time)
    #                     # )
    #                     self._dhcp_state = STATE_DHCP_REQUEST
    #                 else:
    #                     if self._debug:
    #                         print("* DHCP: Received OFFER with non-matching xid")
    #             else:
    #                 if self._debug:
    #                     print("* DHCP: Received DHCP Message is not OFFER")
    #
    #     elif self._dhcp_state == STATE_DHCP_REQUEST:
    #         if self._sock.available():
    #             if self._debug:
    #                 print("* DHCP: Parsing ACK")
    #             msg_type, xid = None, None  # self.parse_dhcp_response()
    #             # Check if transaction ID matches, otherwise it may be
    #             # for another device
    #             if htonl(self._transaction_id) == int.from_bytes(xid, "big"):
    #                 if msg_type == DHCP_ACK:
    #                     if self._debug:
    #                         print("* DHCP: Successful lease")
    #                     self._sock.close()
    #                     self._sock = None
    #                     self._dhcp_state = STATE_DHCP_LEASED
    #                     self._last_lease_time = self._start_time
    #                     if self._lease_time == 0:
    #                         self._lease_time = DEFAULT_LEASE_TIME
    #                     if self._t1 == 0:
    #                         # T1 is 50% of _lease_time
    #                         self._t1 = self._lease_time >> 1
    #                     if self._t2 == 0:
    #                         # T2 is 87.5% of _lease_time
    #                         self._t2 = self._lease_time - (self._lease_time >> 3)
    #                     self._renew_in_sec = self._t1
    #                     self._rebind_in_sec = self._t2
    #                     self._eth.ifconfig = (
    #                         self.local_ip,
    #                         self.subnet_mask,
    #                         self.gateway_ip,
    #                         self.dns_server_ip,
    #                     )
    #                     gc.collect()
    #                 else:
    #                     if self._debug:
    #                         print("* DHCP: Received DHCP Message is not ACK")
    #             else:
    #                 if self._debug:
    #                     print("* DHCP: Received non-matching xid")
    #
    #     elif self._dhcp_state == STATE_DHCP_WAIT:
    #         if time.monotonic() > (self._start_time + DHCP_WAIT_TIME):
    #             if self._debug:
    #                 print("* DHCP: Begin retry")
    #             self._dhcp_state = STATE_DHCP_START
    #             if time.monotonic() > (self._last_lease_time + self._rebind_in_sec):
    #                 self.dhcp_server_ip = BROADCAST_SERVER_ADDR
    #             if time.monotonic() > (self._last_lease_time + self._lease_time):
    #                 reset_ip = (0, 0, 0, 0)
    #                 self._eth.ifconfig = (reset_ip, reset_ip, reset_ip, reset_ip)
    #
    #     elif self._dhcp_state == STATE_DHCP_LEASED:
    #         if time.monotonic() > (self._last_lease_time + self._renew_in_sec):
    #             self._dhcp_state = STATE_DHCP_START
    #             if self._debug:
    #                 print("* DHCP: Time to renew lease")
    #
    #     if self._dhcp_state in (
    #         STATE_DHCP_DISCOVER,
    #         STATE_DHCP_REQUEST,
    #     ) and time.monotonic() > (self._start_time + self._response_timeout):
    #         self._dhcp_state = STATE_DHCP_WAIT
    #         if self._sock is not None:
    #             self._sock.close()
    #             self._sock = None
