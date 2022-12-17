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
from adafruit_wiznet5k.adafruit_wiznet5k_socket import htonl


# DHCP State Machine
STATE_DHCP_START = const(0x00)
STATE_DHCP_DISCOVER = const(0x01)
STATE_DHCP_REQUEST = const(0x02)
STATE_DHCP_LEASED = const(0x03)
STATE_DHCP_REREQUEST = const(0x04)
STATE_DHCP_RELEASE = const(0x05)
STATE_DHCP_WAIT = const(0x06)
STATE_DHCP_DISCONN = const(0x07)

STATE_INIT = const(0x01)
STATE_SELECTING = const(0x02)
STATE_REQUESTING = const(0x03)
STATE_BOUND = const(0x04)
STATE_RENEWING = const(0x05)
STATE_REBINDING = const(0x06)
STATE_RELEASING = const(0x07)

# DHCP wait time between attempts
DHCP_WAIT_TIME = const(60)

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
_BUFF = bytearray(318)


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
        self._dhcp_state = STATE_DHCP_START
        self._initial_xid = 0
        self._transaction_id = 0
        self._start_time = 0
        self._next_resend = 0
        self._retries = 0
        self._max_retries = 0

        # DHCP server configuration
        self.dhcp_server_ip = BROADCAST_SERVER_ADDR
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

    # pylint: disable=too-many-branches, too-many-statements
    def _dhcp_state_machine(self) -> None:
        """
        DHCP state machine without wait loops to enable cooperative multitasking.
        This state machine is used both by the initial blocking lease request and
        the non-blocking DHCP maintenance function.
        """
        if self._eth.link_status:
            if self._dhcp_state == STATE_DHCP_DISCONN:
                self._dhcp_state = STATE_DHCP_START
        else:
            if self._dhcp_state != STATE_DHCP_DISCONN:
                self._dhcp_state = STATE_DHCP_DISCONN
                self.dhcp_server_ip = BROADCAST_SERVER_ADDR
                self._last_lease_time = 0
                reset_ip = (0, 0, 0, 0)
                self._eth.ifconfig = (reset_ip, reset_ip, reset_ip, reset_ip)
                if self._sock is not None:
                    self._sock.close()
                    self._sock = None

        if self._dhcp_state == STATE_DHCP_START:
            self._start_time = time.monotonic()
            self._transaction_id = (self._transaction_id + 1) & 0x7FFFFFFF
            try:
                self._sock = socket.socket(type=socket.SOCK_DGRAM)
            except RuntimeError:
                if self._debug:
                    print("* DHCP: Failed to allocate socket")
                self._dhcp_state = STATE_DHCP_WAIT
            else:
                self._sock.settimeout(self._response_timeout)
                self._sock.bind((None, 68))
                self._sock.connect((self.dhcp_server_ip, DHCP_SERVER_PORT))
                if self._last_lease_time == 0 or time.monotonic() > (
                    self._last_lease_time + self._lease_time
                ):
                    if self._debug:
                        print("* DHCP: Send discover to {}".format(self.dhcp_server_ip))
                    # self.send_dhcp_message(
                    #     STATE_DHCP_DISCOVER, (time.monotonic() - self._start_time)
                    # )
                    self._dhcp_state = STATE_DHCP_DISCOVER
                else:
                    if self._debug:
                        print("* DHCP: Send request to {}".format(self.dhcp_server_ip))
                    # self.send_dhcp_message(
                    #     DHCP_REQUEST, (time.monotonic() - self._start_time), True
                    # )
                    self._dhcp_state = STATE_DHCP_REQUEST

        elif self._dhcp_state == STATE_DHCP_DISCOVER:
            if self._sock.available():
                if self._debug:
                    print("* DHCP: Parsing OFFER")
                msg_type, xid = None, None  # self.parse_dhcp_response()
                if msg_type == DHCP_OFFER:
                    # Check if transaction ID matches, otherwise it may be an offer
                    # for another device
                    if htonl(self._transaction_id) == int.from_bytes(xid, "big"):
                        if self._debug:
                            print(
                                "* DHCP: Send request to {}".format(self.dhcp_server_ip)
                            )
                        self._transaction_id = (self._transaction_id + 1) & 0x7FFFFFFF
                        # self.send_dhcp_message(
                        #     DHCP_REQUEST, (time.monotonic() - self._start_time)
                        # )
                        self._dhcp_state = STATE_DHCP_REQUEST
                    else:
                        if self._debug:
                            print("* DHCP: Received OFFER with non-matching xid")
                else:
                    if self._debug:
                        print("* DHCP: Received DHCP Message is not OFFER")

        elif self._dhcp_state == STATE_DHCP_REQUEST:
            if self._sock.available():
                if self._debug:
                    print("* DHCP: Parsing ACK")
                msg_type, xid = None, None  # self.parse_dhcp_response()
                # Check if transaction ID matches, otherwise it may be
                # for another device
                if htonl(self._transaction_id) == int.from_bytes(xid, "big"):
                    if msg_type == DHCP_ACK:
                        if self._debug:
                            print("* DHCP: Successful lease")
                        self._sock.close()
                        self._sock = None
                        self._dhcp_state = STATE_DHCP_LEASED
                        self._last_lease_time = self._start_time
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

        elif self._dhcp_state == STATE_DHCP_WAIT:
            if time.monotonic() > (self._start_time + DHCP_WAIT_TIME):
                if self._debug:
                    print("* DHCP: Begin retry")
                self._dhcp_state = STATE_DHCP_START
                if time.monotonic() > (self._last_lease_time + self._rebind_in_sec):
                    self.dhcp_server_ip = BROADCAST_SERVER_ADDR
                if time.monotonic() > (self._last_lease_time + self._lease_time):
                    reset_ip = (0, 0, 0, 0)
                    self._eth.ifconfig = (reset_ip, reset_ip, reset_ip, reset_ip)

        elif self._dhcp_state == STATE_DHCP_LEASED:
            if time.monotonic() > (self._last_lease_time + self._renew_in_sec):
                self._dhcp_state = STATE_DHCP_START
                if self._debug:
                    print("* DHCP: Time to renew lease")

        if self._dhcp_state in (
            STATE_DHCP_DISCOVER,
            STATE_DHCP_REQUEST,
        ) and time.monotonic() > (self._start_time + self._response_timeout):
            self._dhcp_state = STATE_DHCP_WAIT
            if self._sock is not None:
                self._sock.close()
                self._sock = None

    def request_dhcp_lease(self) -> bool:
        """Request to renew or acquire a DHCP lease."""
        if self._dhcp_state in (STATE_DHCP_LEASED, STATE_DHCP_WAIT):
            self._dhcp_state = STATE_DHCP_START

        while self._dhcp_state not in (STATE_DHCP_LEASED, STATE_DHCP_WAIT):
            self._dhcp_state_machine()

        return self._dhcp_state == STATE_DHCP_LEASED

    def maintain_dhcp_lease(self) -> None:
        """Maintain DHCP lease"""
        self._dhcp_state_machine()

    def _dsm_reset(self):
        """I'll get to it"""
        self._retries = 0

    def _resend_time(self) -> float:
        """I'll get to it"""
        self._retries += 1
        return self._retries + randint(0, 2) + time.monotonic()

    def _set_next_state(self, *, next_state: int, max_retries: int) -> None:
        """I'll get to it"""
        self._sock.send(_BUFF)
        self._retries = 0
        self._max_retries = max_retries
        self._next_resend = self._resend_time()
        self._dhcp_state = next_state

    def _arp_check_for_ip_collision(self) -> bool:
        """I'll get to it"""
        timeout = 0.25
        arp_packet = bytearray(b"0x00" * 28)
        # Set ARP headers
        arp_packet[:8] = (0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01)
        arp_packet[8:14] = self._mac_address
        arp_packet[24:] = self.local_ip
        for _ in range(3):
            self._sock.send(arp_packet)
            stop_time = time.monotonic() + timeout
            while time.monotonic() < stop_time:
                if self._sock.available():
                    buffer = self._sock.recv()
                    if (
                        tuple(buffer[18:24]) == self._mac_address
                        and tuple(buffer[14:18]) == self.local_ip
                    ):
                        # Another device is already using this IP address.
                        return False
        # No response to ARP request, can accept this IP address.
        return True

    def _new_dhcp_state_machine(self, *, blocking: bool = False) -> None:
        """I'll get to it"""

        global _BUFF  # pylint: disable=global-variable-not-assigned, global-statement
        wait_for_link = 5
        # discover_max_retries = 3

        while blocking:
            pass  # Dummy for pylint
        # pylint: disable=too-many-nested-blocks
        while True:
            if self._dhcp_state == STATE_BOUND:
                if time.monotonic() > self._t1:
                    self._dhcp_state = STATE_RENEWING
                elif time.monotonic() > self._t2:
                    self._dhcp_state = STATE_REBINDING
                else:
                    return

            if self._dhcp_state == STATE_INIT:
                self._dsm_reset()
                time_to_stop = time.monotonic() + wait_for_link
                while not self._eth.link_status:
                    if time.monotonic() > time_to_stop:
                        raise TimeoutError("Ethernet link is down")
                    time.sleep(1)
                self._generate_dhcp_message(message_type=DHCP_DISCOVER, time_elapsed=0)
                self._set_next_state(next_state=STATE_DHCP_DISCOVER, max_retries=3)

            if self._dhcp_state == STATE_DHCP_DISCOVER:
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
                                if msg_type == DHCP_OFFER:
                                    self._generate_dhcp_message(
                                        message_type=DHCP_REQUEST, time_elapsed=0
                                    )
                                    self._set_next_state(
                                        next_state=STATE_REQUESTING, max_retries=3
                                    )
                                    break
                        if not blocking:
                            break
                    self._next_resend = self._resend_time()
                    if not blocking:
                        break

                if self._dhcp_state == STATE_REQUESTING:
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
                                    if msg_type == DHCP_NAK:
                                        self._set_next_state(
                                            next_state=STATE_INIT, max_retries=0
                                        )
                                        break
                                    if msg_type == DHCP_ACK:
                                        ...
                            if not blocking:
                                break
                        self._next_resend = self._resend_time()
                        if not blocking:
                            break

    def _generate_dhcp_message(
        self,
        *,
        message_type: int,
        time_elapsed: float,
        broadcast: bool = False,
        renew: bool = False,
    ) -> None:
        """
        Assemble a DHCP message packet.

        :param int time_elapsed: Time in seconds since transaction began.
        :param float time_elapsed: Number of seconds elapsed since DHCP process started.
        :param bool renew: Set True for renew and rebind, defaults to False.
        :param bool broadcast: Used to set the flag requiring a broadcast reply from the
            DHCP server.
        """

        def option_data(
            pointer: int, option_code: int, option_data: Union[Tuple[int, ...], bytes]
        ) -> int:
            """Helper function to set DHCP option data for a DHCP
            message.

            :param int pointer: Pointer to start of DHCP option.
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

        _BUFF[:] = b"\x00" * len(_BUFF)
        # OP.HTYPE.HLEN.HOPS
        _BUFF[0:4] = (DHCP_BOOT_REQUEST, DHCP_HTYPE10MB, DHCP_HLENETHERNET, DHCP_HOPS)
        # Transaction ID (xid)
        _BUFF[4:8] = self._transaction_id.to_bytes(4, "big")
        # seconds elapsed
        _BUFF[8:10] = int(time_elapsed).to_bytes(2, "big")
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

        :return Tuple[int, bytearray]: DHCP packet type and ID.
        """

        def option_data(pointer: int) -> Tuple[int, int, bytes]:
            """Helper function to extract DHCP option data from a
            response.

            :param int pointer: Pointer to start of DHCP option.

            :returns Tuple[int, int, bytes]: Pointer to next option,
                option type and option data.
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
            raise ValueError("No client ID in the response.")
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
