# SPDX-FileCopyrightText: 2009-2010 MCQN Ltd
# SPDX-FileCopyrightText: Brent Rubell for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""
`adafruit_wiznet5k_dns`
================================================================================

Pure-Python implementation of the Arduino DNS client for WIZnet 5k-based
ethernet modules.

* Author(s): MCQN Ltd, Brent Rubell

"""
try:
    from typing import Tuple
except ImportError:
    pass

import time
from random import getrandbits
from micropython import const
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket

QUERY_FLAG = const(0x00)
OPCODE_STANDARD_QUERY = const(0x00)
RECURSION_DESIRED_FLAG = 1 << 8

TYPE_A = const(0x0001)
CLASS_IN = const(0x0001)
DATA_LEN = const(0x0004)

# Return codes for gethostbyname
SUCCESS = const(1)
TIMED_OUT = const(-1)
INVALID_SERVER = const(-2)
TRUNCATED = const(-3)
INVALID_RESPONSE = const(-4)

DNS_PORT = const(0x35)  # port used for DNS request


def _debug_print(*, debug: bool, message: str) -> None:
    """Helper function to improve code readability."""
    if debug:
        print(message)


def _build_dns_query(domain: bytes) -> Tuple[int, bytearray]:
    """Builds DNS header."""
    # generate a random, 16-bit, request identifier
    query_id = getrandbits(16)
    query = bytearray(
        [
            query_id >> 8,
            query_id & 0xFF,
            0x01,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )
    host = domain.decode("utf-8").split(".")
    # write out each label of host
    for label in host:
        # Append the length of the label
        query.append(len(label))
        # Append the label
        query += bytes(label, "utf-8")
    # Hard code null, question type and class as they never vary.
    query += bytearray([0x00, 0x00, 0x01, 0x00, 0x01])
    return query_id, query


class DNS:
    """W5K DNS implementation.

    :param iface: Network interface
    """

    def __init__(self, iface, dns_address, debug=False):
        self._debug = debug
        self._iface = iface
        socket.set_interface(iface)
        self._sock = socket.socket(type=socket.SOCK_DGRAM)
        self._sock.settimeout(1)

        self._dns_server = dns_address
        self._host = 0
        self._request_id = 0  # request identifier
        self._pkt_buf = bytearray()

    def gethostbyname(self, hostname):
        """Translate a host name to IPv4 address format.

        :param str hostname: Desired host name to connect to.

        Returns the IPv4 address as a bytearray if successful, -1 otherwise.
        """
        if self._dns_server is None:
            return INVALID_SERVER
        self._host = hostname
        # build DNS request packet
        self._request_id, self._pkt_buf = _build_dns_query(self._host)

        # Send DNS request packet
        self._sock.bind((None, DNS_PORT))
        self._sock.connect((self._dns_server, DNS_PORT))
        _debug_print(debug=self._debug, message="* DNS: Sending request packet...")
        self._sock.send(self._pkt_buf)

        # wait and retry 3 times for a response
        retries = 0
        addr = -1
        while (retries < 5) and (addr == -1):
            # wait for a response
            start_time = time.monotonic()
            packet_sz = self._sock.available()
            while packet_sz <= 0:
                packet_sz = self._sock.available()
                if (time.monotonic() - start_time) > 1.0:
                    _debug_print(
                        debug=self._debug,
                        message="* DNS ERROR: Did not receive DNS response!",
                    )
                    return -1
                time.sleep(0.05)
            # recv packet into buf
            self._pkt_buf = self._sock.recv()
            addr = self._parse_dns_response()
            if addr == -1:
                _debug_print(
                    debug=self._debug,
                    message="* DNS ERROR: Failed to resolve DNS response, retrying…",
                )
            retries += 1

        self._sock.close()
        return addr

    def _parse_dns_response(
        self,
    ):  # pylint: disable=too-many-return-statements, too-many-branches, too-many-statements, too-many-locals
        """Receives and parses DNS query response.
        Returns desired hostname address if obtained, -1 otherwise.

        """

        if self._debug:
            print("DNS Packet Received: ", self._pkt_buf)

        # Validate request identifier
        xid = int.from_bytes(self._pkt_buf[0:2], "big")
        if not xid == self._request_id:
            _debug_print(
                debug=self._debug,
                message="* DNS ERROR: Response ID {x:x} does not match query ID {y:x}".format(
                    x=xid, y=self._request_id
                ),
            )
            return -1
        # Validate flags
        flags = int.from_bytes(self._pkt_buf[2:4], "big")
        if not flags in (0x8180, 0x8580):
            _debug_print(
                debug=self._debug,
                message="* DNS ERROR: Invalid flags 0x{x:x}, bx{x:b}".format(x=flags),
            )
            return -1
        # Number of questions
        qr_count = int.from_bytes(self._pkt_buf[4:6], "big")
        if not qr_count >= 1:
            _debug_print(
                debug=self._debug,
                message="* DNS ERROR: Question count >=1, {}".format(qr_count),
            )
            return -1
        # Number of answers
        an_count = int.from_bytes(self._pkt_buf[6:8], "big")
        _debug_print(
            debug=self._debug, message="* DNS Answer Count: {}".format(an_count)
        )
        if not an_count >= 1:
            return -1

        # Parse query
        ptr = 12
        name_len = 1
        while name_len > 0:
            # read the length of the name
            name_len = self._pkt_buf[ptr]
            if name_len == 0x00:
                # we reached the end of this name
                ptr += 1  # inc. pointer by 0x00
                break
            # advance pointer
            ptr += name_len + 1

        # Validate Query is Type A
        q_type = int.from_bytes(self._pkt_buf[ptr : ptr + 2], "big")
        if not q_type == TYPE_A:
            _debug_print(
                debug=self._debug,
                message="* DNS ERROR: Incorrect Query Type: {}".format(q_type),
            )
            return -1
        ptr += 2

        # Validate Query is Type A
        q_class = int.from_bytes(self._pkt_buf[ptr : ptr + 2], "big")
        if not q_class == TYPE_A:
            _debug_print(
                debug=self._debug,
                message="* DNS ERROR: Incorrect Query Class: {}".format(q_class),
            )
            return -1
        ptr += 2

        # Let's take the first type-a answer
        if self._pkt_buf[ptr] != 0xC0:
            return -1
        ptr += 1

        if self._pkt_buf[ptr] != 0xC:
            return -1
        ptr += 1

        # Validate Answer Type A
        ans_type = int.from_bytes(self._pkt_buf[ptr : ptr + 2], "big")
        if not ans_type == TYPE_A:
            _debug_print(
                debug=self._debug,
                message="* DNS ERROR: Incorrect Answer Type: {}".format(ans_type),
            )
            return -1
        ptr += 2

        # Validate Answer Class IN
        ans_class = int.from_bytes(self._pkt_buf[ptr : ptr + 2], "big")
        if not ans_class == TYPE_A:
            _debug_print(
                debug=self._debug,
                message="* DNS ERROR: Incorrect Answer Class: {}".format(ans_class),
            )
            return -1
        ptr += 2

        # skip over TTL
        ptr += 4

        # Validate addr is IPv4
        data_len = int.from_bytes(self._pkt_buf[ptr : ptr + 2], "big")
        if not data_len == DATA_LEN:
            _debug_print(
                debug=self._debug,
                message="* DNS ERROR: Unexpected Data Length: {}".format(data_len),
            )
            return -1
        ptr += 2
        # Return address
        return self._pkt_buf[ptr : ptr + 4]
