# SPDX-FileCopyrightText: 2009-2010 MCQN Ltd
# SPDX-FileCopyrightText: Brent Rubell for Adafruit Industries
#
# SPDX-License-Identifier: MIT

# Each function only has one return statement. Pylint seems confused.
# pylint: disable=inconsistent-return-statements
"""
`adafruit_wiznet5k_dns`
================================================================================

Pure-Python implementation of the Arduino DNS client for WIZnet 5k-based
ethernet modules.

* Author(s): MCQN Ltd, Brent Rubell, Martin Stephens

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


def _build_dns_query(domain: bytes) -> Tuple[int, int, bytearray]:
    """Builds DNS header."""
    # generate a random, 16-bit, request identifier
    query_id = getrandbits(16)
    # Hard code everything except the ID, it never changes in this implementation.
    query = bytearray(
        [
            query_id >> 8,  # Query MSB.
            query_id & 0xFF,  # Query LSB.
            0x01,  # Flags MSB: QR=0, 4 bit Opcode=0, AA=0, TC=0, RD=1 (recursion is desired).
            0x00,  # Flags LSB: RA=0, 3 bit Z=0, 4 bit RCode=0.
            0x00,  # QDcount MSB:
            0x01,  # QDcount LSB: Question count, always 1 in this implementation.
            0x00,  # ANcount MSB:
            0x00,  # ANcount LSB: Answer Record Count, 0 in queries.
            0x00,  # NScount MSB:
            0x00,  # NScount LSB: Authority Record Count, 0 in queries.
            0x00,  # ARcount MSB:
            0x00,  # ARcount LSB: Additional Record Count, 0 in queries.
        ]
    )
    host = domain.decode("utf-8").split(".")
    # Write out each label of question name.
    for label in host:
        # Append the length of the label
        query.append(len(label))
        # Append the label
        query += bytes(label, "utf-8")
    # Hard code null, question type and class as they never vary.
    query += bytearray(
        [
            0x00,  # Null, indicates end of question name
            0x00,  # Question Type MSB:
            0x01,  # Question Type LSB: Always 1 (Type A) in this implementation.
            0x00,  # Question Class MSB:
            0x01,  # Question Class LSB: Always 1 (Class IN) in this implementation.
        ]
    )
    return query_id, len(query), query


def _parse_dns_response(
    *, response: bytearray, query_id: int, query_length: int, debug: bool
) -> bytearray:
    # pylint: disable=too-many-branches
    """
    Parses a DNS query response.

    :param bytearray response: Data returned as a DNS query response.
    :param int query_id: The ID of the query that generated the response, used to validate
        the response.
    :param int query_length: The number of bytes in the DNS query that generated the response.
    :param bool debug: Whether to output debugging messsages.

    :returns bytearray: Four byte IPv4 address.

    :raises ValueError: If the response does not yield a valid IPv4 address from a type A,
        class IN answer.
    """
    # Validate request identifier
    response_id = int.from_bytes(response[0:2], "big")
    if response_id != query_id:
        raise ValueError(
            "* DNS ERROR: Response ID {x:x} does not match query ID {y:x}".format(
                x=response_id, y=query_id
            )
        )
    # Validate flags
    flags = int.from_bytes(response[2:4], "big")
    # Mask out authenticated, truncated and recursion bits, unimportant to parsing.
    flags &= 0xF87F
    # Check that the response bit is set, the query is standard and no error occurred.
    if flags != 0x8000:
        raise ValueError("* DNS ERROR: Invalid flags 0x{x:x}, bx{x:b}.".format(x=flags))
    # Number of questions
    question_count = int.from_bytes(response[4:6], "big")
    # Never more than one question per DNS query in this implementation.
    if question_count != 1:
        raise ValueError(
            "* DNS ERROR: Question count should be 1, is {}.".format(question_count)
        )
    # Number of answers
    answer_count = int.from_bytes(response[6:8], "big")
    _debug_print(debug=debug, message="* DNS Answer Count: {}.".format(answer_count))
    if answer_count < 1:
        raise ValueError(
            "* DNS ERROR: Answer count should be > 0, is {}.".format(answer_count)
        )

    # Parse answers
    pointer = query_length  # Response header is the same length as the query header.
    # pylint: disable=too-many-nested-blocks
    try:
        for answer in range(answer_count):
            label_length = response[pointer]
            if label_length == 0xC0:
                # Pointer to the domain name, skip over it.
                pointer += 2
            else:
                # Domain name, skip through it.
                while label_length != 0x00:  # Null represents root of domain name
                    pointer += label_length
                    label_length = response[pointer]
            # Check for a type A answer.
            if int.from_bytes(response[pointer : pointer + 2], "big") == TYPE_A:
                # Check for an IN class answer.
                if (
                    int.from_bytes(response[pointer + 2 : pointer + 4], "big")
                    == CLASS_IN
                ):
                    _debug_print(
                        debug=debug,
                        message="Type A, class IN found in answer {x} of {y}.".format(
                            x=answer + 1, y=answer_count
                        ),
                    )
                    # Set pointer to start of resource record.
                    pointer += 8
                    # Confirm that the resource record is 4 bytes (an IPv4 address).
                    if (
                        int.from_bytes(response[pointer : pointer + 2], "big")
                        == DATA_LEN
                    ):
                        ipv4 = response[pointer + 2 : pointer + 6]
                        # Low probability that the response was truncated inside the 4 byte address.
                        if len(ipv4) != DATA_LEN:
                            raise ValueError("IPv4 address is not 4 bytes.")
                        _debug_print(
                            debug=debug,
                            message="IPv4 address found : 0x{:x}.".format(
                                int.from_bytes(ipv4, "big")
                            ),
                        )
                        return ipv4
            # Set pointer to start of next answer
            pointer += 10 + int.from_bytes(response[pointer + 8 : pointer + 10], "big")
            _debug_print(
                debug=debug,
                message="Answer {x} of {y} was not type A, class IN.".format(
                    x=answer + 1, y=answer_count
                ),
            )
    except (IndexError, ValueError) as error:
        # IndexError means we ran out of data in an answer, maybe truncated.
        # ValueError means we ran out of answers.
        raise ValueError(
            "No type A, class IN answers found in the DNS response."
        ) from error


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
        self._query_id = 0  # Request ID.
        self._query_length = 0  # Length of last query.

    def gethostbyname(self, hostname):
        """Translate a host name to IPv4 address format.

        :param str hostname: Desired host name to connect to.

        Returns the IPv4 address as a bytearray if successful, -1 otherwise.
        """
        if self._dns_server is None:
            return INVALID_SERVER

        # build DNS request packet
        self._query_id, self._query_length, buffer = _build_dns_query(hostname)

        # Send DNS request packet
        self._sock.bind((None, DNS_PORT))
        self._sock.connect((self._dns_server, DNS_PORT))
        _debug_print(debug=self._debug, message="* DNS: Sending request packet...")
        self._sock.send(buffer)

        # Read and parse the DNS response
        ipaddress = -1
        for _ in range(5):
            #  wait for a response
            socket_timeout = time.monotonic() + 1.0
            packet_size = self._sock.available()
            while packet_size == 0:
                packet_size = self._sock.available()
                if time.monotonic() > socket_timeout:
                    _debug_print(
                        debug=self._debug,
                        message="* DNS ERROR: Did not receive DNS response (socket timeout).",
                    )
                    return -1
                time.sleep(0.05)
            # recv packet into buf
            buffer = self._sock.recv()
            _debug_print(
                debug=self._debug,
                message="DNS Packet Received: {}".format(buffer),
            )
            try:
                ipaddress = _parse_dns_response(
                    response=buffer,
                    query_id=self._query_id,
                    query_length=self._query_length,
                    debug=self._debug,
                )
                break
            except ValueError:
                _debug_print(
                    debug=self._debug,
                    message="* DNS ERROR: Failed to resolve DNS response, retrying…",
                )
        self._sock.close()
        return ipaddress
