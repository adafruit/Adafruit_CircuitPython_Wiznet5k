# SPDX-FileCopyrightText: 2019 ladyada for Adafruit Industries
# SPDX-FileCopyrightText: 2020 Brent Rubell for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""
`adafruit_wiznet5k_socket`
================================================================================

A socket compatible interface with the Wiznet5k module.

* Author(s): ladyada, Brent Rubell, Patrick Van Oosterwijck, Adam Cummick

"""
from __future__ import annotations

try:
    from typing import TYPE_CHECKING, Optional, Tuple, List, Union

    if TYPE_CHECKING:
        from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K
except ImportError:
    pass

import gc
import time
from micropython import const

import adafruit_wiznet5k as wiznet5k

# pylint: disable=invalid-name
_the_interface: Optional[WIZNET5K] = None


def set_interface(iface: WIZNET5K) -> None:
    """
    Helper to set the global internet interface.

    :param wiznet5k.adafruit_wiznet5k.WIZNET5K iface: The ethernet interface.
    """
    global _the_interface  # pylint: disable=global-statement, invalid-name
    _the_interface = iface


def htonl(x: int) -> int:
    """
    Convert 32-bit positive integer from host to network byte order.

    :param int x: 32-bit positive integer from host.

    :return int: 32-bit positive integer in network byte order.
    """
    return int.from_bytes(x.to_bytes(4, "little"), "big")


def htons(x: int) -> int:
    """
    Convert 16-bit positive integer from host to network byte order.

    :param int x: 16-bit positive integer from host.

    :return int: 16-bit positive integer in network byte order.
    """
    return ((x << 8) & 0xFF00) | ((x >> 8) & 0xFF)


SOCK_STREAM = const(0x21)  # TCP
TCP_MODE = 80
SOCK_DGRAM = const(0x02)  # UDP
AF_INET = const(3)
SOCKET_INVALID = const(255)


# pylint: disable=too-many-arguments, unused-argument
def getaddrinfo(
    host: str,
    port: int,
    family: int = 0,
    socktype: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> List[Tuple[int, int, int, str, Tuple[str, int]]]:
    """
    Translate the host/port argument into a sequence of 5-tuples that contain all the necessary
    arguments for creating a socket connected to that service.

    :param str host: a domain name, a string representation of an IPv4/v6 address or
        None.
    :param int port: Port number to connect to (0 - 65536).
    :param int family: Ignored and hardcoded as 0x03 (the only family implemented) by the function.
    :param int socktype: The type of socket, either SOCK_STREAM (0x21) for TCP or SOCK_DGRAM (0x02)
        for UDP, defaults to 0x00.
    :param int proto: Unused in this implementation of socket.
    :param int flags: Unused in this implementation of socket.

    :return List[Tuple[int, int, int, str, Tuple[str, int]]]: Address info entries.
    """
    if not isinstance(port, int):
        raise ValueError("Port must be an integer")
    octets = host.split(".", 3)
    if len(octets) == 4 and "".join(octets).isdigit():
        for octet in octets:
            if int(octet) > 255:
                pass
    else:
        host = gethostbyname(host)
    return [(AF_INET, socktype, proto, "", (host, port))]


def gethostbyname(hostname: str) -> str:
    """
    Lookup a host name's IPv4 address.

    :param str hostname: Hostname to lookup.

    :return str: IPv4 address (a string of the form '0.0.0.0').
    """
    address = _the_interface.get_host_by_name(hostname)
    address = "{}.{}.{}.{}".format(address[0], address[1], address[2], address[3])
    return address


# pylint: disable=invalid-name, too-many-public-methods
class socket:
    """
    A simplified implementation of the Python 'socket' class for connecting
    to a Wiznet5k module.
    """

    # pylint: disable=redefined-builtin,unused-argument
    def __init__(
        self,
        family: int = AF_INET,
        type: int = SOCK_STREAM,
        proto: int = 0,
        fileno: Optional[int] = None,
    ) -> None:
        """
        :param int family: Socket address (and protocol) family, defaults to AF_INET.
        :param int type: Socket type, use SOCK_STREAM for TCP and SOCK_DGRAM for UDP,
            defaults to SOCK_STREAM.
        :param int proto: Unused, retained for compatibility.
        :param Optional[int] fileno: Unused, retained for compatibility.
        :param Optional[int] socknum: Unused, retained for compatibility.
        """
        if family != AF_INET:
            raise RuntimeError("Only AF_INET family supported by W5K modules.")
        self._sock_type = type
        self._buffer = b""
        self._timeout = 0
        self._listen_port = None

        self._socknum = _the_interface.get_socket()
        if self._socknum == SOCKET_INVALID:
            raise RuntimeError("Failed to allocate socket.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._sock_type == SOCK_STREAM:
            self._disconnect()
            stamp = time.monotonic()
            while self._status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_FIN_WAIT:
                if time.monotonic() - stamp > 1000:
                    raise RuntimeError("Failed to disconnect socket")
        self.close()
        stamp = time.monotonic()
        while self._status != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED:
            if time.monotonic() - stamp > 1000:
                raise RuntimeError("Failed to close socket")

    @property
    def _socknum(self) -> int:
        """
        Return the socket object's socket number.

        :return int: Socket number.
        """
        return self._socknum

    @property
    def _status(self) -> int:
        """
        Return the status of the socket.

        :return int: Status of the socket.
        """
        return _the_interface.socket_status(self._socknum)[0]

    @property
    def _connected(self) -> bool:
        """
        Return whether connected to the socket.

        :return bool: Whether connected.
        """
        if self._socknum >= _the_interface.max_sockets:
            return False
        status = _the_interface.socket_status(self._socknum)[0]
        if (
            status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSE_WAIT
            and self._available() == 0
        ):
            result = False
        else:
            result = status not in (
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_TIME_WAIT,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_FIN_WAIT,
            )
        if not result and status != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN:
            self.close()
        return result

    def getpeername(self) -> Tuple[str, int]:
        """
        Return the remote address to which the socket is connected.

        :return Tuple[str, int]: IPv4 address and port the socket is connected to.
        """
        return _the_interface.remote_ip(self._socknum), _the_interface.remote_port(
            self._socknum
        )

    def bind(self, address: Tuple[Optional[str], int]) -> None:
        """Bind the socket to address. The socket must not already be bound.

        The hardware sockets on WIZNET5K systems all share the same IPv4 address that
        was assigned at startup. Ports can only be bound to this address.

        :param Tuple[Optional[str], int] address: Address as a (host, port) tuple.

        :raises ValueError: If the IPv4 address specified is not the address
            assigned to the WIZNET5K interface.
        """
        if not self._listen_port:
            if gethostbyname(address[0]) != _the_interface.pretty_ip(
                _the_interface.ip_address
            ):
                raise ValueError(
                    "The IPv4 address requested must match {}, "
                    "the one assigned to the WIZNET5K interface.".format(
                        _the_interface.pretty_ip(_the_interface.ip_address)
                    )
                )
            self._listen_port = address[1]
            # For UDP servers we need to open the socket here because we won't call
            # listen
            if self._sock_type == SOCK_DGRAM:
                _the_interface.socket_listen(
                    self._socknum,
                    self._listen_port,
                    wiznet5k.adafruit_wiznet5k.SNMR_UDP,
                )
                self._buffer = b""
        else:
            raise ConnectionError("The socket is already bound.")

    def listen(self, backlog: int = 0) -> None:
        """
        Enable a server to accept connections.

        :param int backlog: Included for compatibility but ignored.
        """
        assert self._listen_port is not None, "Use bind to set the port before listen!"
        _the_interface.socket_listen(self._socknum, self._listen_port)
        self._buffer = b""

    def accept(
        self,
    ) -> Tuple[socket, Tuple[str, int]]:
        """
        Accept a connection.

        The socket must be bound to an address and listening for connections.

        The return value is a pair (conn, address) where conn is a new
        socket object to send and receive data on the connection, and address is
        the address bound to the socket on the other end of the connection.

        :returns OptionalTuple[socket, Tuple[str, int]]: TThe return value is a pair
        (conn, address) where conn is a new socket object to send and receive data on
        the connection, and address is the address bound to the socket on the other
        end of the connection.
        """
        stamp = time.monotonic()
        while self._status not in (
            wiznet5k.adafruit_wiznet5k.SNSR_SOCK_SYNRECV,
            wiznet5k.adafruit_wiznet5k.SNSR_SOCK_ESTABLISHED,
        ):
            if 0 < self._timeout < time.monotonic() - stamp:
                raise TimeoutError("Failed to accept connection.")
            if self._status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED:
                self.close()
                self.listen()

        new_listen_socknum, addr = _the_interface.socket_accept(self._socknum)
        current_socknum = self._socknum
        # Create a new socket object and swap socket nums, so we can continue listening
        client_sock = socket()
        # TODO: See if this can be done with setattr
        client_sock.__setattr__(  # pylint: disable=unnecessary-dunder-call
            "_socknum", current_socknum
        )
        self.__setattr__(  # pylint: disable=unnecessary-dunder-call
            "_socknum", new_listen_socknum
        )
        self.bind((None, self._listen_port))
        self.listen()
        while self._status != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN:
            raise RuntimeError("Failed to open new listening socket")
        return client_sock, addr

    def connect(self, address: Tuple[str, int]) -> None:
        """
        Connect to a remote socket at address.

        :param Tuple[str, int] address: Remote socket as a (host, port) tuple.
        """
        if self._listen_port is not None:
            _the_interface.src_port = self._listen_port
        result = _the_interface.socket_connect(
            self._socknum, bytes(gethostbyname(address[0])), address[1], self._sock_type
        )
        _the_interface.src_port = 0
        if not result:
            raise RuntimeError("Failed to connect to host ", address[0])
        self._buffer = b""

    def send(self, data: Union[bytes, bytearray]) -> int:
        """
        Send data to the socket.

        Send data to the socket. The socket must be connected to a remote socket.
        Applications are responsible for checking that all data has been sent; if
        only some of the data was transmitted, the application needs to attempt
        delivery of the remaining data.

        :param bytearray data: Data to send to the socket.

        :returns int: Number of bytes sent.
        """
        bytes_sent = _the_interface.socket_write(self._socknum, data, self._timeout)
        gc.collect()
        return bytes_sent

    # def sendto(self, data: bytearray, address: [Tuple[str, int]]) -> int:

    def sendto(self, data: bytearray, *flags_and_or_address: any) -> int:
        """
        Connect to a remote socket and send data.

        :param bytearray data: Data to send to the socket.

        Either:
        :param [Tuple[str, int]] address: Remote socket as a (host, port) tuple.

        Or:
        :param int flags: Not implemented, kept for compatibility.
        :param Tuple[int, Tuple(str, int)] address: Remote socket as a (host, port) tuple
        """
        # May be called with (data, address) or (data, flags, address)
        other_args = list(flags_and_or_address)
        if len(other_args) in (1, 2):
            address = other_args[-1]
        else:
            raise ValueError("Incorrect number of arguments, should be 2 or 3.")
        self.connect(address)
        return self.send(data)

    def recv(
        # pylint: disable=too-many-branches
        self,
        bufsize: int,
        flags: int = 0,
    ) -> bytes:
        """
        Receive data from the socket.

        :param int bufsize: Maximum number of bytes to receive.
        :param int flags: ignored, present for compatibility.

        :returns bytes: Data from the socket.
        """
        stop_time = time.monotonic() + self._timeout
        if self._timeout != 0.0:
            while not self._available():
                if self._timeout is not None and time.monotonic() > stop_time:
                    break
                time.sleep(0.05)
        bytes_on_socket = self._available()
        if not bytes_on_socket:
            return b""
        bytes_to_read = min(bytes_on_socket, bufsize)
        if self._sock_type == SOCK_STREAM:
            bytes_read = _the_interface.socket_read(self._socknum, bytes_to_read)[1]
        else:
            bytes_read = _the_interface.read_udp(self._socknum, bytes_to_read)[1]
        gc.collect()
        return bytes(bytes_read)

    def _embed_recv(
        self, bufsize: int = 0, flags: int = 0
    ) -> bytes:  # pylint: disable=too-many-branches
        """
        Read from the connected remote address.

        :param int bufsize: Maximum number of bytes to receive, ignored by the
            function, defaults to 0.
        :param int flags: ignored, present for compatibility.

        :return bytes: All data available from the connection.
        """
        # print("Socket read", bufsize)
        ret = None
        avail = self._available()
        if avail:
            if self._sock_type == SOCK_STREAM:
                self._buffer += _the_interface.socket_read(self._socknum, avail)[1]
            elif self._sock_type == SOCK_DGRAM:
                self._buffer += _the_interface.read_udp(self._socknum, avail)[1]
        gc.collect()
        ret = self._buffer
        # print("RET ptr:", id(ret), id(self._buffer))
        self._buffer = b""
        gc.collect()
        return ret

    def recvfrom(self, bufsize: int, flags: int = 0) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive data from the socket.

        :param int bufsize: Maximum number of bytes to receive.
        :param int flags: Ignored, present for compatibility.

        :return Tuple[bytes, Tuple[str, int]]: a tuple (bytes, address)
            where address is a tuple (ip, port)
        """
        return (
            self.recv(bufsize),
            (
                _the_interface.pretty_ip(_the_interface.udp_from_ip[self._socknum]),
                _the_interface.udp_from_port[self._socknum],
            ),
        )

    def recv_into(self, buffer: bytearray, nbytes: int = 0, flags: int = 0) -> int:
        """
        Receive up to nbytes bytes from the socket, storing the data into a buffer
        rather than creating a new bytestring.

        :param bytearray buffer: Data buffer to read into.
        :param nbytes: Maximum number of bytes to receive (if 0, use length of buffer).
        :param int flags: ignored, present for compatibility.

        :return int: the number of bytes received
        """
        if nbytes == 0:
            nbytes = len(buffer)
        bytes_received = self.recv(nbytes)
        nbytes = len(bytes_received)
        buffer[:nbytes] = bytes_received
        return nbytes

    def recvfrom_into(
        self, buffer: bytearray, nbytes: int = 0, flags: int = 0
    ) -> Tuple[int, Tuple[str, int]]:
        """
        Receive data from the socket, writing it into buffer instead of creating a new bytestring.

        :param bytearray buffer: Data buffer.
        :param int nbytes: Maximum number of bytes to receive.
        :param int flags: Unused, present for compatibility.

        :return Tuple[int, Tuple[str, int]]: A tuple (nbytes, address) where nbytes is the
        number of bytes received and address is a tuple (IPv4 address, port).
        """
        return (
            self.recv_into(buffer, nbytes),
            (
                _the_interface.remote_ip(self._socknum),
                _the_interface.remote_port(self._socknum),
            ),
        )

    def _readline(self) -> bytes:
        """
        Read a line from the socket.

        Deprecated, will be removed in the future.

        Attempt to return as many bytes as we can up to but not including a carriage return and
        linefeed character pair.

        :return bytes: The data read from the socket.
        """
        stamp = time.monotonic()
        while b"\r\n" not in self._buffer:
            avail = self._available()
            if avail:
                if self._sock_type == SOCK_STREAM:
                    self._buffer += _the_interface.socket_read(self._socknum, avail)[1]
                elif self._sock_type == SOCK_DGRAM:
                    self._buffer += _the_interface.read_udp(self._socknum, avail)[1]
            if not avail and 0 < self._timeout < time.monotonic() - stamp:
                self.close()
                raise RuntimeError("Didn't receive response, failing out...")
        firstline, self._buffer = self._buffer.split(b"\r\n", 1)
        gc.collect()
        return firstline

    def _disconnect(self) -> None:
        """Disconnect a TCP socket."""
        assert self._sock_type == SOCK_STREAM, "Socket must be a TCP socket."
        _the_interface.socket_disconnect(self._socknum)

    def close(self) -> None:
        """Close the socket."""
        _the_interface.socket_close(self._socknum)

    def _available(self) -> int:
        """
        Return how many bytes of data are available to be read from the socket.

        :return int: Number of bytes available.
        """
        return _the_interface.socket_available(self._socknum, self._sock_type)

    def settimeout(self, value: float) -> None:
        """
        Set the socket read timeout.

        :param float value: Socket read timeout in seconds.

        """
        # TODO: Implement None and 0.0 as valid once all socket funcs can handle them.
        if value < 0:
            raise ValueError("Timeout period should be non-negative.")
        self._timeout = value

    def gettimeout(self) -> Optional[float]:
        """
        Timeout associated with socket operations.

        :return Optional[float]: Timeout in seconds, or None if no timeout is set.
        """
        return self._timeout

    @property
    def family(self) -> int:
        """Socket family (always 0x03 in this implementation)."""
        return 3

    @property
    def type(self):
        """Socket type."""
        return self._sock_type

    @property
    def proto(self):
        """Socket protocol (always 0x00 in this implementation)."""
        return 0
