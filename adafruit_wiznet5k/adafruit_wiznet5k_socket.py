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
    return (
        ((x) << 24 & 0xFF000000)
        | ((x) << 8 & 0x00FF0000)
        | ((x) >> 8 & 0x0000FF00)
        | ((x) >> 24 & 0x000000FF)
    )


def htons(x: int) -> int:
    """
    Convert 16-bit positive integer from host to network byte order.

    :param int x: 16-bit positive integer from host.

    :return int: 16-bit positive integer in network byte order.
    """
    return (((x) << 8) & 0xFF00) | (((x) >> 8) & 0xFF)


SOCK_STREAM = const(0x21)  # TCP
_TCP_MODE = 80
SOCK_DGRAM = const(0x02)  # UDP
AF_INET = const(3)
_SOCKET_INVALID = const(255)


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
    if is_ipv4(host):
        return [(AF_INET, socktype, proto, "", (host, port))]
    return [(AF_INET, socktype, proto, "", (gethostbyname(host), port))]


def gethostbyname(hostname: str) -> str:
    """
    Lookup a host name's IPv4 address.

    :param str hostname: Hostname to lookup.

    :return str: IPv4 address (a string of the form '255.255.255.255').
    """
    addr = _the_interface.get_host_by_name(hostname)
    addr = "{}.{}.{}.{}".format(addr[0], addr[1], addr[2], addr[3])
    return addr


def is_ipv4(host: str) -> bool:
    """
    Check if a hostname is an IPv4 address (a string of the form '255.255.255.255').

    :param str host: Hostname to check.

    :return bool:
    """
    octets = host.split(".", 3)
    if len(octets) != 4 or not "".join(octets).isdigit():
        return False
    for octet in octets:
        if int(octet) > 255:
            return False
    return True


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
        socknum: Optional[int] = None,
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
        if self._socknum == _SOCKET_INVALID:
            raise RuntimeError("Failed to allocate socket.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._sock_type == SOCK_STREAM:
            self.disconnect()
            stamp = time.monotonic()
            while self.status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_FIN_WAIT:
                if time.monotonic() - stamp > 1000:
                    raise RuntimeError("Failed to disconnect socket")
        self.close()
        stamp = time.monotonic()
        while self.status != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED:
            if time.monotonic() - stamp > 1000:
                raise RuntimeError("Failed to close socket")

    @property
    def socknum(self) -> int:
        """
        Return the socket object's socket number.

        :return int: Socket number.
        """
        return self._socknum

    @property
    def status(self) -> int:
        """
        Return the status of the socket.

        :return int: Status of the socket.
        """
        return _the_interface.socket_status(self.socknum)[0]

    @property
    def connected(self) -> bool:
        """
        Return whether connected to the socket.

        :return bool: Whether connected.
        """
        # pylint: disable=protected-access

        if self.socknum >= _the_interface.max_sockets:
            return False
        status = _the_interface.socket_status(self.socknum)[0]
        if (
            status == wiznet5k.adafruit_wiznet5k._SNSR_SOCK_CLOSE_WAIT
            and self.available() == 0
        ):
            result = False
        else:
            result = status not in (
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN,
                wiznet5k.adafruit_wiznet5k._SNSR_SOCK_TIME_WAIT,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_FIN_WAIT,
            )
        if not result and status != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN:
            self.close()
        return result

    def getpeername(self) -> Union[str, bytearray]:
        """
        Return the remote address to which the socket is connected.

        :return Union[str, bytearray]: An IPv4 address (a string of the form '255.255.255.255').
            An error may return a bytearray.
        """
        return _the_interface.remote_ip(self.socknum)

    def inet_aton(self, ip_string: str) -> bytearray:
        """
        Convert an IPv4 address from dotted-quad string format.

        :param str ip_string: IPv4 address (a string of the form '255.255.255.255').

        :return bytearray: IPv4 address as a 4 byte bytearray.
        """
        self._buffer = b""
        self._buffer = [int(item) for item in ip_string.split(".")]
        self._buffer = bytearray(self._buffer)
        return self._buffer

    def bind(self, address: Tuple[Optional[str], int]) -> None:
        """Bind the socket to the listen port.

        If the host is specified the interface will be reconfigured to that IP address.

        :param Tuple[Optional[str], int] address: Address as a (host, port) tuple. The host
            may be an IPv4 address (a string of the form '255.255.255.255'), or None.
            The port number is in the range (0 - 65536).
        """
        if address[0] is not None:
            ip_address = _the_interface.unpretty_ip(address[0])
            current_ip, subnet_mask, gw_addr, dns = _the_interface.ifconfig
            if ip_address != current_ip:
                _the_interface.ifconfig = (ip_address, subnet_mask, gw_addr, dns)
        self._listen_port = address[1]
        # For UDP servers we need to open the socket here because we won't call
        # listen
        if self._sock_type == SOCK_DGRAM:
            _the_interface.socket_listen(
                self.socknum, self._listen_port, wiznet5k.adafruit_wiznet5k.SNMR_UDP
            )
            self._buffer = b""

    def listen(self, backlog: Optional[int] = None) -> None:
        """
        Listen on the port specified by bind.

        :param Optional[int] backlog: Included for compatibility but ignored.
        """
        if self._listen_port is None:
            raise RuntimeError("Use bind to set the port before listen!")
        _the_interface.socket_listen(self.socknum, self._listen_port)
        self._buffer = b""

    def accept(
        self,
    ) -> Optional[Tuple[socket, Tuple[Union[str, bytearray], Union[int, bytearray]],]]:
        # wiznet5k.adafruit_wiznet5k_socket.socket,
        """
        Accept a connection.

        The socket must be bound to an address and listening for connections.

        The return value is a pair (conn, address) where conn is a new
        socket object to send and receive data on the connection, and address is
        the address bound to the socket on the other end of the connection.

        :return Optional[Tuple[socket.socket, Tuple[Union[str, bytearray], Union[int, bytearray]]]:
            If successful (socket object, (IP address, port)). If errors occur, the IP address
            and / or the port may be returned as bytearrays.
        """
        stamp = time.monotonic()
        while self.status not in (
            wiznet5k.adafruit_wiznet5k.SNSR_SOCK_SYNRECV,
            wiznet5k.adafruit_wiznet5k.SNSR_SOCK_ESTABLISHED,
        ):
            if self._timeout > 0 and time.monotonic() - stamp > self._timeout:
                return None
            if self.status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED:
                self.close()
                self.listen()

        new_listen_socknum, addr = _the_interface.socket_accept(self.socknum)
        current_socknum = self.socknum
        # Create a new socket object and swap socket nums, so we can continue listening
        client_sock = socket()
        client_sock._socknum = current_socknum  # pylint: disable=protected-access
        self._socknum = new_listen_socknum  # pylint: disable=protected-access
        self.bind((None, self._listen_port))
        self.listen()
        while self.status != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN:
            raise RuntimeError("Failed to open new listening socket")
        return client_sock, addr

    def connect(
        self,
        address: Tuple[Union[str, Tuple[int, int, int, int]], int],
        conntype: Optional[int] = None,
    ) -> None:
        """
        Connect to a remote socket.

        :param Tuple[Union[str, Tuple[int, int, int, int]], int] address: Remote socket as
            a (host, port) tuple. The host may be a tuple in the form (0, 0, 0, 0) or a string.
        :param Optional[int] conntype: Raises an exception if set to 3, unused otherwise, defaults
            to None.
        """
        if conntype == 0x03:
            raise NotImplementedError(
                "Error: SSL/TLS is not currently supported by CircuitPython."
            )
        host, port = address

        if hasattr(host, "split"):
            try:
                host = tuple(map(int, host.split(".")))
            except ValueError:
                host = _the_interface.get_host_by_name(host)
        if self._listen_port is not None:
            _the_interface.src_port = self._listen_port
        result = _the_interface.socket_connect(
            self.socknum, host, port, conn_mode=self._sock_type
        )
        _the_interface.src_port = 0
        if not result:
            raise RuntimeError("Failed to connect to host", host)
        self._buffer = b""

    def send(self, data: Union[bytes, bytearray]) -> None:
        """
        Send data to the socket.

        The socket must be connected to a remote socket.

        :param bytearray data: Data to send to the socket.
        """
        _the_interface.socket_write(self.socknum, data, self._timeout)
        gc.collect()

    def sendto(self, data: bytearray, address: [Tuple[str, int]]) -> None:
        """
        Connect to a remote socket and send data.

        :param bytearray data: Data to send to the socket.
        :param tuple address: Remote socket as a (host, port) tuple.
        """
        self.connect(address)
        return self.send(data)

    def recv(
        # pylint: disable=too-many-branches
        self,
        bufsize: int = 0,
        flags: int = 0,
    ) -> bytes:
        """
        Read from the connected remote address.

        :param int bufsize: Maximum number of bytes to receive.
        :param int flags: ignored, present for compatibility.

        :return bytes: Data from the remote address.
        """
        if self.status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED:
            return b""

        if bufsize == 0:
            # read everything on the socket
            while True:
                avail = self.available()
                if avail:
                    if self._sock_type == SOCK_STREAM:
                        self._buffer += _the_interface.socket_read(self.socknum, avail)[
                            1
                        ]
                    elif self._sock_type == SOCK_DGRAM:
                        self._buffer += _the_interface.read_udp(self.socknum, avail)[1]
                        break
                else:
                    break
            gc.collect()
            ret = self._buffer
            self._buffer = b""
            gc.collect()
            return ret
        stamp = time.monotonic()

        to_read = bufsize - len(self._buffer)
        received = []
        while to_read > 0:
            avail = self.available()
            if avail:
                stamp = time.monotonic()
                if self._sock_type == SOCK_STREAM:
                    recv = _the_interface.socket_read(
                        self.socknum, min(to_read, avail)
                    )[1]
                elif self._sock_type == SOCK_DGRAM:
                    recv = _the_interface.read_udp(self.socknum, min(to_read, avail))[1]
                    to_read = len(recv)  # only get this dgram
                recv = bytes(recv)
                received.append(recv)
                to_read -= len(recv)
                gc.collect()
            if self._timeout > 0 and time.monotonic() - stamp > self._timeout:
                break
        self._buffer += b"".join(received)

        ret = None
        if len(self._buffer) == bufsize:
            ret = self._buffer
            self._buffer = b""
        else:
            ret = self._buffer[:bufsize]
            self._buffer = self._buffer[bufsize:]
        gc.collect()
        return ret

    def embed_recv(
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
        avail = self.available()
        if avail:
            if self._sock_type == SOCK_STREAM:
                self._buffer += _the_interface.socket_read(self.socknum, avail)[1]
            elif self._sock_type == SOCK_DGRAM:
                self._buffer += _the_interface.read_udp(self.socknum, avail)[1]
        gc.collect()
        ret = self._buffer
        # print("RET ptr:", id(ret), id(self._buffer))
        self._buffer = b""
        gc.collect()
        return ret

    def recvfrom(
        self, bufsize: int = 0, flags: int = 0
    ) -> Tuple[bytes, Tuple[str, int]]:
        """
        Read some bytes from the connected remote address.

        :param int bufsize: Maximum number of bytes to receive.
        :param int flags: ignored, present for compatibility.

        :return Tuple[bytes, Tuple[str, int]]: a tuple (bytes, address)
            where address is a tuple (ip, port)
        """
        return (
            self.recv(bufsize),
            (
                _the_interface.pretty_ip(_the_interface.udp_from_ip[self.socknum]),
                _the_interface.udp_from_port[self.socknum],
            ),
        )

    def recv_into(self, buf: bytearray, nbytes: int = 0, flags: int = 0) -> int:
        """
        Read from the connected remote address into the provided buffer.

        :param bytearray buf: Data buffer
        :param nbytes: Maximum number of bytes to receive
        :param int flags: ignored, present for compatibility.

        :return int: the number of bytes received
        """
        if nbytes == 0:
            nbytes = len(buf)
        ret = self.recv(nbytes)
        nbytes = len(ret)
        buf[:nbytes] = ret
        return nbytes

    def recvfrom_into(
        self, buf: bytearray, nbytes: int = 0, flags: int = 0
    ) -> Tuple[int, Tuple[str, int]]:
        """
        Read some bytes from the connected remote address into the provided buffer.

        :param bytearray buf: Data buffer.
        :param int nbytes: Maximum number of bytes to receive.
        :param int flags: Unused, present for compatibility.

        :return Tuple[int, Tuple[str, int]]: A tuple (nbytes, address) where address is a
            tuple (ip, port)
        """
        return (
            self.recv_into(buf, nbytes),
            (
                _the_interface.remote_ip(self.socknum),
                _the_interface.remote_port(self.socknum),
            ),
        )

    def readline(self) -> bytes:
        """
        Read a line from the socket.

        Attempt to return as many bytes as we can up to but not including a carriage return and
        linefeed character pair.

        :return bytes: The data read from the socket.
        """
        stamp = time.monotonic()
        while b"\r\n" not in self._buffer:
            avail = self.available()
            if avail:
                if self._sock_type == SOCK_STREAM:
                    self._buffer += _the_interface.socket_read(self.socknum, avail)[1]
                elif self._sock_type == SOCK_DGRAM:
                    self._buffer += _the_interface.read_udp(self.socknum, avail)[1]
            if (
                not avail
                and self._timeout > 0
                and time.monotonic() - stamp > self._timeout
            ):
                self.close()
                raise RuntimeError("Didn't receive response, failing out...")
        firstline, self._buffer = self._buffer.split(b"\r\n", 1)
        gc.collect()
        return firstline

    def disconnect(self) -> None:
        """Disconnect a TCP socket."""
        if self._sock_type != SOCK_STREAM:
            raise RuntimeError("Socket must be a TCP socket.")
        _the_interface.socket_disconnect(self.socknum)

    def close(self) -> None:
        """Close the socket."""
        _the_interface.socket_close(self.socknum)

    def available(self) -> int:
        """
        Return how many bytes of data are available to be read from the socket.

        :return int: Number of bytes available.
        """
        return _the_interface.socket_available(self.socknum, self._sock_type)

    def settimeout(self, value: float) -> None:
        """
        Set the socket read timeout.

        :param float value: Socket read timeout in seconds.
        """
        if value < 0:
            raise Exception("Timeout period should be non-negative.")
        self._timeout = value

    def gettimeout(self) -> Optional[float]:
        """
        Timeout associated with socket operations.

        :return Optional[float]: Timeout in seconds, or None if no timeout is set.
        """
        return self._timeout
