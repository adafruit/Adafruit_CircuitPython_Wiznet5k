# SPDX-FileCopyrightText: 2019 ladyada for Adafruit Industries
# SPDX-FileCopyrightText: 2020 Brent Rubell for Adafruit Industries
#
# SPDX-License-Identifier: MIT
"""
`adafruit_wiznet5k_socketpool`
================================================================================

A socket compatible interface with the Wiznet5k module.

* Author(s): ladyada, Brent Rubell, Patrick Van Oosterwijck, Adam Cummick, Martin Stephens

"""

from __future__ import annotations

try:
    from typing import TYPE_CHECKING, List, Optional, Tuple, Union

    if TYPE_CHECKING:
        from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K
except ImportError:
    pass

import errno
import gc
from sys import byteorder

from adafruit_ticks import ticks_diff, ticks_ms
from micropython import const

import adafruit_wiznet5k as wiznet5k

_SOCKET_TYPE_TO_WIZNET = b"\0\x21\2"
_SOCKET_INVALID = const(255)

_global_socketpool = {}


class SocketPool:
    """WIZNET5K SocketPool library"""

    # These must match circuitpython "socketpool" values. However, we cannot
    # depend on socketpool being importable, so hard-code them here.
    SOCK_STREAM = 1
    SOCK_DGRAM = 2

    SOL_SOCKET = 0xFFF
    SO_REUSEADDR = 0x0004

    AF_INET = const(3)

    def __new__(cls, iface: WIZNET5K):
        # We want to make sure to return the same pool for the same interface
        if iface not in _global_socketpool:
            _global_socketpool[iface] = super().__new__(cls)
        return _global_socketpool[iface]

    def __init__(self, iface: WIZNET5K):
        self._interface = iface
        self._default_socket_timeout = None

    @staticmethod
    def _is_ipv4_string(ipv4_address: str) -> bool:
        """Check for a valid IPv4 address in dotted-quad string format
        (for example, "123.45.67.89").

        :param: str ipv4_address: The string to test.

        :return bool: True if a valid IPv4 address, False otherwise.
        """
        octets = ipv4_address.split(".", 3)
        if len(octets) == 4 and "".join(octets).isdigit():
            if all(0 <= int(octet) <= 255 for octet in octets):
                return True
        return False

    def getdefaulttimeout(self) -> Optional[float]:
        """
        Return the default timeout in seconds for new socket objects. A value of
        None indicates that new socket objects have no timeout. When the socket module is
        first imported, the default is None.
        """
        return self._default_socket_timeout

    def setdefaulttimeout(self, _timeout: Optional[float]) -> None:
        """
        Set the default timeout in seconds (float) for new socket objects. When the socket
        module is first imported, the default is None. See settimeout() for possible values
        and their respective meanings.

        :param Optional[float] _timeout: The default timeout in seconds or None.
        """
        if _timeout is None or _timeout >= 0:
            self._default_socket_timeout = _timeout
        else:
            raise ValueError("Timeout must be None, 0.0 or a positive numeric value.")

    @staticmethod
    def htonl(x: int) -> int:
        """
        Convert 32-bit positive integer from host to network byte order.

        :param int x: 32-bit positive integer from host.

        :return int: 32-bit positive integer in network byte order.
        """
        if byteorder == "big":
            return x
        return int.from_bytes(x.to_bytes(4, "little"), "big")

    @staticmethod
    def htons(x: int) -> int:
        """
        Convert 16-bit positive integer from host to network byte order.

        :param int x: 16-bit positive integer from host.

        :return int: 16-bit positive integer in network byte order.
        """
        if byteorder == "big":
            return x
        return ((x << 8) & 0xFF00) | ((x >> 8) & 0xFF)

    def inet_aton(self, ip_address: str) -> bytes:
        """
        Convert an IPv4 address from dotted-quad string format (for example, "123.45.67.89")
        to 32-bit packed binary format, as a bytes object four characters in length. This is
        useful when conversing with a program that uses the standard C library and needs
        objects of type struct in_addr, which is the C type for the 32-bit packed binary this
        function returns.

        :param str ip_address: The IPv4 address to convert.

        :return bytes: The converted IPv4 address.
        """
        if not self._is_ipv4_string(ip_address):
            raise ValueError("The IPv4 address must be a dotted-quad string.")
        return self._interface.unpretty_ip(ip_address)

    def inet_ntoa(self, ip_address: Union[bytes, bytearray]) -> str:
        """
        Convert a 32-bit packed IPv4 address (a bytes-like object four bytes in length) to
        its standard dotted-quad string representation (for example, "123.45.67.89"). This is
        useful when conversing with a program that uses the standard C library and needs
        objects of type struct in_addr, which is the C type for the 32-bit packed binary data
        this function takes as an argument.

        :param Union[bytes, bytearray ip_address: The IPv4 address to convert.

        :return str: The converted ip_address:
        """
        if len(ip_address) != 4:
            raise ValueError("The IPv4 address must be 4 bytes.")
        return self._interface.pretty_ip(ip_address)

    def getaddrinfo(
        self,
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> List[Tuple[int, int, int, str, Tuple[str, int]]]:
        """
        Translate the host/port argument into a sequence of 5-tuples that contain all the necessary
        arguments for creating a socket connected to that service.

        :param str host: a domain name, a string representation of an IPv4 address or
            None.
        :param int port: Port number to connect to (0 - 65536).
        :param int family: Ignored and hardcoded as 0x03 (the only family implemented) by the
            function.
        :param int type: The type of socket, either SOCK_STREAM (0x21) for TCP or SOCK_DGRAM (0x02)
            for UDP, defaults to 0.
        :param int proto: Unused in this implementation of socket.
        :param int flags: Unused in this implementation of socket.

        :return List[Tuple[int, int, int, str, Tuple[str, int]]]: Address info entries in the form
            (family, type, proto, canonname, sockaddr). In these tuples, family, type, proto are
            meant to be passed to the socket() function. canonname will always be an empty string,
            sockaddr is a tuple describing a socket address, whose format is (address, port), and
            is meant to be passed to the socket.connect() method.
        """
        if not isinstance(port, int):
            raise ValueError("Port must be an integer")
        if not self._is_ipv4_string(host):
            host = self.gethostbyname(host)
        return [(SocketPool.AF_INET, type, proto, "", (host, port))]

    def gethostbyname(self, hostname: str) -> str:
        """
        Translate a host name to IPv4 address format. The IPv4 address is returned as a string, such
        as '100.50.200.5'. If the host name is an IPv4 address itself it is returned unchanged.

        :param str hostname: Hostname to lookup.

        :return str: IPv4 address (a string of the form '0.0.0.0').
        """
        if self._is_ipv4_string(hostname):
            return hostname
        address = self._interface.get_host_by_name(hostname)
        address = f"{address[0]}.{address[1]}.{address[2]}.{address[3]}"
        return address

    def socket(
        self,
        family: int = AF_INET,
        type: int = SOCK_STREAM,
        proto: int = 0,
        fileno: Optional[int] = None,
    ):
        """Create a new socket and return it"""
        return Socket(self, family, type, proto, fileno)


class Socket:
    """
    A simplified implementation of the Python 'socket' class for connecting
    to a Wiznet5k module.
    """

    def __init__(
        self,
        socket_pool: SocketPool,
        family: int = SocketPool.AF_INET,
        type: int = SocketPool.SOCK_STREAM,
        proto: int = 0,
        fileno: Optional[int] = None,
    ) -> None:
        """
        :param int family: Socket address (and protocol) family, defaults to AF_INET.
        :param int type: Socket type, use SOCK_STREAM for TCP and SOCK_DGRAM for UDP,
            defaults to SOCK_STREAM.
        :param int proto: Unused, retained for compatibility.
        :param Optional[int] fileno: Unused, retained for compatibility.
        """
        if family != SocketPool.AF_INET:
            raise RuntimeError("Only AF_INET family supported by W5K modules.")
        self._socket_pool = socket_pool
        self._interface = self._socket_pool._interface
        self._socket_closed = False
        self._sock_type = type
        self._buffer = b""
        self._timeout = self._socket_pool._default_socket_timeout
        self._listen_port = None

        self._socknum = self._interface.get_socket(reserve_socket=True)
        if self._socknum == _SOCKET_INVALID:
            raise RuntimeError("Failed to allocate socket.")

    def __del__(self):
        self._interface.release_socket(self._socknum)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._interface.release_socket(self._socknum)
        if self._sock_type == SocketPool.SOCK_STREAM:
            self._interface.write_snir(
                self._socknum, 0xFF & (~wiznet5k.adafruit_wiznet5k.SNIR_DISCON)
            )  # Reset socket interrupt register.
            self._interface.socket_disconnect(self._socknum)
            mask = wiznet5k.adafruit_wiznet5k.SNIR_TIMEOUT | wiznet5k.adafruit_wiznet5k.SNIR_DISCON
            while not self._interface.read_snir(self._socknum) & mask:
                pass
        self._interface.write_snir(self._socknum, 0xFF)  # Reset socket interrupt register.
        self._interface.socket_close(self._socknum)
        while (
            self._interface.socket_status(self._socknum)
            != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED
        ):
            pass

    # This works around problems with using a class method as a decorator.
    def _check_socket_closed(func):
        """Decorator to check whether the socket object has been closed."""

        def wrapper(self, *args, **kwargs):
            if self._socket_closed:
                raise RuntimeError("The socket has been closed.")
            return func(self, *args, **kwargs)

        return wrapper

    @property
    def _status(self) -> int:
        """
        Return the status of the socket.

        :return int: Status of the socket.
        """
        return self._interface.socket_status(self._socknum)

    @property
    def _connected(self) -> bool:
        """
        Return whether connected to the socket.

        :return bool: Whether connected.
        """

        if self._socknum >= self._interface.max_sockets:
            return False
        status = self._interface.socket_status(self._socknum)
        if status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSE_WAIT and self._available() == 0:
            result = False
        else:
            result = status not in {
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_TIME_WAIT,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_FIN_WAIT,
            }
        if not result and status != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN:
            self.close()
        return result

    @_check_socket_closed
    def getpeername(self) -> Tuple[str, int]:
        """
        Return the remote address to which the socket is connected.

        :return Tuple[str, int]: IPv4 address and port the socket is connected to.
        """
        return self._interface.remote_ip(self._socknum), self._interface.remote_port(self._socknum)

    @_check_socket_closed
    def bind(self, address: Tuple[Optional[str], int]) -> None:
        """
        Bind the socket to address. The socket must not already be bound.

        The hardware sockets on WIZNET5K systems all share the same IPv4 address. The
        address is assigned at startup. Ports can only be bound to this address.

        :param Tuple[Optional[str], int] address: Address as a (host, port) tuple.

        :raises ValueError: If the IPv4 address specified is not the address
            assigned to the WIZNET5K interface.
        """
        # Check to see if the socket is bound.
        if self._listen_port:
            raise ConnectionError("The socket is already bound.")
        self._bind(address)

    def _bind(self, address: Tuple[Optional[str], int]) -> None:
        """
        Helper function to allow bind() to check for an existing connection and for
        accept() to generate a new socket connection.

        :param Tuple[Optional[str], int] address: Address as a (host, port) tuple.
        """
        if address[0]:
            if self._socket_pool.gethostbyname(address[0]) != self._interface.pretty_ip(
                self._interface.ip_address
            ):
                raise ValueError(
                    f"The IPv4 address requested must match {self._interface.pretty_ip(self._interface.ip_address)}, "
                    "the one assigned to the WIZNET5K interface."
                )
        self._listen_port = address[1]
        # For UDP servers we need to open the socket here because we won't call
        # listen
        if self._sock_type == SocketPool.SOCK_DGRAM:
            self._interface.socket_listen(
                self._socknum,
                self._listen_port,
                wiznet5k.adafruit_wiznet5k.SNMR_UDP,
            )
            self._buffer = b""

    @_check_socket_closed
    def listen(self, backlog: int = 0) -> None:
        """
        Enable a server to accept connections.

        :param int backlog: Included for compatibility but ignored.
        """
        if self._listen_port is None:
            raise RuntimeError("Use bind to set the port before listen!")
        self._interface.socket_listen(self._socknum, self._listen_port)
        self._buffer = b""

    @_check_socket_closed
    def accept(
        self,
    ) -> Tuple[Socket, Tuple[str, int]]:
        """
        Accept a connection. The socket must be bound to an address and listening for connections.

        :return Tuple[socket, Tuple[str, int]]: The return value is a pair
            (conn, address) where conn is a new socket object to send and receive data on
            the connection, and address is the address bound to the socket on the other
            end of the connection.
        """
        stamp = ticks_ms()
        while self._status not in {
            wiznet5k.adafruit_wiznet5k.SNSR_SOCK_SYNRECV,
            wiznet5k.adafruit_wiznet5k.SNSR_SOCK_ESTABLISHED,
            wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN,
        }:
            if self._timeout and 0 < self._timeout < ticks_diff(ticks_ms(), stamp) / 1000:
                raise TimeoutError("Failed to accept connection.")
            if self._status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSE_WAIT:
                self._disconnect()
                self.listen()
            if self._status == wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED:
                self.close()
                self.listen()

        _, addr = self._interface.socket_accept(self._socknum)
        current_socknum = self._socknum
        # Create a new socket object and swap socket nums, so we can continue listening
        client_sock = Socket(self._socket_pool)
        self._socknum = client_sock._socknum
        client_sock._socknum = current_socknum
        self._bind((None, self._listen_port))
        self.listen()
        if self._status != wiznet5k.adafruit_wiznet5k.SNSR_SOCK_LISTEN:
            raise RuntimeError("Failed to open new listening socket")
        return client_sock, addr

    @_check_socket_closed
    def connect(self, address: Tuple[str, int]) -> None:
        """
        Connect to a remote socket at address.

        :param Tuple[str, int] address: Remote socket as a (host, port) tuple.
        """
        if self._listen_port is not None:
            self._interface.src_port = self._listen_port
        result = self._interface.socket_connect(
            self._socknum,
            self._interface.unpretty_ip(self._socket_pool.gethostbyname(address[0])),
            address[1],
            _SOCKET_TYPE_TO_WIZNET[self._sock_type],
        )
        self._interface.src_port = 0
        if not result:
            raise RuntimeError("Failed to connect to host ", address[0])
        self._buffer = b""

    @_check_socket_closed
    def send(self, data: Union[bytes, bytearray]) -> int:
        """
        Send data to the socket. The socket must be connected to a remote socket.
        Applications are responsible for checking that all data has been sent; if
        only some of the data was transmitted, the application needs to attempt
        delivery of the remaining data.

        :param bytearray data: Data to send to the socket.

        :return int: Number of bytes sent.
        """
        _timeout = 0 if self._timeout is None else self._timeout
        bytes_sent = self._interface.socket_write(self._socknum, data, _timeout)
        gc.collect()
        return bytes_sent

    @_check_socket_closed
    def sendto(self, data: bytearray, *flags_and_or_address: any) -> int:
        """
        Send data to the socket. The socket should not be connected to a remote socket, since the
        destination socket is specified by address. Return the number of bytes sent..

        Either:
        :param bytearray data: Data to send to the socket.
        :param [Tuple[str, int]] address: Remote socket as a (host, port) tuple.

        Or:
        :param bytearray data: Data to send to the socket.
        :param int flags: Not implemented, kept for compatibility.
        :param Tuple[int, Tuple(str, int)] address: Remote socket as a (host, port) tuple
        """
        # May be called with (data, address) or (data, flags, address)
        other_args = list(flags_and_or_address)
        if len(other_args) in {1, 2}:
            address = other_args[-1]
        else:
            raise ValueError("Incorrect number of arguments, should be 2 or 3.")
        self.connect(address)
        return self.send(data)

    @_check_socket_closed
    def recv(
        self,
        bufsize: int,
        flags: int = 0,
    ) -> bytes:
        """
        Receive data from the socket. The return value is a bytes object representing the data
        received. The maximum amount of data to be received at once is specified by bufsize.

        :param int bufsize: Maximum number of bytes to receive.
        :param int flags: ignored, present for compatibility.

        :return bytes: Data from the socket.
        """
        buf = bytearray(bufsize)
        nread = self.recv_into(buf, bufsize)
        if nread == 0:
            return b""
        if nread < bufsize:
            return bytes(buf[:nread])
        return bytes(buf)

    def _embed_recv(self, bufsize: int = 0, flags: int = 0) -> bytes:
        """
        Read from the connected remote address.

        :param int bufsize: Maximum number of bytes to receive, ignored by the
            function, defaults to 0.
        :param int flags: ignored, present for compatibility.

        :return bytes: All data available from the connection.
        """
        avail = self._available()
        if avail:
            if self._sock_type == SocketPool.SOCK_STREAM:
                self._buffer += self._interface.socket_read(self._socknum, avail)[1]
            elif self._sock_type == SocketPool.SOCK_DGRAM:
                self._buffer += self._interface.read_udp(self._socknum, avail)[1]
        gc.collect()
        ret = self._buffer
        self._buffer = b""
        gc.collect()
        return ret

    @_check_socket_closed
    def recvfrom(self, bufsize: int, flags: int = 0) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive data from the socket. The return value is a pair (bytes, address) where bytes is
        a bytes object representing the data received and address is the address of the socket
        sending the data.

        :param int bufsize: Maximum number of bytes to receive.
        :param int flags: Ignored, present for compatibility.

        :return Tuple[bytes, Tuple[str, int]]: a tuple (bytes, address)
            where address is a tuple (address, port)
        """
        return (
            self.recv(bufsize),
            (
                self._interface.pretty_ip(self._interface.udp_from_ip[self._socknum]),
                self._interface.udp_from_port[self._socknum],
            ),
        )

    @_check_socket_closed
    def recv_into(self, buffer: bytearray, nbytes: int = 0, flags: int = 0) -> int:
        """
        Receive up to nbytes bytes from the socket, storing the data into a buffer
        rather than creating a new bytestring.

        :param bytearray buffer: Data buffer to read into.
        :param nbytes: Maximum number of bytes to receive (if 0, use length of buffer).
        :param int flags: ignored, present for compatibility.

        :return int: the number of bytes received
        """
        if not 0 <= nbytes <= len(buffer):
            raise ValueError("nbytes must be 0 to len(buffer)")

        last_read_time = ticks_ms()
        num_to_read = len(buffer) if nbytes == 0 else nbytes
        num_read = 0
        while num_to_read > 0:
            # we might have read socket data into the self._buffer with:
            # _readline
            if len(self._buffer) > 0:
                bytes_to_read = min(num_to_read, len(self._buffer))
                buffer[num_read : num_read + bytes_to_read] = self._buffer[:bytes_to_read]
                num_read += bytes_to_read
                num_to_read -= bytes_to_read
                self._buffer = self._buffer[bytes_to_read:]
                # explicitly recheck num_to_read to avoid extra checks
                continue

            num_avail = self._available()
            if num_avail > 0:
                last_read_time = ticks_ms()
                bytes_to_read = min(num_to_read, num_avail)
                if self._sock_type == SocketPool.SOCK_STREAM:
                    bytes_read = self._interface.socket_read(self._socknum, bytes_to_read)[1]
                else:
                    bytes_read = self._interface.read_udp(self._socknum, bytes_to_read)[1]
                buffer[num_read : num_read + len(bytes_read)] = bytes_read
                num_read += len(bytes_read)
                num_to_read -= len(bytes_read)
            elif num_read > 0:
                # We got a message, but there are no more bytes to read, so we can stop.
                break
            elif self._status in {
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSED,
                wiznet5k.adafruit_wiznet5k.SNSR_SOCK_CLOSE_WAIT,
            }:
                # No bytes to read and we will not get more, stop.
                break
            # No bytes yet, or more bytes requested.
            if self._timeout is None:
                # blocking mode
                continue
            if self._timeout == 0:
                # non-blocking mode
                break
            if ticks_diff(ticks_ms(), last_read_time) / 1000 > self._timeout:
                raise OSError(errno.ETIMEDOUT)
        return num_read

    @_check_socket_closed
    def recvfrom_into(
        self, buffer: bytearray, nbytes: int = 0, flags: int = 0
    ) -> Tuple[int, Tuple[str, int]]:
        """
        Receive data from the socket, writing it into buffer instead of creating a new bytestring.
        The return value is a pair (nbytes, address) where nbytes is the number of bytes received
        and address is the address of the socket sending the data.

        :param bytearray buffer: Data buffer.
        :param int nbytes: Maximum number of bytes to receive.
        :param int flags: Unused, present for compatibility.

        :return Tuple[int, Tuple[str, int]]: The number of bytes and address.
        """
        return (
            self.recv_into(buffer, nbytes),
            (
                self._interface.pretty_ip(self._interface.udp_from_ip[self._socknum]),
                self._interface.udp_from_port[self._socknum],
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
        stamp = ticks_ms()
        while b"\r\n" not in self._buffer:
            avail = self._available()
            if avail:
                if self._sock_type == SocketPool.SOCK_STREAM:
                    self._buffer += self._interface.socket_read(self._socknum, avail)[1]
                elif self._sock_type == SocketPool.SOCK_DGRAM:
                    self._buffer += self._interface.read_udp(self._socknum, avail)[1]
                if (
                    self._timeout
                    and not avail
                    and 0 < self._timeout < ticks_diff(ticks_ms(), stamp) / 1000
                ):
                    self.close()
                    raise RuntimeError("Didn't receive response, failing out...")
        firstline, self._buffer = self._buffer.split(b"\r\n", 1)
        gc.collect()
        return firstline

    def _disconnect(self) -> None:
        """Disconnect a TCP socket."""
        if self._sock_type != SocketPool.SOCK_STREAM:
            raise RuntimeError("Socket must be a TCP socket.")
        self._interface.socket_disconnect(self._socknum)

    @_check_socket_closed
    def close(self) -> None:
        """
        Mark the socket closed. Once that happens, all future operations on the socket object
        will fail. The remote end will receive no more data.
        """
        self._interface.release_socket(self._socknum)
        self._interface.socket_close(self._socknum)
        self._socket_closed = True

    def _available(self) -> int:
        """
        Return how many bytes of data are available to be read from the socket.

        :return int: Number of bytes available.
        """
        return self._interface.socket_available(
            self._socknum,
            _SOCKET_TYPE_TO_WIZNET[self._sock_type],
        )

    @_check_socket_closed
    def setsockopt(self, level: int, opt: int, value: any) -> None:
        """
        Set a socket option.

        Only SOL_SOCKET SO_REUSEADDR is accepted (and the value is ignored).

        Other calls result in OSError."""
        if level == SocketPool.SOL_SOCKET and opt == SocketPool.SO_REUSEADDR:
            return
        raise OSError

    @_check_socket_closed
    def settimeout(self, value: Optional[float]) -> None:
        """
        Set a timeout on blocking socket operations. The value argument can be a
        non-negative floating point number expressing seconds, or None. If a non-zero
        value is given, subsequent socket operations will raise a timeout exception
        if the timeout period value has elapsed before the operation has completed.
        If zero is given, the socket is put in non-blocking mode. If None is given,
        the socket is put in blocking mode..

        :param Optional[float] value: Socket read timeout in seconds.
        """
        if value is None or value >= 0:
            self._timeout = value
        else:
            raise ValueError("Timeout must be None, 0.0 or a positive numeric value.")

    @_check_socket_closed
    def gettimeout(self) -> Optional[float]:
        """
        Return the timeout in seconds (float) associated with socket operations, or None if no
        timeout is set. This reflects the last call to setblocking() or settimeout().

        :return Optional[float]: Timeout in seconds, or None if no timeout is set.
        """
        return self._timeout

    @_check_socket_closed
    def setblocking(self, flag: bool) -> None:
        """
        Set blocking or non-blocking mode of the socket: if flag is false, the socket is set
        to non-blocking, else to blocking mode.

        This method is a shorthand for certain settimeout() calls:

        sock.setblocking(True) is equivalent to sock.settimeout(None)
        sock.setblocking(False) is equivalent to sock.settimeout(0.0)

        :param bool flag: The blocking mode of the socket.

        :raises TypeError: If flag is not a bool.

        """
        if flag is True:
            self.settimeout(None)
        elif flag is False:
            self.settimeout(0.0)
        else:
            raise TypeError("Flag must be a boolean.")

    @_check_socket_closed
    def getblocking(self) -> bool:
        """
        Return True if socket is in blocking mode, False if in non-blocking.

        This is equivalent to checking socket.gettimeout() == 0.

        :return bool: Blocking mode of the socket.
        """
        return self.gettimeout() == 0

    @property
    @_check_socket_closed
    def family(self) -> int:
        """Socket family (always 0x03 in this implementation)."""
        return 3

    @property
    @_check_socket_closed
    def type(self):
        """Socket type."""
        return self._sock_type

    @property
    @_check_socket_closed
    def proto(self):
        """Socket protocol (always 0x00 in this implementation)."""
        return 0
