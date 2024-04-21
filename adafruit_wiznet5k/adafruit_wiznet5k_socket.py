# SPDX-FileCopyrightText: 2019 ladyada for Adafruit Industries
# SPDX-FileCopyrightText: 2020 Brent Rubell for Adafruit Industries
#
# SPDX-License-Identifier: MIT
#
# CPython uses type as an argument in socket.socket, so disable checking in Pylint
# pylint: disable=redefined-builtin
"""
`adafruit_wiznet5k_socket`
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


# pylint: disable=unused-import
from adafruit_wiznet5k.adafruit_wiznet5k_socketpool import (
    SocketPool,
    SOCK_STREAM,
    AF_INET,
)

_socket_pool = SocketPool()


# pylint: disable=protected-access
def _is_ipv4_string(ipv4_address: str) -> bool:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool._is_ipv4_string(ipv4_address)


def set_interface(iface: WIZNET5K) -> None:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.set_interface(iface)


def getdefaulttimeout() -> Optional[float]:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool._default_socket_timeout()


def setdefaulttimeout(_timeout: Optional[float]) -> None:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.setdefaulttimeout(_timeout)


def htonl(x: int) -> int:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.htonl(x)


def htons(x: int) -> int:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.htons(x)


def inet_aton(ip_address: str) -> bytes:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.inet_aton(ip_address)


def inet_ntoa(ip_address: Union[bytes, bytearray]) -> str:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.inet_ntoa(ip_address)


# pylint: disable=too-many-arguments
def getaddrinfo(
    host: str,
    port: int,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> List[Tuple[int, int, int, str, Tuple[str, int]]]:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.getaddrinfo(host, port, family, type, proto, flags)


def gethostbyname(hostname: str) -> str:
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.gethostbyname(hostname)


def socket(
    family: int = AF_INET,
    type: int = SOCK_STREAM,
    proto: int = 0,
    fileno: Optional[int] = None,
):
    """Definition in adafruit_wiznet_socketpool.py"""
    return _socket_pool.socket(family, type, proto, fileno)
