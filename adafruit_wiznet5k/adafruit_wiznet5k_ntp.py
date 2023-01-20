# SPDX-FileCopyrightText: 2019 Brent Rubell for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""
`adafruit_wiznet5k_ntp`
================================================================================

Network Time Protocol (NTP) helper for CircuitPython

 * Author(s): Brent Rubell, irinakim

Implementation Notes
--------------------
**Hardware:**
**Software and Dependencies:**


"""
from __future__ import annotations

try:
    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K
except ImportError:
    pass
import time
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket

# __version__ = "0.0.0+auto.0"
# __repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_NTP.git"


class NTP:
    """Wiznet5k NTP Client."""

    def __init__(
        self,
        iface: WIZNET5K,
        ntp_address: str,
        utc: float,
        debug: bool = False,
    ) -> None:
        """
        :param adafruit_wiznet5k.WIZNET5K iface: Wiznet 5k object.
        :param str ntp_address: The hostname of the NTP server.
        :param float utc: Numbers of hours to offset time from UTC.
        :param bool debug: Enable debugging output, defaults to False.
        """
        self._debug = debug
        self._iface = iface
        socket.set_interface(self._iface)
        self._sock = socket.socket(type=socket.SOCK_DGRAM)
        self._sock.settimeout(1)
        self._utc = utc

        self._ntp_server = ntp_address
        self._host = 0
        self._request_id = 0  # request identifier

        self._pkt_buf_ = bytearray([0x23] + [0x00] * 55)

    def get_time(self) -> time.struct_time:
        """
        Get the time from the NTP server.

        :return time.struct_time: The local time.
        """
        self._sock.bind((None, 50001))
        max_retries = 4
        for retry in range(max_retries):
            self._sock.sendto(self._pkt_buf_, (self._ntp_server, 123))
            end_time = time.monotonic() + 0.2 * 2**retry
            while time.monotonic() < end_time:
                data = self._sock.recv(64)  # NTP returns a 48 byte message.
                if data:
                    sec = data[40:44]
                    int_cal = int.from_bytes(sec, "big")
                    # UTC offset may be a float as some offsets are half hours so force int.
                    cal = int(int_cal - 2208988800 + self._utc * 3600)
                    cal = time.localtime(cal)
                    return cal
        raise TimeoutError(
            "No reply from NTP server after {} attempts.".format(max_retries)
        )
