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
try:
    import typing  # pylint: disable=unused-import

    from adafruit_wiznet5k import adafruit_wiznet5k
except ImportError:
    pass
import time
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket

##__version__ = "0.0.0+auto.0"
##__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_NTP.git"


class NTP:
    """Wiznet5k NTP Client."""

    def __init__(
        self,
        iface: adafruit_wiznet5k.WIZNET5K,
        ntp_address: str,
        utc: int,  # TODO: Should be float. India is UTC + 7.5
        debug: bool = False,
    ) -> None:
        """
        :param adafruit_wiznet5k.WIZNET5K iface: Wiznet 5k object.
        :param str ntp_address: The hostname of the NTP server.
        :param int utc: Numbers of hours to offset time from UTC.
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

        :return int: Time in seconds since the epoch.
        """
        self._sock.bind((None, 50001))
        self._sock.sendto(self._pkt_buf_, (self._ntp_server, 123))
        while True:
            data = self._sock.recv()
            if data:
                sec = data[40:44]
                int_cal = int.from_bytes(sec, "big")
                cal = int_cal - 2208988800 + self._utc * 3600
                cal = time.localtime(cal)
                return cal
