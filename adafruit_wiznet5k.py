# The MIT License (MIT)
#
# Copyright (c) 2020 Brent Rubell for Adafruit Industries
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
`adafruit_wiznet5k`
================================================================================

Pure-Python interface for WIZNET 5k ethernet modules.


* Author(s): Brent Rubell

Implementation Notes
--------------------

**Hardware:**

.. todo:: Add links to any specific hardware product page(s), or category page(s). Use unordered list & hyperlink rST
   inline format: "* `Link Text <url>`_"

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases


# * Adafruit's Bus Device library: https://github.com/adafruit/Adafruit_CircuitPython_BusDevice
"""

# imports
import time
import adafruit_bus_device.spi_device as spidev
from micropython import const
from digitalio import DigitalInOut

__version__ = "0.0.0-auto.0"
__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k.git"

# Registers
REG_MR = const(0x0000) # Mode Register
REG_VERSIONR_W5500 = const(0x0039) # W5500 Silicon Version Register

# Register commands
MR_RST = const(0x80) # Mode Register RST

# Default hardware MAC address
DEFAULT_MAC = [0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED]

# Maximum number of sockets to support, differs between chip versions.
W5200_W5500_MAX_SOCK_NUM = const(0x08)

class wiznet:
    """Interface for WIZNET5k module.
    :param ~busio.SPI spi_bus: The SPI bus the Wiznet module is connected to.
    :param ~digitalio.DigitalInOut cs: Chip select pin.
    :param ~digitalio.DigitalInOut rst: Optional reset pin. 
    :param str mac_address: The Wiznet's MAC Address.
    :param int timeout: Times out if no response from DHCP server.

    """

    def __init__(self, spi_bus, cs, reset=None,
                mac_address=DEFAULT_MAC, timeout=None, debug=False):
        self._debug = debug
        self._device = spidev.SPIDevice(spi_bus, cs,
                                        baudrate=8000000,
                                        polarity=0, phase=0)
        self.mac_address = mac_address
        self._chip_type = None
        time.sleep(1)
        # init c.s.
        self._cs = cs
        self._cs.switch_to_output()
        self._cs.value = 1

        # Detect if chip is Wiznet W5500
        if self.detect_w5500() == 1:
            # TODO: perform w5500 initialization
        else:
            raise TypeError("Wiznet chip not detected or unsupported by this library.")


    def detect_w5500(self):
        """Detects W5500 chip.

        """
        assert self.sw_reset() == 0, "Chip not reset properly!"
        self._chip_type = "w5500"
        self.write_mr(0x08)
        assert self.read_mr()[0] == 0x08, "Expected 0x08."

        self.write_mr(0x10)
        assert self.read_mr()[0] == 0x10, "Expected 0x10."

        self.write_mr(0x00)
        assert self.read_mr()[0] == 0x00, "Expected 0x00."

        if self.read(REG_VERSIONR_W5500, 0x00)[0] != 0x04:
            return -1
        return 1

    def sw_reset(self):
        """Performs a soft-reset on a Wiznet chip
        by writing to its MR register reset bit.

        """
        mr = self.read_mr()
        self.write_mr(0x80)
        mr = self.read_mr()
        if mr[0] != 0x00:
            return -1
        return 0


    def read_mr(self):
        """Reads from the Mode Register (MR).

        """
        res = self.read(REG_MR, 0x00)
        return res

    def write_mr(self, data):
        """Writes to the mode register (MR).
        :param int data: Data to write to the mode register.

        """
        self.write(REG_MR, 0x04, data)

    def write(self, addr, cb, data):
        """Writes data to a register address.
        :param int addr: Register address.
        :param int cb: Common register block (?)
        :param int data: Data to write to the register.

        """
        with self._device as bus_device:
            bus_device.write(bytes([addr >> 8]))
            bus_device.write(bytes([addr & 0xFF]))
            bus_device.write(bytes([cb]))
            bus_device.write(bytes([data]))

    def read(self, addr, cb):
        """Reads data from a register address.
        :param int addr: Register address.
        :param int cb: Common register block (?)

        """
        with self._device as bus_device:
            bus_device.write(bytes([addr >> 8]))
            bus_device.write(bytes([addr & 0xFF]))
            bus_device.write(bytes([cb]))
            result = bytearray(1)
            bus_device.readinto(result)
        return result



