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
from adafruit_wiznet5k.adafruit_wiznet5k_dhcp import DHCP as DHCP

__version__ = "0.0.0-auto.0"
__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k.git"

# Wiznet5k Registers
REG_MR             = const(0x0000) # Mode Register
REG_VERSIONR_W5500 = const(0x0039) # W5500 Silicon Version Register
REG_SHAR           = const(0x0009) # Source Hardware Address Register
REG_SIPR           = const(0x000F) # Source IP Address Register
REG_PHYCFGR        = const(0x002E) # W5500 PHY Configuration Register

# Wiznet5k Socket Registers
REG_SNMR           = const(0x0000) # Socket n Mode Register
REG_SNCR           = const(0x0001) # Socket n Command Register
REG_SNIR           = const(0x0002) # Socket n Interrupt Register
REG_SNSR           = const(0x0003) # Socket n Status Register
REG_SNPORT         = const(0x0004) # Socket n Source Port

CH_SIZE            = const(0x100)

# Register commands
MR_RST = const(0x80) # Mode Register RST


# Default hardware MAC address
DEFAULT_MAC = [0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED]
# Maximum number of sockets to support, differs between chip versions.
W5200_W5500_MAX_SOCK_NUM = const(0x08)

class WIZNET:
    """Interface for WIZNET5k module.
    :param ~busio.SPI spi_bus: The SPI bus the Wiznet module is connected to.
    :param ~digitalio.DigitalInOut cs: Chip select pin.
    :param ~digitalio.DigitalInOut rst: Optional reset pin. 
    :param str mac: The Wiznet's MAC Address.
    :param int timeout: Times out if no response from DHCP server.

    """

    def __init__(self, spi_bus, cs, reset=None,
                 mac=DEFAULT_MAC, timeout=None, response_timeout=None):
        self._device = spidev.SPIDevice(spi_bus, cs,
                                        baudrate=8000000,
                                        polarity=0, phase=0)
        self._chip_type = None
        # init c.s.
        self._cs = cs
        # initialize the module
        assert self._w5100_init() == 1, "Unsuccessfully initialized Wiznet module."
        # Set MAC address
        self.mac_address = mac
        # Set IP address
        self.ip_address = (0, 0, 0, 0)


    @property
    def max_sockets(self):
        """Returns max number of sockets supported by chip.
        """
        if self._chip_type == "w5500":
            return W5200_W5500_MAX_SOCK_NUM
        else:
            return -1

    @property
    def chip(self):
        """Returns the chip type.
        """
        return self._chip_type

    @property
    def ip_address(self):
        """Returns the hardware's IP address.
        """
        return self.read(REG_SIPR, 0x00, 4)

    @ip_address.setter
    def ip_address(self, ip_address):
        """Returns the hardware's IP address.
        :param tuple ip_address: Desired IP address.
        """
        # inline void setIPAddress(const uint8_t * addr) { writeSIPR(addr); }
        #   __GP_REGISTER_N(SIPR,   0x000F, 4); // Source IP address
        self._write_16(REG_SIPR, 0x04, ip_address, 4)

    @property
    def mac_address(self):
        """Returns the hardware's MAC address.

        """
        return self.read(REG_SHAR, 0x00, 6)

    @mac_address.setter
    def mac_address(self, address):
        """Sets the hardware MAC address.
        :param tuple address: Hardware MAC address.

        """
        self._write_16(REG_SHAR, 0x04, address, 6)

    @property
    def link_status(self):
        """Returns the PHY's link status.
        1: Link up.
        0: Link down.
        """
        if self._chip_type == "w5500":
            data =  self.read(REG_PHYCFGR, 0x00)
            return data[0] & 0x01
        else:
            return 0

    def pretty_ip(self, ip): # pylint: disable=no-self-use, invalid-name
        """Converts a bytearray IP address to a
        dotted-quad string for printing

        """
        return "%d.%d.%d.%d" % (ip[0], ip[1], ip[2], ip[3])

    def pretty_mac(self, mac): # pylint: disable=no-self-use, invalid-name
        """Converts a bytearray MAC address to a
        dotted-quad string for printing

        """
        return "%s:%s:%s:%s:%s:%s" % (hex(mac[0]), hex(mac[1]), hex(mac[2]),
                                      hex(mac[3]), hex(mac[4]), hex(mac[5]))

    def _w5100_init(self):
        """Initializes and detects a wiznet5k module.

        """
        time.sleep(1)
        self._cs.switch_to_output()
        self._cs.value = 1

        # Detect if chip is Wiznet W5500
        if self.detect_w5500() == 1:
            # perform w5500 initialization
            for i in range(0, W5200_W5500_MAX_SOCK_NUM):
                ctrl_byte = (0x0C + (i<<5))
                self.write(0x1E, ctrl_byte, 2)
                self.write(0x1F, ctrl_byte, 2)
        else:
            return 0
        return 1


    def detect_w5500(self):
        """Detects W5500 chip.

        """
        assert self.sw_reset() == 0, "Chip not reset properly!"
        self._write_mr(0x08)
        assert self._read_mr()[0] == 0x08, "Expected 0x08."

        self._write_mr(0x10)
        assert self._read_mr()[0] == 0x10, "Expected 0x10."

        self._write_mr(0x00)
        assert self._read_mr()[0] == 0x00, "Expected 0x00."

        if self.read(REG_VERSIONR_W5500, 0x00)[0] != 0x04:
            return -1
        self._chip_type = "w5500"
        self._ch_base_msb = 0x10
        return 1

    def sw_reset(self):
        """Performs a soft-reset on a Wiznet chip
        by writing to its MR register reset bit.

        """
        mr = self._read_mr()
        self._write_mr(0x80)
        mr = self._read_mr()
        if mr[0] != 0x00:
            return -1
        return 0


    def _read_mr(self):
        """Reads from the Mode Register (MR).

        """
        res = self.read(REG_MR, 0x00)
        return res

    def _write_mr(self, data):
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

    def read(self, addr, cb, length=1):
        """Reads data from a register address.
        :param int addr: Register address.
        :param int cb: Common register block (?)

        """
        with self._device as bus_device:
            bus_device.write(bytes([addr >> 8]))
            bus_device.write(bytes([addr & 0xFF]))
            bus_device.write(bytes([cb]))
            result = bytearray(length)
            bus_device.readinto(result)
        return result

    def _write_16(self, addr, buf, data, len):
        """Writes data to a register address.
        :param int addr: Register address.
        :param int buf: Buffer.
        :param int data: Data to write to the register.
        :param int len: Length of data to write.

        """
        with self._device as bus_device:
            bus_device.write(bytes([addr >> 8]))
            bus_device.write(bytes([addr & 0xFF]))
            bus_device.write(bytes([buf]))
            for i in range(0, len):
                bus_device.write(bytes([data[i]]))
        return len

    # socket-specific methods

    # socket-specific methods
    def _read_snsr(self, socket, length=None):
        """Returns status of socket 'socket'.
        """
        ch_base = self._ch_base_msb << 8
        if length is None:
            return self.read(ch_base+0*0x00+REG_SNSR, 0x01)
        return self.read(ch_base+0*0x00+REG_SNSR, 0x01, length)

    def _read_snmr(self, socket, protocol):
        """Read Socket n Mode Register

        """
        return self._read_socket(socket, protocol)

    def _write_snmr(self, socket, protocol):
        """Write to Socket n Mode Register.

        """
        self._write_socket(socket, REG_SNMR, protocol)

    def _write_snir(self, socket, data):
        """Write to Socket n Interrupt Register.
        """
        self._write_socket(socket, REG_SNIR, data)

    def _write_sock_port(self, socket, port):
        """Write to the socket port number.
        """
        self._write_socket(socket, REG_SNPORT, port >> 8)
        self._write_socket(socket, REG_SNPORT+1, port & 0xFF)

    def _write_sncr(self, socket, data):
        self._write_socket(socket, REG_SNCR, data)

    def _read_sncr(self, socket):
        self._read_socket(socket, REG_SNCR)

    def _read_snmr(self, socket):
        return self._read_socket(socket, REG_SNMR)

    def _exec_sock_cmd(self, socket, cmd):
        # TODO
        pass

    def _write_socket(self, socket, address, data):
        """Write to a W5k socket register.

        """
        base = self._ch_base_msb << 8
        cntl_byte = (socket<<5)+0x0C;
        self.write(base + socket * CH_SIZE + address, cntl_byte, data)

    def _read_socket(self, socket, address):
        """Read a W5k socket register.

        """
        base = self._ch_base_msb << 8
        cntl_byte = (socket<<5)+0x08;
        return self.read(base + socket * CH_SIZE + address, cntl_byte)
