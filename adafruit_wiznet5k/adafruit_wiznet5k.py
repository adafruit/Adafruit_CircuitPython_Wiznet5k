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
REG_GAR            = const(0x0001) # Gateway IP Address
REG_SUBR           = const(0x0005) # Subnet Mask Address
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
REG_SNDIPR         = const(0x000C) # Destination IP Address
REG_SNDPORT        = const(0x0010) # Destination Port
REG_SNRX_RSR       = const(0x0026) # RX Free Size

# SNSR Commands
SNSR_SOCK_CLOSED      = const(0x00)
SNSR_SOCK_INIT        = const(0x13)
SNSR_SOCK_LISTEN      = const(0x14)
SNSR_SOCK_SYNSENT     = const(0x15)
SNSR_SOCK_SYNRECV     = const(0x16)
SNSR_SOCK_ESTABLISHED = const(0x17)
SNSR_SOCK_FIN_WAIT    = const(0x18)
SNSR_SOCK_CLOSING     = const(0x1A)
SNSR_SOCK_TIME_WAIT   = const(0x1B)
SNSR_SOCK_CLOSE_WAIT  = const(0x1C)
SNSR_SOCK_LAST_ACK    = const(0x1D)
SNSR_SOCK_UDP         = const(0x22)
SNSR_SOCK_IPRAW       = const(0x32)
SNSR_SOCK_MACRAW      = const(0x42)
SNSR_SOCK_PPPOE       = const(0x5F)

# Sock Commands (CMD)
CMD_SOCK_OPEN      = const(0x01)
CMD_SOCK_LISTEN    = const(0x02)
CMD_SOCK_CONNECT   = const(0x04)
CMD_SOCK_DISCON    = const(0x08)
CMD_SOCK_CLOSE     = const(0x10)
CMD_SOCK_SEND      = const(0x20)
CMD_SOCK_SEND_MAC  = const(0x21)
CMD_SOCK_SEND_KEEP = const(0x22)
CMD_SOCK_RECV      = const(0x40)

# Socket registers
SNMR_CLOSE  = const(0x00);
SNMR_TCP    = const(0x21);
SNMR_UDP    = const(0x02);
SNMR_IPRAW  = const(0x03);
SNMR_MACRAW = const(0x04);
SNMR_PPPOE  = const(0x05);

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
                 mac=DEFAULT_MAC, timeout=5.0, response_timeout=5.0):
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
        self._timeout = timeout
        self._sock = 0
        self._src_port = 0

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
        self._write_n(REG_SIPR, 0x04, ip_address)

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
        self._write_n(REG_SHAR, 0x04, address)

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

    @property
    def remote_ip(self):
        """Returns the remote IP Address.
        """
        remote_ip = bytearray(4)

        if self._sock >= self.max_sockets:
            return remote_ip
        for octet in range(0, 4):
             remote_ip[octet] = self._read_socket(self._sock, REG_SNDIPR+octet)[0]

        return self.pretty_ip(remote_ip)

    @property
    def socket_available(self):
        """Determines how many bytes are waiting to be ready on the socket.
        """
        if self._sock >= self.max_sockets:
            return 0
        # return Ethernet.socketRecvAvailable(sockindex);


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

    def _write_n(self, addr, buf, data):
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
            for i in range(0, len(data)):
                bus_device.write(bytes([data[i]]))
        return len

    # socket-specific methods

    def sock_status(self, sock):
        return self._read_snsr(sock)

    def begin(self, dns):
        """Begin ethernet connection.
        """
        self._dns = dns
        SUBNET_ADDR = (255, 255, 255, 0)
        # Assume gateway IP is on the same network as the local IP
        gateway_ip = self.ip_address
        # Set the last octet to 1
        gateway_ip[3] = 1

        for octet in range(0, 4):
            self.write(REG_GAR+octet, 0x04, gateway_ip[octet])

        for octet in range(0, 4):
            self.write(REG_SUBR+octet, 0x04, SUBNET_ADDR[octet])

    def connect(self, server_ip, server_port):
        """Connect to server address.
        """
        # TODO: implement dhcp, using a static server_ip for now

        # initialize a socket and set the mode
        ret = self.sock_open(self._sock, server_ip, self._src_port, server_port, SNMR_TCP)
        if ret == 1: # socket unsuccessfully opened
            return 0

        # connect socket
        self._write_sncr(self._sock, CMD_SOCK_CONNECT)
        self._read_sncr(self._sock)

        while self.sock_status(self._sock)[0] != SNSR_SOCK_ESTABLISHED:
            if self.sock_status(self._sock)[0] == SNSR_SOCK_CLOSED:
                return 0
        return 1

    def get_socket(self):
        """Request, allocates and returns a socket from the W5k
        chip. Returned socket number may not exceed max_sockets. 
        """
        sock = 0
        for _sock in range(0, self.max_sockets):
            status = self.sock_status(_sock)
            if status[0] == SNSR_SOCK_CLOSED or status[0] == SNSR_SOCK_FIN_WAIT or status[0] == SNSR_SOCK_CLOSE_WAIT:
                sock = _sock
                break

        if sock == self.max_sockets:
            return 0

        self._src_port+=1
        if (self._src_port == 0):
            self._src_port = 1024

        return sock

    def socket_open(self, socket_num, dest, port, conn_mode=SNMR_TCP):
        """Opens a socket to a destination IP address or hostname. By default, we use
        'conn_mode'=SNMR_TCP but we may also use SNMR_UDP.
        """
        if self._read_snsr(socket_num)[0] == SNSR_SOCK_CLOSED:
            print("w5k socket begin, protocol={}, port={}".format(conn_mode, src_port))
            time.sleep(0.00025)

            self._write_snmr(socket_num, conn_mode)
            self._write_snir(socket_num, 0xFF)

            if self._src_port > 0:
                # write to socket source port
                self._write_sock_port(socket_num, self._src_port)
            else:
                # if source port is not set, set the local port number
                self._write_sock_port(socket_num, LOCAL_PORT)

            # set socket destination IP addr. and port
            self._write_sndipr(socket_num, addr)
            self._write_sndport(socket_num, port)

            # open socket
            self._write_sncr(socket_num, CMD_SOCK_OPEN)
            assert self._read_sncr(socket_num)[0] == 0x00, "Error: Unable to open socket!"
            assert self._read_snsr((socket_num))[0] == 0x13, "Error: Unable to open socket!"

            return 0
        return 1

    def sock_available(self):
        print('data avail.:', self._read_snrx_rsr(self._sock))
        #if self._sock != self.max_sockets:
        #    return self._get_rx_rcv_size(self._sock)
        #return 0

    def _get_rx_rcv_size(self, sock):
        val = 0
        val_1=0
        while True:
            val_1 = self._read_snrx_rsr(sock)
            if val_1 != 0:
                val = self._read_snrx_rsr(sock)
            if not (val != val_1):
                break
        return val

    def _read_snrx_rsr(self, sock):
        data = self._read_socket(sock, REG_SNRX_RSR)
        data += self._read_socket(sock, REG_SNRX_RSR+1)
        return data

    def _write_sndipr(self, sock, ip_addr):
        """Writes to socket destination IP Address.

        """
        for octet in range(0, 4):
            self._write_socket(sock, REG_SNDIPR+octet, ip_addr[octet])

    def _write_sndport(self, sock, port):
        """Writes to socket destination port.

        """
        self._write_socket(sock, REG_SNDPORT, port >> 8)
        self._write_socket(sock, REG_SNDPORT+1, port & 0xFF)

    def _read_snsr(self, sock):
        """Reads Socket n Status Register.

        """
        return self._read_socket(sock, REG_SNSR)

    def _read_snmr(self, sock, protocol):
        """Read Socket n Mode Register

        """
        return self._read_socket(sock, protocol)

    def _write_snmr(self, sock, protocol):
        """Write to Socket n Mode Register.

        """
        self._write_socket(sock, REG_SNMR, protocol)

    def _write_snir(self, sock, data):
        """Write to Socket n Interrupt Register.
        """
        self._write_socket(sock, REG_SNIR, data)

    def _write_sock_port(self, sock, port):
        """Write to the socket port number.
        """
        self._write_socket(sock, REG_SNPORT, port >> 8)
        self._write_socket(sock, REG_SNPORT+1, port & 0xFF)

    def _write_sncr(self, sock, data):
        self._write_socket(sock, REG_SNCR, data)

    def _read_sncr(self, sock):
        return self._read_socket(sock, REG_SNCR)

    def _read_snmr(self, sock):
        return self._read_socket(sock, REG_SNMR)

    def _read_snir(self, sock):
        return self._read_socket(sock, REG_SNIR)
    
    def _read_sndipr(self, sock):
        return self._read_socket(sock, REG_SNDIPR)

    def _write_socket(self, sock, address, data, length=None):
        """Write to a W5k socket register.
        """
        base = self._ch_base_msb << 8
        cntl_byte = (sock<<5)+0x0C;
        if length is None:
            return self.write(base + sock * CH_SIZE + address, cntl_byte, data)
        return self._write_n(base + sock * CH_SIZE + address, cntl_byte, data)

    def _read_socket(self, sock, address):
        """Read a W5k socket register.
        """
        cntl_byte = (sock<<5)+0x08;
        return self.read(address, cntl_byte)
