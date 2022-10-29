# SPDX-FileCopyrightText: 2010 WIZnet
# SPDX-FileCopyrightText: 2010 Arduino LLC
# SPDX-FileCopyrightText: 2008 Bjoern Hartmann
# SPDX-FileCopyrightText: 2018 Paul Stoffregen
# SPDX-FileCopyrightText: 2020 Brent Rubell for Adafruit Industries
# SPDX-FileCopyrightText: 2021 Patrick Van Oosterwijck
# SPDX-FileCopyrightText: 2021 Adam Cummick
#
# SPDX-License-Identifier: MIT
"""
`adafruit_wiznet5k`
================================================================================

Pure-Python interface for WIZNET 5k ethernet modules.

* Author(s): WIZnet, Arduino LLC, Bjoern Hartmann, Paul Stoffregen, Brent Rubell,
  Patrick Van Oosterwijck

Implementation Notes
--------------------

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases

* Adafruit's Bus Device library: https://github.com/adafruit/Adafruit_CircuitPython_BusDevice
"""
# pylint: disable=too-many-lines
try:
    from typing import Optional, Union, List, Tuple, Sequence
    from circuitpython_typing import WriteableBuffer
    import busio
    import digitalio
except ImportError:
    pass

from random import randint
import time
from micropython import const

from adafruit_bus_device.spi_device import SPIDevice
import adafruit_wiznet5k.adafruit_wiznet5k_dhcp as dhcp
import adafruit_wiznet5k.adafruit_wiznet5k_dns as dns


__version__ = "0.0.0+auto.0"
__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k.git"


# Wiznet5k Registers
REG_MR = const(0x0000)  # Mode
REG_GAR = const(0x0001)  # Gateway IP Address
REG_SUBR = const(0x0005)  # Subnet Mask Address
REG_VERSIONR_W5500 = const(0x0039)  # W5500 Silicon Version
REG_VERSIONR_W5100S = const(0x0080)  # W5100S Silicon Version
REG_SHAR = const(0x0009)  # Source Hardware Address
REG_SIPR = const(0x000F)  # Source IP Address
REG_PHYCFGR = const(0x002E)  # W5500 PHY Configuration
REG_PHYCFGR_W5100S = const(0x003C)  # W5100S PHY Configuration

# Wiznet5k Socket Registers
REG_SNMR = const(0x0000)  # Socket n Mode
REG_SNCR = const(0x0001)  # Socket n Command
REG_SNIR = const(0x0002)  # Socket n Interrupt
REG_SNSR = const(0x0003)  # Socket n Status
REG_SNPORT = const(0x0004)  # Socket n Source Port
REG_SNDIPR = const(0x000C)  # Destination IP Address
REG_SNDPORT = const(0x0010)  # Destination Port
REG_SNRX_RSR = const(0x0026)  # RX Free Size
REG_SNRX_RD = const(0x0028)  # Read Size Pointer
REG_SNTX_FSR = const(0x0020)  # Socket n TX Free Size
REG_SNTX_WR = const(0x0024)  # TX Write Pointer

# SNSR Commands
SNSR_SOCK_CLOSED = const(0x00)
SNSR_SOCK_INIT = const(0x13)
SNSR_SOCK_LISTEN = const(0x14)
SNSR_SOCK_SYNSENT = const(0x15)
SNSR_SOCK_SYNRECV = const(0x16)
SNSR_SOCK_ESTABLISHED = const(0x17)
SNSR_SOCK_FIN_WAIT = const(0x18)
SNSR_SOCK_CLOSING = const(0x1A)
SNSR_SOCK_TIME_WAIT = const(0x1B)
SNSR_SOCK_CLOSE_WAIT = const(0x1C)
SNSR_SOCK_LAST_ACK = const(0x1D)
SNSR_SOCK_UDP = const(0x22)
SNSR_SOCK_IPRAW = const(0x32)
SNSR_SOCK_MACRAW = const(0x42)
SNSR_SOCK_PPPOE = const(0x5F)

# Sock Commands (CMD)
CMD_SOCK_OPEN = const(0x01)
CMD_SOCK_LISTEN = const(0x02)
CMD_SOCK_CONNECT = const(0x04)
CMD_SOCK_DISCON = const(0x08)
CMD_SOCK_CLOSE = const(0x10)
CMD_SOCK_SEND = const(0x20)
CMD_SOCK_SEND_MAC = const(0x21)
CMD_SOCK_SEND_KEEP = const(0x22)
CMD_SOCK_RECV = const(0x40)

# Socket n Interrupt Register
SNIR_SEND_OK = const(0x10)
SNIR_TIMEOUT = const(0x08)
SNIR_RECV = const(0x04)
SNIR_DISCON = const(0x02)
SNIR_CON = const(0x01)

CH_SIZE = const(0x100)
SOCK_SIZE = const(0x800)  # MAX W5k socket size
SOCK_MASK = const(0x7FF)
# Register commands
MR_RST = const(0x80)  # Mode Register RST
# Socket mode register
SNMR_CLOSE = const(0x00)
SNMR_TCP = const(0x21)
SNMR_UDP = const(0x02)
SNMR_IPRAW = const(0x03)
SNMR_MACRAW = const(0x04)
SNMR_PPPOE = const(0x05)

MAX_PACKET = const(4000)
LOCAL_PORT = const(0x400)
# Default hardware MAC address
DEFAULT_MAC = (0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED)

# Maximum number of sockets to support, differs between chip versions.
W5200_W5500_MAX_SOCK_NUM = const(0x08)
W5100_MAX_SOCK_NUM = const(0x04)
SOCKET_INVALID = const(255)

# Source ports in use
SRC_PORTS = [0] * W5200_W5500_MAX_SOCK_NUM


class WIZNET5K:  # pylint: disable=too-many-public-methods, too-many-instance-attributes
    """Interface for WIZNET5K module."""

    TCP_MODE = const(0x21)
    UDP_MODE = const(0x02)
    TLS_MODE = const(0x03)  # This is NOT currently implemented

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        spi_bus: busio.SPI,
        cs: digitalio.DigitalInOut,
        reset: Optional[digitalio.DigitalInOut] = None,
        is_dhcp: bool = True,
        mac: Union[List[int], Tuple[int]] = DEFAULT_MAC,
        hostname: Optional[str] = None,
        dhcp_timeout: float = 30,
        debug: bool = False,
    ) -> None:
        """
        :param busio.SPI spi_bus: The SPI bus the Wiznet module is connected to.
        :param digitalio.DigitalInOut cs: Chip select pin.
        :param digitalio.DigitalInOut reset: Optional reset pin, defaults to None.
        :param bool is_dhcp: Whether to start DHCP automatically or not, defaults to True.
        :param Union[List[int], Tuple[int]] mac: The Wiznet's MAC Address, defaults to
            (0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED).
        :param str hostname: The desired hostname, with optional {} to fill in the MAC
            address, defaults to None.
        :param float dhcp_timeout: Timeout in seconds for DHCP response, defaults to 30.
        :param bool debug: Enable debugging output, defaults to False.
        """
        self._debug = debug
        self._chip_type = None
        self._device = SPIDevice(spi_bus, cs, baudrate=8000000, polarity=0, phase=0)
        # init c.s.
        self._cs = cs

        # reset wiznet module prior to initialization
        if reset:
            reset.value = False
            time.sleep(0.1)
            reset.value = True
            time.sleep(0.1)

        # Buffer for reading params from module
        self._pbuff = bytearray(8)
        self._rxbuf = bytearray(MAX_PACKET)

        # attempt to initialize the module
        self._ch_base_msb = 0
        assert self._w5100_init() == 1, "Failed to initialize WIZnet module."
        # Set MAC address
        self.mac_address = mac
        self.src_port = 0
        self._dns = (0, 0, 0, 0)
        # udp related
        self.udp_datasize = [0] * self.max_sockets
        self.udp_from_ip = [b"\x00\x00\x00\x00"] * self.max_sockets
        self.udp_from_port = [0] * self.max_sockets

        # First, wait link status is on
        # to avoid the code during DHCP, socket listen, connect ...
        # assert self.link_status, "Ethernet cable disconnected!"
        start_time = time.monotonic()
        while True:
            if self.link_status or ((time.monotonic() - start_time) > 5):
                break
            time.sleep(1)
            if self._debug:
                print("My Link is:", self.link_status)
        self._dhcp_client = None

        # Set DHCP
        if is_dhcp:
            ret = self.set_dhcp(hostname, dhcp_timeout)
            if ret != 0:
                self._dhcp_client = None
            assert ret == 0, "Failed to configure DHCP Server!"

    def set_dhcp(
        self, hostname: Optional[str] = None, response_timeout: float = 30
    ) -> int:
        """
        Initialize the DHCP client and attempt to retrieve and set network
        configuration from the DHCP server.

        :param Optional[str] hostname: The desired hostname for the DHCP server with optional {} to
            fill in the MAC address, defaults to None.
        :param float response_timeout: Time to wait for server to return packet in seconds,
            defaults to 30.

        :return int: 0 if DHCP configured, -1 otherwise.
        """
        if self._debug:
            print("* Initializing DHCP")

        # Return IP assigned by DHCP
        self._dhcp_client = dhcp.DHCP(
            self, self.mac_address, hostname, response_timeout, debug=self._debug
        )
        ret = self._dhcp_client.request_dhcp_lease()
        if ret == 1:
            if self._debug:
                _ifconfig = self.ifconfig
                print("* Found DHCP Server:")
                print(
                    "IP: {}\nSubnet Mask: {}\nGW Addr: {}\nDNS Server: {}".format(
                        *_ifconfig
                    )
                )
            return 0
        return -1

    def maintain_dhcp_lease(self) -> None:
        """Maintain the DHCP lease."""
        if self._dhcp_client is not None:
            self._dhcp_client.maintain_dhcp_lease()

    def get_host_by_name(self, hostname: str) -> bytes:
        """
        Convert a hostname to a packed 4-byte IP Address.

        :param str hostname: The host name to be converted.

        :return Union[int, bytes]: a 4 bytearray.
        """
        if self._debug:
            print("* Get host by name")
        if isinstance(hostname, str):
            hostname = bytes(hostname, "utf-8")
        # Return IP assigned by DHCP
        _dns_client = dns.DNS(self, self._dns, debug=self._debug)
        ret = _dns_client.gethostbyname(hostname)
        if self._debug:
            print("* Resolved IP: ", ret)
        assert ret != -1, "Failed to resolve hostname!"
        return ret

    @property
    def max_sockets(self) -> int:
        """
        Maximum number of sockets supported by chip.

        :return int: Maximum supported sockets.
        """
        if self._chip_type == "w5500":
            return W5200_W5500_MAX_SOCK_NUM
        if self._chip_type == "w5100s":
            return W5100_MAX_SOCK_NUM
        return -1

    @property
    def chip(self) -> str:
        """
        Ethernet controller chip type.

        :return str: The chip type."""
        return self._chip_type

    @property
    def ip_address(self) -> bytearray:
        """
        Configured IP address.

        :return bytearray.
        """
        return self.read(REG_SIPR, 0x00, 4)

    def pretty_ip(
        self,
        # pylint: disable=no-self-use, invalid-name
        ip: bytearray,
    ) -> str:
        """
        Convert a bytearray IP address to a dotted-quad string for printing.

        :param bytearray ip: A four byte IP address.

        :return str: The IP address (a string of the form '255.255.255.255').
        """
        return "%d.%d.%d.%d" % (ip[0], ip[1], ip[2], ip[3])

    def unpretty_ip(
        self,
        # pylint: disable=no-self-use, invalid-name
        ip: str,
    ) -> bytes:
        """
        Convert a dotted-quad string to a four byte IP address.

        :param str ip: The IP address (a string of the form '255.255.255.255') to be converted.

        :return bytes: The IP address in four bytes.
        """
        octets = [int(x) for x in ip.split(".")]
        return bytes(octets)

    @property
    def mac_address(self) -> bytearray:
        """
        Ethernet hardware's MAC address.

        :return bytearray: The six byte MAC address."""
        return self.read(REG_SHAR, 0x00, 6)

    @mac_address.setter
    def mac_address(self, address: Sequence[Union[int, bytes]]) -> None:
        """
        Sets the hardware MAC address.

        :param tuple address: Hardware MAC address.
        """
        self.write(REG_SHAR, 0x04, address)

    def pretty_mac(
        self,
        # pylint: disable=no-self-use, invalid-name
        mac: bytearray,
    ) -> str:
        """
        Convert a bytearray MAC address to a ':' seperated string for display.

        :param bytearray mac: The MAC address.

        :return str: Mac Address in the form 00:00:00:00:00:00

        """
        return "%s:%s:%s:%s:%s:%s" % (
            hex(mac[0]),
            hex(mac[1]),
            hex(mac[2]),
            hex(mac[3]),
            hex(mac[4]),
            hex(mac[5]),
        )

    def remote_ip(self, socket_num: int) -> Union[str, bytearray]:
        """
        IP address of the host which sent the current incoming packet.

        :param int socket_num: ID number of the socket to check.

        :return Union[str, bytearray]: The four byte IP address.
        """
        if socket_num >= self.max_sockets:
            return self._pbuff
        for octet in range(0, 4):
            self._pbuff[octet] = self._read_socket(socket_num, REG_SNDIPR + octet)[0]
        return self.pretty_ip(self._pbuff)

    @property
    def link_status(self) -> int:
        """Physical hardware (PHY) connection status.

        :return int: 1 if the link is up, 0 if the link is down.
        """
        if self._chip_type == "w5500":
            data = self.read(REG_PHYCFGR, 0x00)
            return data[0] & 0x01
        if self._chip_type == "w5100s":
            data = self.read(REG_PHYCFGR_W5100S, 0x00)
            return data[0] & 0x01
        return 0

    def remote_port(self, socket_num: int) -> Union[int, bytearray]:
        """
        Port of the host which sent the current incoming packet.

        :param int socket_num: ID number of the socket to check.

        :return Union[int, bytearray]: The port number of the socket connection.
        """
        # TODO: why return the buffer?
        if socket_num >= self.max_sockets:
            return self._pbuff
        for octet in range(2):
            self._pbuff[octet] = self._read_socket(socket_num, REG_SNDPORT + octet)[0]
        return int((self._pbuff[0] << 8) | self._pbuff[0])

    @property
    def ifconfig(
        self,
    ) -> Tuple[bytearray, bytearray, bytearray, Tuple[int, int, int, int]]:  # *1
        """
        Network configuration information.

        :return Tuple[bytearray, bytearray, bytearray, Tuple[int, int, int, int]]: \
        The IP address, subnet mask, gateway address and DNS server address."""
        return (
            self.ip_address,
            self.read(REG_SUBR, 0x00, 4),
            self.read(REG_GAR, 0x00, 4),
            self._dns,
        )

    @ifconfig.setter
    def ifconfig(
        self, params: Tuple[bytearray, bytearray, bytearray, Tuple[int, int, int, int]]
    ) -> None:
        """
        Set network configuration.

        :params Tuple[bytearray, bytearray, bytearray, Tuple[int, int, int, int]]: \
        Configuration settings - (ip_address, subnet_mask, gateway_address, dns_server).
        """
        # TODO: Might be better if params can be str as well
        ip_address, subnet_mask, gateway_address, dns_server = params

        self.write(REG_SIPR, 0x04, ip_address)
        self.write(REG_SUBR, 0x04, subnet_mask)
        self.write(REG_GAR, 0x04, gateway_address)

        self._dns = dns_server

    def _w5100_init(self) -> int:
        """
        Detect and initialize a Wiznet5k ethernet module.

        :return int: 1 if the initialization succeeds, 0 if it fails.
        """
        time.sleep(1)
        # TODO: Isn't the CS pin initialized in busio?
        self._cs.switch_to_output()
        self._cs.value = 1

        # Detect if chip is Wiznet W5500
        if self.detect_w5500() == 1:
            # perform w5500 initialization
            for i in range(0, W5200_W5500_MAX_SOCK_NUM):
                ctrl_byte = 0x0C + (i << 5)
                self.write(0x1E, ctrl_byte, 2)
                self.write(0x1F, ctrl_byte, 2)
        else:
            # Detect if chip is Wiznet W5100S
            if self.detect_w5100s() == 1:
                pass
            else:
                return 0
        return 1

    def detect_w5500(self) -> int:
        """
        Detect W5500 chip.

        :return int: 1 if a W5500 chip is detected, -1 if not.
        """
        self._chip_type = "w5500"
        assert self.sw_reset() == 0, "Chip not reset properly!"
        self._write_mr(0x08)
        # assert self._read_mr()[0] == 0x08, "Expected 0x08."
        if self._read_mr()[0] != 0x08:
            return -1

        self._write_mr(0x10)
        # assert self._read_mr()[0] == 0x10, "Expected 0x10."
        if self._read_mr()[0] != 0x10:
            return -1

        self._write_mr(0x00)
        # assert self._read_mr()[0] == 0x00, "Expected 0x00."
        if self._read_mr()[0] != 0x00:
            return -1

        if self.read(REG_VERSIONR_W5500, 0x00)[0] != 0x04:
            return -1
        # self._chip_type = "w5500"
        # self._ch_base_msb = 0x10
        return 1

    def detect_w5100s(self) -> int:
        """
        Detect W5100S chip.

        :return int: 1 if a W5100 chip is detected, -1 if not.
        """
        self._chip_type = "w5100s"
        # sw reset
        assert self.sw_reset() == 0, "Chip not reset properly!"
        if self.read(REG_VERSIONR_W5100S, 0x00)[0] != 0x51:
            return -1

        self._ch_base_msb = 0x0400
        return 1

    def sw_reset(self) -> int:
        """Perform a soft-reset on the Wiznet chip.

        Perform a soft reset by writing to the chip's MR register reset bit.

        :return int: 0 if the reset succeeds, -1 if not.
        """
        # TODO: mode_reg appears to be unused, maybe self._read_mr starts the reset?
        mode_reg = self._read_mr()
        self._write_mr(0x80)
        mode_reg = self._read_mr()

        # W5100S case => 0x03
        if (mode_reg[0] != 0x00) and (mode_reg[0] != 0x03):
            return -1
        return 0

    def _read_mr(self) -> bytearray:
        """Read from the Mode Register (MR)."""
        res = self.read(REG_MR, 0x00)
        return res

    def _write_mr(self, data: int) -> None:
        """Write to the mode register (MR)."""
        self.write(REG_MR, 0x04, data)

    def read(
        self,
        addr: int,
        callback: int,
        length: int = 1,
        buffer: Optional[WriteableBuffer] = None,
    ) -> Union[WriteableBuffer, bytearray]:
        """
        Read data from a register address.

        :param int addr: Register address to read.
        :param int callback: Callback reference.
        :param int length: Number of bytes to read from the register, defaults to 1.
        :param Optional[WriteableBuffer] buffer: Buffer to read data into, defaults to None.

        :return Union[WriteableBuffer, bytearray]: The data read from the chip.
        """
        with self._device as bus_device:
            if self._chip_type == "w5500":
                bus_device.write(bytes([addr >> 8]))  # pylint: disable=no-member
                bus_device.write(bytes([addr & 0xFF]))  # pylint: disable=no-member
                bus_device.write(bytes([callback]))  # pylint: disable=no-member
            else:
                # if self._chip_type == "w5100s":
                bus_device.write(bytes([0x0F]))  # pylint: disable=no-member
                bus_device.write(bytes([addr >> 8]))  # pylint: disable=no-member
                bus_device.write(bytes([addr & 0xFF]))  # pylint: disable=no-member

            if buffer is None:
                self._rxbuf = bytearray(length)
                bus_device.readinto(self._rxbuf)  # pylint: disable=no-member
                return self._rxbuf
            bus_device.readinto(buffer, end=length)  # pylint: disable=no-member
            return buffer

    def write(
        self, addr: int, callback: int, data: Union[int, Sequence[Union[int, bytes]]]
    ) -> None:
        """
        Write data to a register address.

        :param int addr: Destination address.
        :param int callback: Callback reference.
        :param Union[int, Sequence[Union[int, bytes]]] data: Data to write to the register address.
        """
        # TODO: Call with int means an error in a previous function
        with self._device as bus_device:
            if self._chip_type == "w5500":
                bus_device.write(bytes([addr >> 8]))  # pylint: disable=no-member
                bus_device.write(bytes([addr & 0xFF]))  # pylint: disable=no-member
                bus_device.write(bytes([callback]))  # pylint: disable=no-member
            else:
                # if self._chip_type == "w5100s":
                bus_device.write(bytes([0xF0]))  # pylint: disable=no-member
                bus_device.write(bytes([addr >> 8]))  # pylint: disable=no-member
                bus_device.write(bytes([addr & 0xFF]))  # pylint: disable=no-member

            if hasattr(data, "from_bytes"):
                bus_device.write(bytes([data]))  # pylint: disable=no-member
            else:
                for i, _ in enumerate(data):
                    bus_device.write(bytes([data[i]]))  # pylint: disable=no-member

    # Socket-Register API

    def socket_available(self, socket_num: int, sock_type: int = SNMR_TCP) -> int:
        """
        Return the number of bytes available to be read from the socket.

        :param int socket_num: Socket to check for available bytes.
        :param int sock_type: Socket type. Use SNMR_TCP for TCP or SNMR_UDP for UDP, \
        defaults to SNMR_TCP.

        :return int: Number of bytes available to read.
        """
        if self._debug:
            print(
                "* socket_available called on socket {}, protocol {}".format(
                    socket_num, sock_type
                )
            )
        assert socket_num <= self.max_sockets, "Provided socket exceeds max_sockets."

        res = self._get_rx_rcv_size(socket_num)

        if sock_type == SNMR_TCP:
            return res
        if res > 0:
            if self.udp_datasize[socket_num]:
                return self.udp_datasize[socket_num]
            # parse the udp rx packet
            # read the first 8 header bytes
            ret, self._pbuff = self.socket_read(socket_num, 8)
            if ret > 0:
                self.udp_from_ip[socket_num] = self._pbuff[:4]
                self.udp_from_port[socket_num] = (self._pbuff[4] << 8) + self._pbuff[5]
                self.udp_datasize[socket_num] = (self._pbuff[6] << 8) + self._pbuff[7]
                ret = self.udp_datasize[socket_num]
                return ret
        return 0

    def socket_status(self, socket_num: int) -> Union[bytearray, None]:
        """
        Return the socket connection status.

        Can be: SNSR_SOCK_CLOSED, SNSR_SOCK_INIT, SNSR_SOCK_LISTEN, SNSR_SOCK_SYNSENT,
        SNSR_SOCK_SYNRECV, SNSR_SYN_SOCK_ESTABLISHED, SNSR_SOCK_FIN_WAIT,
        SNSR_SOCK_CLOSING, SNSR_SOCK_TIME_WAIT, SNSR_SOCK_CLOSE_WAIT, SNSR_LAST_ACK,
        SNSR_SOCK_UDP, SNSR_SOCK_IPRAW, SNSR_SOCK_MACRAW, SNSR_SOCK_PPOE.

        :param int socket_num: ID of socket to check.

        :return: Union[bytearray, None]
        """
        return self._read_snsr(socket_num)

    def socket_connect(
        self,
        socket_num: int,
        dest: Union[bytes, bytearray],
        port: int,
        conn_mode: int = SNMR_TCP,
    ) -> int:
        """
        Open and verify a connection from a socket to a destination IP address
        or hostname. A TCP connection is made by default. A UDP connection can also
        be made.

        :param int socket_num: ID of the socket to be connected.
        :param Union[bytes, bytearray] dest: The destination as a host name or IP address.
        :param int port: Port to connect to (0 - 65,536).
        :param int conn_mode: The connection mode. Use SNMR_TCP for TCP or SNMR_UDP for UDP,
        defaults to SNMR_TCP.
        """
        assert self.link_status, "Ethernet cable disconnected!"
        if self._debug:
            print(
                "* w5k socket connect, protocol={}, port={}, ip={}".format(
                    conn_mode, port, self.pretty_ip(dest)
                )
            )
        # initialize a socket and set the mode
        res = self.socket_open(socket_num, conn_mode=conn_mode)
        if res == 1:
            raise RuntimeError("Failed to initalize a connection with the socket.")

        # set socket destination IP and port
        self._write_sndipr(socket_num, dest)
        self._write_sndport(socket_num, port)
        self._send_socket_cmd(socket_num, CMD_SOCK_CONNECT)

        if conn_mode == SNMR_TCP:
            # wait for tcp connection establishment
            while self.socket_status(socket_num)[0] != SNSR_SOCK_ESTABLISHED:
                time.sleep(0.001)
                if self._debug:
                    print("SN_SR:", self.socket_status(socket_num)[0])
                if self.socket_status(socket_num)[0] == SNSR_SOCK_CLOSED:
                    raise RuntimeError("Failed to establish connection.")
        elif conn_mode == SNMR_UDP:
            self.udp_datasize[socket_num] = 0
        return 1

    def _send_socket_cmd(self, socket: int, cmd: int) -> None:
        """Send a socket command to a socket."""
        self._write_sncr(socket, cmd)
        while self._read_sncr(socket) != b"\x00":
            if self._debug:
                print("waiting for sncr to clear...")

    def get_socket(self) -> int:
        """Request, allocate and return a socket from the W5k chip.

        Cycles through the sockets to find the first available one, if any.

        :return int: The first available socket. Returns 0xFF if no sockets are free.
        """
        if self._debug:
            print("*** Get socket")

        sock = SOCKET_INVALID
        for _sock in range(self.max_sockets):
            status = self.socket_status(_sock)[0]
            if status == SNSR_SOCK_CLOSED:
                sock = _sock
                break

        if self._debug:
            print("Allocated socket #{}".format(sock))
        return sock

    def socket_listen(
        self, socket_num: int, port: int, conn_mode: int = SNMR_TCP
    ) -> None:
        """
        Listen on a socket's port.

        :param int socket_num: ID of socket to listen on.
        :param int port: Port to listen on (0 - 65,535).
        :param int conn_mode: Connection mode SNMR_TCP for TCP or SNMR_UDP for
            UDP, defaults to SNMR_TCP.
        """
        assert self.link_status, "Ethernet cable disconnected!"
        if self._debug:
            print(
                "* Listening on port={}, ip={}".format(
                    port, self.pretty_ip(self.ip_address)
                )
            )
        # Initialize a socket and set the mode
        self.src_port = port
        res = self.socket_open(socket_num, conn_mode=conn_mode)
        self.src_port = 0
        if res == 1:
            raise RuntimeError("Failed to initalize the socket.")
        # Send listen command
        self._send_socket_cmd(socket_num, CMD_SOCK_LISTEN)
        # Wait until ready
        status = [SNSR_SOCK_CLOSED]
        while status[0] not in (SNSR_SOCK_LISTEN, SNSR_SOCK_ESTABLISHED, SNSR_SOCK_UDP):
            status = self._read_snsr(socket_num)
            if status[0] == SNSR_SOCK_CLOSED:
                raise RuntimeError("Listening socket closed.")

    def socket_accept(
        self, socket_num: int
    ) -> Tuple[int, Tuple[Union[str, bytearray], Union[int, bytearray]]]:
        """
        Destination IP address and port from an incoming connection.

        Return the next socket number so listening can continue, along with
        the IP address and port of the incoming connection.

        :param int socket_num: Socket number with connection to check.

        :return Tuple[int, Tuple[Union[str, bytearray], Union[int, bytearray]]]:
            If successful, the next (socket number, (destination IP address, destination port)).

        If errors occur, the destination IP address and / or the destination port may be
        returned as bytearrays.
        """
        dest_ip = self.remote_ip(socket_num)
        dest_port = self.remote_port(socket_num)
        next_socknum = self.get_socket()
        if self._debug:
            print(
                "* Dest is ({}, {}), Next listen socknum is #{}".format(
                    dest_ip, dest_port, next_socknum
                )
            )
        return next_socknum, (dest_ip, dest_port)

    def socket_open(self, socket_num: int, conn_mode: int = SNMR_TCP) -> int:
        """
        Open an IP socket.

        The socket may connect via TCP or UDP protocols.

        :param int socket_num: The socket number to open.
        :param int conn_mode: The protocol to use. Use SNMR_TCP for TCP or SNMR_UDP for \
        UDP, defaults to SNMR_TCP.

        :return int: 1 if the socket was opened, 0 if not.
        """
        assert self.link_status, "Ethernet cable disconnected!"
        if self._debug:
            print("*** Opening socket %d" % socket_num)
        status = self._read_snsr(socket_num)[0]
        if status in (
            SNSR_SOCK_CLOSED,
            SNSR_SOCK_TIME_WAIT,
            SNSR_SOCK_FIN_WAIT,
            SNSR_SOCK_CLOSE_WAIT,
            SNSR_SOCK_CLOSING,
            SNSR_SOCK_UDP,
        ):
            if self._debug:
                print("* Opening W5k Socket, protocol={}".format(conn_mode))
            time.sleep(0.00025)

            self._write_snmr(socket_num, conn_mode)
            self._write_snir(socket_num, 0xFF)

            if self.src_port > 0:
                # write to socket source port
                self._write_sock_port(socket_num, self.src_port)
            else:
                s_port = randint(49152, 65535)
                while s_port in SRC_PORTS:
                    s_port = randint(49152, 65535)
                self._write_sock_port(socket_num, s_port)
                SRC_PORTS[socket_num] = s_port

            # open socket
            self._write_sncr(socket_num, CMD_SOCK_OPEN)
            self._read_sncr(socket_num)
            assert (
                self._read_snsr((socket_num))[0] == 0x13
                or self._read_snsr((socket_num))[0] == 0x22
            ), "Could not open socket in TCP or UDP mode."
            return 0
        return 1

    def socket_close(self, socket_num: int) -> None:
        """
        Close a socket.

        :param int socket_num: The socket to close.
        """
        if self._debug:
            print("*** Closing socket #%d" % socket_num)
        self._write_sncr(socket_num, CMD_SOCK_CLOSE)
        self._read_sncr(socket_num)

    def socket_disconnect(self, socket_num: int) -> None:
        """
        Disconnect a TCP or UDP connection.

        :param int socket_num: The socket to close.
        """
        if self._debug:
            print("*** Disconnecting socket #%d" % socket_num)
        self._write_sncr(socket_num, CMD_SOCK_DISCON)
        self._read_sncr(socket_num)

    def socket_read(
        self, socket_num: int, length: int
    ) -> Tuple[int, Union[int, bytearray]]:
        """
        Read data from a TCP socket.

        :param int socket_num: The socket to read data from.
        :param int length: The number of bytes to read from the socket.

        :return Tuple[int, Union[int, bytearray]]: If the read was successful then the first
        item of the tuple is the length of the data and the second is the data. If the read
        was unsuccessful then both items equal an error code, 0 for no data waiting and -1
        for no connection to the socket.
        """
        assert self.link_status, "Ethernet cable disconnected!"
        assert socket_num <= self.max_sockets, "Provided socket exceeds max_sockets."

        # Check if there is data available on the socket
        ret = self._get_rx_rcv_size(socket_num)
        if self._debug:
            print("Bytes avail. on sock: ", ret)
        if ret == 0:
            # no data on socket?
            status = self._read_snmr(socket_num)
            if status in (SNSR_SOCK_LISTEN, SNSR_SOCK_CLOSED, SNSR_SOCK_CLOSE_WAIT):
                # remote end closed its side of the connection, EOF state
                ret = 0
                resp = 0
            else:
                # connection is alive, no data waiting to be read
                ret = -1
                resp = -1
        elif ret > length:
            # set ret to the length of buffer
            ret = length

        if ret > 0:
            if self._debug:
                print("\t * Processing {} bytes of data".format(ret))
            # Read the starting save address of the received data
            ptr = self._read_snrx_rd(socket_num)

            if self._chip_type == "w5500":
                # Read data from the starting address of snrx_rd
                ctrl_byte = 0x18 + (socket_num << 5)

                resp = self.read(ptr, ctrl_byte, ret)
            else:
                # if self._chip_type == "w5100s":
                offset = ptr & SOCK_MASK
                src_addr = offset + (socket_num * SOCK_SIZE + 0x6000)
                if offset + ret > SOCK_SIZE:
                    size = SOCK_SIZE - offset
                    resp1 = self.read(src_addr, 0x00, size)
                    size = ret - size
                    src_addr = socket_num * SOCK_SIZE + 0x6000
                    resp2 = self.read(src_addr, 0x00, size)
                    resp = resp1 + resp2
                else:
                    resp = self.read(src_addr, 0x00, ret)

            #  After reading the received data, update Sn_RX_RD to the increased
            # value as many as the reading size.
            ptr = (ptr + ret) & 0xFFFF
            self._write_snrx_rd(socket_num, ptr)

            # Notify the W5k of the updated Sn_Rx_RD
            self._write_sncr(socket_num, CMD_SOCK_RECV)
            self._read_sncr(socket_num)
        return ret, resp

    def read_udp(
        self, socket_num: int, length: int
    ) -> Union[int, Tuple[int, Union[int, bytearray]]]:
        """
        Read UDP socket's current message bytes.

        :param int socket_num: The socket to read data from.
        :param int length: The number of bytes to read from the socket.

        :return Union[int, Tuple[int, Union[int, bytearray]]]: If the read was successful then
            the first item of the tuple is the length of the data and the second is the data.
            If the read was unsuccessful then -1 is returned.
        """
        if self.udp_datasize[socket_num] > 0:
            if self.udp_datasize[socket_num] <= length:
                ret, resp = self.socket_read(socket_num, self.udp_datasize[socket_num])
            else:
                ret, resp = self.socket_read(socket_num, length)
                # just consume the rest, it is lost to the higher layers
                self.socket_read(socket_num, self.udp_datasize[socket_num] - length)
            self.udp_datasize[socket_num] = 0
            return ret, resp
        return -1

    def socket_write(
        self, socket_num: int, buffer: bytearray, timeout: float = 0
    ) -> int:
        """
        Write data to a socket.

        :param int socket_num: The socket to write to.
        :param bytearray buffer: The data to write to the socket.

        :return int: The number of bytes written to the buffer.
        """
        assert self.link_status, "Ethernet cable disconnected!"
        assert socket_num <= self.max_sockets, "Provided socket exceeds max_sockets."
        status = 0
        ret = 0
        free_size = 0  # TODO: Bug report
        if len(buffer) > SOCK_SIZE:
            ret = SOCK_SIZE
        else:
            ret = len(buffer)
        stamp = time.monotonic()

        # if buffer is available, start the transfer
        free_size = self._get_tx_free_size(socket_num)
        while free_size < ret:
            free_size = self._get_tx_free_size(socket_num)
            status = self.socket_status(socket_num)[0]
            if status not in (SNSR_SOCK_ESTABLISHED, SNSR_SOCK_CLOSE_WAIT) or (
                timeout and time.monotonic() - stamp > timeout
            ):
                ret = 0
                break

        # Read the starting address for saving the transmitting data.
        ptr = self._read_sntx_wr(socket_num)
        offset = ptr & SOCK_MASK
        if self._chip_type == "w5500":
            dst_addr = offset + (socket_num * SOCK_SIZE + 0x8000)

            txbuf = buffer[:ret]
            cntl_byte = 0x14 + (socket_num << 5)
            self.write(dst_addr, cntl_byte, txbuf)

        else:
            # if self._chip_type == "w5100s":
            dst_addr = offset + (socket_num * SOCK_SIZE + 0x4000)

            if offset + ret > SOCK_SIZE:
                size = SOCK_SIZE - offset
                txbuf = buffer[0:size]
                self.write(dst_addr, 0x00, txbuf)
                txbuf = buffer[size:ret]
                size = ret - size
                dst_addr = socket_num * SOCK_SIZE + 0x4000
                self.write(dst_addr, 0x00, txbuf)
            else:
                txbuf = buffer[:ret]  # TODO: Bug report
                self.write(dst_addr, 0x00, buffer[:ret])

        # update sn_tx_wr to the value + data size
        ptr = (ptr + ret) & 0xFFFF
        self._write_sntx_wr(socket_num, ptr)

        self._write_sncr(socket_num, CMD_SOCK_SEND)
        self._read_sncr(socket_num)

        # check data was  transferred correctly
        while (
            self._read_socket(socket_num, REG_SNIR)[0] & SNIR_SEND_OK
        ) != SNIR_SEND_OK:
            if self.socket_status(socket_num)[0] in (
                SNSR_SOCK_CLOSED,
                SNSR_SOCK_TIME_WAIT,
                SNSR_SOCK_FIN_WAIT,
                SNSR_SOCK_CLOSE_WAIT,
                SNSR_SOCK_CLOSING,
            ) or (timeout and time.monotonic() - stamp > timeout):
                # self.socket_close(socket_num)
                return 0
            time.sleep(0.01)

        self._write_snir(socket_num, SNIR_SEND_OK)
        return ret

    # Socket-Register Methods
    def _get_rx_rcv_size(self, sock: int) -> int:
        """Size of received and saved in socket buffer."""
        val = 0
        val_1 = self._read_snrx_rsr(sock)
        while val != val_1:
            val_1 = self._read_snrx_rsr(sock)
            if val_1 != 0:
                val = self._read_snrx_rsr(sock)
        return int.from_bytes(val, "big")

    def _get_tx_free_size(self, sock: int) -> int:
        """Free size of socket's tx buffer block."""
        val = 0
        val_1 = self._read_sntx_fsr(sock)
        while val != val_1:
            val_1 = self._read_sntx_fsr(sock)
            if val_1 != 0:
                val = self._read_sntx_fsr(sock)
        return int.from_bytes(val, "big")

    def _read_snrx_rd(self, sock: int) -> int:
        self._pbuff[0] = self._read_socket(sock, REG_SNRX_RD)[0]
        self._pbuff[1] = self._read_socket(sock, REG_SNRX_RD + 1)[0]
        return self._pbuff[0] << 8 | self._pbuff[1]

    def _write_snrx_rd(self, sock: int, data: int) -> None:
        self._write_socket(sock, REG_SNRX_RD, data >> 8 & 0xFF)
        self._write_socket(sock, REG_SNRX_RD + 1, data & 0xFF)

    def _write_sntx_wr(self, sock: int, data: int) -> None:
        self._write_socket(sock, REG_SNTX_WR, data >> 8 & 0xFF)
        self._write_socket(sock, REG_SNTX_WR + 1, data & 0xFF)

    def _read_sntx_wr(self, sock: int) -> int:
        self._pbuff[0] = self._read_socket(sock, 0x0024)[0]
        self._pbuff[1] = self._read_socket(sock, 0x0024 + 1)[0]
        return self._pbuff[0] << 8 | self._pbuff[1]

    def _read_sntx_fsr(self, sock: int) -> Union[bytearray, None]:
        data = self._read_socket(sock, REG_SNTX_FSR)
        data += self._read_socket(sock, REG_SNTX_FSR + 1)
        return data

    def _read_snrx_rsr(self, sock: int) -> Union[bytearray, None]:
        data = self._read_socket(sock, REG_SNRX_RSR)
        data += self._read_socket(sock, REG_SNRX_RSR + 1)
        return data

    def _write_sndipr(self, sock: int, ip_addr: bytearray) -> None:
        """Write to socket destination IP Address."""
        for octet in range(0, 4):
            self._write_socket(sock, REG_SNDIPR + octet, ip_addr[octet])

    def _write_sndport(self, sock: int, port: int) -> None:
        """Write to socket destination port."""
        self._write_socket(sock, REG_SNDPORT, port >> 8)
        self._write_socket(sock, REG_SNDPORT + 1, port & 0xFF)

    def _read_snsr(self, sock: int) -> Union[bytearray, None]:
        """Read Socket n Status Register."""
        return self._read_socket(sock, REG_SNSR)

    def _write_snmr(self, sock: int, protocol: int) -> None:
        """Write to Socket n Mode Register."""
        self._write_socket(sock, REG_SNMR, protocol)

    def _write_snir(self, sock: int, data: int) -> None:
        """Write to Socket n Interrupt Register."""
        self._write_socket(sock, REG_SNIR, data)

    def _write_sock_port(self, sock: int, port: int) -> None:
        """Write to the socket port number."""
        self._write_socket(sock, REG_SNPORT, port >> 8)
        self._write_socket(sock, REG_SNPORT + 1, port & 0xFF)

    def _write_sncr(self, sock: int, data: int) -> None:
        self._write_socket(sock, REG_SNCR, data)

    def _read_sncr(self, sock: int) -> Union[bytearray, None]:
        return self._read_socket(sock, REG_SNCR)

    def _read_snmr(self, sock: int) -> Union[bytearray, None]:
        return self._read_socket(sock, REG_SNMR)

    def _write_socket(self, sock: int, address: int, data: int) -> None:
        """Write to a W5k socket register."""
        if self._chip_type == "w5500":
            cntl_byte = (sock << 5) + 0x0C
            return self.write(address, cntl_byte, data)
        if self._chip_type == "w5100s":
            cntl_byte = 0
            return self.write(
                self._ch_base_msb + sock * CH_SIZE + address, cntl_byte, data
            )
        return None

    def _read_socket(self, sock: int, address: int) -> Union[bytearray, None]:  # *1
        """Read a W5k socket register."""
        if self._chip_type == "w5500":
            cntl_byte = (sock << 5) + 0x08
            return self.read(address, cntl_byte)
        if self._chip_type == "w5100s":
            cntl_byte = 0
            return self.read(self._ch_base_msb + sock * CH_SIZE + address, cntl_byte)
        # TODO: If the chip is not supported, this should raise an exception.
        return None
