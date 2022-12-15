# SPDX-FileCopyrightText: 2022 Martin Stephens
#
# SPDX-License-Identifier: MIT
"""Tests to confirm that there are no changes in behaviour to public methods and functions."""

# pylint: disable=no-self-use, redefined-outer-name, protected-access, invalid-name, too-many-arguments
import pytest

from micropython import const
import adafruit_wiznet5k.adafruit_wiznet5k_dhcp as wiz_dhcp

#
DEFAULT_DEBUG_ON = True


@pytest.fixture
def wiznet(mocker):
    return mocker.patch("adafruit_wiznet5k.adafruit_wiznet5k.WIZNET5K", autospec=True)


@pytest.fixture
def wrench(mocker):
    return mocker.patch(
        "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.socket", autospec=True
    )


class TestDHCPInit:
    def test_constants(self):
        # DHCP State Machine
        assert wiz_dhcp.STATE_DHCP_START == const(0x00)
        assert wiz_dhcp.STATE_DHCP_DISCOVER == const(0x01)
        assert wiz_dhcp.STATE_DHCP_REQUEST == const(0x02)
        assert wiz_dhcp.STATE_DHCP_LEASED == const(0x03)
        assert wiz_dhcp.STATE_DHCP_REREQUEST == const(0x04)
        assert wiz_dhcp.STATE_DHCP_RELEASE == const(0x05)
        assert wiz_dhcp.STATE_DHCP_WAIT == const(0x06)
        assert wiz_dhcp.STATE_DHCP_DISCONN == const(0x07)

        # DHCP wait time between attempts
        assert wiz_dhcp.DHCP_WAIT_TIME == const(60)

        # DHCP Message Types
        assert wiz_dhcp.DHCP_DISCOVER == const(1)
        assert wiz_dhcp.DHCP_OFFER == const(2)
        assert wiz_dhcp.DHCP_REQUEST == const(3)
        assert wiz_dhcp.DHCP_DECLINE == const(4)
        assert wiz_dhcp.DHCP_ACK == const(5)
        assert wiz_dhcp.DHCP_NAK == const(6)
        assert wiz_dhcp.DHCP_RELEASE == const(7)
        assert wiz_dhcp.DHCP_INFORM == const(8)

        # DHCP Message OP Codes
        assert wiz_dhcp.DHCP_BOOT_REQUEST == const(0x01)
        assert wiz_dhcp.DHCP_BOOT_REPLY == const(0x02)

        assert wiz_dhcp.DHCP_HTYPE10MB == const(0x01)
        assert wiz_dhcp.DHCP_HTYPE100MB == const(0x02)

        assert wiz_dhcp.DHCP_HLENETHERNET == const(0x06)
        assert wiz_dhcp.DHCP_HOPS == const(0x00)

        assert wiz_dhcp.MAGIC_COOKIE == const(0x63825363)
        assert wiz_dhcp.MAX_DHCP_OPT == const(0x10)

        # Default DHCP Server port
        assert wiz_dhcp.DHCP_SERVER_PORT == const(67)
        # DHCP Lease Time, in seconds
        assert wiz_dhcp.DEFAULT_LEASE_TIME == const(900)
        assert wiz_dhcp.BROADCAST_SERVER_ADDR == (255, 255, 255, 255)

        # DHCP Response Options
        assert wiz_dhcp.MSG_TYPE == 53
        assert wiz_dhcp.SUBNET_MASK == 1
        assert wiz_dhcp.ROUTERS_ON_SUBNET == 3
        assert wiz_dhcp.DNS_SERVERS == 6
        assert wiz_dhcp.DHCP_SERVER_ID == 54
        assert wiz_dhcp.T1_VAL == 58
        assert wiz_dhcp.T2_VAL == 59
        assert wiz_dhcp.LEASE_TIME == 51
        assert wiz_dhcp.OPT_END == 255

        # Packet buffer
        assert wiz_dhcp._BUFF == bytearray(318)

    @pytest.mark.parametrize(
        "mac_address",
        (
            [1, 2, 3, 4, 5, 6],
            (7, 8, 9, 10, 11, 12),
            bytes([1, 2, 4, 6, 7, 8]),
        ),
    )
    def test_dhcp_setup_default(self, mocker, wiznet, wrench, mac_address):
        # Test with mac address as tuple, list and bytes with default values.
        mock_randint = mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.randint", autospec=True
        )
        mock_randint.return_value = 0x1234567
        dhcp_client = wiz_dhcp.DHCP(wiznet, mac_address)
        assert dhcp_client._eth == wiznet
        assert dhcp_client._response_timeout == 30.0
        assert dhcp_client._debug is False
        assert dhcp_client._mac_address == mac_address
        wrench.set_interface.assert_called_once_with(wiznet)
        assert dhcp_client._sock is None
        assert dhcp_client._dhcp_state == wiz_dhcp.STATE_DHCP_START
        assert dhcp_client._initial_xid == 0
        mock_randint.assert_called_once()
        assert dhcp_client._transaction_id == 0x1234567
        assert dhcp_client._start_time == 0
        assert dhcp_client.dhcp_server_ip == wiz_dhcp.BROADCAST_SERVER_ADDR
        assert dhcp_client.local_ip == 0
        assert dhcp_client.gateway_ip == 0
        assert dhcp_client.subnet_mask == 0
        assert dhcp_client.dns_server_ip == 0
        assert dhcp_client._lease_time == 0
        assert dhcp_client._last_lease_time == 0
        assert dhcp_client._renew_in_sec == 0
        assert dhcp_client._rebind_in_sec == 0
        assert dhcp_client._t1 == 0
        assert dhcp_client._t2 == 0
        mac_string = "".join("{:02X}".format(o) for o in mac_address)
        assert dhcp_client._hostname == bytes(
            "WIZnet{}".split(".", maxsplit=1)[0].format(mac_string)[:42], "utf-8"
        )

    def test_dhcp_setup_other_args(self, wiznet):
        mac_address = (7, 8, 9, 10, 11, 12)
        dhcp_client = wiz_dhcp.DHCP(
            wiznet, mac_address, hostname="fred.com", response_timeout=25.0, debug=True
        )

        assert dhcp_client._response_timeout == 25.0
        assert dhcp_client._debug is True
        mac_string = "".join("{:02X}".format(o) for o in mac_address)
        assert dhcp_client._hostname == bytes(
            "fred.com".split(".", maxsplit=1)[0].format(mac_string)[:42], "utf-8"
        )


class TestSendDHCPMessage:
    DHCP_SEND_01 = bytearray(
        b"\x01\x01\x06\x00\xff\xff\xffo\x00\x17\x80\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x05\x06\x07"
        b"\x08\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x01="
        b"\x07\x01\x04\x05\x06\x07\x08\t\x0c\x12WIZnet040506070809"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x007\x06\x01\x03"
        b"\x06\x0f:;\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    DHCP_SEND_02 = bytearray(
        b"\x01\x01\x06\x00\xff\xff\xffo\x00#\x80\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18#.9DO\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x02=\x07\x01\x18#.9DO"
        b"\x0c\x04bert\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x007\x06"
        b"\x01\x03\x06\x0f:;\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    DHCP_SEND_03 = bytearray(
        b"\x01\x01\x06\x00\xff\xff\xffo\x00#\x80\x00\n\n\n+\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\xffa$e*c\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00c\x82Sc5\x01\x02=\x07\x01\xffa$e*c\x0c\x05cl"
        b"ash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x007"
        b"\x06\x01\x03\x06\x0f:;\xff\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )

    def test_send_with_defaults(self, wiznet, wrench):
        assert len(wiz_dhcp._BUFF) == 318
        dhcp_client = wiz_dhcp.DHCP(wiznet, (4, 5, 6, 7, 8, 9))
        dhcp_client._sock = wrench.socket(type=wrench.SOCK_DGRAM)
        dhcp_client._transaction_id = 0x6FFFFFFF
        dhcp_client.send_dhcp_message(1, 23.4)
        dhcp_client._sock.send.assert_called_once_with(self.DHCP_SEND_01)
        assert len(wiz_dhcp._BUFF) == 318

    @pytest.mark.parametrize(
        "mac_address, hostname, state, time_elapsed, renew, local_ip, server_ip, result",
        (
            (
                (4, 5, 6, 7, 8, 9),
                None,
                wiz_dhcp.STATE_DHCP_DISCOVER,
                23.4,
                False,
                0,
                0,
                DHCP_SEND_01,
            ),
            (
                (24, 35, 46, 57, 68, 79),
                "bert.co.uk",
                wiz_dhcp.STATE_DHCP_REQUEST,
                35.5,
                False,
                (192, 168, 3, 4),
                (222, 123, 23, 10),
                DHCP_SEND_02,
            ),
            (
                (255, 97, 36, 101, 42, 99),
                "clash.net",
                wiz_dhcp.STATE_DHCP_REQUEST,
                35.5,
                True,
                (10, 10, 10, 43),
                (145, 66, 45, 22),
                DHCP_SEND_03,
            ),
        ),
    )
    def test_send_dhcp_message(
        self,
        wiznet,
        wrench,
        mac_address,
        hostname,
        state,
        time_elapsed,
        renew,
        local_ip,
        server_ip,
        result,
    ):
        dhcp_client = wiz_dhcp.DHCP(wiznet, mac_address, hostname=hostname)
        # Mock out socket to check what is sent
        dhcp_client._sock = wrench.socket(type=wrench.SOCK_DGRAM)
        # Set client attributes for test
        dhcp_client.local_ip = local_ip
        dhcp_client.dhcp_server_ip = server_ip
        dhcp_client._transaction_id = 0x6FFFFFFF
        # Test
        dhcp_client.send_dhcp_message(state, time_elapsed, renew=renew)
        dhcp_client._sock.send.assert_called_once_with(result)
        assert len(wiz_dhcp._BUFF) == 318
