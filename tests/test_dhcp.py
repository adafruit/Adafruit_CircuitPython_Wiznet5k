# SPDX-FileCopyrightText: 2022 Martin Stephens
#
# SPDX-License-Identifier: MIT
"""Tests to confirm that there are no changes in behaviour to public methods and functions."""
# pylint: disable=no-self-use, redefined-outer-name, protected-access, invalid-name, too-many-arguments
import pytest
from micropython import const
import dummy_dhcp_data as dhcp_data
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


@pytest.mark.skip()
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

        assert wiz_dhcp.MAGIC_COOKIE == b"c\x82Sc"
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
    def test_generate_message_with_defaults(self, wiznet, wrench):
        assert len(wiz_dhcp._BUFF) == 318
        dhcp_client = wiz_dhcp.DHCP(wiznet, (4, 5, 6, 7, 8, 9))
        dhcp_client._sock = wrench.socket(type=wrench.SOCK_DGRAM)
        dhcp_client._transaction_id = 0x6FFFFFFF
        dhcp_client._generate_dhcp_message(
            message_type=wiz_dhcp.DHCP_DISCOVER, time_elapsed=23.4
        )
        assert wiz_dhcp._BUFF == dhcp_data.DHCP_SEND_01
        assert len(wiz_dhcp._BUFF) == 318

    @pytest.mark.parametrize(
        "mac_address, hostname, msg_type, time_elapsed, renew, \
        broadcast_only, local_ip, server_ip, result",
        (
            (
                (4, 5, 6, 7, 8, 9),
                None,
                wiz_dhcp.DHCP_DISCOVER,
                23.4,
                False,
                False,
                (0, 0, 0, 0),
                (0, 0, 0, 0),
                dhcp_data.DHCP_SEND_02,
            ),
            (
                (24, 35, 46, 57, 68, 79),
                "bert.co.uk",
                wiz_dhcp.DHCP_REQUEST,
                35.5,
                True,
                True,
                (192, 168, 3, 4),
                (222, 123, 23, 10),
                dhcp_data.DHCP_SEND_03,
            ),
            (
                (255, 97, 36, 101, 42, 99),
                "clash.net",
                wiz_dhcp.DHCP_REQUEST,
                35.5,
                False,
                True,
                (10, 10, 10, 43),
                (145, 66, 45, 22),
                dhcp_data.DHCP_SEND_04,
            ),
        ),
    )
    def test_generate_dhcp_message_with_options(
        self,
        wiznet,
        mac_address,
        hostname,
        msg_type,
        time_elapsed,
        renew,
        broadcast_only,
        local_ip,
        server_ip,
        result,
    ):
        dhcp_client = wiz_dhcp.DHCP(wiznet, mac_address, hostname=hostname)
        # Set client attributes for test
        dhcp_client.local_ip = local_ip
        dhcp_client.dhcp_server_ip = server_ip
        dhcp_client._transaction_id = 0x6FFFFFFF
        # Test
        dhcp_client._generate_dhcp_message(
            message_type=msg_type,
            time_elapsed=time_elapsed,
            renew=renew,
            broadcast=broadcast_only,
        )
        assert len(wiz_dhcp._BUFF) == 318
        assert wiz_dhcp._BUFF == result


class TestParseDhcpMessage:
    @pytest.mark.parametrize(
        "xid, local_ip, msg_type, subnet, dhcp_ip, gate_ip, dns_ip, lease, t1, t2, response",
        (
            (
                0x7FFFFFFF,
                (192, 168, 5, 22),
                2,
                (192, 168, 6, 2),
                (234, 111, 222, 123),
                (121, 121, 4, 5),
                (5, 6, 7, 8),
                65792,
                2236928,
                3355392,
                dhcp_data.GOOD_DATA_01,
            ),
            (
                0x3456789A,
                (18, 36, 64, 10),
                5,
                (10, 11, 7, 222),
                (122, 78, 145, 3),
                (10, 11, 14, 15),
                (19, 17, 11, 7),
                15675,
                923456,
                43146718,
                dhcp_data.GOOD_DATA_02,
            ),
        ),
    )
    # pylint: disable=too-many-locals
    def test_parse_good_data(
        self,
        wiznet,
        xid,
        local_ip,
        msg_type,
        subnet,
        dhcp_ip,
        gate_ip,
        dns_ip,
        lease,
        t1,
        t2,
        response,
    ):
        wiz_dhcp._BUFF = response
        dhcp_client = wiz_dhcp.DHCP(wiznet, (1, 2, 3, 4, 5, 6))
        dhcp_client._transaction_id = xid
        response_type = dhcp_client._parse_dhcp_response()
        assert response_type == msg_type
        assert dhcp_client.local_ip == local_ip
        assert dhcp_client.subnet_mask == subnet
        assert dhcp_client.dhcp_server_ip == dhcp_ip
        assert dhcp_client.gateway_ip == gate_ip
        assert dhcp_client.dns_server_ip == dns_ip
        assert dhcp_client._lease_time == lease
        assert dhcp_client._t1 == t1
        assert dhcp_client._t2 == t2

    def test_parsing_failures(self, wiznet, wrench):
        # Test for bad OP code, ID mismatch, no server ID, bad Magic Cookie
        bad_data = dhcp_data.BAD_DATA
        dhcp_client = wiz_dhcp.DHCP(wiznet, (1, 2, 3, 4, 5, 6))
        dhcp_client._sock = wrench.socket(type=wrench.SOCK_DGRAM)
        dhcp_client._sock.recv.return_value = bad_data
        # Transaction ID mismatch.
        dhcp_client._transaction_id = 0x42424242
        with pytest.raises(ValueError):
            dhcp_client._parse_dhcp_response()
        # Bad OP code.
        bad_data[0] = 0
        dhcp_client._transaction_id = 0x7FFFFFFF
        dhcp_client._initial_xid = dhcp_client._transaction_id.to_bytes(4, "little")
        with pytest.raises(ValueError):
            dhcp_client._parse_dhcp_response()
        bad_data[0] = 2  # Reset to good value
        # No server ID.
        bad_data[28:34] = (0, 0, 0, 0, 0, 0)
        with pytest.raises(ValueError):
            dhcp_client._parse_dhcp_response()
        bad_data[28:34] = (1, 1, 1, 1, 1, 1)  # Reset to good value
        # Bad Magic Cookie.
        bad_data[236] = 0
        with pytest.raises(ValueError):
            dhcp_client._parse_dhcp_response()
