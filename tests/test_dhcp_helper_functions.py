# SPDX-FileCopyrightText: 2022 Martin Stephens
#
# SPDX-License-Identifier: MIT
"""Tests to confirm that there are no changes in behaviour to methods and functions.
These test are not exhaustive, but are a sanity check while making changes to the module."""
import time

# pylint: disable=no-self-use, redefined-outer-name, protected-access, invalid-name, too-many-arguments
import pytest
from freezegun import freeze_time
from micropython import const
import dhcp_dummy_data as dhcp_data
import adafruit_wiznet5k.adafruit_wiznet5k_dhcp as wiz_dhcp


@pytest.fixture
def mock_wiznet5k(mocker):
    """Mock WIZNET5K so that the DHCP class can be tested without hardware."""
    return mocker.patch("adafruit_wiznet5k.adafruit_wiznet5k.WIZNET5K", autospec=True)


@pytest.fixture
def mock_socket(mocker):
    """Mock socket module to allow test data to be read and written by the DHCP module."""
    return mocker.patch(
        "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.socket", autospec=True
    )


@pytest.fixture
def mock_dhcp(mocker, mock_wiznet5k):
    dhcp = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
    dhcp._wiz_sock = mocker.patch(
        "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.socket.socket", autospec=True
    )
    return dhcp


class TestDHCPInit:
    def test_constants(self):
        """Test all the constants in the DHCP module."""
        # DHCP State Machine
        assert wiz_dhcp.STATE_INIT == const(0x01)
        assert wiz_dhcp.STATE_SELECTING == const(0x02)
        assert wiz_dhcp.STATE_REQUESTING == const(0x03)
        assert wiz_dhcp.STATE_BOUND == const(0x04)
        assert wiz_dhcp.STATE_RENEWING == const(0x05)
        assert wiz_dhcp.STATE_REBINDING == const(0x06)

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
        assert wiz_dhcp.UNASSIGNED_IP_ADDR == (0, 0, 0, 0)

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
        assert wiz_dhcp.BUFF_LENGTH == 318
        assert wiz_dhcp._BUFF == bytearray(318)

    @pytest.mark.parametrize(
        "mac_address",
        (
            [1, 2, 3, 4, 5, 6],
            (7, 8, 9, 10, 11, 12),
            bytes([1, 2, 4, 6, 7, 8]),
        ),
    )
    def test_dhcp_setup_default(self, mocker, mock_wiznet5k, mock_socket, mac_address):
        """Test intial settings from DHCP.__init__."""
        # Test with mac address as tuple, list and bytes with default values.
        mock_randint = mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.randint", autospec=True
        )
        mock_randint.return_value = 0x1234567
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, mac_address)
        assert dhcp_client._eth == mock_wiznet5k
        assert dhcp_client._response_timeout == 30.0
        assert dhcp_client._debug is False
        assert dhcp_client._mac_address == mac_address
        mock_socket.set_interface.assert_called_once_with(mock_wiznet5k)
        assert dhcp_client._wiz_sock is None
        assert dhcp_client._dhcp_state == wiz_dhcp.STATE_INIT
        mock_randint.assert_called_once()
        assert dhcp_client._transaction_id == 0x1234567
        assert dhcp_client._start_time == 0
        assert dhcp_client.dhcp_server_ip == wiz_dhcp.BROADCAST_SERVER_ADDR
        assert dhcp_client.local_ip == wiz_dhcp.UNASSIGNED_IP_ADDR
        assert dhcp_client.gateway_ip == wiz_dhcp.UNASSIGNED_IP_ADDR
        assert dhcp_client.subnet_mask == wiz_dhcp.UNASSIGNED_IP_ADDR
        assert dhcp_client.dns_server_ip == wiz_dhcp.UNASSIGNED_IP_ADDR
        assert dhcp_client._lease_time == 0
        assert dhcp_client._t1 == 0
        assert dhcp_client._t2 == 0
        mac_string = "".join("{:02X}".format(o) for o in mac_address)
        assert dhcp_client._hostname == bytes(
            "WIZnet{}".split(".", maxsplit=1)[0].format(mac_string)[:42], "utf-8"
        )

    def test_dhcp_setup_other_args(self, mock_wiznet5k):
        """Test instantiating DHCP with none default values."""
        mac_address = (7, 8, 9, 10, 11, 12)
        dhcp_client = wiz_dhcp.DHCP(
            mock_wiznet5k,
            mac_address,
            hostname="fred.com",
            response_timeout=25.0,
            debug=True,
        )

        assert dhcp_client._response_timeout == 25.0
        assert dhcp_client._debug is True
        mac_string = "".join("{:02X}".format(o) for o in mac_address)
        assert dhcp_client._hostname == bytes(
            "fred.com".split(".", maxsplit=1)[0].format(mac_string)[:42], "utf-8"
        )


@freeze_time("2022-10-20")
class TestSendDHCPMessage:
    def test_generate_message_with_default_attributes(self, mock_wiznet5k, mock_socket):
        """Test the _generate_message function with default values."""
        assert len(wiz_dhcp._BUFF) == 318
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (4, 5, 6, 7, 8, 9))
        dhcp_client._wiz_sock = mock_socket.socket(type=mock_socket.SOCK_DGRAM)
        dhcp_client._transaction_id = 0x6FFFFFFF
        dhcp_client._start_time = time.monotonic() - 23.4
        dhcp_client._generate_dhcp_message(message_type=wiz_dhcp.DHCP_DISCOVER)
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
                wiz_dhcp.DHCP_DISCOVER,
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
                wiz_dhcp.DHCP_DISCOVER,
                35.5,
                False,
                True,
                (10, 10, 10, 43),
                (145, 66, 45, 22),
                dhcp_data.DHCP_SEND_04,
            ),
        ),
    )
    def test_generate_dhcp_message_discover_with_non_defaults(
        self,
        mock_wiznet5k,
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
        """Test the generate_dhcp_message function with different message types and
        none default attributes."""
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, mac_address, hostname=hostname)
        # Set client attributes for test
        dhcp_client.local_ip = local_ip
        dhcp_client.dhcp_server_ip = server_ip
        dhcp_client._transaction_id = 0x6FFFFFFF
        dhcp_client._start_time = time.monotonic() - time_elapsed
        # Test
        dhcp_client._generate_dhcp_message(
            message_type=msg_type,
            renew=renew,
            broadcast=broadcast_only,
        )
        assert len(wiz_dhcp._BUFF) == 318
        assert wiz_dhcp._BUFF == result

    @pytest.mark.parametrize(
        "mac_address, hostname, msg_type, time_elapsed, renew, \
        broadcast_only, local_ip, server_ip, result",
        (
            (
                (255, 97, 36, 101, 42, 99),
                "helicopter.org",
                wiz_dhcp.DHCP_REQUEST,
                16.3,
                False,
                True,
                (10, 10, 10, 43),
                (145, 66, 45, 22),
                dhcp_data.DHCP_SEND_05,
            ),
            (
                (75, 63, 166, 4, 200, 101),
                None,
                wiz_dhcp.DHCP_REQUEST,
                72.4,
                False,
                True,
                (100, 101, 102, 4),
                (245, 166, 5, 11),
                dhcp_data.DHCP_SEND_06,
            ),
        ),
    )
    def test_generate_dhcp_message_with_request_options(
        self,
        mock_wiznet5k,
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
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, mac_address, hostname=hostname)
        # Set client attributes for test
        dhcp_client.local_ip = local_ip
        dhcp_client.dhcp_server_ip = server_ip
        dhcp_client._transaction_id = 0x6FFFFFFF
        dhcp_client._start_time = time.monotonic() - time_elapsed
        # Test
        dhcp_client._generate_dhcp_message(
            message_type=msg_type, renew=renew, broadcast=broadcast_only
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
        mock_wiznet5k,
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
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
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

    def test_parsing_failures(self, mock_wiznet5k, mock_socket):
        # Test for bad OP code, ID mismatch, no server ID, bad Magic Cookie
        bad_data = dhcp_data.BAD_DATA
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        dhcp_client._wiz_sock = mock_socket.socket(type=mock_socket.SOCK_DGRAM)
        dhcp_client._wiz_sock.recv.return_value = bad_data
        # Transaction ID mismatch.
        dhcp_client._transaction_id = 0x42424242
        with pytest.raises(ValueError):
            dhcp_client._parse_dhcp_response()
        # Bad OP code.
        bad_data[0] = 0
        dhcp_client._transaction_id = 0x7FFFFFFF
        with pytest.raises(ValueError):
            dhcp_client._parse_dhcp_response()
        bad_data[0] = 2  # Reset to good value
        # No server ID.
        bad_data[28:34] = (0, 0, 0, 0, 0, 0)
        with pytest.raises(ValueError):
            dhcp_client._parse_dhcp_response()
        bad_data[28:34] = (1, 1, 1, 1, 1, 1)  # Reset to a good value for next test.
        # Bad Magic Cookie.
        bad_data[236] = 0
        with pytest.raises(ValueError):
            dhcp_client._parse_dhcp_response()


class TestResetDsmReset:
    def test_socket_reset(self, mock_wiznet5k, mock_socket):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))

        dhcp_client._dsm_reset()
        assert dhcp_client._wiz_sock is None

        dhcp_client._wiz_sock = mock_socket.socket(type=mock_socket.SOCK_DGRAM)

        dhcp_client._dsm_reset()
        assert dhcp_client._wiz_sock is None

    @freeze_time("2022-11-10")
    def test_reset_dsm_parameters(self, mock_wiznet5k):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        dhcp_client.dhcp_server_ip = (1, 2, 3, 4)
        dhcp_client.local_ip = (2, 3, 4, 5)
        dhcp_client.subnet_mask = (3, 4, 5, 6)
        dhcp_client.dns_server_ip = (7, 8, 8, 10)
        dhcp_client._renew = True
        dhcp_client._retries = 4
        dhcp_client._transaction_id = 3
        dhcp_client._start_time = None

        dhcp_client._dsm_reset()

        assert dhcp_client.dhcp_server_ip == wiz_dhcp.BROADCAST_SERVER_ADDR
        assert dhcp_client.local_ip == wiz_dhcp.UNASSIGNED_IP_ADDR
        assert dhcp_client.subnet_mask == wiz_dhcp.UNASSIGNED_IP_ADDR
        assert dhcp_client.dns_server_ip == wiz_dhcp.UNASSIGNED_IP_ADDR
        assert dhcp_client._renew is False
        assert dhcp_client._retries == 0
        assert dhcp_client._transaction_id == 4
        assert dhcp_client._start_time == time.monotonic()


class TestSocketRelease:
    def test_socket_set_to_none(self, mock_wiznet5k, mock_socket):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        dhcp_client._socket_release()
        assert dhcp_client._wiz_sock is None

        dhcp_client._wiz_sock = mock_socket.socket(type=mock_socket.SOCK_DGRAM)
        dhcp_client._socket_release()
        assert dhcp_client._wiz_sock is None


class TestSmallHelperFunctions:
    def test_increment_transaction_id(self, mock_wiznet5k):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        # Test that transaction_id increments.
        dhcp_client._transaction_id = 4
        dhcp_client._increment_transaction_id()
        assert dhcp_client._transaction_id == 5
        # Test that transaction_id rolls over from 0x7fffffff to zero
        dhcp_client._transaction_id = 0x7FFFFFFF
        dhcp_client._increment_transaction_id()
        assert dhcp_client._transaction_id == 0

    @freeze_time("2022-10-10")
    @pytest.mark.parametrize("rand_int", (-1, 0, 1))
    def test_next_retry_time_default_attrs(self, mocker, mock_wiznet5k, rand_int):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.randint",
            autospec=True,
            return_value=rand_int,
        )
        now = time.monotonic()
        for retry in range(3):
            dhcp_client._retries = retry
            assert dhcp_client._next_retry_time_and_retry() == int(
                2**retry * 4 + rand_int + now
            )
            assert dhcp_client._retries == retry + 1

    @freeze_time("2022-10-10")
    @pytest.mark.parametrize("interval", (2, 7, 10))
    def test_next_retry_time_optional_attrs(self, mocker, mock_wiznet5k, interval):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.randint",
            autospec=True,
            return_value=0,
        )
        now = time.monotonic()
        for retry in range(3):
            dhcp_client._retries = retry
            assert dhcp_client._next_retry_time_and_retry(interval=interval) == int(
                2**retry * interval + now
            )

    def test_setup_socket_with_no_error(self, mock_wiznet5k, mock_socket):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        dhcp_client._dhcp_connection_setup()
        mock_socket.socket.assert_called_once()
        dhcp_client._wiz_sock.settimeout.assert_called_once_with(
            dhcp_client._response_timeout
        )
        dhcp_client._wiz_sock.bind.assert_called_once_with((None, 68))
        dhcp_client._wiz_sock.connect.assert_called_once_with(
            (wiz_dhcp.BROADCAST_SERVER_ADDR, 67)
        )

    def test_setup_socket_with_error_then_ok_blocking(
        self, mocker, mock_wiznet5k, mock_socket
    ):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        dhcp_client._blocking = True
        mock_socket.socket.side_effect = [RuntimeError, mocker.Mock()]
        assert dhcp_client._dhcp_connection_setup() is None
        # Function should ignore the error, then set the socket and call settimeout
        dhcp_client._wiz_sock.settimeout.assert_called_once_with(
            dhcp_client._response_timeout
        )

    def test_setup_socket_with_error_then_ok_nonblocking(
        self, mocker, mock_wiznet5k, mock_socket
    ):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        dhcp_client._blocking = False
        mock_socket.socket.side_effect = [RuntimeError, mocker.Mock()]
        assert dhcp_client._dhcp_connection_setup() is None
        # Function should ignore the error, then return, _sock is None
        assert dhcp_client._wiz_sock is None

    @freeze_time("2022-10-02", auto_tick_seconds=2)
    def test_setup_socket_with_error_then_timeout(self, mock_wiznet5k, mock_socket):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        dhcp_client._blocking = True
        mock_socket.socket.side_effect = [RuntimeError, RuntimeError]
        # Function should timeout, raise an exception and not set a socket
        with pytest.raises(TimeoutError):
            dhcp_client._dhcp_connection_setup()
        assert dhcp_client._wiz_sock is None

    @pytest.mark.parametrize(
        "next_state, msg_type, retries",
        (
            (wiz_dhcp.STATE_SELECTING, wiz_dhcp.DHCP_DISCOVER, 2),
            (wiz_dhcp.STATE_REQUESTING, wiz_dhcp.DHCP_REQUEST, 3),
        ),
    )
    def test_send_message_set_next_state_good_data(
        self, mocker, mock_wiznet5k, next_state, msg_type, retries
    ):
        mocker.patch.object(wiz_dhcp.DHCP, "_generate_dhcp_message")
        mocker.patch.object(wiz_dhcp.DHCP, "_next_retry_time_and_retry")
        message = bytearray(b"HelloWorld")
        wiz_dhcp._BUFF = bytearray(message)
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        dhcp_client._wiz_sock = mocker.Mock()
        dhcp_client._send_message_set_next_state(
            next_state=next_state, max_retries=retries
        )
        assert dhcp_client._retries == 0
        assert dhcp_client._max_retries == retries
        assert dhcp_client._dhcp_state == next_state
        dhcp_client._generate_dhcp_message.assert_called_once_with(
            message_type=msg_type
        )
        dhcp_client._wiz_sock.send.assert_called_once_with(message)
        dhcp_client._next_retry_time_and_retry.assert_called_once()

    @pytest.mark.parametrize(
        "next_state",
        (
            wiz_dhcp.STATE_INIT,
            wiz_dhcp.STATE_REBINDING,
            wiz_dhcp.STATE_RENEWING,
            wiz_dhcp.STATE_BOUND,
        ),
    )
    def test_send_message_set_next_state_bad_state(self, mock_wiznet5k, next_state):
        # Test with all states that should not call this function.
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, (1, 2, 3, 4, 5, 6))
        with pytest.raises(ValueError):
            dhcp_client._send_message_set_next_state(
                next_state=next_state, max_retries=4
            )


class TestReceiveResponse:

    minimum_packet_length = 236

    @freeze_time("2022-10-10")
    @pytest.mark.parametrize(
        "bytes_on_socket", (wiz_dhcp.BUFF_LENGTH, minimum_packet_length + 1)
    )
    def test_receive_response_good_data(self, mock_dhcp, bytes_on_socket):
        mock_dhcp._next_resend = time.monotonic() + 15
        mock_dhcp._wiz_sock.recv.return_value = bytes([0] * bytes_on_socket)
        response = mock_dhcp._receive_dhcp_response()
        assert response == bytes_on_socket
        assert response > 236

    @freeze_time("2022-10-10")
    @pytest.mark.parametrize(
        "bytes_on_socket", ([bytes([0] * minimum_packet_length), bytes([0] * 1)],)
    )
    def test_receive_response_short_packet(self, mock_dhcp, bytes_on_socket):
        mock_dhcp._next_resend = time.monotonic() + 15
        mock_dhcp._wiz_sock.recv.side_effect = bytes_on_socket
        assert mock_dhcp._receive_dhcp_response() > 236

    @freeze_time("2022-10-10", auto_tick_seconds=5)
    def test_timeout(self, mock_dhcp):
        mock_dhcp._next_resend = time.monotonic() + 15
        mock_dhcp._wiz_sock.recv.side_effect = [
            b"",
            b"",
            b"",
            b"",
            b"",
            bytes([0] * 240),
        ]
        assert mock_dhcp._receive_dhcp_response() == 0

    @freeze_time("2022-10-10")
    @pytest.mark.parametrize("bytes_returned", ([240], [230, 30]))
    def test_buffer_handling(self, mock_dhcp, bytes_returned):
        total_bytes = sum(bytes_returned)
        mock_dhcp._next_resend = time.monotonic() + 15
        wiz_dhcp._BUFF = bytearray([1] * wiz_dhcp.BUFF_LENGTH)
        expected_result = bytearray([2] * total_bytes) + (
            bytes([0] * (wiz_dhcp.BUFF_LENGTH - total_bytes))
        )
        mock_dhcp._wiz_sock.recv.side_effect = (bytes([2] * x) for x in bytes_returned)
        assert mock_dhcp._receive_dhcp_response() == total_bytes
        assert wiz_dhcp._BUFF == expected_result

    @freeze_time("2022-10-10")
    def test_buffer_does_not_overrun(self, mocker, mock_dhcp):
        mock_dhcp._next_resend = time.monotonic() + 15
        mock_dhcp._wiz_sock.recv.return_value = bytes([2] * wiz_dhcp.BUFF_LENGTH)
        mock_dhcp._receive_dhcp_response()
        mock_dhcp._wiz_sock.recv.assert_called_once_with(wiz_dhcp.BUFF_LENGTH)
        mock_dhcp._wiz_sock.recv.reset_mock()
        mock_dhcp._wiz_sock.recv.side_effect = [bytes([2] * 200), bytes([2] * 118)]
        mock_dhcp._receive_dhcp_response()
        assert mock_dhcp._wiz_sock.recv.call_count == 2
        assert mock_dhcp._wiz_sock.recv.call_args_list == [
            mocker.call(318),
            mocker.call(118),
        ]
