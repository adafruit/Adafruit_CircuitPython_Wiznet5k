# SPDX-FileCopyrightText: 2022 Martin Stephens
#
# SPDX-License-Identifier: MIT
"""Tests to confirm that there are no changes in behaviour to methods and functions.
These test are not exhaustive, but are a sanity check while making changes to the module."""
import time

# pylint: disable=no-self-use, redefined-outer-name, protected-access, invalid-name, too-many-arguments
import pytest
from freezegun import freeze_time

# from micropython import const
import dhcp_dummy_data as dhcp_data
import adafruit_wiznet5k.adafruit_wiznet5k_dhcp as wiz_dhcp


@pytest.fixture
def mock_wiznet5k(mocker):
    """Mock WIZNET5K so that the DHCP class can be tested without hardware."""
    return mocker.patch("adafruit_wiznet5k.adafruit_wiznet5k.WIZNET5K", autospec=True)


@pytest.fixture
def mock_dhcp(mock_wiznet5k):
    dhcp = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
    return dhcp


class TestDHCPInit:
    def test_constants(self):
        """Test all the constants in the DHCP module."""

    @pytest.mark.parametrize(
        "mac_address",
        (
            bytes((1, 2, 3, 4, 5, 6)),
            bytes((7, 8, 9, 10, 11, 12)),
            bytes((1, 2, 4, 6, 7, 8)),
        ),
    )
    def test_dhcp_setup_default(self, mocker, mock_wiznet5k, mac_address):
        """Test intial settings from DHCP.__init__."""
        # Test with mac address as tuple, list and bytes with default values.
        mock_randint = mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.randint", autospec=True
        )
        mock_randint.return_value = 0x1234567
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, mac_address)
        assert dhcp_client._eth == mock_wiznet5k
        assert dhcp_client._debug is False
        assert dhcp_client._mac_address == mac_address
        assert dhcp_client._wiz_sock is None
        assert dhcp_client._dhcp_state == wiz_dhcp._STATE_INIT
        mock_randint.assert_called_once()
        assert dhcp_client._transaction_id == 0x1234567
        assert dhcp_client._start_time == 0
        assert dhcp_client.dhcp_server_ip == wiz_dhcp._BROADCAST_SERVER_ADDR
        assert dhcp_client.local_ip == wiz_dhcp._UNASSIGNED_IP_ADDR
        assert dhcp_client.gateway_ip == wiz_dhcp._UNASSIGNED_IP_ADDR
        assert dhcp_client.subnet_mask == wiz_dhcp._UNASSIGNED_IP_ADDR
        assert dhcp_client.dns_server_ip == wiz_dhcp._UNASSIGNED_IP_ADDR
        assert dhcp_client._lease == 0
        assert dhcp_client._t1 == 0
        assert dhcp_client._t2 == 0
        mac_string = "".join("{:02X}".format(o) for o in mac_address)
        assert dhcp_client._hostname == bytes(
            "WIZnet{}".split(".", maxsplit=1)[0].format(mac_string)[:42], "utf-8"
        )

    def test_dhcp_setup_other_args(self, mock_wiznet5k):
        """Test instantiating DHCP with none default values."""
        mac_address = bytes((7, 8, 9, 10, 11, 12))
        dhcp_client = wiz_dhcp.DHCP(
            mock_wiznet5k,
            mac_address,
            hostname="fred.com",
            debug=True,
        )

        assert dhcp_client._debug is True
        mac_string = "".join("{:02X}".format(o) for o in mac_address)
        assert dhcp_client._hostname == bytes(
            "fred.com".split(".", maxsplit=1)[0].format(mac_string)[:42], "utf-8"
        )

    @pytest.mark.parametrize(
        "mac_address, error_type",
        (
            ("fdsafa", TypeError),
            ((1, 2, 3, 4, 5, 6), TypeError),
            (b"12345", ValueError),
            (b"1234567", ValueError),
        ),
    )
    def test_mac_address_checking(self, mock_wiznet5k, mac_address, error_type):
        with pytest.raises(error_type):
            wiz_dhcp.DHCP(
                mock_wiznet5k,
                mac_address,
                hostname="fred.com",
                debug=True,
            )


@freeze_time("2022-10-20")
class TestSendDHCPMessage:
    def test_generate_message_with_default_attributes(self, mock_wiznet5k):
        """Test the _generate_message function with default values."""
        assert len(wiz_dhcp._BUFF) == 512
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((4, 5, 6, 7, 8, 9)))
        dhcp_client._transaction_id = 0x6FFFFFFF
        dhcp_client._start_time = time.monotonic() - 23.4
        dhcp_client._generate_dhcp_message(message_type=wiz_dhcp._DHCP_DISCOVER)
        assert wiz_dhcp._BUFF == dhcp_data.DHCP_SEND_01
        assert len(wiz_dhcp._BUFF) == 512

    @pytest.mark.parametrize(
        "mac_address, hostname, msg_type, time_elapsed, renew, \
        broadcast_only, local_ip, server_ip, result",
        (
            (
                bytes((4, 5, 6, 7, 8, 9)),
                None,
                wiz_dhcp._DHCP_DISCOVER,
                23.4,
                False,
                False,
                b"\x00\x00\x00\x00",
                b"\x00\x00\x00\x00",
                dhcp_data.DHCP_SEND_02,
            ),
            (
                bytes((24, 35, 46, 57, 68, 79)),
                "bert.co.uk",
                wiz_dhcp._DHCP_DISCOVER,
                35.5,
                True,
                True,
                b"\xc0\xa8\x03\x04",
                b"\xe0\x7b\x17\x0a",
                dhcp_data.DHCP_SEND_03,
            ),
            (
                bytes((255, 97, 36, 101, 42, 99)),
                "clash.net",
                wiz_dhcp._DHCP_DISCOVER,
                35.5,
                False,
                True,
                b"\x0a\x0a\x0a\x2b",
                b"\x91\x42\x2d\x16",
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
        dhcp_client._renew = renew
        # Test
        dhcp_client._generate_dhcp_message(
            message_type=msg_type,
            broadcast=broadcast_only,
        )
        assert len(wiz_dhcp._BUFF) == 512
        assert wiz_dhcp._BUFF == result

    @pytest.mark.parametrize(
        "mac_address, hostname, msg_type, time_elapsed,  \
        broadcast_only, local_ip, server_ip, result",
        (
            (
                bytes((255, 97, 36, 101, 42, 99)),
                "helicopter.org",
                wiz_dhcp._DHCP_REQUEST,
                16.3,
                True,
                bytes((10, 10, 10, 43)),
                bytes((145, 66, 45, 22)),
                dhcp_data.DHCP_SEND_05,
            ),
            (
                bytes((75, 63, 166, 4, 200, 101)),
                None,
                wiz_dhcp._DHCP_REQUEST,
                72.4,
                True,
                bytes((100, 101, 102, 4)),
                bytes((245, 166, 5, 11)),
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
            message_type=msg_type, broadcast=broadcast_only
        )
        assert len(wiz_dhcp._BUFF) == 512
        assert wiz_dhcp._BUFF == result


class TestParseDhcpMessage:
    @pytest.mark.parametrize(
        "xid, local_ip, msg_type, subnet, dhcp_ip, gate_ip, dns_ip, lease, t1, t2, response",
        (
            (
                0x7FFFFFFF,
                b"\xc0\xa8\x05\x16",
                2,
                b"\xc0\xa8\x06\x02",
                b"\xeao\xde{",
                b"yy\x04\x05",
                b"\x05\x06\x07\x08",
                65792,
                2236928,
                3355392,
                dhcp_data.GOOD_DATA_01,
            ),
            (
                0x3456789A,
                b"\x12$@\n",
                5,
                b"\n\x0b\x07\xde",
                b"zN\x91\x03",
                b"\n\x0b\x0e\x0f",
                b"\x13\x11\x0b\x07",
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
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        dhcp_client._transaction_id = xid
        response_type = dhcp_client._parse_dhcp_response()
        assert response_type == msg_type
        assert dhcp_client.local_ip == local_ip
        assert dhcp_client.subnet_mask == subnet
        assert dhcp_client.dhcp_server_ip == dhcp_ip
        assert dhcp_client.gateway_ip == gate_ip
        assert dhcp_client.dns_server_ip == dns_ip
        assert dhcp_client._lease == lease
        assert dhcp_client._t1 == t1
        assert dhcp_client._t2 == t2

    def test_parsing_failures(self, mock_wiznet5k):
        # Test for bad OP code, ID mismatch, no server ID, bad Magic Cookie
        bad_data = dhcp_data.BAD_DATA
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        dhcp_client._eth._read_socket_register.return_value = (len(bad_data), bad_data)
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


@freeze_time("2022-11-10")
def test_dsm_reset(mocker, mock_wiznet5k):
    dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
    mocker.patch.object(dhcp_client, "_dhcp_connection_setup", autospec=True)
    mocker.patch.object(dhcp_client, "_socket_release", autospec=True)
    dhcp_client.dhcp_server_ip = bytes((1, 2, 3, 4))
    dhcp_client.local_ip = bytes((2, 3, 4, 5))
    dhcp_client.subnet_mask = bytes((3, 4, 5, 6))
    dhcp_client.dns_server_ip = bytes((7, 8, 8, 10))
    dhcp_client._renew = True
    dhcp_client._retries = 4
    dhcp_client._transaction_id = 3
    dhcp_client._start_time = None

    dhcp_client._dsm_reset()
    dhcp_client._dhcp_connection_setup.assert_called_once()
    dhcp_client._socket_release.assert_called_once()
    assert mock_wiznet5k.ifconfig == (
        wiz_dhcp._UNASSIGNED_IP_ADDR,
        wiz_dhcp._UNASSIGNED_IP_ADDR,
        wiz_dhcp._UNASSIGNED_IP_ADDR,
        wiz_dhcp._UNASSIGNED_IP_ADDR,
    )
    assert dhcp_client.dhcp_server_ip == wiz_dhcp._BROADCAST_SERVER_ADDR
    assert dhcp_client.local_ip == wiz_dhcp._UNASSIGNED_IP_ADDR
    assert dhcp_client.subnet_mask == wiz_dhcp._UNASSIGNED_IP_ADDR
    assert dhcp_client.dns_server_ip == wiz_dhcp._UNASSIGNED_IP_ADDR
    assert dhcp_client._renew is None
    assert dhcp_client._transaction_id == 4
    assert dhcp_client._start_time == time.monotonic()


class TestSocketRelease:
    def test_socket_set_to_none(self, mock_wiznet5k):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        dhcp_client._socket_release()
        assert dhcp_client._wiz_sock is None

        dhcp_client._wiz_sock = 2
        dhcp_client._socket_release()
        assert dhcp_client._wiz_sock is None


class TestSmallHelperFunctions:
    def test_increment_transaction_id(self, mock_wiznet5k):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
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
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.randint",
            autospec=True,
            return_value=rand_int,
        )
        now = time.monotonic()
        for retry in range(3):
            assert dhcp_client._next_retry_time(attempt=retry) == int(
                2**retry * 4 + rand_int + now
            )

    @freeze_time("2022-10-10")
    @pytest.mark.parametrize("interval", (2, 7, 10))
    def test_next_retry_time_optional_attrs(self, mocker, mock_wiznet5k, interval):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.randint",
            autospec=True,
            return_value=0,
        )
        now = time.monotonic()
        for retry in range(3):
            assert dhcp_client._next_retry_time(
                attempt=retry, interval=interval
            ) == int(2**retry * interval + now)

    @freeze_time("2022-7-6")
    def test_setup_socket_with_no_error(self, mocker, mock_wiznet5k):
        mocker.patch.object(mock_wiznet5k, "get_socket", return_value=2)
        mocker.patch.object(mock_wiznet5k, "read_snsr", return_value=0x22)
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        dhcp_client._dhcp_connection_setup()
        mock_wiznet5k.get_socket.assert_called_once()
        mock_wiznet5k.write_snmr.assert_called_once_with(2, 0x02)
        mock_wiznet5k.write_sock_port(2, 68)
        mock_wiznet5k.write_sncr(2, 0x01)
        mock_wiznet5k.write_sndport.assert_called_once_with(
            2, wiz_dhcp._DHCP_SERVER_PORT
        )
        assert dhcp_client._wiz_sock == 2

    @freeze_time("2022-7-6", auto_tick_seconds=2)
    def test_setup_socket_with_timeout_on_get_socket(self, mocker, mock_wiznet5k):
        mocker.patch.object(mock_wiznet5k, "get_socket", return_value=0xFF)
        mocker.patch.object(mock_wiznet5k, "read_snsr", return_value=b"\x22")
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        with pytest.raises(RuntimeError):
            dhcp_client._dhcp_connection_setup()
        assert dhcp_client._wiz_sock is None

    @freeze_time("2022-7-6", auto_tick_seconds=2)
    def test_setup_socket_with_timeout_on_socket_is_udp(self, mocker, mock_wiznet5k):
        mocker.patch.object(mock_wiznet5k, "get_socket", return_value=2)
        mocker.patch.object(mock_wiznet5k, "read_snsr", return_value=0x21)
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        with pytest.raises(RuntimeError):
            dhcp_client._dhcp_connection_setup()
        assert dhcp_client._wiz_sock is None


class TestHandleDhcpMessage:
    @pytest.mark.parametrize(
        "fsm_state, msg_in",
        (
            (wiz_dhcp._STATE_SELECTING, wiz_dhcp._DHCP_DISCOVER),
            (wiz_dhcp._STATE_REQUESTING, wiz_dhcp._DHCP_REQUEST),
        ),
    )
    @freeze_time("2022-5-5")
    def test_good_data(self, mocker, mock_wiznet5k, fsm_state, msg_in):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        # Mock out methods to allow _handle_dhcp_message to run.
        mocker.patch.object(
            dhcp_client, "_generate_dhcp_message", autospec=True, return_value=300
        )
        mocker.patch.object(dhcp_client, "_process_messaging_states", autospec=True)
        mocker.patch.object(
            dhcp_client, "_receive_dhcp_response", autospec=True, return_value=300
        )
        # Non zero value is a good message for _handle_dhcp_message.
        mocker.patch.object(
            dhcp_client, "_parse_dhcp_response", autospec=True, return_value=0x01
        )
        mocker.patch.object(
            dhcp_client,
            "_next_retry_time",
            autospec=True,
            return_value=time.monotonic() + 5,
        )
        # Set initial FSM state.
        dhcp_client._wiz_sock = 3
        dhcp_client._dhcp_state = fsm_state
        dhcp_client._blocking = True
        dhcp_client._renew = False
        # Test.
        assert dhcp_client._handle_dhcp_message() == 1
        # Confirm that the msg_type sent matches the FSM state.
        dhcp_client._generate_dhcp_message.assert_called_once_with(message_type=msg_in)
        dhcp_client._eth.write_sndipr.assert_called_once_with(
            3, dhcp_client.dhcp_server_ip
        )
        dhcp_client._eth.write_sndport.assert_called_once_with(
            dhcp_client._wiz_sock, wiz_dhcp._DHCP_SERVER_PORT
        )
        dhcp_client._eth.socket_write.assert_called_once_with(3, wiz_dhcp._BUFF[:300])
        dhcp_client._next_retry_time.assert_called_once_with(attempt=0)
        dhcp_client._receive_dhcp_response.assert_called_once_with(time.monotonic() + 5)
        # If the initial message was good, receive is only called once.
        dhcp_client._parse_dhcp_response.assert_called_once()

    @freeze_time("2022-5-5", auto_tick_seconds=1)
    def test_timeout_blocking_no_response(self, mocker, mock_wiznet5k):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        # Mock out methods to allow _handle_dhcp_message to run.
        mocker.patch.object(
            dhcp_client, "_generate_dhcp_message", autospec=True, return_value=300
        )
        mocker.patch.object(dhcp_client, "_process_messaging_states", autospec=True)
        # No message bytes returned, so the handler should loop.
        mocker.patch.object(
            dhcp_client, "_receive_dhcp_response", autospec=True, return_value=0
        )
        mocker.patch.object(
            dhcp_client, "_parse_dhcp_response", autospec=True, side_effect=[ValueError]
        )
        mocker.patch.object(
            dhcp_client,
            "_next_retry_time",
            autospec=True,
            return_value=time.monotonic() + 5,
        )
        # Set initial FSM state.
        dhcp_client._wiz_sock = 3
        dhcp_client._dhcp_state = wiz_dhcp._STATE_REQUESTING
        dhcp_client._blocking = True
        dhcp_client._renew = False
        # Test that a TimeoutError is raised.
        with pytest.raises(TimeoutError):
            dhcp_client._handle_dhcp_message()
        # Confirm that _receive_dhcp_response is called repeatedly.
        assert dhcp_client._receive_dhcp_response.call_count == 4
        # Check that message parsing not called.
        dhcp_client._parse_dhcp_response.assert_not_called()

    @freeze_time("2022-5-5", auto_tick_seconds=1)
    def test_timeout_blocking_bad_message(self, mocker, mock_wiznet5k):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        # Mock out methods to allow _handle_dhcp_message to run.
        mocker.patch.object(
            dhcp_client, "_generate_dhcp_message", autospec=True, return_value=300
        )
        # Return False to model a bad message type, which should loop.
        mocker.patch.object(
            dhcp_client, "_process_messaging_states", autospec=True, return_value=False
        )
        mocker.patch.object(
            dhcp_client, "_receive_dhcp_response", autospec=True, return_value=300
        )
        mocker.patch.object(
            dhcp_client, "_parse_dhcp_response", autospec=True, side_effect=ValueError
        )
        mocker.patch.object(
            dhcp_client,
            "_next_retry_time",
            autospec=True,
            return_value=time.monotonic() + 5,
        )
        # Set initial FSM state.
        dhcp_client._wiz_sock = 3
        dhcp_client._dhcp_state = wiz_dhcp._STATE_REQUESTING
        dhcp_client._blocking = True
        dhcp_client._renew = False
        # Test that a TimeoutError is raised.
        with pytest.raises(TimeoutError):
            dhcp_client._handle_dhcp_message()
        # Confirm that processing methods are called repeatedly.
        assert dhcp_client._receive_dhcp_response.call_count == 4
        assert dhcp_client._parse_dhcp_response.call_count == 4

    @freeze_time("2022-5-5")
    @pytest.mark.parametrize(
        "renew, blocking", (("renew", False), ("renew", True), (None, False))
    )
    def test_no_response_non_blocking_renewing(
        self, mocker, mock_wiznet5k, renew, blocking
    ):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        # Mock out methods to allow _handle_dhcp_message to run.
        mocker.patch.object(
            dhcp_client, "_generate_dhcp_message", autospec=True, return_value=300
        )
        mocker.patch.object(dhcp_client, "_process_messaging_states", autospec=True)
        # No message bytes returned, so the handler do nothing and return.
        mocker.patch.object(
            dhcp_client, "_receive_dhcp_response", autospec=True, return_value=0
        )
        mocker.patch.object(
            dhcp_client, "_parse_dhcp_response", autospec=True, return_value=0x00
        )
        mocker.patch.object(
            dhcp_client,
            "_next_retry_time",
            autospec=True,
            return_value=time.monotonic() + 5,
        )
        # Set initial FSM state.
        dhcp_client._wiz_sock = 3
        dhcp_client._dhcp_state = wiz_dhcp._STATE_REQUESTING
        # Combinations of renew and blocking that will not loop.
        dhcp_client._blocking = blocking
        dhcp_client._renew = renew
        # Test.
        assert dhcp_client._handle_dhcp_message() == 0
        dhcp_client._next_retry_time.assert_called_once_with(attempt=0)
        dhcp_client._receive_dhcp_response.assert_called_once_with(time.monotonic() + 5)
        # No bytes returned so don't call parse or process message.
        dhcp_client._parse_dhcp_response.assert_not_called()

    @freeze_time("2022-5-5")
    @pytest.mark.parametrize(
        "renew, blocking", (("renew", False), ("renew", True), (None, False))
    )
    def test_bad_message_non_blocking_renewing(
        self, mocker, mock_wiznet5k, renew, blocking
    ):
        dhcp_client = wiz_dhcp.DHCP(mock_wiznet5k, bytes((1, 2, 3, 4, 5, 6)))
        # Mock out methods to allow _handle_dhcp_message to run.
        mocker.patch.object(
            dhcp_client, "_generate_dhcp_message", autospec=True, return_value=300
        )
        # Bad message so check that the handler does not loop.
        mocker.patch.object(dhcp_client, "_process_messaging_states", autospec=False)
        mocker.patch.object(
            dhcp_client, "_receive_dhcp_response", autospec=True, return_value=300
        )
        mocker.patch.object(
            dhcp_client, "_parse_dhcp_response", autospec=True, side_effect=ValueError
        )
        mocker.patch.object(
            dhcp_client,
            "_next_retry_time",
            autospec=True,
            return_value=time.monotonic() + 5,
        )
        # Set initial FSM state.
        dhcp_client._wiz_sock = 3
        dhcp_client._dhcp_state = wiz_dhcp._STATE_REQUESTING
        # Combinations of renew and blocking that will not loop.
        dhcp_client._blocking = blocking
        dhcp_client._renew = renew
        # Test.
        assert dhcp_client._handle_dhcp_message() == 0
        dhcp_client._next_retry_time.assert_called_once_with(attempt=0)
        dhcp_client._receive_dhcp_response.assert_called_once_with(time.monotonic() + 5)
        # Bad message returned so call parse and process message.
        dhcp_client._parse_dhcp_response.assert_called_once()


class TestReceiveResponse:
    minimum_packet_length = 236

    @freeze_time("2022-10-10")
    @pytest.mark.parametrize(
        "bytes_on_socket", (wiz_dhcp._BUFF_LENGTH, minimum_packet_length + 1)
    )
    def test_receive_response_good_data(self, mock_dhcp, bytes_on_socket):
        mock_dhcp._eth.read_udp.return_value = (
            bytes_on_socket,
            bytes([0] * bytes_on_socket),
        )
        response = mock_dhcp._receive_dhcp_response(time.monotonic() + 15)
        assert response == bytes_on_socket
        assert response > 236

    # @freeze_time("2022-10-10")
    # def test_receive_response_short_packet(self, mock_dhcp):
    #     mock_dhcp._eth.read_udp.side_effect = [
    #         (236, bytes([0] * 236)),
    #         (1, bytes([0] * 1)),
    #     ]
    #     assert mock_dhcp._receive_dhcp_response(time.monotonic() + 15) > 236

    @freeze_time("2022-10-10", auto_tick_seconds=5)
    def test_timeout(self, mock_dhcp):
        mock_dhcp._next_resend = time.monotonic() + 15
        mock_dhcp._eth.read_udp.side_effect = [
            (0, b""),
            (0, b""),
            (0, b""),
            (0, b""),
            (0, b""),
            bytes([0] * 240),
        ]
        assert mock_dhcp._receive_dhcp_response(time.monotonic() + 15) == 0

    @freeze_time("2022-10-10")
    @pytest.mark.parametrize("bytes_returned", ([240], [230, 30]))
    def test_buffer_handling(self, mock_dhcp, bytes_returned):
        total_bytes = sum(bytes_returned)
        mock_dhcp._next_resend = time.monotonic() + 15
        wiz_dhcp._BUFF = bytearray([1] * wiz_dhcp._BUFF_LENGTH)
        expected_result = bytearray([2] * total_bytes) + (
            bytes([0] * (wiz_dhcp._BUFF_LENGTH - total_bytes))
        )
        mock_dhcp._eth.read_udp.side_effect = (
            (x, bytes([2] * x)) for x in bytes_returned
        )
        assert mock_dhcp._receive_dhcp_response(time.monotonic() + 15) == total_bytes
        assert wiz_dhcp._BUFF == expected_result

    @freeze_time("2022-10-10")
    def test_buffer_does_not_overrun(self, mocker, mock_dhcp):
        mock_dhcp._wiz_sock = 1
        mock_dhcp._next_resend = time.monotonic() + 15
        mock_dhcp._eth.read_udp.return_value = (
            wiz_dhcp._BUFF_LENGTH,
            bytes([2] * wiz_dhcp._BUFF_LENGTH),
        )
        mock_dhcp._receive_dhcp_response(time.monotonic() + 10)
        mock_dhcp._eth.read_udp.assert_called_once_with(1, wiz_dhcp._BUFF_LENGTH)
        mock_dhcp._eth.read_udp.reset_mock()
        mock_dhcp._eth.read_udp.side_effect = [
            (200, bytes([2] * 200)),
            (118, bytes([2] * 118)),
        ]
        mock_dhcp._receive_dhcp_response(time.monotonic() + 10)
        assert mock_dhcp._eth.read_udp.call_count == 2
        assert mock_dhcp._eth.read_udp.call_args_list == [
            mocker.call(1, 512),
            mocker.call(1, 312),
        ]


class TestProcessMessagingStates:
    @pytest.mark.parametrize(
        "state, bad_messages",
        (
            (
                wiz_dhcp._STATE_SELECTING,
                (
                    0,
                    wiz_dhcp._DHCP_ACK,
                    wiz_dhcp._DHCP_REQUEST,
                    wiz_dhcp._DHCP_DECLINE,
                    wiz_dhcp._DHCP_DISCOVER,
                    wiz_dhcp._DHCP_NAK,
                    wiz_dhcp._DHCP_INFORM,
                    wiz_dhcp._DHCP_RELEASE,
                ),
            ),
            (
                wiz_dhcp._STATE_REQUESTING,
                (
                    0,
                    wiz_dhcp._DHCP_OFFER,
                    wiz_dhcp._DHCP_REQUEST,
                    wiz_dhcp._DHCP_DECLINE,
                    wiz_dhcp._DHCP_DISCOVER,
                    wiz_dhcp._DHCP_INFORM,
                    wiz_dhcp._DHCP_RELEASE,
                ),
            ),
        ),
    )
    def test_called_with_bad_or_no_message(self, mock_dhcp, state, bad_messages):
        # Setup with the current state.
        mock_dhcp._dhcp_state = state
        # Test against 0 (no message) and all bad message types.
        for message_type in bad_messages:
            # Test.
            mock_dhcp._process_messaging_states(message_type=message_type)
            # Confirm that a 0 message does not change state.
            assert mock_dhcp._dhcp_state == state

    def test_called_from_selecting_good_message(self, mock_dhcp):
        # Setup with the required state.
        mock_dhcp._dhcp_state = wiz_dhcp._STATE_SELECTING
        # Test.
        mock_dhcp._process_messaging_states(message_type=wiz_dhcp._DHCP_OFFER)
        # Confirm correct new state.
        assert mock_dhcp._dhcp_state == wiz_dhcp._STATE_REQUESTING

    @freeze_time("2022-3-4")
    @pytest.mark.parametrize("lease_time", (200, 8000))
    def test_called_from_requesting_with_ack(self, mock_dhcp, lease_time):
        # Setup with the required state.
        mock_dhcp._dhcp_state = wiz_dhcp._STATE_REQUESTING
        # Set the lease_time (zero forces a default to be used).
        mock_dhcp._lease = lease_time
        # Set renew to "renew" to confirm that an ACK sets it to None.
        mock_dhcp._renew = "renew"
        # Set a start time.
        mock_dhcp._start_time = time.monotonic()
        # Test.
        mock_dhcp._process_messaging_states(message_type=wiz_dhcp._DHCP_ACK)
        # Confirm timers are correctly set.
        assert mock_dhcp._t1 == time.monotonic() + lease_time // 2
        assert mock_dhcp._t2 == time.monotonic() + lease_time - lease_time // 8
        assert mock_dhcp._lease == time.monotonic() + lease_time
        # Check that renew is forced to None
        assert mock_dhcp._renew is None
        # FSM state should be bound.
        assert mock_dhcp._dhcp_state == wiz_dhcp._STATE_BOUND

    def test_called_from_requesting_with_nak(self, mock_dhcp):
        # Setup with the required state.
        mock_dhcp._dhcp_state = wiz_dhcp._STATE_REQUESTING
        # Test.
        mock_dhcp._process_messaging_states(message_type=wiz_dhcp._DHCP_NAK)
        # FSM state should be init after receiving a NAK response.
        assert mock_dhcp._dhcp_state == wiz_dhcp._STATE_INIT
