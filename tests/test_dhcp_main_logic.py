# SPDX-FileCopyrightText: 2022 Martin Stephens
#
# SPDX-License-Identifier: MIT
"""Tests to confirm that there are no changes in behaviour to methods and functions.
These test are not exhaustive, but are a sanity check while making changes to the module."""
import time

# pylint: disable=no-self-use, redefined-outer-name, protected-access, invalid-name, too-many-arguments
import pytest
from freezegun import freeze_time
import adafruit_wiznet5k.adafruit_wiznet5k_dhcp as wiz_dhcp


@pytest.fixture
def mock_wiznet5k(mocker):
    """Mock WIZNET5K so that the DHCP class can be tested without hardware."""
    return mocker.patch("adafruit_wiznet5k.adafruit_wiznet5k.WIZNET5K", autospec=True)


@pytest.fixture
def mock_socket(mocker):
    """Mock socket module to allow test data to be read and written by the DHCP module."""
    return mocker.patch(
        "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.socket.socket", autospec=True
    )


@pytest.fixture
def dhcp_with_mock_5k(mock_wiznet5k):
    """Instance of DHCP with mock WIZNET5K interface."""
    return wiz_dhcp.DHCP(mock_wiznet5k, (4, 5, 6, 7, 8, 9))


@pytest.fixture
def dhcp_mock_5k_with_socket(dhcp_with_mock_5k, mock_socket):
    """Instance of DHCP with mock WIZNET5K interface and a mock socket."""
    dhcp_with_mock_5k._sock = mock_socket()
    return dhcp_with_mock_5k


class TestHandleDhcpMessage:
    @freeze_time("2022-06-10")
    def test_with_valid_data_on_socket_selecting(
        self, mocker, dhcp_mock_5k_with_socket
    ):
        # Mock the methods that will be checked for this test.
        mocker.patch.object(
            dhcp_mock_5k_with_socket,
            "_parse_dhcp_response",
            autospec=True,
            return_value=wiz_dhcp.DHCP_OFFER,
        )
        mocker.patch.object(
            dhcp_mock_5k_with_socket, "_send_message_set_next_state", autospec=True
        )
        # Set up initial values for the test
        wiz_dhcp._BUFF = b""
        dhcp_mock_5k_with_socket._sock.available.return_value = 24
        dhcp_mock_5k_with_socket._sock.recv.return_value = b"HelloWorld"
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING
        # Test
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Check response
        assert wiz_dhcp._BUFF == b"HelloWorld"
        dhcp_mock_5k_with_socket._parse_dhcp_response.assert_called_once()
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_called_once_with(
            next_state=wiz_dhcp.STATE_REQUESTING, max_retries=3
        )

    @freeze_time("2022-06-10")
    def test_with_valid_data_on_socket_requesting(
        self, mocker, dhcp_mock_5k_with_socket
    ):
        # Mock the methods that will be checked for this test.
        mocker.patch.object(
            dhcp_mock_5k_with_socket,
            "_parse_dhcp_response",
            autospec=True,
            return_value=wiz_dhcp.DHCP_ACK,
        )
        mocker.patch.object(
            dhcp_mock_5k_with_socket, "_send_message_set_next_state", autospec=True
        )
        # Set up initial values for the test
        wiz_dhcp._BUFF = b""
        dhcp_mock_5k_with_socket._sock.available.return_value = 24
        dhcp_mock_5k_with_socket._sock.recv.return_value = b"HelloWorld"
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_REQUESTING
        initial_transaction_id = dhcp_mock_5k_with_socket._transaction_id
        # Test
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Check response
        assert wiz_dhcp._BUFF == b"HelloWorld"
        assert dhcp_mock_5k_with_socket._transaction_id == initial_transaction_id + 1
        assert dhcp_mock_5k_with_socket._renew is False
        assert dhcp_mock_5k_with_socket._sock is None
        assert dhcp_mock_5k_with_socket._dhcp_state == wiz_dhcp.STATE_BOUND
        dhcp_mock_5k_with_socket._parse_dhcp_response.assert_called_once()
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_not_called()

    @freeze_time("2022-06-10")
    @pytest.mark.parametrize(
        "fsm_state, msg_type",
        (
            (wiz_dhcp.STATE_SELECTING, wiz_dhcp.DHCP_ACK),
            (wiz_dhcp.STATE_REQUESTING, wiz_dhcp.DHCP_OFFER),
        ),
    )
    def test_with_wrong_message_type_on_socket_nonblocking(
        self,
        mocker,
        dhcp_mock_5k_with_socket,
        fsm_state,
        msg_type,
    ):
        # Mock the methods that will be checked for this test.
        mocker.patch.object(
            dhcp_mock_5k_with_socket,
            "_parse_dhcp_response",
            autospec=True,
            return_value=msg_type,
        )
        mocker.patch.object(
            dhcp_mock_5k_with_socket, "_send_message_set_next_state", autospec=True
        )
        # Set up initial values for the test
        wiz_dhcp._BUFF = b""
        dhcp_mock_5k_with_socket._sock.available.return_value = 32
        dhcp_mock_5k_with_socket._sock.recv.return_value = b"TweetTweet"
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        dhcp_mock_5k_with_socket._dhcp_state = fsm_state
        # Test
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Check response
        dhcp_mock_5k_with_socket._sock.recv.assert_called_once()
        assert wiz_dhcp._BUFF == b"TweetTweet"
        dhcp_mock_5k_with_socket._parse_dhcp_response.assert_called_once()
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_not_called()
        assert dhcp_mock_5k_with_socket._dhcp_state == fsm_state

    @freeze_time("2022-06-10")
    @pytest.mark.parametrize(
        "fsm_state, msg_type, next_state",
        (
            (
                wiz_dhcp.STATE_SELECTING,
                [wiz_dhcp.DHCP_ACK, wiz_dhcp.DHCP_ACK, wiz_dhcp.DHCP_OFFER],
                wiz_dhcp.STATE_REQUESTING,
            ),
            (
                wiz_dhcp.STATE_REQUESTING,
                [
                    wiz_dhcp.DHCP_OFFER,
                    wiz_dhcp.DHCP_OFFER,
                    wiz_dhcp.DHCP_ACK,
                ],
                wiz_dhcp.STATE_BOUND,
            ),
        ),
    )
    def test_with_wrong_message_type_on_socket_blocking(
        self, mocker, dhcp_mock_5k_with_socket, fsm_state, msg_type, next_state
    ):
        # Mock the methods that will be checked for this test.
        mocker.patch.object(
            dhcp_mock_5k_with_socket,
            "_parse_dhcp_response",
            autospec=True,
            side_effect=msg_type,
        )
        mocker.patch.object(
            dhcp_mock_5k_with_socket,
            "_send_message_set_next_state",
            autospec=True,
        )
        # Set up initial values for the test
        wiz_dhcp._BUFF = b""
        dhcp_mock_5k_with_socket._sock.available.return_value = 32
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        dhcp_mock_5k_with_socket._dhcp_state = fsm_state
        dhcp_mock_5k_with_socket._blocking = True
        # Test
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Check response
        assert dhcp_mock_5k_with_socket._parse_dhcp_response.call_count == 3
        if fsm_state == wiz_dhcp.STATE_SELECTING:
            dhcp_mock_5k_with_socket._send_message_set_next_state.assert_called_once()
        elif fsm_state == wiz_dhcp.STATE_REQUESTING:  # Not called for STATE_REQUESTING
            dhcp_mock_5k_with_socket._send_message_set_next_state.assert_not_called()
            assert dhcp_mock_5k_with_socket._dhcp_state == next_state
