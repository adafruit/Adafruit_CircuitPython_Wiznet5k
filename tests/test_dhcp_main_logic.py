# SPDX-FileCopyrightText: 2022 Martin Stephens
#
# SPDX-License-Identifier: MIT
"""Tests to confirm the behaviour of methods and functions in the finite state machine.
These test are not exhaustive, but are a sanity check while making changes to the module."""
import time

# pylint: disable=no-self-use, redefined-outer-name, protected-access, invalid-name, too-many-arguments
import pytest
from freezegun import freeze_time
import adafruit_wiznet5k.adafruit_wiznet5k_dhcp as wiz_dhcp


@pytest.fixture
def dhcp_mock_5k_with_socket(mocker):
    """Instance of DHCP with mock WIZNET5K interface and a mock socket."""
    # Reset the send / receive buffer for each run test.
    wiz_dhcp._BUFF = b""
    # Mock the WIZNET5K class to factor its behaviour out of the tests and to control
    # responses from methods.
    mock_wiznet5k = mocker.patch(
        "adafruit_wiznet5k.adafruit_wiznet5k.WIZNET5K", autospec=True
    )
    # Instantiate DHCP class for testing.
    dhcp = wiz_dhcp.DHCP(mock_wiznet5k, (4, 5, 6, 7, 8, 9))
    # Mock the socket for injecting recv() and available() values and to monitor calls
    # to send()
    dhcp._sock = mocker.patch(
        "adafruit_wiznet5k.adafruit_wiznet5k_dhcp.socket.socket", autospec=True
    )
    # Mock the _parse_dhcp_response method to inject message types without supplying
    # fake DHCP message packets.
    mocker.patch.object(dhcp, "_parse_dhcp_response", autospec=True)
    # Mock the _send_message_set_next_state to monitor calls to it.
    mocker.patch.object(dhcp, "_send_message_set_next_state", autospec=True)
    yield dhcp


@pytest.mark.parametrize("blocking", (True, False))
def test_state_machine_blocking_set_correctly(dhcp_mock_5k_with_socket, blocking):
    # Set the initial state to the opposite of the attribute.
    dhcp_mock_5k_with_socket._blocking = not blocking
    # Test.
    dhcp_mock_5k_with_socket._dhcp_state_machine(blocking=blocking)
    # Check that the attribute is correct.
    assert dhcp_mock_5k_with_socket._blocking is blocking


def test_state_machine_default_blocking(dhcp_mock_5k_with_socket):
    # Default is False so set to True.
    dhcp_mock_5k_with_socket._blocking = True
    # Test.
    dhcp_mock_5k_with_socket._dhcp_state_machine()
    # Check that _blocking is False.
    assert dhcp_mock_5k_with_socket._blocking is False


class TestHandleDhcpMessage:
    """
    Test the _handle_dhcp_message() method."""

    @freeze_time("2022-06-10")
    def test_with_valid_data_on_socket_selecting(self, dhcp_mock_5k_with_socket):
        # Set up initial values for the test.
        # Start FSM in SELECTING state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING
        # Receive the expected OFFER message type.
        dhcp_mock_5k_with_socket._parse_dhcp_response.return_value = wiz_dhcp.DHCP_OFFER
        # Have some data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 24
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Confirm that the message would be parsed.
        dhcp_mock_5k_with_socket._parse_dhcp_response.assert_called_once()
        # Confirm that the correct next FSM state was set.
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_called_once_with(
            next_state=wiz_dhcp.STATE_REQUESTING, max_retries=3
        )

    @freeze_time("2022-06-10")
    def test_with_valid_data_on_socket_requesting_not_renew(
        self, dhcp_mock_5k_with_socket
    ):
        # Set up initial values for the test.
        # Start FSM in REQUESTING state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_REQUESTING
        # Receive the expected OFFER message type.
        dhcp_mock_5k_with_socket._parse_dhcp_response.return_value = wiz_dhcp.DHCP_ACK
        # Have some data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 24
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Store the transaction ID for comparison.
        initial_transaction_id = dhcp_mock_5k_with_socket._transaction_id
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Transaction ID incremented.
        assert dhcp_mock_5k_with_socket._transaction_id == initial_transaction_id + 1
        # Renew has not changed.
        assert dhcp_mock_5k_with_socket._renew is False
        # The socket has been released.
        assert dhcp_mock_5k_with_socket._sock is None
        # The correct state has been set.
        assert dhcp_mock_5k_with_socket._dhcp_state == wiz_dhcp.STATE_BOUND
        # No DHCP message to be sent.
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
        dhcp_mock_5k_with_socket,
        fsm_state,
        msg_type,
    ):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._parse_dhcp_response.return_value = msg_type
        # Receive the incorrect message type.
        dhcp_mock_5k_with_socket._dhcp_state = fsm_state
        # Have some data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 32
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Nonblocking mode.
        dhcp_mock_5k_with_socket._blocking = False
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Only one call to recv() (and therefore other methods) because nonblocking.
        dhcp_mock_5k_with_socket._sock.recv.assert_called_once()
        dhcp_mock_5k_with_socket._parse_dhcp_response.assert_called_once()
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_not_called()
        # Confirm that the FSM state has not changed.
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
        self, dhcp_mock_5k_with_socket, fsm_state, msg_type, next_state
    ):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = fsm_state
        # Receive the incorrect message types, then a correct one.
        dhcp_mock_5k_with_socket._parse_dhcp_response.side_effect = msg_type
        # Have some data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 32
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Put FSM into blocking mode so that multiple attempts are made.
        dhcp_mock_5k_with_socket._blocking = True
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Confirm call count matches the number of messages received.
        assert dhcp_mock_5k_with_socket._parse_dhcp_response.call_count == len(msg_type)
        # Confirm correct calls to _send_message_set_next_state are made.
        if fsm_state == wiz_dhcp.STATE_SELECTING:
            dhcp_mock_5k_with_socket._send_message_set_next_state.assert_called_once()
        elif fsm_state == wiz_dhcp.STATE_REQUESTING:  # Not called for STATE_REQUESTING
            dhcp_mock_5k_with_socket._send_message_set_next_state.assert_not_called()
            # Confirm correct final FSM state.
            assert dhcp_mock_5k_with_socket._dhcp_state == next_state

    @freeze_time("2022-06-10")
    def test_with_no_data_on_socket_blocking(
        self,
        dhcp_mock_5k_with_socket,
    ):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING
        # Return a correct message type once data is on the socket.
        dhcp_mock_5k_with_socket._parse_dhcp_response.return_value = wiz_dhcp.DHCP_OFFER
        # No data on the socket, and finally some data.
        dhcp_mock_5k_with_socket._sock.available.side_effect = [0, 0, 32]
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Put FSM into blocking mode so that multiple attempts are made.
        dhcp_mock_5k_with_socket._blocking = True
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Check available() called the correct number of times.
        assert dhcp_mock_5k_with_socket._sock.available.call_count == 3
        # Confirm that only one message was processed.
        dhcp_mock_5k_with_socket._sock.recv.assert_called_once()

    @freeze_time("2022-06-10")
    def test_with_no_data_on_socket_nonblocking(
        self,
        dhcp_mock_5k_with_socket,
    ):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING
        # Return a correct message type if data is on the socket.
        dhcp_mock_5k_with_socket._parse_dhcp_response.return_value = wiz_dhcp.DHCP_OFFER
        # No data on the socket, and finally some data.
        dhcp_mock_5k_with_socket._sock.available.side_effect = [0, 0, 32]
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Put FSM into nonblocking mode so that a single attempt is made.
        dhcp_mock_5k_with_socket._blocking = False
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Available should only be called once in nonblocking mode.
        dhcp_mock_5k_with_socket._sock.available.assert_called_once()
        # Check that no data was read from the socket.
        dhcp_mock_5k_with_socket._sock.recv.assert_not_called()
        # Confirm that the FSM state has not changed.
        assert dhcp_mock_5k_with_socket._dhcp_state == wiz_dhcp.STATE_SELECTING

    @freeze_time("2022-06-10")
    def test_with_valueerror_nonblocking(
        self,
        dhcp_mock_5k_with_socket,
    ):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING
        # Raise exceptions due to bad DHCP messages.
        dhcp_mock_5k_with_socket._parse_dhcp_response.side_effect = [
            ValueError,
            ValueError,
        ]
        # Have some data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 32
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Put FSM into nonblocking mode so that a single attempt is made.
        dhcp_mock_5k_with_socket._blocking = False
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Available should only be called once in nonblocking mode.
        dhcp_mock_5k_with_socket._sock.available.assert_called_once()
        # Confirm that _send_message_set_next_state not called.
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_not_called()
        # Check that FSM state has not changed.
        assert dhcp_mock_5k_with_socket._dhcp_state == wiz_dhcp.STATE_SELECTING

    @freeze_time("2022-06-10")
    def test_with_valueerror_blocking(
        self,
        dhcp_mock_5k_with_socket,
    ):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING
        # Raise exceptions due to bad DHCP messages, then a good one.
        dhcp_mock_5k_with_socket._parse_dhcp_response.side_effect = [
            ValueError,
            ValueError,
            wiz_dhcp.DHCP_OFFER,
        ]
        # Have some data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 32
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Put FSM into blocking mode so that multiple attempts are made.
        dhcp_mock_5k_with_socket._blocking = True
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Check available() called three times.
        assert dhcp_mock_5k_with_socket._sock.available.call_count == 3
        # Confirm that _send_message_set_next_state was called to change FSM state.
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_called_once_with(
            next_state=wiz_dhcp.STATE_REQUESTING, max_retries=3
        )

    @freeze_time("2022-06-10", auto_tick_seconds=1)
    def test_timeout_blocking(
        self,
        dhcp_mock_5k_with_socket,
    ):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING
        # Never have data on the socket to force a timeout.
        dhcp_mock_5k_with_socket._sock.available.return_value = 0
        # Set an initial value for timeout.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Set maximum retries to 3.
        dhcp_mock_5k_with_socket._max_retries = 3
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Put FSM into blocking mode so that multiple attempts are made.
        dhcp_mock_5k_with_socket._blocking = True
        # Test that a TimeoutError is raised.
        with pytest.raises(TimeoutError):
            dhcp_mock_5k_with_socket._handle_dhcp_message()

    @freeze_time("2022-06-10", auto_tick_seconds=1)
    def test_timeout_nonblocking(
        self,
        dhcp_mock_5k_with_socket,
    ):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING
        # Never have data on the socket to force a timeout.
        dhcp_mock_5k_with_socket._sock.available.return_value = 0
        # Set up initial values for the test
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Set maximum retries to 3.
        dhcp_mock_5k_with_socket._max_retries = 3
        # Test an initial negotiation, not a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = False
        # Put FSM into nonblocking mode so that a single attempt is made.
        dhcp_mock_5k_with_socket._blocking = False
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Confirm that the retries was not incremented, i.e. the loop executed once.
        assert dhcp_mock_5k_with_socket._retries == 0

    @freeze_time("2022-06-10")
    def test_requesting_with_renew_nak(self, dhcp_mock_5k_with_socket):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_REQUESTING
        # Return a correct message type.
        dhcp_mock_5k_with_socket._parse_dhcp_response.return_value = wiz_dhcp.DHCP_NAK
        # Have some data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 32
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Put FSM into nonblocking mode so that a single attempt is made.
        dhcp_mock_5k_with_socket._blocking = False
        # Test a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = True
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Confirm _renew remains True
        assert dhcp_mock_5k_with_socket._renew is True
        # Confirm that a NAK puts the FSM into the INIT state.
        assert dhcp_mock_5k_with_socket._dhcp_state == wiz_dhcp.STATE_INIT

    @freeze_time("2022-06-10")
    def test_requesting_with_renew_ack(self, dhcp_mock_5k_with_socket):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_REQUESTING
        # Return a correct message type.
        dhcp_mock_5k_with_socket._parse_dhcp_response.return_value = wiz_dhcp.DHCP_ACK
        # Have some data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 32
        # Avoid a timeout before checking the message.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Put FSM into nonblocking mode so that a single attempt is made.
        dhcp_mock_5k_with_socket._blocking = False
        # Test a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = True
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Lease renewed so confirm _renew is False.
        assert dhcp_mock_5k_with_socket._renew is False
        # Confirm that socket was released.
        assert dhcp_mock_5k_with_socket._sock is None
        # Confirm that the state is BOUND.
        assert dhcp_mock_5k_with_socket._dhcp_state == wiz_dhcp.STATE_BOUND

    @freeze_time("2022-06-10")
    def test_requesting_with_renew_no_data(self, dhcp_mock_5k_with_socket):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_REQUESTING
        # Never have data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 0
        # Initial timeout value.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Put FSM into nonblocking mode so that a single attempt is made.
        dhcp_mock_5k_with_socket._blocking = False
        # Test a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = True
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Confirm that _renew remains True
        assert dhcp_mock_5k_with_socket._renew is True
        # Confirm that state remains as REQUESTING
        assert dhcp_mock_5k_with_socket._dhcp_state == wiz_dhcp.STATE_REQUESTING

    @freeze_time("2022-06-10", auto_tick_seconds=60)
    def test_requesting_with_timeout_renew(self, dhcp_mock_5k_with_socket):
        # Set up initial values for the test.
        # Start FSM in required state.
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_REQUESTING
        # Never have data on the socket.
        dhcp_mock_5k_with_socket._sock.available.return_value = 0
        # Initial timeout value.
        dhcp_mock_5k_with_socket._next_resend = time.monotonic() + 5
        # Set retries to 3 so that it times out on the first pass.
        dhcp_mock_5k_with_socket._retries = 3
        # Test a renewal or rebind.
        dhcp_mock_5k_with_socket._renew = True
        # Put FSM into blocking mode so that multiple attempts are made.
        dhcp_mock_5k_with_socket._blocking = True
        # Test.
        dhcp_mock_5k_with_socket._handle_dhcp_message()
        # Confirm that _renew remains True
        assert dhcp_mock_5k_with_socket._renew is True
        # Confirm that state remains as REQUESTING
        assert dhcp_mock_5k_with_socket._dhcp_state == wiz_dhcp.STATE_REQUESTING


class TestStateMachine:
    def test_init_state(self, mocker, dhcp_mock_5k_with_socket):
        mocker.patch.object(dhcp_mock_5k_with_socket, "_dsm_reset")
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_INIT

        dhcp_mock_5k_with_socket._dhcp_state_machine()

        dhcp_mock_5k_with_socket._dsm_reset.assert_called_once()
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_called_once_with(
            next_state=wiz_dhcp.STATE_SELECTING, max_retries=3
        )

    def test_selecting_state(self, mocker, dhcp_mock_5k_with_socket):
        mocker.patch.object(dhcp_mock_5k_with_socket, "_handle_dhcp_message")

        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_SELECTING

        dhcp_mock_5k_with_socket._dhcp_state_machine()

        assert dhcp_mock_5k_with_socket._max_retries == 3
        dhcp_mock_5k_with_socket._handle_dhcp_message.assert_called_once()

    def test_requesting_state(self, mocker, dhcp_mock_5k_with_socket):
        mocker.patch.object(dhcp_mock_5k_with_socket, "_handle_dhcp_message")

        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_REQUESTING

        dhcp_mock_5k_with_socket._dhcp_state_machine()

        assert dhcp_mock_5k_with_socket._max_retries == 3
        dhcp_mock_5k_with_socket._handle_dhcp_message.assert_called_once()

    @pytest.mark.parametrize(
        "elapsed_time, expected_state",
        (
            (
                20.0,
                wiz_dhcp.STATE_BOUND,
            ),
            (60.0, wiz_dhcp.STATE_BOUND),
            (110.0, wiz_dhcp.STATE_BOUND),
            (160.0, wiz_dhcp.STATE_INIT),
        ),
    )
    def test_bound_state(self, dhcp_mock_5k_with_socket, elapsed_time, expected_state):
        with freeze_time("2022-10-12") as frozen_datetime:
            dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_BOUND
            dhcp_mock_5k_with_socket._t1 = time.monotonic() + 50
            dhcp_mock_5k_with_socket._t2 = time.monotonic() + 100
            dhcp_mock_5k_with_socket._lease_time = time.monotonic() + 150

            frozen_datetime.tick(elapsed_time)

            dhcp_mock_5k_with_socket._dhcp_state_machine()

        assert dhcp_mock_5k_with_socket._dhcp_state == expected_state
        if expected_state == wiz_dhcp.STATE_INIT:
            assert dhcp_mock_5k_with_socket._blocking is True

    @freeze_time("2022-10-15")
    def test_renewing_state(self, mocker, dhcp_mock_5k_with_socket):
        mocker.patch.object(dhcp_mock_5k_with_socket, "_socket_setup")
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_RENEWING

        dhcp_mock_5k_with_socket._dhcp_state_machine()

        assert dhcp_mock_5k_with_socket._renew is True
        assert dhcp_mock_5k_with_socket._start_time == time.monotonic()
        dhcp_mock_5k_with_socket._socket_setup.assert_called_once()
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_called_once_with(
            next_state=wiz_dhcp.STATE_REQUESTING, max_retries=3
        )

    @freeze_time("2022-10-15")
    def test_rebinding_state(self, mocker, dhcp_mock_5k_with_socket):
        mocker.patch.object(dhcp_mock_5k_with_socket, "_socket_setup")
        dhcp_mock_5k_with_socket._dhcp_state = wiz_dhcp.STATE_REBINDING
        dhcp_mock_5k_with_socket._dhcp_server_ip = (8, 8, 8, 8)

        dhcp_mock_5k_with_socket._dhcp_state_machine()

        assert dhcp_mock_5k_with_socket.dhcp_server_ip == wiz_dhcp.BROADCAST_SERVER_ADDR
        assert dhcp_mock_5k_with_socket._renew is True
        assert dhcp_mock_5k_with_socket._start_time == time.monotonic()
        dhcp_mock_5k_with_socket._socket_setup.assert_called_once()
        dhcp_mock_5k_with_socket._send_message_set_next_state.assert_called_once_with(
            next_state=wiz_dhcp.STATE_REQUESTING, max_retries=3
        )
