# SPDX-FileCopyrightText: 2022 Martin Stephens
#
# SPDX-License-Identifier: MIT

# pylint: disable=no-self-use, redefined-outer-name, protected-access, invalid-name, too-many-arguments
"""Tests to confirm that there are no changes in behaviour to public methods and funtions."""
import pytest
import freezegun
from micropython import const
import adafruit_wiznet5k.adafruit_wiznet5k_dns as wiz_dns
from adafruit_wiznet5k.adafruit_wiznet5k_socket import socket


DEFAULT_DEBUG_ON = False


@pytest.fixture
def wiznet(mocker):
    return mocker.patch("adafruit_wiznet5k.adafruit_wiznet5k.WIZNET5K", autospec=True)


@pytest.fixture
def wrench(mocker):
    return mocker.patch(
        "adafruit_wiznet5k.adafruit_wiznet5k_socket.socket", autospec=True
    )


class TestDNSInit:
    def test_constants(self):
        assert wiz_dns._QUERY_FLAG == const(0x00)
        assert wiz_dns._OPCODE_STANDARD_QUERY == const(0x00)
        assert wiz_dns._RECURSION_DESIRED_FLAG == 1 << 8

        assert wiz_dns._TYPE_A == const(0x0001)
        assert wiz_dns._CLASS_IN == const(0x0001)
        assert wiz_dns._DATA_LEN == const(0x0004)

        # Return codes for gethostbyname
        assert wiz_dns._SUCCESS == const(1)
        assert wiz_dns._TIMED_OUT == const(-1)
        assert wiz_dns._INVALID_SERVER == const(-2)
        assert wiz_dns._TRUNCATED == const(-3)
        assert wiz_dns._INVALID_RESPONSE == const(-4)

        assert wiz_dns._DNS_PORT == const(0x35)  # port used for DNS request

    def test_dns_setup_default(self, wiznet, wrench):
        # Test with DNS address as string and default values.
        dns_server = wiz_dns.DNS(wiznet, "8.8.8.8")
        assert dns_server._iface == wiznet
        assert dns_server._dns_server == "8.8.8.8"
        assert dns_server._debug is False
        assert isinstance(dns_server._sock, socket)
        # assert dns_server._host == b""
        assert dns_server._query_id == 0
        assert dns_server._query_length == 0
        wrench.assert_called_once_with(type=2)

    def test_dns_setup_other_args(self, wiznet):
        # Test with DNS address as tuple and debug on.
        dns_server = wiz_dns.DNS(wiznet, (1, 2, 3, 4), debug=True)
        assert dns_server._dns_server == (1, 2, 3, 4)
        assert dns_server._debug is True
        # assert dns_server._host == b""


class TestDnsGetHostByName:
    @pytest.mark.parametrize(
        "domain, request_id, dns_bytes_sent, dns_bytes_recv, ipv4",
        (
            (
                "www.apple.com",  # Response with CNAME and A type answers.
                0x3476,
                bytearray(
                    b"\x34\x76\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x05apple\x03com\x00"
                    b"\x00\x01\x00\x01"
                ),
                bytearray(
                    b"\x34\x76\x81\x80\x00\x01\x00\x04\x00\x00\x00\x00\x03\x77\x77\x77\x05\x61"
                    b"\x70\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00"
                    b"\x01\x00\x00\x02\xf3\x00\x1b\x03\x77\x77\x77\x05\x61\x70\x70\x6c\x65\x03"
                    b"\x63\x6f\x6d\x07\x65\x64\x67\x65\x6b\x65\x79\x03\x6e\x65\x74\x00\xc0\x2b"
                    b"\x00\x05\x00\x01\x00\x00\x0a\xf2\x00\x2f\x03\x77\x77\x77\x05\x61\x70\x70"
                    b"\x6c\x65\x03\x63\x6f\x6d\x07\x65\x64\x67\x65\x6b\x65\x79\x03\x6e\x65\x74"
                    b"\x0b\x67\x6c\x6f\x62\x61\x6c\x72\x65\x64\x69\x72\x06\x61\x6b\x61\x64\x6e"
                    b"\x73\xc0\x41\xc0\x52\x00\x05\x00\x01\x00\x00\x01\x7d\x00\x18\x05\x65\x36"
                    b"\x38\x35\x38\x04\x64\x73\x63\x78\x0a\x61\x6b\x61\x6d\x61\x69\x65\x64\x67"
                    b"\x65\xc0\x41\xc0\x8d\x00\x01\x00\x01\x00\x00\x00\x14\x00\x04\x17\x38\x9c"
                    b"\x56"
                ),
                bytearray(b"\x178\x9cV"),
            ),
            (
                "learn.adafruit.com",  # Response with multiple A type answers.
                0x9912,
                bytearray(
                    b"\x99\x12\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05learn\x08adafruit\x03"
                    b"com\x00\x00\x01\x00\x01"
                ),
                bytearray(
                    b"\x99\x12\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x05\x6c\x65\x61\x72\x6e"
                    b"\x08\x61\x64\x61\x66\x72\x75\x69\x74\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"
                    b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x68\x14\x27\xf0\xc0\x0c"
                    b"\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x68\x14\x26\xf0"
                ),
                b"\x68\x14\x27\xf0",
            ),
        ),
    )
    def test_good_domain_names_give_correct_ipv4(
        self,
        mocker,
        wiznet,
        wrench,
        domain,
        request_id,
        dns_bytes_sent,
        dns_bytes_recv,
        ipv4,
    ):
        """show that the correct IPv4 is returned for a given domain name."""
        # Pylint does not understand that the wrench fixture is required.
        # pylint: disable=unused-argument

        # Mock randombits so that the IDs for request and reply match
        mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dns.getrandbits",
            return_value=request_id,
        )
        # Set up mock server calls.
        dns_server = wiz_dns.DNS(wiznet, "8.8.8.8", debug=DEFAULT_DEBUG_ON)
        dns_server._sock._available.return_value = len(dns_bytes_recv)
        dns_server._sock.recv.return_value = dns_bytes_recv

        # Check that the correct IPv4 address was received.
        assert dns_server.gethostbyname(bytes(domain, "utf-8")) == ipv4
        # Check that correct socket calls were made.
        dns_server._sock.bind.assert_called_once_with(("", 0x35))
        dns_server._sock.connect.assert_called_once()
        dns_server._sock.send.assert_called_once_with(dns_bytes_sent)

    @pytest.mark.parametrize(
        "dns_bytes_recv, response, _",
        (
            (bytearray(b"\x99\x12\x81\x80\x00\x01\x00"), -1, "Query ID mismatch"),
            (
                bytearray(b"\x93\x21\x01\x00\x00\x01\x00"),
                -1,
                "Query / reply bit not set",
            ),
            (bytearray(b"\x93\x21\x81\x80\x00\x00\x00"), -1, "Question count != 0"),
            (bytearray(b"\x93\x21\x81\x80\x00\x02\x00"), -1, "Question count != 1"),
            (bytearray(b"\x93\x21\x81\x80\x00\x02\x00\x00"), -1, "Answer count == 0"),
            (bytearray(b"\x93\x21\x81\x80\x00\x02\x00\x00"), -1, "Answer count == 0"),
        ),
    )
    def test_bad_response_returns_correct_value(
        self, mocker, wiznet, wrench, dns_bytes_recv, response, _
    ):
        """Show that the correct error code is returned from a bad DNS response."""
        # Pylint does not understand that the wrench fixture is required.
        # pylint: disable=unused-argument

        # Mock randombits so that the ID for request is consistent.
        mocker.patch(
            "adafruit_wiznet5k.adafruit_wiznet5k_dns.getrandbits",
            return_value=0x9321,
        )
        # Set up mock server calls.
        dns_server = wiz_dns.DNS(wiznet, "8.8.8.8", debug=DEFAULT_DEBUG_ON)
        dns_server._sock._available.return_value = len(dns_bytes_recv)
        dns_server._sock.recv.return_value = dns_bytes_recv

        # Check that the correct response was received.
        assert dns_server.gethostbyname(bytes("apple.com", "utf-8")) == response

        # Check that the correct number of calls to _sock.available were made.
        dns_server._sock._available.assert_called()
        assert len(dns_server._sock._available.call_args_list) == 5

    @freezegun.freeze_time("2022-3-4", auto_tick_seconds=0.1)
    def test_retries_with_no_data_on_socket(self, wiznet, wrench):
        """Confirm correct calls made to socket when no data available."""
        # Pylint does not understand that the wrench fixture is required.
        # pylint: disable=unused-argument

        dns_server = wiz_dns.DNS(wiznet, "8.8.8.8", debug=DEFAULT_DEBUG_ON)
        dns_server._sock._available.return_value = 0
        dns_server._sock.recv.return_value = b""
        dns_server.gethostbyname(bytes("domain.name", "utf-8"))

        # Check how many times the socket was polled for data before giving up.
        dns_server._sock._available.assert_called()
        assert len(dns_server._sock._available.call_args_list) == 12
        # Check that no attempt made to read data from the socket.
        dns_server._sock.recv.assert_not_called()

    def test_retries_with_bad_data_on_socket(self, wiznet, wrench):
        """Confirm correct calls made to socket when bad data available."""
        # Pylint does not understand that the wrench fixture is required.
        # pylint: disable=unused-argument

        dns_server = wiz_dns.DNS(wiznet, "8.8.8.8", debug=DEFAULT_DEBUG_ON)
        dns_server._sock._available.return_value = 7
        dns_server._sock.recv.return_value = b"\x99\x12\x81\x80\x00\x01\x00"
        dns_server.gethostbyname(bytes("domain.name", "utf-8"))

        # Check how many times the socket was polled for data before giving up.
        dns_server._sock._available.assert_called()
        assert len(dns_server._sock._available.call_args_list) == 5
        # Check how many attempts were made to read data from the socket.
        dns_server._sock.recv.assert_called()
        assert len(dns_server._sock.recv.call_args_list) == 5
