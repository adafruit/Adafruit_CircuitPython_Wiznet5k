import time

import board
import busio
import digitalio
from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket

# Name address for wifitest.adafruit.com
SERVER_ADDRESS = (('104.236.193.178'), 80)

cs = digitalio.DigitalInOut(board.D10)
spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

# Initialize ethernet interface with DHCP
eth = WIZNET(spi_bus, cs)

print("DHCP Assigned IP: ", eth.pretty_ip(eth.ip_address))

socket.set_interface(eth)

# Create a new socket
sock = socket.socket()

print("Connecting to: ", SERVER_ADDRESS[0])
sock.connect(SERVER_ADDRESS)

print("Connected to ", sock.getpeername())

# Make a HTTP Request
sock.send(b"GET /testwifi/index.html HTTP/1.1\n")
sock.send(b"Host: 104.236.193.178")
sock.send(b"Connection: close\n")
sock.send(b"\n")

while True:
    bytes_avail = sock.available()
    print("{} bytes on socket".format(bytes_avail))
    if bytes_avail > 0:
        l = sock.recv(bytes_avail)
        break
    time.sleep(1)