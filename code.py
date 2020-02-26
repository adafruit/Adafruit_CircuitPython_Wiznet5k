import time

import board
import busio
import digitalio
from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket

# Static IP Configuration
MY_IP = (192, 168, 0, 105)
MY_SUBNET_ADDR = (255, 255, 255, 0)
MY_GW_ADDR = (192, 168, 0, 1)
MY_DNS = (192, 168, 0, 1)


# Destination server address
#SERVER_ADDR = 74,125,232,128
SERVER_ADDR = 192,168,0,170
PORT = 2399

cs = digitalio.DigitalInOut(board.D10)
spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

# Initialize wiznet5k module interface
eth = WIZNET(spi_bus, cs, dhcp=False)

# Check if ethernet cable is connected
assert eth.link_status == 1, "Link down. Please connect an ethernet cable."

# Set ifconfig
eth.ifconfig = ((MY_IP, MY_SUBNET_ADDR, MY_GW_ADDR, MY_DNS))



socket.set_interface(eth)

sock = socket.socket()
print(sock._socknum)

sock.connect((SERVER_ADDR, PORT))

data = bytearray(b'Hello CircuitPython')
eth.socket_write(sock._socknum, data)