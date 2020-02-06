import time

import board
import busio
import digitalio
from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET
import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket

# Static IP Configuration
MY_IP = (192, 168, 0, 105)
MY_DNS = (192, 168, 0, 1)

# MAC Address
MY_MAC = [0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED]

SERVER_ADDR = (74,125,232,128)

cs = digitalio.DigitalInOut(board.D10)
spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

# Initialize wiznet5k module interface
eth = WIZNET(spi_bus, cs)

# Check if ethernet cable is connected
assert eth.link_status == 1, "Link down. Please connect an ethernet cable."

# Assign static IP
eth.ip_address = MY_IP

# Print connection information
eth.pretty_mac(eth.mac_address)

print("Hardware IP Address: ", eth.pretty_ip(eth.ip_address))
print("Hardware MAC Address: ", eth.pretty_mac(eth.mac_address))

eth.begin(MY_DNS)

socket.set_interface(eth)
sock = socket.socket()

