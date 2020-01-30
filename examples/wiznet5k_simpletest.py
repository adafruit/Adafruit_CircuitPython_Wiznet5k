import time

import board
import busio
import digitalio
from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET
from adafruit_wiznet5k.adafruit_wiznet5k_socket import SOCKET

cs = digitalio.DigitalInOut(board.D10)
spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

# Initialize wiznet5k module interface
eth = WIZNET(spi_bus, cs)

# Check if ethernet cable is connected
assert eth.link_status == 1, "Link down. Please connect an ethernet cable."

# Print connection information
print("Hardware MAC Address: ", eth.mac_address)
print("Hardware IP Address: ", eth.ip_address)


#socket = SOCKET(eth)
