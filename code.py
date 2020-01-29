import time
import board
import busio
import digitalio
from adafruit_wiznet5k import wiznet


cs = digitalio.DigitalInOut(board.D10)
spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

# Initialize wiznet5k module interface
eth = wiznet(spi_bus, cs)