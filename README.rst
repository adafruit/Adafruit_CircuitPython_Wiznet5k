Introduction
============

.. image:: https://readthedocs.org/projects/adafruit-circuitpython-wiznet5k/badge/?version=latest
    :target: https://docs.circuitpython.org/projects/wiznet5k/en/latest/
    :alt: Documentation Status

.. image:: https://img.shields.io/discord/327254708534116352.svg
    :target: https://adafru.it/discord
    :alt: Discord

.. image:: https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k/workflows/Build%20CI/badge.svg
    :target: https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k/actions
    :alt: Build Status

Pure-Python interface for WIZNET 5k ethernet modules.

Dependencies
=============
This driver depends on:

* `Adafruit CircuitPython <https://github.com/adafruit/circuitpython>`_
* `Bus Device <https://github.com/adafruit/Adafruit_CircuitPython_BusDevice>`_

Please ensure all dependencies are available on the CircuitPython filesystem.
This is easily achieved by downloading
`the Adafruit library and driver bundle <https://circuitpython.org/libraries>`_.

Installing from PyPI
=====================
On supported GNU/Linux systems like the Raspberry Pi, you can install the driver locally `from
PyPI <https://pypi.org/project/adafruit-circuitpython-wiznet5k/>`_. To install for current user:

.. code-block:: shell

    pip3 install adafruit-circuitpython-wiznet5k

To install system-wide (this may be required in some cases):

.. code-block:: shell

    sudo pip3 install adafruit-circuitpython-wiznet5k

To install in a virtual environment in your current project:

.. code-block:: shell

    mkdir project-name && cd project-name
    python3 -m venv .env
    source .env/bin/activate
    pip3 install adafruit-circuitpython-wiznet5k

Usage Example
=============
This example demonstrates making a HTTP GET request to
wifitest.adafruit.com.

.. code-block:: python

    import board
    import busio
    import digitalio
    import adafruit_requests as requests
    from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K
    import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket

    print("Wiznet5k WebClient Test")

    TEXT_URL = "http://wifitest.adafruit.com/testwifi/index.html"
    JSON_URL = "http://api.coindesk.com/v1/bpi/currentprice/USD.json"

    cs = digitalio.DigitalInOut(board.D10)
    spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

    # Initialize ethernet interface with DHCP
    eth = WIZNET5K(spi_bus, cs)

    # Initialize a requests object with a socket and ethernet interface
    requests.set_socket(socket, eth)

    print("Chip Version:", eth.chip)
    print("MAC Address:", [hex(i) for i in eth.mac_address])
    print("My IP address is:", eth.pretty_ip(eth.ip_address))
    print("IP lookup adafruit.com: %s" %eth.pretty_ip(eth.get_host_by_name("adafruit.com")))


    #eth._debug = True
    print("Fetching text from", TEXT_URL)
    r = requests.get(TEXT_URL)
    print('-'*40)
    print(r.text)
    print('-'*40)
    r.close()

    print()
    print("Fetching json from", JSON_URL)
    r = requests.get(JSON_URL)
    print('-'*40)
    print(r.json())
    print('-'*40)
    r.close()

    print("Done!")

This example demonstrates a simple web server that allows setting the Neopixel color.

.. code-block:: python

    import board
    import busio
    import digitalio
    import neopixel

    from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K
    import adafruit_wiznet5k.adafruit_wiznet5k_wsgiserver as server
    from adafruit_wsgi.wsgi_app import WSGIApp

    print("Wiznet5k Web Server Test")

    # Status LED
    led = neopixel.NeoPixel(board.NEOPIXEL, 1)
    led.brightness = 0.3
    led[0] = (0, 0, 255)

    # W5500 connections
    cs = digitalio.DigitalInOut(board.D10)
    spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

    # Initialize Ethernet interface with DHCP
    eth = WIZNET5K(spi_bus, cs)

    # Here we create our application, registering the
    # following functions to be called on specific HTTP GET requests routes

    web_app = WSGIApp()

    @web_app.route("/led/<r>/<g>/<b>")
    def led_on(request, r, g, b):
        print("LED handler")
        led.fill((int(r), int(g), int(b)))
        return ("200 OK", [], ["LED set!"])

    @web_app.route("/")
    def root(request):
        print("Root handler")
        return ("200 OK", [], ["Root document"])

    @web_app.route("/large")
    def large(request):
        print("Large pattern handler")
        return ("200 OK", [], ["*-.-" * 2000])


    # Here we setup our server, passing in our web_app as the application
    server.set_interface(eth)
    wsgiServer = server.WSGIServer(80, application=web_app)

    print("Open this IP in your browser: ", eth.pretty_ip(eth.ip_address))

    # Start the server
    wsgiServer.start()
    while True:
        # Our main loop where we have the server poll for incoming requests
        wsgiServer.update_poll()
        # Maintain DHCP lease
        eth.maintain_dhcp_lease()
        # Could do any other background tasks here, like reading sensors

Documentation
=============

API documentation for this library can be found on `Read the Docs <https://docs.circuitpython.org/projects/wiznet5k/en/latest/>`_.

This library was written by `Arduino LLC <https://github.com/arduino-libraries/Ethernet/blob/master/AUTHORS>`_. We've converted it to work

For information on building library documentation, please check out `this guide <https://learn.adafruit.com/creating-and-sharing-a-circuitpython-library/sharing-our-docs-on-readthedocs#sphinx-5-1>`_.

Contributing
============

