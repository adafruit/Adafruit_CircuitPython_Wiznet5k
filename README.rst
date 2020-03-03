Introduction
============

.. image:: https://readthedocs.org/projects/adafruit-circuitpython-wiznet5k/badge/?version=latest
    :target: https://circuitpython.readthedocs.io/projects/wiznet5k/en/latest/
    :alt: Documentation Status

.. image:: https://img.shields.io/discord/327254708534116352.svg
    :target: https://discord.gg/nBQh6qu
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

    import time

    import board
    import busio
    import digitalio
    from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET
    import adafruit_wiznet5k.adafruit_wiznet5k_socket as socket

    cs = digitalio.DigitalInOut(board.D10)
    spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

    # Initialize ethernet interface with DHCP
    eth = WIZNET5K(spi_bus, cs, debug=True)

    print("DHCP Assigned IP: ", eth.pretty_ip(eth.ip_address))

    socket.set_interface(eth)

    host = 'wifitest.adafruit.com'
    port = 80

    addr_info = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    sock = socket.socket(addr_info[0], addr_info[1], addr_info[2])

    print("Connected to ", sock.getpeername())

    # Make a HTTP Request
    sock.send(b"GET /testwifi/index.html HTTP/1.1\n")
    sock.send(b"Host: 104.236.193.178\n")
    sock.send(b"Connection: close\n\n")

    bytes_avail = 0
    while not bytes_avail:
        bytes_avail = sock.available()
        if bytes_avail > 0:
            data = sock.recv(bytes_avail)
            print(data)
            break
        time.sleep(0.05)

Contributing
============

Contributions are welcome! Please read our `Code of Conduct
<https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k/blob/master/CODE_OF_CONDUCT.md>`_
before contributing to help this project stay welcoming.

Documentation
=============

For information on building library documentation, please check out `this guide <https://learn.adafruit.com/creating-and-sharing-a-circuitpython-library/sharing-our-docs-on-readthedocs#sphinx-5-1>`_.

License
=============

This library was written by `Arduino LLC <https://github.com/arduino-libraries/Ethernet/blob/master/AUTHORS>`_. We've converted it to work
with `CircuitPython <https://circuitpython.org/>`_ and made changes so it works similarly to `CircuitPython's WIZNET5k wrapper for the WIZnet
5500 Ethernet interface <https://circuitpython.readthedocs.io/en/latest/shared-bindings/wiznet/wiznet5k.html>`_ and CPython's `Socket low-level
networking interface module <https://docs.python.org/3.8/library/socket.html>`_.

This open source code is licensed under the LGPL license (see LICENSE for details).