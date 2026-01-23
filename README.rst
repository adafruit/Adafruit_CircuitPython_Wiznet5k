Introduction
============

.. image:: https://readthedocs.org/projects/wiznet5k/badge/?version=latest
    :target: https://docs.circuitpython.org/projects/wiznet5k/en/latest/
    :alt: Documentation Status

.. image:: https://raw.githubusercontent.com/adafruit/Adafruit_CircuitPython_Bundle/main/badges/adafruit_discord.svg
    :target: https://adafru.it/discord
    :alt: Discord

.. image:: https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k/workflows/Build%20CI/badge.svg
    :target: https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k/actions
    :alt: Build Status

.. image:: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json
    :target: https://github.com/astral-sh/ruff
    :alt: Code Style: Ruff

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
    python3 -m venv .venv
    source .venv/bin/activate
    pip3 install adafruit-circuitpython-wiznet5k

Usage Example
=============
This example demonstrates making a HTTP GET request to
wifitest.adafruit.com.

.. code-block:: python

    import board
    import busio
    import digitalio
    import adafruit_connection_manager
    import adafruit_requests
    from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K

    print("Wiznet5k WebClient Test")

    TEXT_URL = "http://wifitest.adafruit.com/testwifi/index.html"
    JSON_URL = "http://api.coindesk.com/v1/bpi/currentprice/USD.json"

    cs = digitalio.DigitalInOut(board.D10)
    spi_bus = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)

    # Initialize ethernet interface with DHCP
    eth = WIZNET5K(spi_bus, cs)

    # Initialize a requests session
    pool = adafruit_connection_manager.get_radio_socketpool(eth)
    ssl_context = adafruit_connection_manager.get_radio_ssl_context(eth)
    requests = adafruit_requests.Session(pool, ssl_context)

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

Documentation
=============

API documentation for this library can be found on `Read the Docs <https://docs.circuitpython.org/projects/wiznet5k/en/latest/>`_.

For information on building library documentation, please check out `this guide <https://learn.adafruit.com/creating-and-sharing-a-circuitpython-library/sharing-our-docs-on-readthedocs#sphinx-5-1>`_.

Contributing
============

Contributions are welcome! Please read our `Code of Conduct
<https://github.com/adafruit/Adafruit_CircuitPython_Wiznet5k/blob/main/CODE_OF_CONDUCT.md>`_
before contributing to help this project stay welcoming.

License
=============

This library was written by `Arduino LLC <https://github.com/arduino-libraries/Ethernet/blob/master/AUTHORS>`_. We've converted it to work
with `CircuitPython <https://circuitpython.org/>`_ and made changes so it works similarly to `CircuitPython's WIZNET5k wrapper for the WIZnet
5500 Ethernet interface <https://docs.circuitpython.org/en/latest/shared-bindings/wiznet/wiznet5k.html>`_ and CPython's `Socket low-level
networking interface module <https://docs.python.org/3.8/library/socket.html>`_.

This open source code is licensed under the LGPL license (see LICENSE for details).
