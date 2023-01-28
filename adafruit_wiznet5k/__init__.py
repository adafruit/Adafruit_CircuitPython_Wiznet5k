# SPDX-FileCopyrightText: 2023 Martin Stephens
#
# SPDX-License-Identifier: MIT

"""Makes a debug message function available to all modules."""
try:
    from typing import TYPE_CHECKING, Optional, Union, Tuple, Sequence

    if TYPE_CHECKING:
        from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K
except ImportError:
    pass

import gc


def debug_msg(
    message: Union[Exception, str, bytes, bytearray], debugging: bool
) -> None:
    """
    Helper function to print debugging messages. If the message is a bytes type
    object, create a hexdump.

    :param Union[Exception, str, bytes, bytearray] message: The message to print.
    :param bool debugging: Only print if debugging is True.
    """
    if debugging:
        if isinstance(message, (bytes, bytearray)):
            message = _hexdump(message)
        print(message)
        del message
        gc.collect()


def _hexdump(src: bytes, length: int = 16):
    """
    Create a hexdump of a bytes object.

    :param bytes src: The bytes object to hexdump.
    :param int length: The number of bytes per line of the hexdump. Defaults to 16.

    :returns str: The hexdump.
    """
    result = []
    for i in range(0, len(src), length):
        chunk = src[i : i + length]
        hexa = " ".join(("%0*X" % (2, x) for x in chunk))
        text = "".join((chr(x) if 0x20 <= x < 0x7F else "." for x in chunk))
        result.append("%04X   %-*s   %s" % (i, length * (2 + 1), hexa, text))
    return "\n".join(result)
