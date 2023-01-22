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
    Helper function to print debugging messages.

    :param Union[Exception, str, bytes, bytearray] message: The message to print. If the
        message is a bytes type object, create a hexdump.
    :param bool debugging: Only print if debugging is True.
    """
    if debugging:
        if isinstance(message, (bytes, bytearray)):
            temp = ""
            for index, value in enumerate(message):
                if not index % 16:
                    temp += "\n"
                elif not index % 8:
                    temp += "  "
                else:
                    temp += " "
                temp += "{:02x}".format(value)
            message = temp
        print(message)
        del message
        gc.collect()
