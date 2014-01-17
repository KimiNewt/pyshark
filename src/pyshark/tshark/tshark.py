"""
Module used for the actual running of TShark
"""
import os
import sys

from pyshark.config import get_config


class TSharkNotFoundException(Exception):
    pass


def get_tshark_path():
    """
    Finds the path of the tshark executable according to the list in the configuration.

    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    config = get_config()
    if sys.platform.startswith('win'):
        possible_paths = config.get('tshark', 'windows_paths').split(',')
    else:
        possible_paths = config.get('tshark', 'linux_paths').split(',')

    for path in possible_paths:
        if os.path.exists(path):
            return path
    raise TSharkNotFoundException('TShark not found in the following locations: ' + ', '.join(possible_paths) +
                                  ' Either place tshark there or add more paths to the config file.')
