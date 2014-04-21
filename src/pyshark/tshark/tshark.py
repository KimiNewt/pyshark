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
    Finds the path of the tshark executable. If the user has specified a
    location in config.ini it will be used. Otherwise default locations
    will be searched.

    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    config = get_config()

    if sys.platform.startswith('win'):
        win32_progs = os.environ['ProgramFiles(x86)']
        win64_progs = os.environ['ProgramFiles']
        tshark_path = ('Wireshark', 'tshark.exe')
        possible_paths = [config.get('tshark', 'tshark_path'),
                          os.path.join(win32_progs, *tshark_path),
                          os.path.join(win64_progs, *tshark_path)]
    else:
        possible_paths = [config.get('tshark', 'tshark_path'),
                          '/usr/bin/tshark',
                          '/usr/lib/tshark',
                          '/usr/local/bin/tshark']
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    raise TSharkNotFoundException('TShark not found in the following locations: ' + ', '.join(possible_paths) +
                                  ' Either place tshark there or add more paths to the config file.')
