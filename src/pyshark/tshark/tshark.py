"""
Module used for the actual running of TShark
"""
from distutils.version import LooseVersion
import os
import subprocess
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
        win32_progs = os.environ.get('ProgramFiles(x86)', '')
        win64_progs = os.environ.get('ProgramFiles', '')
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

def get_tshark_version():
    parameters = [get_tshark_path(), '-v']
    version_output = subprocess.check_output(parameters).decode("ascii")
    version_line = version_output.splitlines()[0]
    version_string = version_line.split()[1]

    return version_string

def get_tshark_display_filter_flag():
    """
    Returns '-Y' for tshark versions >= 1.10.0 and '-R' for older versions.
    """
    tshark_version = get_tshark_version()
    if LooseVersion(tshark_version) >= LooseVersion("1.10.0"):
        return '-Y'
    else:
        return '-R'

def get_tshark_interfaces():
    """
    Returns a list of interface numbers from the output tshark -D. Used
    internally to capture on multiple interfaces.
    """
    parameters = [get_tshark_path(), '-D']
    tshark_interfaces = subprocess.check_output(parameters).decode("ascii")
    
    return [line.split('.')[0] for line in tshark_interfaces.splitlines()]
