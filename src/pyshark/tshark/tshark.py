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
    possible_paths = [config.get('tshark', 'tshark_path')]

    # Windows search order: configuration file's path, common paths.
    if sys.platform.startswith('win'):
        for env in ('ProgramFiles(x86)', 'ProgramFiles'):
            program_files = os.getenv(env)
            if program_files is not None:
                possible_paths.append(
                    os.path.join(program_files, 'Wireshark', 'tshark.exe')
                )
    # Linux, etc. search order: configuration file's path, the system's path
    else:
        os_path = os.getenv('PATH', '/usr/bin:/usr/lib/tshark:/usr/local/bin')
        for path in os_path.split(':'):
            possible_paths.append(os.path.join(path, 'tshark'))

    for path in possible_paths:
        if os.path.exists(path):
            return path
    raise TSharkNotFoundException(
        'TShark not found. Try adding its location to the configuration file. '
        'Search these paths: {}'.format(possible_paths)
    )

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
